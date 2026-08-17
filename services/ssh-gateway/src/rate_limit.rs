use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

const DEFAULT_BURST: u32 = 20;
const DEFAULT_REFILL_PER_SECOND: f64 = 2.0;
const DEFAULT_MAXIMUM_CLIENTS: usize = 2_048;
const DEFAULT_CLIENT_EXPIRY: Duration = Duration::from_secs(10 * 60);
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct ClientTicketLimiter {
    state: Mutex<LimiterState>,
    burst: f64,
    refill_per_second: f64,
    maximum_clients: usize,
    client_expiry: Duration,
    cleanup_interval: Duration,
}

struct LimiterState {
    clients: HashMap<IpAddr, Bucket>,
    next_cleanup: Instant,
}

struct Bucket {
    tokens: f64,
    updated_at: Instant,
    last_seen_at: Instant,
}

impl ClientTicketLimiter {
    pub(crate) fn new() -> Self {
        Self::with_policy(
            DEFAULT_BURST,
            DEFAULT_REFILL_PER_SECOND,
            DEFAULT_MAXIMUM_CLIENTS,
            DEFAULT_CLIENT_EXPIRY,
            DEFAULT_CLEANUP_INTERVAL,
            Instant::now(),
        )
    }

    pub(crate) fn allow(&self, client_ip: IpAddr) -> bool {
        self.allow_at(normalize_client_ip(client_ip), Instant::now())
    }

    fn with_policy(
        burst: u32,
        refill_per_second: f64,
        maximum_clients: usize,
        client_expiry: Duration,
        cleanup_interval: Duration,
        now: Instant,
    ) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                clients: HashMap::new(),
                next_cleanup: now + cleanup_interval,
            }),
            burst: f64::from(burst),
            refill_per_second,
            maximum_clients,
            client_expiry,
            cleanup_interval,
        }
    }

    fn allow_at(&self, client_ip: IpAddr, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            // Poisoning means limiter state is no longer trustworthy. Never
            // degrade into an unbounded stream of control-plane requests.
            return false;
        };

        if now >= state.next_cleanup {
            self.remove_expired(&mut state, now);
            state.next_cleanup = now + self.cleanup_interval;
        }

        if let Some(bucket) = state.clients.get_mut(&client_ip) {
            let elapsed = now
                .checked_duration_since(bucket.updated_at)
                .unwrap_or_default()
                .as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.burst);
            bucket.updated_at = now;
            bucket.last_seen_at = now;
            if bucket.tokens < 1.0 {
                return false;
            }
            bucket.tokens -= 1.0;
            return true;
        }

        if state.clients.len() >= self.maximum_clients {
            // Force one cleanup at the hard boundary even when the periodic
            // cleanup is not due. If no idle entry can be reclaimed, reject
            // the new client rather than growing memory without bound.
            self.remove_expired(&mut state, now);
            if state.clients.len() >= self.maximum_clients {
                return false;
            }
        }

        state.clients.insert(
            client_ip,
            Bucket {
                tokens: self.burst - 1.0,
                updated_at: now,
                last_seen_at: now,
            },
        );
        true
    }

    fn remove_expired(&self, state: &mut LimiterState, now: Instant) {
        state.clients.retain(|_, bucket| {
            now.checked_duration_since(bucket.last_seen_at)
                .unwrap_or_default()
                < self.client_expiry
        });
    }
}

fn normalize_client_ip(client_ip: IpAddr) -> IpAddr {
    match client_ip {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return IpAddr::V4(mapped);
            }
            let mut octets = address.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(now: Instant) -> ClientTicketLimiter {
        ClientTicketLimiter::with_policy(
            3,
            2.0,
            2,
            Duration::from_secs(60),
            Duration::from_secs(10),
            now,
        )
    }

    #[test]
    fn token_bucket_enforces_burst_and_refill() {
        let now = Instant::now();
        let limiter = limiter(now);
        let client = "203.0.113.10".parse().unwrap();
        assert!(limiter.allow_at(client, now));
        assert!(limiter.allow_at(client, now));
        assert!(limiter.allow_at(client, now));
        assert!(!limiter.allow_at(client, now));
        assert!(limiter.allow_at(client, now + Duration::from_millis(500)));
        assert!(!limiter.allow_at(client, now + Duration::from_millis(500)));
    }

    #[test]
    fn cardinality_is_bounded_and_idle_clients_expire() {
        let now = Instant::now();
        let limiter = limiter(now);
        assert!(limiter.allow_at("198.51.100.1".parse().unwrap(), now));
        assert!(limiter.allow_at("198.51.100.2".parse().unwrap(), now));
        assert!(!limiter.allow_at("198.51.100.3".parse().unwrap(), now));

        let after_expiry = now + Duration::from_secs(61);
        assert!(limiter.allow_at("198.51.100.3".parse().unwrap(), after_expiry));
        assert_eq!(limiter.state.lock().unwrap().clients.len(), 1);
    }

    #[test]
    fn ipv6_clients_are_grouped_by_64_bit_network() {
        let first = normalize_client_ip("2001:db8:abcd:42::1".parse().unwrap());
        let second = normalize_client_ip("2001:db8:abcd:42:ffff::99".parse().unwrap());
        let other = normalize_client_ip("2001:db8:abcd:43::1".parse().unwrap());
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(
            normalize_client_ip("::ffff:192.0.2.8".parse().unwrap()),
            "192.0.2.8".parse::<IpAddr>().unwrap()
        );
    }
}
