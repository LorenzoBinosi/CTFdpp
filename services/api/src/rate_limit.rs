use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub(crate) struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, Window>>>,
}

struct Window {
    started: Instant,
    count: u32,
    interval: Duration,
}

impl RateLimiter {
    pub(crate) async fn allow(
        &self,
        operation: &str,
        subject: &str,
        limit: u32,
        interval: Duration,
    ) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        windows.retain(|_, window| now.duration_since(window.started) < window.interval);
        let key = format!("{operation}:{subject}");
        let window = windows.entry(key).or_insert(Window {
            started: now,
            count: 0,
            interval,
        });
        if window.interval != interval || now.duration_since(window.started) >= window.interval {
            window.started = now;
            window.count = 0;
            window.interval = interval;
        }
        if window.count >= limit {
            return false;
        }
        window.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn isolates_operations_and_subjects() {
        let limiter = RateLimiter::default();
        let interval = Duration::from_secs(60);
        assert!(limiter.allow("login", "one", 1, interval).await);
        assert!(!limiter.allow("login", "one", 1, interval).await);
        assert!(limiter.allow("register", "one", 1, interval).await);
        assert!(limiter.allow("login", "two", 1, interval).await);
    }

    #[tokio::test]
    async fn short_windows_do_not_erase_longer_windows() {
        let limiter = RateLimiter::default();
        assert!(
            limiter
                .allow("verification", "one", 1, Duration::from_secs(60))
                .await
        );
        assert!(
            limiter
                .allow("login", "one", 1, Duration::from_secs(5))
                .await
        );
        assert!(
            !limiter
                .allow("verification", "one", 1, Duration::from_secs(60))
                .await
        );
    }
}
