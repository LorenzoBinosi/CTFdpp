use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, bail};
use tokio::net::lookup_host;
use tokio::time::timeout;

use crate::config::{Config, local_interface_networks};

pub(crate) async fn resolve(config: &Config, hostname: &str, port: u16) -> Result<SocketAddr> {
    if !config.port_allowed(port) {
        bail!("destination port is outside SSH_ALLOWED_PORTS");
    }
    if !safe_hostname(hostname) {
        bail!("destination hostname is invalid");
    }

    let addresses = timeout(config.connect_timeout, lookup_host((hostname, port)))
        .await
        .context("SSH destination DNS lookup timed out")?
        .with_context(|| format!("failed to resolve SSH destination {hostname}"))?
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        bail!("SSH destination did not resolve to an address");
    }

    let runtime_local_networks = local_interface_networks()?;
    let address = select_resolved_address(config, &addresses, &runtime_local_networks)?;
    Ok(SocketAddr::new(address, port))
}

fn select_resolved_address(
    config: &Config,
    addresses: &BTreeSet<IpAddr>,
    runtime_local_networks: &[ipnet::IpNet],
) -> Result<IpAddr> {
    if addresses.is_empty() {
        bail!("SSH destination did not resolve to an address");
    }
    if addresses
        .iter()
        .any(|address| !address_allowed_with_local(config, *address, runtime_local_networks))
    {
        bail!("SSH destination resolution included a disallowed address");
    }
    addresses
        .iter()
        .next()
        .copied()
        .context("SSH destination did not resolve to an address")
}

#[cfg(test)]
pub(crate) fn address_allowed(config: &Config, address: IpAddr) -> bool {
    address_allowed_with_local(config, address, &[])
}

fn address_allowed_with_local(
    config: &Config,
    address: IpAddr,
    runtime_local_networks: &[ipnet::IpNet],
) -> bool {
    if let IpAddr::V6(address) = address {
        if let Some(mapped) = address.to_ipv4_mapped() {
            return address_allowed_with_local(config, IpAddr::V4(mapped), runtime_local_networks);
        }
    }
    if intrinsically_unsafe(address) {
        return false;
    }
    if config
        .local_denied_cidrs
        .iter()
        .chain(runtime_local_networks)
        .any(|network| network.contains(&address))
    {
        return false;
    }
    let required_scope = sensitive_minimum_prefix(address);
    config.allowed_cidrs.iter().any(|network| {
        network.contains(&address)
            && required_scope.is_none_or(|minimum| network.prefix_len() >= minimum)
    })
}

fn intrinsically_unsafe(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (address.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn sensitive_minimum_prefix(address: IpAddr) -> Option<u8> {
    match address {
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            match (first, second) {
                (0, _) => Some(8),
                (10, _) => Some(8),
                (100, 64..=127) => Some(10),
                (172, 16..=31) => Some(12),
                (192, 168) => Some(16),
                (192, 0) => Some(24),
                (192, 0x02) => Some(24),
                (198, 18..=19) => Some(15),
                (198, 51) => Some(24),
                (203, 0) => Some(24),
                (240..=255, _) => Some(4),
                _ => None,
            }
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            if segments[..6] == [0, 0, 0, 0, 0, 0]
                || (segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && segments[2..6] == [0, 0, 0, 0])
            {
                Some(96)
            } else if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1 {
                Some(48)
            } else if segments[0] == 0x0100 && segments[1..4] == [0, 0, 0] {
                Some(64)
            } else if segments[0] & 0xfe00 == 0xfc00 {
                Some(7)
            } else if segments[0] & 0xffc0 == 0xfec0 {
                Some(10)
            } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                Some(32)
            } else if segments[0] == 0x2001 && segments[1] <= 0x01ff {
                Some(23)
            } else if segments[0] == 0x2002 {
                Some(16)
            } else if segments[0] == 0x3fff && segments[1] & 0xf000 == 0 {
                Some(20)
            } else {
                None
            }
        }
    }
}

fn safe_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('-')
        && value.is_ascii()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_-".contains(character))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, PortRange};
    use reqwest::Url;
    use std::{collections::BTreeSet, path::PathBuf, time::Duration};

    fn config() -> Config {
        Config {
            bind_address: "127.0.0.1:8091".parse().unwrap(),
            api_base_url: Url::parse("http://api:8080/").unwrap(),
            api_service_token: "secret".to_owned(),
            identity_directory: PathBuf::from("/tmp/ssh-identities"),
            allowed_origins: BTreeSet::from(["https://ctf.example".to_owned()]),
            allowed_cidrs: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            local_denied_cidrs: vec![],
            allowed_ports: vec![PortRange { start: 22, end: 22 }],
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(600),
            maximum_session: Duration::from_secs(1800),
            heartbeat_interval: Duration::from_secs(15),
            maximum_sessions: 32,
        }
    }

    #[test]
    fn metadata_and_loopback_addresses_are_always_denied() {
        let config = config();
        for address in ["127.0.0.1", "::1", "169.254.169.254", "0.0.0.0"] {
            assert!(!address_allowed(&config, address.parse().unwrap()));
        }
        assert!(address_allowed(&config, "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn broad_public_ranges_do_not_implicitly_authorize_private_or_reserved_space() {
        let broad = config();
        for address in [
            "10.2.3.4",
            "172.20.1.2",
            "192.168.1.2",
            "100.64.1.2",
            "192.0.2.4",
            "fc00::1234",
            "2001:db8::1",
        ] {
            assert!(
                !address_allowed(&broad, address.parse().unwrap()),
                "{address}"
            );
        }

        let mut scoped = config();
        scoped.allowed_cidrs.extend([
            "10.2.0.0/16".parse::<ipnet::IpNet>().unwrap(),
            "172.20.0.0/16".parse::<ipnet::IpNet>().unwrap(),
            "192.168.1.0/24".parse::<ipnet::IpNet>().unwrap(),
            "100.64.0.0/16".parse::<ipnet::IpNet>().unwrap(),
            "192.0.2.0/24".parse::<ipnet::IpNet>().unwrap(),
            "fc00::/48".parse::<ipnet::IpNet>().unwrap(),
            "2001:db8::/48".parse::<ipnet::IpNet>().unwrap(),
        ]);
        for address in [
            "10.2.3.4",
            "172.20.1.2",
            "192.168.1.2",
            "100.64.1.2",
            "192.0.2.4",
            "fc00::1234",
            "2001:db8::1",
        ] {
            assert!(
                address_allowed(&scoped, address.parse().unwrap()),
                "{address}"
            );
        }
    }

    #[test]
    fn rejects_ssh_option_injection_in_hostname() {
        assert!(!safe_hostname("-oProxyCommand=bad"));
        assert!(!safe_hostname("host name"));
        for valid in [
            "host-1.example",
            "ssh_host.internal",
            "host.example.",
            "host..example",
        ] {
            assert!(safe_hostname(valid), "{valid}");
        }
    }

    #[test]
    fn locally_connected_networks_override_explicit_destination_allowlists() {
        let mut config = config();
        config.allowed_cidrs.push("172.20.0.0/16".parse().unwrap());
        config
            .local_denied_cidrs
            .push("172.20.0.0/24".parse().unwrap());

        assert!(!address_allowed(&config, "172.20.0.10".parse().unwrap()));
        assert!(address_allowed(&config, "172.20.1.10".parse().unwrap()));
    }

    #[test]
    fn mixed_allowed_and_disallowed_dns_answers_fail_closed() {
        let config = config();
        let mixed = BTreeSet::from([
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            "192.168.1.5".parse::<IpAddr>().unwrap(),
        ]);
        assert!(select_resolved_address(&config, &mixed, &[]).is_err());

        let public = BTreeSet::from([
            "8.8.4.4".parse::<IpAddr>().unwrap(),
            "8.8.8.8".parse::<IpAddr>().unwrap(),
        ]);
        assert!(select_resolved_address(&config, &public, &[]).is_ok());
    }

    #[test]
    fn dns_resolution_has_an_explicit_timeout() {
        let source = include_str!("destination.rs");
        assert!(source.contains("timeout(config.connect_timeout, lookup_host"));
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_cannot_bypass_ipv4_policy() {
        let config = config();
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.2.3.4",
            "::ffff:172.20.0.1",
        ] {
            assert!(!address_allowed(&config, address.parse().unwrap()));
        }
        assert!(address_allowed(&config, "::ffff:8.8.8.8".parse().unwrap()));
    }
}
