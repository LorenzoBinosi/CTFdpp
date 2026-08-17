use std::{
    collections::BTreeSet,
    env,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use reqwest::Url;

// The API considers an active terminal abandoned after 45 seconds without a
// heartbeat. Keep this bound in sync with the stale-session predicate in
// `services/api/src/routes/ssh_hosts.rs` and leave a full heartbeat of margin.
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) bind_address: SocketAddr,
    pub(crate) api_base_url: Url,
    pub(crate) api_service_token: String,
    pub(crate) identity_directory: PathBuf,
    pub(crate) allowed_origins: BTreeSet<String>,
    pub(crate) allowed_cidrs: Vec<IpNet>,
    pub(crate) local_denied_cidrs: Vec<IpNet>,
    pub(crate) allowed_ports: Vec<PortRange>,
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) maximum_session: Duration,
    pub(crate) heartbeat_interval: Duration,
    pub(crate) maximum_sessions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortRange {
    pub(crate) start: u16,
    pub(crate) end: u16,
}

impl PortRange {
    pub(crate) fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        let bind_address = env::var("CTFZONE_SSH_GATEWAY_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8091".to_owned())
            .parse()
            .context("CTFZONE_SSH_GATEWAY_BIND must be a socket address")?;
        let api_base_url = parse_api_url(&required("API_BASE_URL")?)?;
        let api_service_token = required("SSH_GATEWAY_SERVICE_TOKEN")?;
        if api_service_token.contains(['\r', '\n']) {
            bail!("SSH_GATEWAY_SERVICE_TOKEN must be a valid HTTP header value");
        }
        let identity_directory = PathBuf::from(required("SSH_IDENTITY_DIRECTORY")?);
        validate_identity_directory(&identity_directory)?;
        let allowed_origins = parse_origins(&required("SSH_ALLOWED_ORIGINS")?)?;
        let allowed_cidrs = parse_cidrs(&required("SSH_ALLOWED_CIDRS")?)?;
        let local_denied_cidrs = local_interface_networks()?;
        let allowed_ports = parse_ports(&required("SSH_ALLOWED_PORTS")?)?;
        let connect_timeout = Duration::from_secs(positive_u64("SSH_CONNECT_TIMEOUT_SECONDS", 10)?);
        let idle_timeout = Duration::from_secs(positive_u64("SSH_IDLE_TIMEOUT_SECONDS", 600)?);
        let maximum_session = Duration::from_secs(positive_u64("SSH_MAX_SESSION_SECONDS", 1800)?);
        let heartbeat_interval =
            Duration::from_secs(positive_u64("SSH_HEARTBEAT_INTERVAL_SECONDS", 15)?);
        validate_session_timing(idle_timeout, maximum_session, heartbeat_interval)?;
        let maximum_sessions = positive_u64("SSH_MAXIMUM_SESSIONS", 32)?
            .try_into()
            .context("SSH_MAXIMUM_SESSIONS does not fit this platform")?;

        Ok(Self {
            bind_address,
            api_base_url,
            api_service_token,
            identity_directory,
            allowed_origins,
            allowed_cidrs,
            local_denied_cidrs,
            allowed_ports,
            connect_timeout,
            idle_timeout,
            maximum_session,
            heartbeat_interval,
            maximum_sessions,
        })
    }

    pub(crate) fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(origin)
    }

    pub(crate) fn port_allowed(&self, port: u16) -> bool {
        self.allowed_ports.iter().any(|range| range.contains(port))
    }
}

fn validate_session_timing(
    idle_timeout: Duration,
    maximum_session: Duration,
    heartbeat_interval: Duration,
) -> Result<()> {
    if idle_timeout > maximum_session {
        bail!("SSH_IDLE_TIMEOUT_SECONDS cannot exceed SSH_MAX_SESSION_SECONDS");
    }
    if heartbeat_interval >= maximum_session {
        bail!("SSH_HEARTBEAT_INTERVAL_SECONDS must be shorter than the session limit");
    }
    if heartbeat_interval > MAX_HEARTBEAT_INTERVAL {
        bail!(
            "SSH_HEARTBEAT_INTERVAL_SECONDS must not exceed {} seconds",
            MAX_HEARTBEAT_INTERVAL.as_secs()
        );
    }
    Ok(())
}

pub(crate) fn local_interface_networks() -> Result<Vec<IpNet>> {
    let mut networks = Vec::new();
    for interface in getifaddrs().context("failed to inspect local network interfaces")? {
        if !interface.flags.contains(InterfaceFlags::IFF_UP)
            || interface.flags.contains(InterfaceFlags::IFF_LOOPBACK)
        {
            continue;
        }
        let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
            continue;
        };
        let network = if let (Some(address), Some(netmask)) =
            (address.as_sockaddr_in(), netmask.as_sockaddr_in())
        {
            Some(
                IpNet::with_netmask(address.ip().into(), netmask.ip().into())
                    .context("local IPv4 interface has a non-contiguous netmask")?,
            )
        } else if let (Some(address), Some(netmask)) =
            (address.as_sockaddr_in6(), netmask.as_sockaddr_in6())
        {
            Some(
                IpNet::with_netmask(address.ip().into(), netmask.ip().into())
                    .context("local IPv6 interface has a non-contiguous netmask")?,
            )
        } else {
            None
        };
        if let Some(network) = network.map(|network| network.trunc()) {
            if !networks.contains(&network) {
                networks.push(network);
            }
        }
    }
    Ok(networks)
}

fn required(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
        .with_context(|| format!("{name} is required"))
}

fn positive_u64(name: &str, default: u64) -> Result<u64> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .with_context(|| format!("{name} must be a positive integer"))?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn parse_api_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("API_BASE_URL must be an absolute HTTP(S) URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("API_BASE_URL must be an HTTP(S) origin without credentials or query data");
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn parse_origins(value: &str) -> Result<BTreeSet<String>> {
    let mut origins = BTreeSet::new();
    for candidate in split_list(value) {
        let url = Url::parse(candidate).context("SSH_ALLOWED_ORIGINS contains an invalid URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!("SSH_ALLOWED_ORIGINS entries must be HTTP(S) origins without paths");
        }
        origins.insert(url.origin().ascii_serialization());
    }
    if origins.is_empty() {
        bail!("SSH_ALLOWED_ORIGINS must contain at least one origin");
    }
    Ok(origins)
}

fn parse_cidrs(value: &str) -> Result<Vec<IpNet>> {
    let cidrs = split_list(value)
        .map(|candidate| {
            candidate
                .parse::<IpNet>()
                .with_context(|| format!("invalid SSH_ALLOWED_CIDRS entry: {candidate}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if cidrs.is_empty() {
        bail!("SSH_ALLOWED_CIDRS must contain at least one explicit network");
    }
    Ok(cidrs)
}

fn parse_ports(value: &str) -> Result<Vec<PortRange>> {
    let mut ports = Vec::new();
    for candidate in split_list(value) {
        let (start, end) = if let Some((start, end)) = candidate.split_once('-') {
            (parse_port(start)?, parse_port(end)?)
        } else {
            let port = parse_port(candidate)?;
            (port, port)
        };
        if start > end {
            bail!("SSH_ALLOWED_PORTS ranges must be ascending");
        }
        ports.push(PortRange { start, end });
    }
    if ports.is_empty() {
        bail!("SSH_ALLOWED_PORTS must contain at least one port or range");
    }
    Ok(ports)
}

fn parse_port(value: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .with_context(|| format!("invalid SSH port: {value}"))
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_identity_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("SSH_IDENTITY_DIRECTORY must be a normalized absolute directory other than /");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_ports() {
        let ports = parse_ports("22,2200-2299").unwrap();
        assert!(ports.iter().any(|range| range.contains(22)));
        assert!(ports.iter().any(|range| range.contains(2250)));
        assert!(!ports.iter().any(|range| range.contains(23)));
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("99-22").is_err());
    }

    #[test]
    fn serializes_ipv6_origins_with_required_brackets() {
        let origins = parse_origins("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(
            origins,
            BTreeSet::from(["https://[2001:db8::1]:8443".to_owned()])
        );
    }

    #[test]
    fn requires_exact_origins() {
        assert_eq!(
            parse_origins("https://ctf.example, http://localhost:8080")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            ["http://localhost:8080", "https://ctf.example"]
        );
        assert!(parse_origins("https://ctf.example/path").is_err());
        assert!(parse_origins("*").is_err());
    }

    #[test]
    fn identity_root_is_absolute_and_normalized() {
        assert!(validate_identity_directory(Path::new("/var/lib/ctfzone-ssh")).is_ok());
        assert!(validate_identity_directory(Path::new("/var/lib/../ssh")).is_err());
        assert!(validate_identity_directory(Path::new("/")).is_err());
    }

    #[test]
    fn heartbeat_stays_below_the_api_stale_session_window() {
        assert!(
            validate_session_timing(
                Duration::from_secs(600),
                Duration::from_secs(1800),
                Duration::from_secs(30),
            )
            .is_ok()
        );
        assert!(
            validate_session_timing(
                Duration::from_secs(600),
                Duration::from_secs(1800),
                Duration::from_secs(31),
            )
            .is_err()
        );
    }
}
