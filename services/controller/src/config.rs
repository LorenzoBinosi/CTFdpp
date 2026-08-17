use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) bind_address: SocketAddr,
    pub(crate) database_url: String,
    pub(crate) journal_path: PathBuf,
    pub(crate) max_command_attempts: i32,
    pub(crate) reconciliation_interval: Duration,
    pub(crate) remote_driver: RemoteDriver,
    pub(crate) remote_operation_timeout: Duration,
    pub(crate) ssh_default_identity_file: Option<PathBuf>,
    pub(crate) ssh_known_hosts_file: PathBuf,
    pub(crate) stale_claim_after: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteDriver {
    Ssh,
    Mock,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        let bind_address = env::var("CTFZONE_CONTROLLER_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8090".to_owned())
            .parse()
            .context("CTFZONE_CONTROLLER_BIND must be a socket address")?;
        let database_url =
            env::var("DATABASE_URL").context("DATABASE_URL is required by the controller")?;
        let journal_path = PathBuf::from(
            env::var("JOURNAL_PATH")
                .unwrap_or_else(|_| "/var/lib/ctfzone-controller/operations.jsonl".to_owned()),
        );
        let remote_driver = match env::var("REMOTE_DRIVER")
            .unwrap_or_else(|_| "ssh".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "ssh" => RemoteDriver::Ssh,
            "mock" => RemoteDriver::Mock,
            value => bail!("REMOTE_DRIVER must be ssh or mock, got {value}"),
        };
        let remote_operation_timeout =
            Duration::from_secs(positive_u64("REMOTE_OPERATION_TIMEOUT_SECONDS", 60)?);
        if remote_operation_timeout < Duration::from_secs(60) {
            anyhow::bail!("REMOTE_OPERATION_TIMEOUT_SECONDS must be at least 60");
        }
        let stale_claim_after =
            Duration::from_secs(positive_u64("STALE_CLAIM_AFTER_SECONDS", 300)?);
        validate_lease_window(stale_claim_after, remote_operation_timeout)?;

        Ok(Self {
            bind_address,
            database_url,
            journal_path,
            max_command_attempts: positive_i32("MAX_COMMAND_ATTEMPTS", 8)?,
            reconciliation_interval: Duration::from_secs(positive_u64(
                "RECONCILIATION_INTERVAL_SECONDS",
                300,
            )?),
            remote_driver,
            remote_operation_timeout,
            ssh_default_identity_file: env::var("SSH_IDENTITY_FILE")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            ssh_known_hosts_file: PathBuf::from(
                env::var("SSH_KNOWN_HOSTS_FILE")
                    .unwrap_or_else(|_| "/etc/ctfzone/ssh_known_hosts".to_owned()),
            ),
            stale_claim_after,
        })
    }
}

fn validate_lease_window(stale_claim_after: Duration, operation_timeout: Duration) -> Result<()> {
    if stale_claim_after <= operation_timeout.saturating_add(Duration::from_secs(5)) {
        bail!(
            "STALE_CLAIM_AFTER_SECONDS must exceed REMOTE_OPERATION_TIMEOUT_SECONDS by more than 5 seconds"
        );
    }
    Ok(())
}

fn positive_u64(key: &str, default: u64) -> Result<u64> {
    let value = env::var(key)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .with_context(|| format!("{key} must be a positive integer"))?
        .unwrap_or(default);
    if value == 0 {
        bail!("{key} must be a positive integer");
    }
    Ok(value)
}

fn positive_i32(key: &str, default: i32) -> Result<i32> {
    let value = env::var(key)
        .ok()
        .map(|value| value.parse::<i32>())
        .transpose()
        .with_context(|| format!("{key} must be a positive integer"))?
        .unwrap_or(default);
    if value <= 0 {
        bail!("{key} must be a positive integer");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_lease_must_outlive_remote_operations() {
        assert!(validate_lease_window(Duration::from_secs(66), Duration::from_secs(60)).is_ok());
        assert!(validate_lease_window(Duration::from_secs(65), Duration::from_secs(60)).is_err());
    }
}
