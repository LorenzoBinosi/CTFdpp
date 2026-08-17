use std::{path::PathBuf, process::Stdio};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};
use uuid::Uuid;

use crate::config::{Config, RemoteDriver};

const GLOBAL_KNOWN_HOSTS_FILE_OPTION: &str = "GlobalKnownHostsFile=/dev/null";
const MAX_FLAG_VALUE_BYTES: usize = 512;

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
pub(crate) struct RemoteServer {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) ssh_port: i32,
    pub(crate) ssh_user: String,
    pub(crate) helper_path: String,
    pub(crate) identity_file: Option<String>,
    pub(crate) host_key_alias: Option<String>,
    pub(crate) pool: Option<String>,
    pub(crate) capacity: i32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteOperation {
    EnsureInstance,
    InspectInstance,
    StopInstance,
    UpdateDeadline,
}

impl RemoteOperation {
    fn helper_name(self) -> &'static str {
        match self {
            Self::EnsureInstance => "ensure-instance",
            Self::InspectInstance => "inspect-instance",
            Self::StopInstance => "stop-instance",
            Self::UpdateDeadline => "update-deadline",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct RemoteResult {
    pub(crate) container_id: Option<String>,
    pub(crate) remote_ip: Option<String>,
    pub(crate) container_port: Option<i32>,
    pub(crate) published_ip: Option<String>,
    pub(crate) published_port: Option<i32>,
    pub(crate) protocol: Option<String>,
    pub(crate) public_hostname: Option<String>,
    pub(crate) endpoint_url: Option<String>,
    pub(crate) effective_expires_at: Option<DateTime<Utc>>,
    pub(crate) absent: Option<bool>,
    pub(crate) ready: Option<bool>,
    pub(crate) runtime_status: Option<String>,
    pub(crate) health_status: Option<String>,
    pub(crate) stale_generation: Option<bool>,
    pub(crate) effective_generation: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct RemoteExecutor {
    driver: RemoteDriver,
    known_hosts_file: PathBuf,
    default_identity_file: Option<PathBuf>,
    operation_timeout: std::time::Duration,
}

impl RemoteExecutor {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            driver: config.remote_driver,
            known_hosts_file: config.ssh_known_hosts_file.clone(),
            default_identity_file: config.ssh_default_identity_file.clone(),
            operation_timeout: config.remote_operation_timeout,
        }
    }

    pub(crate) async fn execute(
        &self,
        server: &RemoteServer,
        operation: RemoteOperation,
        payload: &Value,
    ) -> Result<RemoteResult> {
        validate_flag_value(operation, payload)?;
        match self.driver {
            RemoteDriver::Mock => self.mock(operation, payload).await,
            RemoteDriver::Ssh => self.ssh(server, operation, payload).await,
        }
    }

    async fn mock(&self, operation: RemoteOperation, payload: &Value) -> Result<RemoteResult> {
        let instance_id = payload
            .get("instance_id")
            .and_then(Value::as_str)
            .unwrap_or("mock");
        let suffix = instance_id.bytes().fold(0_u16, |accumulator, byte| {
            accumulator.wrapping_add(u16::from(byte))
        });
        Ok(match operation {
            RemoteOperation::EnsureInstance | RemoteOperation::InspectInstance => RemoteResult {
                container_id: Some(format!("mock-{instance_id}")),
                remote_ip: Some("10.255.0.2".to_owned()),
                container_port: payload
                    .pointer("/deployment/container_port")
                    .and_then(Value::as_i64)
                    .and_then(|value| i32::try_from(value).ok()),
                published_ip: Some("127.0.0.1".to_owned()),
                published_port: Some(30_000 + i32::from(suffix % 20_000)),
                protocol: payload
                    .pointer("/deployment/protocol")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                effective_expires_at: payload
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok()),
                effective_generation: payload.get("generation").and_then(Value::as_i64),
                ready: Some(true),
                ..RemoteResult::default()
            },
            RemoteOperation::StopInstance => RemoteResult {
                absent: Some(true),
                ..RemoteResult::default()
            },
            RemoteOperation::UpdateDeadline => RemoteResult {
                effective_expires_at: payload
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok()),
                effective_generation: payload.get("generation").and_then(Value::as_i64),
                ..RemoteResult::default()
            },
        })
    }

    async fn ssh(
        &self,
        server: &RemoteServer,
        operation: RemoteOperation,
        payload: &Value,
    ) -> Result<RemoteResult> {
        validate_remote_server(server)?;
        validate_startup_timeout(operation, payload, self.operation_timeout)?;
        let identity_file = server
            .identity_file
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| self.default_identity_file.clone())
            .context("remote server has no SSH identity file")?;
        let target = format!("{}@{}", server.ssh_user, server.hostname);
        let mut command = Command::new("ssh");
        command
            .arg("-F")
            .arg("/dev/null")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(GLOBAL_KNOWN_HOSTS_FILE_OPTION)
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.known_hosts_file.display()
            ))
            .arg("-i")
            .arg(identity_file)
            .arg("-p")
            .arg(server.ssh_port.to_string());
        if let Some(alias) = server.host_key_alias.as_deref() {
            command.arg("-o").arg(format!("HostKeyAlias={alias}"));
        }
        command
            .arg(target)
            .arg(&server.helper_path)
            .arg(operation.helper_name())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().context("failed to start SSH client")?;
        let encoded = serde_json::to_vec(payload).context("failed to encode helper request")?;
        let mut stdin = child.stdin.take().context("SSH stdin was not created")?;
        stdin
            .write_all(&encoded)
            .await
            .context("failed to send request to remote helper")?;
        stdin.shutdown().await.ok();

        let output = timeout(self.operation_timeout, child.wait_with_output())
            .await
            .context("remote helper operation timed out")??;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.trim();
            bail!(
                "remote helper {} failed: {}",
                operation.helper_name(),
                if message.is_empty() {
                    "no diagnostic output"
                } else {
                    message
                }
            );
        }
        serde_json::from_slice::<RemoteResult>(&output.stdout)
            .context("remote helper returned invalid JSON")
    }
}

fn validate_flag_value(operation: RemoteOperation, payload: &Value) -> Result<()> {
    let flag_value = payload.pointer("/deployment/flag_value");
    match (operation, flag_value) {
        (RemoteOperation::EnsureInstance, None | Some(Value::Null)) | (_, None) => Ok(()),
        (RemoteOperation::EnsureInstance, Some(Value::String(value)))
            if !value.is_empty()
                && value.len() <= MAX_FLAG_VALUE_BYTES
                && !value.contains('\0') =>
        {
            Ok(())
        }
        (RemoteOperation::EnsureInstance, Some(_)) => bail!("deployment flag_value is invalid"),
        (_, Some(_)) => bail!("deployment flag_value is allowed only during instance startup"),
    }
}

fn validate_startup_timeout(
    operation: RemoteOperation,
    payload: &Value,
    operation_timeout: std::time::Duration,
) -> Result<()> {
    if !matches!(operation, RemoteOperation::EnsureInstance) {
        return Ok(());
    }
    let startup_seconds = payload
        .pointer("/deployment/healthcheck/startup_timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(45);
    if std::time::Duration::from_secs(startup_seconds.saturating_add(5)) > operation_timeout {
        bail!(
            "challenge startup timeout {startup_seconds}s must leave at least 5s within REMOTE_OPERATION_TIMEOUT_SECONDS"
        );
    }
    Ok(())
}

fn validate_remote_server(server: &RemoteServer) -> Result<()> {
    if server.ssh_port <= 0 || server.ssh_port > 65535 {
        bail!("remote server has an invalid SSH port");
    }
    if !safe_host_component(&server.hostname) || !safe_user(&server.ssh_user) {
        bail!("remote server contains invalid SSH target characters");
    }
    if !server.helper_path.starts_with('/')
        || !server
            .helper_path
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._-".contains(character))
    {
        bail!("remote helper path is invalid");
    }
    if server
        .host_key_alias
        .as_deref()
        .is_some_and(|alias| !safe_host_component(alias))
    {
        bail!("remote host key alias is invalid");
    }
    Ok(())
}

fn safe_host_component(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_-".contains(character))
}

fn safe_user(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ssh_option_injection() {
        assert!(!safe_host_component("-oProxyCommand=bad"));
        assert!(!safe_user("bad@host"));
        assert!(safe_host_component("challenge-1.internal"));
        assert!(safe_user("ctfzone_runtime"));
    }

    #[test]
    fn ignores_ambient_global_known_hosts_files() {
        assert_eq!(
            GLOBAL_KNOWN_HOSTS_FILE_OPTION,
            "GlobalKnownHostsFile=/dev/null"
        );
    }

    #[test]
    fn startup_wait_must_fit_inside_remote_operation_timeout() {
        let payload = serde_json::json!({
            "deployment": {"healthcheck": {"startup_timeout_seconds": 56}}
        });
        assert!(
            validate_startup_timeout(
                RemoteOperation::EnsureInstance,
                &payload,
                std::time::Duration::from_secs(60),
            )
            .is_err()
        );
        assert!(
            validate_startup_timeout(
                RemoteOperation::EnsureInstance,
                &payload,
                std::time::Duration::from_secs(61),
            )
            .is_ok()
        );
    }

    #[test]
    fn generated_flag_handoff_is_bounded_without_echoing_the_value() {
        let valid = serde_json::json!({"deployment": {"flag_value": "é".repeat(256)}});
        assert!(validate_flag_value(RemoteOperation::EnsureInstance, &valid).is_ok());

        for invalid in [
            serde_json::json!({"deployment": {"flag_value": ""}}),
            serde_json::json!({"deployment": {"flag_value": "bad\0flag"}}),
            serde_json::json!({"deployment": {"flag_value": "é".repeat(257)}}),
            serde_json::json!({"deployment": {"flag_value": {"unsafe": true}}}),
        ] {
            let error = validate_flag_value(RemoteOperation::EnsureInstance, &invalid)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "deployment flag_value is invalid");
            assert!(!error.contains("bad\0flag"));
        }
        assert!(
            validate_flag_value(
                RemoteOperation::EnsureInstance,
                &serde_json::json!({"deployment": {"flag_value": null}}),
            )
            .is_ok()
        );
    }

    #[test]
    fn generated_flag_is_rejected_for_non_start_operations() {
        let payload = serde_json::json!({
            "deployment": {"flag_value": "flag{personalized-secret}"}
        });
        for operation in [
            RemoteOperation::InspectInstance,
            RemoteOperation::StopInstance,
            RemoteOperation::UpdateDeadline,
        ] {
            let error = validate_flag_value(operation, &payload)
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                "deployment flag_value is allowed only during instance startup"
            );
            assert!(!error.contains("personalized-secret"));
        }
    }
}
