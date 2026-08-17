use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use uuid::Uuid;

use crate::config::Config;

const SERVICE_TOKEN_HEADER: &str = "x-ctfzone-ssh-gateway-token";
const CLAIM_PATH: &str = "api/v1/internal/ssh/identity-operations/claim";
const TICKET_CONSUME_PATH: &str = "api/v1/internal/ssh/tickets/consume";

#[derive(Clone)]
pub(crate) struct ApiClient {
    client: reqwest::Client,
    base_url: Url,
    service_token: String,
    gateway_instance_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdentityOperationKind {
    Generate,
    Delete,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct IdentityOperation {
    pub(crate) id: Uuid,
    pub(crate) host_id: Uuid,
    pub(crate) kind: IdentityOperationKind,
    pub(crate) claim_token: Uuid,
    pub(crate) attempt: i32,
    pub(crate) lease_expires_at: String,
}

#[derive(Debug, Serialize)]
struct ClaimRequest {
    gateway_instance_id: Uuid,
}

#[derive(Debug, Serialize)]
struct IdentityOperationRequest<'a> {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct FailIdentityRequest<'a> {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
    error_code: &'a str,
}

#[derive(Debug, Serialize)]
struct IdentityHeartbeatRequest {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
}

#[derive(Debug, Serialize)]
struct IdentityInvalidRequest<'a> {
    gateway_instance_id: Uuid,
    error_code: &'a str,
    observed_fingerprint: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TicketPurpose {
    Probe,
    Terminal,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct TicketGrant {
    pub(crate) ticket_id: Uuid,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) purpose: TicketPurpose,
    pub(crate) host_id: Uuid,
    pub(crate) hostname: String,
    pub(crate) ssh_port: u16,
    pub(crate) ssh_user: String,
    pub(crate) identity_public_key: String,
    pub(crate) identity_fingerprint: String,
    pub(crate) trusted_host_public_key: Option<String>,
    pub(crate) trusted_host_key_fingerprint: Option<String>,
    pub(crate) host_key_alias: String,
    pub(crate) idle_timeout_seconds: u64,
    pub(crate) absolute_timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
struct ConsumeTicketRequest<'a> {
    ticket: &'a str,
    gateway_instance_id: Uuid,
    client_ip: IpAddr,
    origin: &'a str,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct CandidateReceipt {
    pub(crate) candidate_id: Uuid,
    pub(crate) host_revision: i64,
}

#[derive(Debug, Serialize)]
struct HostKeyReport<'a> {
    ticket_id: Uuid,
    gateway_instance_id: Uuid,
    public_key: &'a str,
}

#[derive(Debug, Serialize)]
struct GatewayReport {
    gateway_instance_id: Uuid,
}

#[derive(Debug, Serialize)]
struct ClosedReport<'a> {
    gateway_instance_id: Uuid,
    reason: &'a str,
    bytes_from_browser: u64,
    bytes_to_browser: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    data: T,
}

impl ApiClient {
    pub(crate) fn new(config: &Config, gateway_instance_id: Uuid) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("failed to create private API client")?;
        Ok(Self {
            client,
            base_url: config.api_base_url.clone(),
            service_token: config.api_service_token.clone(),
            gateway_instance_id,
        })
    }

    pub(crate) async fn ready(&self) -> bool {
        self.client
            .get(self.url("readyz"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    pub(crate) async fn claim_identity_operation(&self) -> Result<Option<IdentityOperation>> {
        self.post(
            CLAIM_PATH,
            &ClaimRequest {
                gateway_instance_id: self.gateway_instance_id,
            },
        )
        .await
    }

    pub(crate) async fn complete_identity_generation(
        &self,
        operation: &IdentityOperation,
        public_key: &str,
    ) -> Result<()> {
        let path = format!(
            "api/v1/internal/ssh/identity-operations/{}/complete",
            operation.id
        );
        self.post_empty(
            &path,
            &IdentityOperationRequest {
                gateway_instance_id: self.gateway_instance_id,
                claim_token: operation.claim_token,
                public_key: Some(public_key),
            },
        )
        .await
    }

    pub(crate) async fn complete_identity_deletion(
        &self,
        operation: &IdentityOperation,
    ) -> Result<()> {
        let path = format!(
            "api/v1/internal/ssh/identity-operations/{}/complete",
            operation.id
        );
        self.post_empty(
            &path,
            &IdentityOperationRequest {
                gateway_instance_id: self.gateway_instance_id,
                claim_token: operation.claim_token,
                public_key: None,
            },
        )
        .await
    }

    pub(crate) async fn fail_identity_operation(
        &self,
        operation: &IdentityOperation,
        error_code: &str,
    ) -> Result<()> {
        let path = format!(
            "api/v1/internal/ssh/identity-operations/{}/fail",
            operation.id
        );
        self.post_empty(
            &path,
            &FailIdentityRequest {
                gateway_instance_id: self.gateway_instance_id,
                claim_token: operation.claim_token,
                error_code,
            },
        )
        .await
    }

    pub(crate) async fn heartbeat_identity_operation(
        &self,
        operation: &IdentityOperation,
    ) -> Result<bool> {
        let path = format!(
            "api/v1/internal/ssh/identity-operations/{}/heartbeat",
            operation.id
        );
        let response = self
            .request(reqwest::Method::POST, &path)
            .json(&IdentityHeartbeatRequest {
                gateway_instance_id: self.gateway_instance_id,
                claim_token: operation.claim_token,
            })
            .send()
            .await
            .context("identity-operation heartbeat failed")?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::CONFLICT | StatusCode::GONE => Ok(false),
            status => Err(response_error(response, status).await),
        }
    }

    pub(crate) async fn consume_ticket(
        &self,
        ticket: &str,
        client_ip: IpAddr,
        origin: &str,
    ) -> Result<TicketGrant> {
        self.post(
            TICKET_CONSUME_PATH,
            &ConsumeTicketRequest {
                ticket,
                gateway_instance_id: self.gateway_instance_id,
                client_ip,
                origin,
            },
        )
        .await
    }

    pub(crate) async fn report_host_key(
        &self,
        host_id: Uuid,
        ticket_id: Uuid,
        public_key: &str,
    ) -> Result<CandidateReceipt> {
        let path = format!("api/v1/internal/ssh/hosts/{host_id}/host-key-candidates");
        self.post(
            &path,
            &HostKeyReport {
                ticket_id,
                gateway_instance_id: self.gateway_instance_id,
                public_key,
            },
        )
        .await
    }

    pub(crate) async fn report_identity_invalid(
        &self,
        host_id: Uuid,
        error_code: &str,
        observed_fingerprint: Option<&str>,
    ) -> Result<()> {
        let path = format!("api/v1/internal/ssh/hosts/{host_id}/identity-invalid");
        self.post_empty(
            &path,
            &IdentityInvalidRequest {
                gateway_instance_id: self.gateway_instance_id,
                error_code,
                observed_fingerprint,
            },
        )
        .await
    }

    pub(crate) async fn report_connected(&self, session_id: Uuid) -> Result<()> {
        let path = format!("api/v1/internal/ssh/sessions/{session_id}/connected");
        self.post_empty(
            &path,
            &GatewayReport {
                gateway_instance_id: self.gateway_instance_id,
            },
        )
        .await
    }

    pub(crate) async fn heartbeat(
        &self,
        session_id: Uuid,
        bytes_from_browser: u64,
        bytes_to_browser: u64,
    ) -> Result<bool> {
        let path = format!("api/v1/internal/ssh/sessions/{session_id}/heartbeat");
        let response = self
            .request(reqwest::Method::POST, &path)
            .json(&serde_json::json!({
                "gateway_instance_id": self.gateway_instance_id,
                "bytes_from_browser": bytes_from_browser,
                "bytes_to_browser": bytes_to_browser,
            }))
            .send()
            .await
            .context("SSH session heartbeat failed")?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::CONFLICT
            | StatusCode::GONE
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN => Ok(false),
            status => Err(response_error(response, status).await),
        }
    }

    pub(crate) async fn report_closed(
        &self,
        session_id: Uuid,
        reason: &str,
        bytes_from_browser: u64,
        bytes_to_browser: u64,
        exit_code: Option<i32>,
    ) -> Result<()> {
        let path = format!("api/v1/internal/ssh/sessions/{session_id}/closed");
        self.post_empty(
            &path,
            &ClosedReport {
                gateway_instance_id: self.gateway_instance_id,
                reason,
                bytes_from_browser,
                bytes_to_browser,
                exit_code,
            },
        )
        .await
    }

    async fn post<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let response = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .with_context(|| format!("private API request failed: {path}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(response_error(response, status).await);
        }
        let envelope = response
            .json::<Envelope<T>>()
            .await
            .with_context(|| format!("private API returned invalid JSON: {path}"))?;
        if !envelope.success {
            bail!("private API returned an unsuccessful envelope: {path}");
        }
        Ok(envelope.data)
    }

    async fn post_empty<B>(&self, path: &str, body: &B) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let response = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .with_context(|| format!("private API request failed: {path}"))?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(response_error(response, status).await)
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(reqwest::header::ACCEPT, "application/json")
    }

    fn url(&self, path: &str) -> Url {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("constant private API path is a valid relative URL")
    }
}

async fn response_error(response: reqwest::Response, status: StatusCode) -> anyhow::Error {
    let message = response
        .bytes()
        .await
        .ok()
        .filter(|bytes| bytes.len() <= 4096)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "private API rejected the request".to_owned());
    anyhow::anyhow!("{message} ({status})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_paths_never_embed_ticket_or_target_input() {
        assert_eq!(CLAIM_PATH, "api/v1/internal/ssh/identity-operations/claim");
        assert_eq!(TICKET_CONSUME_PATH, "api/v1/internal/ssh/tickets/consume");
        assert!(!TICKET_CONSUME_PATH.contains('?'));
    }
}
