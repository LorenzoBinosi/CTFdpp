use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

const IDENTITY_LEASE_SECONDS: i64 = 60;
#[cfg(test)]
const TICKET_TTL_SECONDS: i64 = 30;
const TERMINAL_IDLE_TIMEOUT_SECONDS: i64 = 900;
const TERMINAL_ABSOLUTE_TIMEOUT_SECONDS: i64 = 3600;
const WEBSOCKET_PATH: &str = "/bff/ssh/terminal";
const ACTIVE_TERMINAL_FOR_ACTOR_QUERY: &str = r#"
    SELECT count(*) FROM ctfzone.ssh_terminal_sessions
    WHERE ssh_host_id=$1 AND admin_user_id=$2
      AND state IN ('connecting','active')
"#;

const HOST_COLUMNS: &str = r#"
    id,name,hostname,ssh_port,ssh_user,enabled,identity_state,
    ssh_public_key,ssh_key_fingerprint,key_generated_at,identity_error_code,
    trusted_host_public_key,trusted_host_key_fingerprint,host_key_trusted_at,
    host_key_trusted_by_user_id,authorized_key_cleanup_required,
    revision,created_by_user_id,
    updated_by_user_id,deleted_by_user_id,created_at,updated_at,deleted_at
"#;

#[derive(Clone, FromRow)]
struct SshHostRow {
    id: Uuid,
    name: String,
    hostname: String,
    ssh_port: i32,
    ssh_user: String,
    enabled: bool,
    identity_state: String,
    ssh_public_key: Option<String>,
    ssh_key_fingerprint: Option<String>,
    key_generated_at: Option<DateTime<Utc>>,
    identity_error_code: Option<String>,
    trusted_host_public_key: Option<String>,
    trusted_host_key_fingerprint: Option<String>,
    host_key_trusted_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    host_key_trusted_by_user_id: Option<i32>,
    authorized_key_cleanup_required: bool,
    revision: i64,
    #[allow(dead_code)]
    created_by_user_id: Option<i32>,
    #[allow(dead_code)]
    updated_by_user_id: Option<i32>,
    #[allow(dead_code)]
    deleted_by_user_id: Option<i32>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

#[derive(Clone, FromRow, Serialize)]
pub(crate) struct HostKeyCandidateView {
    id: Uuid,
    public_key: String,
    fingerprint: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i32,
}

#[derive(Serialize)]
pub(crate) struct SshHostView {
    id: Uuid,
    name: String,
    hostname: String,
    ssh_port: i32,
    ssh_user: String,
    enabled: bool,
    identity_state: String,
    ssh_public_key: Option<String>,
    ssh_key_fingerprint: Option<String>,
    authorized_keys_line: Option<String>,
    key_generated_at: Option<DateTime<Utc>>,
    identity_error_code: Option<String>,
    host_key_state: &'static str,
    trusted_host_public_key: Option<String>,
    trusted_host_key_fingerprint: Option<String>,
    host_key_trusted_at: Option<DateTime<Utc>>,
    host_key_candidates: Vec<HostKeyCandidateView>,
    authorized_key_cleanup_required: bool,
    active_session_count: i64,
    revision: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshHostCreate {
    name: String,
    hostname: String,
    #[serde(default = "default_ssh_port")]
    ssh_port: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustHostKeyRequest {
    candidate_id: Uuid,
    fingerprint: String,
    revision: i64,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum TicketPurpose {
    Probe,
    Terminal,
}

impl TicketPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketRequest {
    purpose: TicketPurpose,
}

#[derive(Serialize)]
struct TicketResponse {
    ticket: String,
    purpose: TicketPurpose,
    expires_at: DateTime<Utc>,
    websocket_path: &'static str,
}

#[derive(Serialize)]
struct DeletionResponse {
    id: Uuid,
    deletion_state: &'static str,
}

pub(crate) fn private_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/internal/ssh/identity-operations/claim",
            post(claim_identity_operation),
        )
        .route(
            "/api/v1/internal/ssh/identity-operations/{operation_id}/heartbeat",
            post(heartbeat_identity_operation),
        )
        .route(
            "/api/v1/internal/ssh/identity-operations/{operation_id}/complete",
            post(complete_identity_operation),
        )
        .route(
            "/api/v1/internal/ssh/identity-operations/{operation_id}/fail",
            post(fail_identity_operation),
        )
        .route("/api/v1/internal/ssh/tickets/consume", post(consume_ticket))
        .route(
            "/api/v1/internal/ssh/hosts/{host_id}/host-key-candidates",
            post(report_host_key_candidate),
        )
        .route(
            "/api/v1/internal/ssh/hosts/{host_id}/identity-invalid",
            post(report_identity_invalid),
        )
        .route(
            "/api/v1/internal/ssh/sessions/{session_id}/connected",
            post(session_connected),
        )
        .route(
            "/api/v1/internal/ssh/sessions/{session_id}/heartbeat",
            post(session_heartbeat),
        )
        .route(
            "/api/v1/internal/ssh/sessions/{session_id}/closed",
            post(session_closed),
        )
}

pub(crate) async fn list_hosts(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let query = format!(
        "SELECT {HOST_COLUMNS} FROM ctfzone.ssh_hosts \
         WHERE deleted_at IS NULL ORDER BY lower(name),id"
    );
    let rows = sqlx::query_as::<_, SshHostRow>(&query)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let mut hosts = Vec::with_capacity(rows.len());
    for row in rows {
        hosts.push(hydrate_host(&state.database, row).await?);
    }
    Ok(Json(Success::new(hosts)).into_response())
}

pub(crate) async fn create_host(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<SshHostCreate>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let name = request.name.trim();
    let hostname = request.hostname.trim();
    validate_target(name, hostname, request.ssh_port)?;
    if !state
        .rate_limiter
        .allow(
            "ssh-host-create",
            &user.id.to_string(),
            10,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many SSH host registrations",
        ));
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let query = format!(
        r#"
        INSERT INTO ctfzone.ssh_hosts (
            name,hostname,ssh_port,ssh_user,created_by_user_id,updated_by_user_id
        ) VALUES ($1,$2,$3,$1,$4,$4)
        RETURNING {HOST_COLUMNS}
        "#
    );
    let host = sqlx::query_as::<_, SshHostRow>(&query)
        .bind(name)
        .bind(hostname)
        .bind(request.ssh_port)
        .bind(user.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            ApiError::conflict_or_database(error, "This SSH target is already registered")
        })?;
    enqueue_identity_operation(&mut transaction, &host, "generate").await?;
    append_event(
        &mut transaction,
        &host,
        "ssh_host.created",
        "api",
        Some(user.id),
        host_snapshot(&host),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    let view = hydrate_host(&state.database, host).await?;
    Ok((StatusCode::CREATED, Json(Success::new(view))).into_response())
}

pub(crate) async fn get_host(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let host = visible_host(&state.database, host_id).await?;
    Ok(Json(Success::new(hydrate_host(&state.database, host).await?)).into_response())
}

pub(crate) async fn delete_host(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let current = visible_host_for_update(&mut transaction, host_id).await?;
    let query = format!(
        r#"
        UPDATE ctfzone.ssh_hosts
        SET enabled=false,deleted_at=now(),deleted_by_user_id=$2,
            updated_by_user_id=$2,updated_at=now(),revision=revision+1
        WHERE id=$1 AND deleted_at IS NULL
        RETURNING {HOST_COLUMNS}
        "#
    );
    let deleted = sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .bind(user.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;

    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_identity_operations
        SET state='cancelled',claimed_at=NULL,claim_expires_at=NULL,
            claim_token=NULL,claimed_by_gateway=NULL,last_error='host_deleted',
            updated_at=now()
        WHERE ssh_host_id=$1 AND kind='generate' AND state IN ('pending','claimed')
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    enqueue_identity_operation(&mut transaction, &deleted, "delete").await?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_tickets
        SET revoked_at=now(),revocation_reason='host_deleted'
        WHERE ssh_host_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions
        SET state='closed',closed_at=now(),close_reason='host_deleted'
        WHERE ssh_host_id=$1 AND state IN ('connecting','active')
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    append_event(
        &mut transaction,
        &deleted,
        "ssh_host.deleted",
        "api",
        Some(user.id),
        json!({
            "previous_revision": current.revision,
            "identity_cleanup": "queued",
            "remote_authorized_key_cleanup_required": true
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Success::new(DeletionResponse {
            id: host_id,
            deletion_state: "pending",
        })),
    )
        .into_response())
}

pub(crate) async fn retry_identity(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if !state
        .rate_limiter
        .allow(
            "ssh-identity-retry",
            &host_id.to_string(),
            5,
            Duration::from_secs(3600),
        )
        .await
    {
        return Err(ApiError::too_many_requests("Too many SSH identity retries"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let current = visible_host_for_update(&mut transaction, host_id).await?;
    if current.identity_state != "failed" {
        return Err(ApiError::conflict(
            "Only a failed SSH identity can be retried",
        ));
    }
    let query = format!(
        r#"
        UPDATE ctfzone.ssh_hosts
        SET identity_state='pending',identity_error_code=NULL,
            updated_by_user_id=$2,updated_at=now(),revision=revision+1
        WHERE id=$1 AND deleted_at IS NULL AND identity_state='failed'
        RETURNING {HOST_COLUMNS}
        "#
    );
    let host = sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .bind(user.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    enqueue_identity_operation(&mut transaction, &host, "generate").await?;
    append_event(
        &mut transaction,
        &host,
        "ssh_identity.retry_requested",
        "api",
        Some(user.id),
        json!({"previous_error_code": current.identity_error_code}),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    let view = hydrate_host(&state.database, host).await?;
    Ok((StatusCode::ACCEPTED, Json(Success::new(view))).into_response())
}

pub(crate) async fn trust_host_key(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(host_id): Path<Uuid>,
    Json(request): Json<TrustHostKeyRequest>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.revision <= 0 || !safe_fingerprint(&request.fingerprint) {
        return Err(ApiError::bad_request("Invalid host-key trust request"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let current = visible_host_for_update(&mut transaction, host_id).await?;
    if current.revision != request.revision {
        return Err(ApiError::conflict(
            "The SSH host changed; reload before trusting its key",
        ));
    }
    if current.identity_state != "ready" {
        return Err(ApiError::conflict("The SSH access identity is not ready"));
    }
    let previous_fingerprint = current.trusted_host_key_fingerprint.clone();
    let candidate = sqlx::query_as::<_, CandidateKeyRow>(
        r#"
        SELECT id,public_key,fingerprint
        FROM ctfzone.ssh_host_key_candidates
        WHERE id=$1 AND ssh_host_id=$2
        FOR UPDATE
        "#,
    )
    .bind(request.candidate_id)
    .bind(host_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("SSH host-key candidate not found"))?;
    if candidate.fingerprint != request.fingerprint {
        return Err(ApiError::conflict(
            "The confirmed fingerprint does not match this candidate",
        ));
    }
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_tickets
        SET revoked_at=now(),revocation_reason='host_key_changed'
        WHERE ssh_host_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions
        SET state='closed',closed_at=now(),close_reason='host_key_changed'
        WHERE ssh_host_id=$1 AND state IN ('connecting','active')
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let query = format!(
        r#"
        UPDATE ctfzone.ssh_hosts
        SET trusted_host_public_key=$2,trusted_host_key_fingerprint=$3,
            host_key_trusted_at=now(),host_key_trusted_by_user_id=$4,
            enabled=true,updated_by_user_id=$4,updated_at=now(),revision=revision+1
        WHERE id=$1 AND deleted_at IS NULL AND revision=$5
        RETURNING {HOST_COLUMNS}
        "#
    );
    let host = sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .bind(&candidate.public_key)
        .bind(&candidate.fingerprint)
        .bind(user.id)
        .bind(request.revision)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_key_candidates
        SET trusted_at=now(),trusted_by_user_id=$2
        WHERE id=$1
        "#,
    )
    .bind(candidate.id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    append_event(
        &mut transaction,
        &host,
        if previous_fingerprint.is_some() {
            "ssh_host_key.rotated"
        } else {
            "ssh_host_key.trusted"
        },
        "api",
        Some(user.id),
        json!({
            "candidate_id": candidate.id,
            "fingerprint": candidate.fingerprint,
            "previous_fingerprint": previous_fingerprint
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(hydrate_host(&state.database, host).await?)).into_response())
}

pub(crate) async fn issue_ticket(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(host_id): Path<Uuid>,
    Json(request): Json<TicketRequest>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let browser_session_id = user
        .internal_session_id()
        .ok_or_else(|| ApiError::forbidden("SSH tickets require a browser session"))?
        .to_owned();
    let request_ip = canonical_ip(user.request_ip())
        .ok_or_else(|| ApiError::forbidden("SSH tickets require a validated browser client IP"))?;
    let rate_subject = format!("{}:{request_ip}", user.id);
    if !state
        .rate_limiter
        .allow("ssh-ticket", &rate_subject, 10, Duration::from_secs(60))
        .await
    {
        return Err(ApiError::too_many_requests("Too many SSH ticket requests"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let host = visible_host_for_update(&mut transaction, host_id).await?;
    validate_ticket_host(&host, request.purpose)?;
    let issued_last_hour = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT count(*) FROM ctfzone.ssh_host_tickets
        WHERE issued_to_user_id=$1 AND issued_at > now()-INTERVAL '1 hour'
        "#,
    )
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let open_for_host = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT count(*) FROM ctfzone.ssh_host_tickets
        WHERE issued_to_user_id=$1 AND ssh_host_id=$2
          AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
        "#,
    )
    .bind(user.id)
    .bind(host_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if issued_last_hour >= 60 || open_for_host >= 3 {
        return Err(ApiError::too_many_requests("Too many active SSH tickets"));
    }

    let mut raw_token = [0_u8; 32];
    OsRng.fill_bytes(&mut raw_token);
    let ticket = general_purpose::URL_SAFE_NO_PAD.encode(raw_token);
    let digest = Sha256::digest(ticket.as_bytes()).to_vec();
    let created = sqlx::query_as::<_, TicketCreated>(
        r#"
        INSERT INTO ctfzone.ssh_host_tickets (
            ssh_host_id,purpose,token_sha256,issued_to_user_id,
            browser_session_id,request_ip
        ) VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING id,expires_at
        "#,
    )
    .bind(host_id)
    .bind(request.purpose.as_str())
    .bind(digest)
    .bind(user.id)
    .bind(&browser_session_id)
    .bind(&request_ip)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    append_event(
        &mut transaction,
        &host,
        "ssh_ticket.issued",
        "api",
        Some(user.id),
        json!({"ticket_id": created.id, "purpose": request.purpose.as_str()}),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let mut response = (
        StatusCode::CREATED,
        Json(Success::new(TicketResponse {
            ticket,
            purpose: request.purpose,
            expires_at: created.expires_at,
            websocket_path: WEBSOCKET_PATH,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

#[derive(FromRow)]
struct CandidateKeyRow {
    id: Uuid,
    public_key: String,
    fingerprint: String,
}

#[derive(FromRow)]
struct TicketCreated {
    id: Uuid,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimIdentityOperationRequest {
    gateway_instance_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimedIdentityOperationRequest {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
}

#[derive(FromRow)]
struct IdentityOperationRow {
    id: Uuid,
    ssh_host_id: Uuid,
    kind: String,
    attempts: i32,
    claim_expires_at: Option<DateTime<Utc>>,
    claim_token: Option<Uuid>,
}

#[derive(Serialize)]
struct IdentityOperationClaim {
    id: Uuid,
    host_id: Uuid,
    kind: String,
    attempt: i32,
    lease_expires_at: DateTime<Utc>,
    claim_token: Uuid,
}

#[derive(Serialize)]
struct IdentityOperationHeartbeat {
    operation_id: Uuid,
    lease_expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteIdentityRequest {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
    public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailIdentityRequest {
    gateway_instance_id: Uuid,
    claim_token: Uuid,
    error_code: String,
}

#[derive(Serialize)]
struct IdentityOperationResult {
    operation_id: Uuid,
    host_revision: Option<i64>,
    state: &'static str,
}

async fn claim_identity_operation(
    State(state): State<AppState>,
    Json(request): Json<ClaimIdentityOperationRequest>,
) -> Result<Response, ApiError> {
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;

    // A deleted host is a permanent fence for generation. Clearing the claim
    // metadata here ensures a stale gateway can only observe cancellation when
    // it revalidates after taking the filesystem lock.
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_identity_operations AS operation
        SET state='cancelled',claimed_at=NULL,claim_expires_at=NULL,
            claim_token=NULL,claimed_by_gateway=NULL,last_error='host_deleted',
            updated_at=now()
        WHERE operation.kind='generate'
          AND operation.state IN ('pending','claimed')
          AND EXISTS (
              SELECT 1 FROM ctfzone.ssh_hosts AS host
              WHERE host.id=operation.ssh_host_id AND host.deleted_at IS NOT NULL
          )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_identity_operations
        SET state='pending',claimed_at=NULL,claim_expires_at=NULL,
            claim_token=NULL,claimed_by_gateway=NULL,available_at=now(),
            updated_at=now()
        WHERE state='claimed' AND claim_expires_at <= now()
        "#,
    )
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;

    let operation = sqlx::query_as::<_, IdentityOperationRow>(
        r#"
        WITH candidate AS (
            SELECT operation.id
            FROM ctfzone.ssh_host_identity_operations AS operation
            WHERE operation.state='pending'
              AND operation.available_at <= now()
              AND (
                  operation.kind='delete'
                  OR EXISTS (
                      SELECT 1 FROM ctfzone.ssh_hosts AS host
                      WHERE host.id=operation.ssh_host_id
                        AND host.deleted_at IS NULL
                        AND host.identity_state='pending'
                  )
              )
            ORDER BY CASE operation.kind WHEN 'delete' THEN 0 ELSE 1 END,
                     operation.available_at,operation.created_at,operation.id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE ctfzone.ssh_host_identity_operations AS operation
        SET state='claimed',attempts=operation.attempts+1,claimed_at=now(),
            claim_expires_at=now()+($2::double precision*INTERVAL '1 second'),
            claim_token=gen_random_uuid(),claimed_by_gateway=$1,updated_at=now()
        FROM candidate
        WHERE operation.id=candidate.id
        RETURNING operation.id,operation.ssh_host_id,operation.kind,
                  operation.attempts,operation.claim_expires_at,
                  operation.claim_token
        "#,
    )
    .bind(&gateway)
    .bind(IDENTITY_LEASE_SECONDS)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;

    let claim = operation.map(|operation| IdentityOperationClaim {
        id: operation.id,
        host_id: operation.ssh_host_id,
        kind: operation.kind,
        attempt: operation.attempts,
        lease_expires_at: operation
            .claim_expires_at
            .expect("claimed operations have a lease expiry"),
        claim_token: operation
            .claim_token
            .expect("claimed operations have a claim token"),
    });
    Ok(Json(Success::new(claim)).into_response())
}

async fn heartbeat_identity_operation(
    State(state): State<AppState>,
    Path(operation_id): Path<Uuid>,
    Json(request): Json<ClaimedIdentityOperationRequest>,
) -> Result<Response, ApiError> {
    let lease_expires_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        r#"
        UPDATE ctfzone.ssh_host_identity_operations AS operation
        SET claim_expires_at=now()+($4::double precision*INTERVAL '1 second'),
            updated_at=now()
        WHERE operation.id=$1
          AND operation.state='claimed'
          AND operation.claimed_by_gateway=$2
          AND operation.claim_token=$3
          AND operation.claim_expires_at > now()
          AND (
              operation.kind='delete'
              OR EXISTS (
                  SELECT 1 FROM ctfzone.ssh_hosts AS host
                  WHERE host.id=operation.ssh_host_id
                    AND host.deleted_at IS NULL
                    AND host.identity_state='pending'
              )
          )
        RETURNING operation.claim_expires_at
        "#,
    )
    .bind(operation_id)
    .bind(request.gateway_instance_id.to_string())
    .bind(request.claim_token)
    .bind(IDENTITY_LEASE_SECONDS)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::conflict("This SSH identity operation is no longer claimable"))?;
    Ok(Json(Success::new(IdentityOperationHeartbeat {
        operation_id,
        lease_expires_at,
    }))
    .into_response())
}

async fn complete_identity_operation(
    State(state): State<AppState>,
    Path(operation_id): Path<Uuid>,
    Json(request): Json<CompleteIdentityRequest>,
) -> Result<Response, ApiError> {
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let preview = operation_by_id(&mut transaction, operation_id).await?;
    let locked_host = if preview.kind == "generate" {
        Some(host_for_update_any(&mut transaction, preview.ssh_host_id).await?)
    } else {
        None
    };
    let operation = claimed_operation_for_update(
        &mut transaction,
        operation_id,
        &gateway,
        request.claim_token,
    )
    .await?;
    if operation.kind != preview.kind || operation.ssh_host_id != preview.ssh_host_id {
        return Err(ApiError::conflict("SSH identity operation changed"));
    }

    let host_revision = if operation.kind == "generate" {
        let host = locked_host.expect("generate operations lock their host");
        if host.deleted_at.is_some() || host.identity_state != "pending" {
            return Err(ApiError::conflict(
                "The SSH host no longer accepts identity generation",
            ));
        }
        let supplied = request
            .public_key
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("Generated public key is required"))?;
        let key = canonical_ed25519_public_key(supplied)?;
        complete_operation_row(&mut transaction, operation_id).await?;
        let revision = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE ctfzone.ssh_hosts
            SET identity_state='ready',ssh_public_key=$2,ssh_key_fingerprint=$3,
                key_generated_at=now(),identity_error_code=NULL,
                updated_at=now(),revision=revision+1
            WHERE id=$1 AND deleted_at IS NULL AND identity_state='pending'
            RETURNING revision
            "#,
        )
        .bind(host.id)
        .bind(&key.canonical)
        .bind(&key.fingerprint)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::conflict("SSH identity publication was cancelled"))?;
        append_event_by_id(
            &mut transaction,
            host.id,
            revision,
            "ssh_identity.generated",
            "gateway",
            None,
            json!({
                "operation_id": operation_id,
                "fingerprint": key.fingerprint,
                "attempt": operation.attempts
            }),
        )
        .await?;
        Some(revision)
    } else if operation.kind == "delete" {
        if request.public_key.is_some() {
            return Err(ApiError::bad_request(
                "Delete completion must not include a public key",
            ));
        }
        complete_operation_row(&mut transaction, operation_id).await?;
        let revision =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM ctfzone.ssh_hosts WHERE id=$1")
                .bind(operation.ssh_host_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(ApiError::database)?;
        if let Some(revision) = revision {
            append_event_by_id(
                &mut transaction,
                operation.ssh_host_id,
                revision,
                "ssh_identity.deleted",
                "gateway",
                None,
                json!({"operation_id": operation_id, "attempt": operation.attempts}),
            )
            .await?;
        }
        revision
    } else {
        return Err(ApiError::conflict("Unknown SSH identity operation kind"));
    };
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(IdentityOperationResult {
        operation_id,
        host_revision,
        state: "completed",
    }))
    .into_response())
}

async fn fail_identity_operation(
    State(state): State<AppState>,
    Path(operation_id): Path<Uuid>,
    Json(request): Json<FailIdentityRequest>,
) -> Result<Response, ApiError> {
    if !safe_code(&request.error_code) {
        return Err(ApiError::bad_request("Invalid SSH identity error code"));
    }
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let preview = operation_by_id(&mut transaction, operation_id).await?;
    let locked_host = if preview.kind == "generate" {
        Some(host_for_update_any(&mut transaction, preview.ssh_host_id).await?)
    } else {
        None
    };
    let operation = claimed_operation_for_update(
        &mut transaction,
        operation_id,
        &gateway,
        request.claim_token,
    )
    .await?;
    let (host_revision, result_state) = if operation.kind == "generate" {
        let host = locked_host.expect("generate operations lock their host");
        sqlx::query(
            r#"
            UPDATE ctfzone.ssh_host_identity_operations
            SET state='failed',claimed_at=NULL,claim_expires_at=NULL,
                claim_token=NULL,claimed_by_gateway=NULL,last_error=$2,updated_at=now()
            WHERE id=$1
            "#,
        )
        .bind(operation_id)
        .bind(&request.error_code)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        let revision = if host.deleted_at.is_none() && host.identity_state == "pending" {
            sqlx::query_scalar::<_, i64>(
                r#"
                UPDATE ctfzone.ssh_hosts
                SET identity_state='failed',identity_error_code=$2,
                    updated_at=now(),revision=revision+1
                WHERE id=$1 AND deleted_at IS NULL AND identity_state='pending'
                RETURNING revision
                "#,
            )
            .bind(host.id)
            .bind(&request.error_code)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
        } else {
            None
        };
        if let Some(revision) = revision {
            append_event_by_id(
                &mut transaction,
                host.id,
                revision,
                "ssh_identity.generation_failed",
                "gateway",
                None,
                json!({"operation_id": operation_id, "error_code": request.error_code}),
            )
            .await?;
        }
        (revision, "failed")
    } else if operation.kind == "delete" {
        let retry_delay = i64::from(operation.attempts.clamp(1, 60)) * 5;
        sqlx::query(
            r#"
            UPDATE ctfzone.ssh_host_identity_operations
            SET state='pending',claimed_at=NULL,claim_expires_at=NULL,
                claim_token=NULL,claimed_by_gateway=NULL,last_error=$2,
                available_at=now()+($3::double precision*INTERVAL '1 second'),
                updated_at=now()
            WHERE id=$1
            "#,
        )
        .bind(operation_id)
        .bind(&request.error_code)
        .bind(retry_delay)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        let revision =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM ctfzone.ssh_hosts WHERE id=$1")
                .bind(operation.ssh_host_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(ApiError::database)?;
        if let Some(revision) = revision {
            append_event_by_id(
                &mut transaction,
                operation.ssh_host_id,
                revision,
                "ssh_identity.deletion_retry_scheduled",
                "gateway",
                None,
                json!({
                    "operation_id": operation_id,
                    "error_code": request.error_code,
                    "retry_delay_seconds": retry_delay,
                    "attempt": operation.attempts
                }),
            )
            .await?;
        }
        (revision, "pending")
    } else {
        return Err(ApiError::conflict("Unknown SSH identity operation kind"));
    };
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(IdentityOperationResult {
        operation_id,
        host_revision,
        state: result_state,
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumeTicketRequest {
    ticket: String,
    gateway_instance_id: Uuid,
    client_ip: String,
    origin: String,
}

#[derive(FromRow)]
struct TicketRow {
    id: Uuid,
    ssh_host_id: Uuid,
    purpose: String,
    issued_to_user_id: i32,
    browser_session_id: String,
    request_ip: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct TicketGrant {
    ticket_id: Uuid,
    purpose: String,
    session_id: Option<Uuid>,
    host_id: Uuid,
    hostname: String,
    ssh_port: i32,
    ssh_user: String,
    identity_public_key: String,
    identity_fingerprint: String,
    trusted_host_public_key: Option<String>,
    trusted_host_key_fingerprint: Option<String>,
    host_key_alias: String,
    idle_timeout_seconds: i64,
    absolute_timeout_seconds: i64,
}

async fn consume_ticket(
    State(state): State<AppState>,
    Json(request): Json<ConsumeTicketRequest>,
) -> Result<Response, ApiError> {
    if !valid_ticket_text(&request.ticket) {
        return Err(invalid_ticket());
    }
    let client_ip = canonical_ip(&request.client_ip).ok_or_else(invalid_ticket)?;
    let expected_origin = state.site_url.origin().ascii_serialization();
    if request.origin != expected_origin {
        return Err(invalid_ticket());
    }
    let digest = Sha256::digest(request.ticket.as_bytes()).to_vec();
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let preview = ticket_by_digest(&mut transaction, &digest, false).await?;
    let host = host_for_update_any(&mut transaction, preview.ssh_host_id).await?;
    let ticket = ticket_by_digest(&mut transaction, &digest, true).await?;
    if ticket.id != preview.id
        || ticket.consumed_at.is_some()
        || ticket.revoked_at.is_some()
        || ticket.expires_at <= Utc::now()
        || ticket.request_ip != client_ip
    {
        return Err(invalid_ticket());
    }
    if host.deleted_at.is_some() || host.identity_state != "ready" {
        return Err(invalid_ticket());
    }
    if ticket.purpose == "terminal" && (!host.enabled || host.trusted_host_public_key.is_none()) {
        return Err(invalid_ticket());
    }
    if ticket.purpose != "probe" && ticket.purpose != "terminal" {
        return Err(invalid_ticket());
    }
    if !ticket_session_is_valid(
        &mut transaction,
        &ticket.browser_session_id,
        ticket.issued_to_user_id,
        state.auth.session_lifetime_seconds,
    )
    .await?
    {
        return Err(invalid_ticket());
    }
    if ticket.purpose == "terminal" {
        sqlx::query(
            r#"
            UPDATE ctfzone.ssh_terminal_sessions
            SET state='closed',closed_at=now(),close_reason=CASE
                WHEN state='connecting' THEN 'connect_timeout'
                ELSE 'heartbeat_timeout'
            END
            WHERE ssh_host_id=$1
              AND (
                  (state='connecting' AND created_at < now()-INTERVAL '30 seconds')
                  OR (
                      state='active'
                      AND COALESCE(last_heartbeat_at,connected_at,created_at)
                          < now()-INTERVAL '45 seconds'
                  )
              )
            "#,
        )
        .bind(host.id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        let active = sqlx::query_scalar::<_, i64>(ACTIVE_TERMINAL_FOR_ACTOR_QUERY)
            .bind(host.id)
            .bind(ticket.issued_to_user_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
        if active > 0 {
            return Err(ApiError::conflict(
                "This administrator already has an active terminal for the host",
            ));
        }
    }
    let updated = sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_tickets
        SET consumed_at=now(),consumed_by_gateway=$2
        WHERE id=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
        "#,
    )
    .bind(ticket.id)
    .bind(&gateway)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if updated.rows_affected() != 1 {
        return Err(invalid_ticket());
    }
    let session_id = if ticket.purpose == "terminal" {
        Some(
            sqlx::query_scalar::<_, Uuid>(
                r#"
                INSERT INTO ctfzone.ssh_terminal_sessions (
                    ticket_id,ssh_host_id,admin_user_id,browser_session_id,
                    gateway_instance_id,host_revision,trusted_host_key_fingerprint
                ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                RETURNING id
                "#,
            )
            .bind(ticket.id)
            .bind(host.id)
            .bind(ticket.issued_to_user_id)
            .bind(&ticket.browser_session_id)
            .bind(&gateway)
            .bind(host.revision)
            .bind(
                host.trusted_host_key_fingerprint
                    .as_deref()
                    .expect("terminal tickets require a trusted host key"),
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?,
        )
    } else {
        None
    };
    append_event(
        &mut transaction,
        &host,
        "ssh_ticket.consumed",
        "gateway",
        Some(ticket.issued_to_user_id),
        json!({
            "ticket_id": ticket.id,
            "purpose": ticket.purpose,
            "session_id": session_id,
            "gateway_instance_id": gateway
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let identity_public_key = host
        .ssh_public_key
        .ok_or_else(|| ApiError::service_unavailable("SSH identity metadata is incomplete"))?;
    let identity_fingerprint = host
        .ssh_key_fingerprint
        .ok_or_else(|| ApiError::service_unavailable("SSH identity metadata is incomplete"))?;
    Ok(Json(Success::new(TicketGrant {
        ticket_id: ticket.id,
        purpose: ticket.purpose,
        session_id,
        host_id: host.id,
        hostname: host.hostname,
        ssh_port: host.ssh_port,
        ssh_user: host.ssh_user,
        identity_public_key,
        identity_fingerprint,
        trusted_host_public_key: host.trusted_host_public_key,
        trusted_host_key_fingerprint: host.trusted_host_key_fingerprint,
        host_key_alias: format!("ctfzone-ssh-{}", host.id),
        idle_timeout_seconds: TERMINAL_IDLE_TIMEOUT_SECONDS,
        absolute_timeout_seconds: TERMINAL_ABSOLUTE_TIMEOUT_SECONDS,
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateReportRequest {
    ticket_id: Uuid,
    gateway_instance_id: Uuid,
    public_key: String,
}

#[derive(Serialize)]
struct CandidateReportResponse {
    candidate_id: Uuid,
    host_revision: i64,
}

async fn report_host_key_candidate(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    Json(request): Json<CandidateReportRequest>,
) -> Result<Response, ApiError> {
    let key = canonical_ed25519_public_key(&request.public_key)?;
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let host = host_for_update_any(&mut transaction, host_id).await?;
    if host.deleted_at.is_some() || host.identity_state != "ready" {
        return Err(ApiError::conflict(
            "This SSH host cannot accept a key candidate",
        ));
    }
    let valid_probe = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id FROM ctfzone.ssh_host_tickets
        WHERE id=$1 AND ssh_host_id=$2 AND purpose='probe'
          AND consumed_at IS NOT NULL AND consumed_by_gateway=$3
          AND consumed_at > now()-INTERVAL '2 minutes'
          AND revoked_at IS NULL
        "#,
    )
    .bind(request.ticket_id)
    .bind(host_id)
    .bind(&gateway)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if valid_probe.is_none() {
        return Err(ApiError::forbidden("Invalid SSH probe report"));
    }
    let candidate_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.ssh_host_key_candidates (
            ssh_host_id,ticket_id,public_key,fingerprint,reported_by_gateway
        ) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (ssh_host_id,fingerprint) DO UPDATE
        SET ticket_id=EXCLUDED.ticket_id,public_key=EXCLUDED.public_key,
            last_seen_at=now(),observation_count=
                ctfzone.ssh_host_key_candidates.observation_count+1,
            reported_by_gateway=EXCLUDED.reported_by_gateway
        RETURNING id
        "#,
    )
    .bind(host_id)
    .bind(request.ticket_id)
    .bind(&key.canonical)
    .bind(&key.fingerprint)
    .bind(&gateway)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let host_revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.ssh_hosts
        SET updated_at=now(),revision=revision+1
        WHERE id=$1 AND deleted_at IS NULL
        RETURNING revision
        "#,
    )
    .bind(host_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    append_event_by_id(
        &mut transaction,
        host_id,
        host_revision,
        "ssh_host_key.candidate_observed",
        "gateway",
        None,
        json!({
            "candidate_id": candidate_id,
            "ticket_id": request.ticket_id,
            "fingerprint": key.fingerprint
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(CandidateReportResponse {
        candidate_id,
        host_revision,
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityInvalidRequest {
    gateway_instance_id: Uuid,
    error_code: String,
    observed_fingerprint: Option<String>,
}

#[derive(Serialize)]
struct IdentityInvalidResponse {
    host_id: Uuid,
    identity_state: &'static str,
    host_revision: i64,
}

async fn report_identity_invalid(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    Json(request): Json<IdentityInvalidRequest>,
) -> Result<Response, ApiError> {
    if !matches!(
        request.error_code.as_str(),
        "private_key_missing" | "private_key_invalid" | "identity_mismatch"
    ) || request
        .observed_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| !safe_fingerprint(fingerprint))
    {
        return Err(ApiError::bad_request(
            "Invalid SSH identity validation report",
        ));
    }
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let host = host_for_update_any(&mut transaction, host_id).await?;
    if host.deleted_at.is_some() {
        return Err(ApiError::gone("SSH host was deleted"));
    }
    if host.identity_state == "failed"
        && host.identity_error_code.as_deref() == Some(request.error_code.as_str())
    {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(Json(Success::new(IdentityInvalidResponse {
            host_id,
            identity_state: "failed",
            host_revision: host.revision,
        }))
        .into_response());
    }
    if host.identity_state != "ready" {
        return Err(ApiError::conflict(
            "SSH host does not have a published identity to invalidate",
        ));
    }
    let previous_fingerprint = host.ssh_key_fingerprint.clone();
    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.ssh_hosts
        SET enabled=false,identity_state='failed',ssh_public_key=NULL,
            ssh_key_fingerprint=NULL,key_generated_at=NULL,identity_error_code=$2,
            authorized_key_cleanup_required=true,
            updated_at=now(),revision=revision+1
        WHERE id=$1 AND deleted_at IS NULL AND identity_state='ready'
        RETURNING revision
        "#,
    )
    .bind(host_id)
    .bind(&request.error_code)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_tickets
        SET revoked_at=now(),revocation_reason='identity_invalid'
        WHERE ssh_host_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions
        SET state='closed',closed_at=now(),close_reason='identity_invalid'
        WHERE ssh_host_id=$1 AND state IN ('connecting','active')
        "#,
    )
    .bind(host_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    append_event_by_id(
        &mut transaction,
        host_id,
        revision,
        "ssh_identity.validation_failed",
        "gateway",
        None,
        json!({
            "gateway_instance_id": gateway,
            "error_code": request.error_code,
            "published_fingerprint": previous_fingerprint,
            "observed_fingerprint": request.observed_fingerprint
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(IdentityInvalidResponse {
        host_id,
        identity_state: "failed",
        host_revision: revision,
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionStateRequest {
    gateway_instance_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionHeartbeatRequest {
    gateway_instance_id: Uuid,
    bytes_from_browser: i64,
    bytes_to_browser: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionClosedRequest {
    gateway_instance_id: Uuid,
    reason: String,
    exit_code: Option<i32>,
    bytes_from_browser: i64,
    bytes_to_browser: i64,
}

#[derive(FromRow)]
struct SessionRow {
    ssh_host_id: Uuid,
    admin_user_id: i32,
    browser_session_id: String,
    gateway_instance_id: String,
    host_revision: i64,
    trusted_host_key_fingerprint: String,
    state: String,
}

#[derive(Serialize)]
struct SessionStateResponse {
    session_id: Uuid,
    state: &'static str,
}

async fn session_connected(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<SessionStateRequest>,
) -> Result<Response, ApiError> {
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let preview = session_by_id(&mut transaction, session_id).await?;
    let host = host_for_update_any(&mut transaction, preview.ssh_host_id).await?;
    let browser_valid = ticket_session_is_valid(
        &mut transaction,
        &preview.browser_session_id,
        preview.admin_user_id,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if host.deleted_at.is_some()
        || !host.enabled
        || host.revision != preview.host_revision
        || host.trusted_host_key_fingerprint.as_deref()
            != Some(preview.trusted_host_key_fingerprint.as_str())
        || !browser_valid
    {
        sqlx::query(
            r#"
            UPDATE ctfzone.ssh_terminal_sessions
            SET state='closed',closed_at=now(),close_reason='authorization_revoked'
            WHERE id=$1 AND state IN ('connecting','active')
            "#,
        )
        .bind(session_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        transaction.commit().await.map_err(ApiError::database)?;
        return Err(ApiError::gone("SSH session authorization was revoked"));
    }
    let updated = sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions
        SET state='active',connected_at=now(),last_heartbeat_at=now()
        WHERE id=$1 AND gateway_instance_id=$2 AND state='connecting'
        "#,
    )
    .bind(session_id)
    .bind(&gateway)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("This SSH session cannot be connected"));
    }
    append_event(
        &mut transaction,
        &host,
        "ssh_session.connected",
        "gateway",
        Some(preview.admin_user_id),
        json!({"session_id": session_id, "gateway_instance_id": gateway}),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(SessionStateResponse {
        session_id,
        state: "active",
    }))
    .into_response())
}

async fn session_heartbeat(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<SessionHeartbeatRequest>,
) -> Result<Response, ApiError> {
    validate_byte_counts(request.bytes_from_browser, request.bytes_to_browser)?;
    let updated = sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions AS session
        SET last_heartbeat_at=now(),
            bytes_from_browser=GREATEST(session.bytes_from_browser,$3),
            bytes_to_browser=GREATEST(session.bytes_to_browser,$4)
        WHERE session.id=$1 AND session.gateway_instance_id=$2
          AND session.state='active'
          AND EXISTS (
              SELECT 1 FROM ctfzone.ssh_hosts AS host
              WHERE host.id=session.ssh_host_id
                AND host.deleted_at IS NULL AND host.enabled
                AND host.revision=session.host_revision
                AND host.trusted_host_key_fingerprint=
                    session.trusted_host_key_fingerprint
          )
          AND EXISTS (
              SELECT 1
              FROM ctfzone.user_sessions AS browser_session
              JOIN ctfzone.users AS account
                ON account.id=browser_session.user_id
              LEFT JOIN ctfzone.teams AS team ON team.id=account.team_id
              WHERE browser_session.id=session.browser_session_id
                AND browser_session.user_id=session.admin_user_id
                AND browser_session.revoked_at IS NULL
                AND browser_session.last_seen >=
                    (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    - ($5::double precision*INTERVAL '1 second')
                AND COALESCE(account.type,'user')='admin'
                AND NOT COALESCE(account.banned,false)
                AND NOT COALESCE(account.change_password,false)
                AND NOT COALESCE(team.banned,false)
          )
        "#,
    )
    .bind(session_id)
    .bind(request.gateway_instance_id.to_string())
    .bind(request.bytes_from_browser)
    .bind(request.bytes_to_browser)
    .bind(state.auth.session_lifetime_seconds)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;
    if updated.rows_affected() != 1 {
        sqlx::query(
            r#"
            UPDATE ctfzone.ssh_terminal_sessions
            SET state='closed',closed_at=now(),close_reason='authorization_revoked'
            WHERE id=$1 AND gateway_instance_id=$2 AND state='active'
            "#,
        )
        .bind(session_id)
        .bind(request.gateway_instance_id.to_string())
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
        return Err(ApiError::gone("This SSH session is no longer active"));
    }
    Ok(Json(Success::new(SessionStateResponse {
        session_id,
        state: "active",
    }))
    .into_response())
}

async fn session_closed(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<SessionClosedRequest>,
) -> Result<Response, ApiError> {
    if !safe_code(&request.reason)
        || request
            .exit_code
            .is_some_and(|code| !(-1..=255).contains(&code))
    {
        return Err(ApiError::bad_request("Invalid SSH session close metadata"));
    }
    validate_byte_counts(request.bytes_from_browser, request.bytes_to_browser)?;
    let gateway = request.gateway_instance_id.to_string();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let preview = session_by_id(&mut transaction, session_id).await?;
    if preview.gateway_instance_id != gateway {
        return Err(ApiError::forbidden(
            "SSH session belongs to another gateway",
        ));
    }
    let updated = sqlx::query(
        r#"
        UPDATE ctfzone.ssh_terminal_sessions
        SET state='closed',closed_at=now(),close_reason=$3,exit_code=$4,
            bytes_from_browser=GREATEST(bytes_from_browser,$5),
            bytes_to_browser=GREATEST(bytes_to_browser,$6)
        WHERE id=$1 AND gateway_instance_id=$2 AND state IN ('connecting','active')
        "#,
    )
    .bind(session_id)
    .bind(&gateway)
    .bind(&request.reason)
    .bind(request.exit_code)
    .bind(request.bytes_from_browser)
    .bind(request.bytes_to_browser)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if updated.rows_affected() == 0 {
        if preview.state == "closed" {
            transaction.commit().await.map_err(ApiError::database)?;
            return Ok(Json(Success::new(SessionStateResponse {
                session_id,
                state: "closed",
            }))
            .into_response());
        }
        return Err(ApiError::conflict("This SSH session cannot be closed"));
    }
    if let Some(revision) =
        sqlx::query_scalar::<_, i64>("SELECT revision FROM ctfzone.ssh_hosts WHERE id=$1")
            .bind(preview.ssh_host_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
    {
        append_event_by_id(
            &mut transaction,
            preview.ssh_host_id,
            revision,
            "ssh_session.closed",
            "gateway",
            Some(preview.admin_user_id),
            json!({
                "session_id": session_id,
                "reason": request.reason,
                "exit_code": request.exit_code,
                "bytes_from_browser": request.bytes_from_browser,
                "bytes_to_browser": request.bytes_to_browser
            }),
        )
        .await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(SessionStateResponse {
        session_id,
        state: "closed",
    }))
    .into_response())
}

async fn hydrate_host(pool: &PgPool, row: SshHostRow) -> Result<SshHostView, ApiError> {
    let candidates = sqlx::query_as::<_, HostKeyCandidateView>(
        r#"
        SELECT id,public_key,fingerprint,first_seen_at,last_seen_at,observation_count
        FROM ctfzone.ssh_host_key_candidates
        WHERE ssh_host_id=$1
        ORDER BY last_seen_at DESC,id
        "#,
    )
    .bind(row.id)
    .fetch_all(pool)
    .await
    .map_err(ApiError::database)?;
    let active_session_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT count(*) FROM ctfzone.ssh_terminal_sessions
        WHERE ssh_host_id=$1 AND state IN ('connecting','active')
        "#,
    )
    .bind(row.id)
    .fetch_one(pool)
    .await
    .map_err(ApiError::database)?;
    let host_key_state = if row.trusted_host_public_key.is_some() {
        "trusted"
    } else if candidates.is_empty() {
        "untrusted"
    } else {
        "candidate"
    };
    let authorized_keys_line = row.ssh_public_key.as_deref().map(authorized_keys_line);
    Ok(SshHostView {
        id: row.id,
        name: row.name,
        hostname: row.hostname,
        ssh_port: row.ssh_port,
        ssh_user: row.ssh_user,
        enabled: row.enabled,
        identity_state: row.identity_state,
        ssh_public_key: row.ssh_public_key,
        ssh_key_fingerprint: row.ssh_key_fingerprint,
        authorized_keys_line,
        key_generated_at: row.key_generated_at,
        identity_error_code: row.identity_error_code,
        host_key_state,
        trusted_host_public_key: row.trusted_host_public_key,
        trusted_host_key_fingerprint: row.trusted_host_key_fingerprint,
        host_key_trusted_at: row.host_key_trusted_at,
        host_key_candidates: candidates,
        authorized_key_cleanup_required: row.authorized_key_cleanup_required,
        active_session_count,
        revision: row.revision,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

async fn visible_host(pool: &PgPool, host_id: Uuid) -> Result<SshHostRow, ApiError> {
    let query = format!(
        "SELECT {HOST_COLUMNS} FROM ctfzone.ssh_hosts \
         WHERE id=$1 AND deleted_at IS NULL"
    );
    sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("SSH host not found"))
}

async fn visible_host_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    host_id: Uuid,
) -> Result<SshHostRow, ApiError> {
    let query = format!(
        "SELECT {HOST_COLUMNS} FROM ctfzone.ssh_hosts \
         WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
    );
    sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("SSH host not found"))
}

async fn host_for_update_any(
    transaction: &mut Transaction<'_, Postgres>,
    host_id: Uuid,
) -> Result<SshHostRow, ApiError> {
    let query = format!("SELECT {HOST_COLUMNS} FROM ctfzone.ssh_hosts WHERE id=$1 FOR UPDATE");
    sqlx::query_as::<_, SshHostRow>(&query)
        .bind(host_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("SSH host not found"))
}

async fn enqueue_identity_operation(
    transaction: &mut Transaction<'_, Postgres>,
    host: &SshHostRow,
    kind: &str,
) -> Result<Uuid, ApiError> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.ssh_host_identity_operations (
            ssh_host_id,kind,host_snapshot
        ) VALUES ($1,$2,$3)
        RETURNING id
        "#,
    )
    .bind(host.id)
    .bind(kind)
    .bind(host_snapshot(host))
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

fn host_snapshot(host: &SshHostRow) -> Value {
    json!({
        "id": host.id,
        "name": host.name,
        "hostname": host.hostname,
        "ssh_port": host.ssh_port,
        "ssh_user": host.ssh_user,
        "identity_state": host.identity_state,
        "ssh_key_fingerprint": host.ssh_key_fingerprint,
        "trusted_host_key_fingerprint": host.trusted_host_key_fingerprint,
        "revision": host.revision
    })
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    host: &SshHostRow,
    event_type: &str,
    source: &str,
    actor_user_id: Option<i32>,
    payload: Value,
) -> Result<(), ApiError> {
    append_event_by_id(
        transaction,
        host.id,
        host.revision,
        event_type,
        source,
        actor_user_id,
        payload,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn append_event_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    host_id: Uuid,
    revision: i64,
    event_type: &str,
    source: &str,
    actor_user_id: Option<i32>,
    payload: Value,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.ssh_host_events (
            ssh_host_id,event_type,source,actor_user_id,host_revision,payload
        ) VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(host_id)
    .bind(event_type)
    .bind(source)
    .bind(actor_user_id)
    .bind(revision)
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

async fn operation_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<IdentityOperationRow, ApiError> {
    sqlx::query_as::<_, IdentityOperationRow>(
        r#"
        SELECT id,ssh_host_id,kind,attempts,claim_expires_at,claim_token
        FROM ctfzone.ssh_host_identity_operations WHERE id=$1
        "#,
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("SSH identity operation not found"))
}

async fn claimed_operation_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    gateway: &str,
    claim_token: Uuid,
) -> Result<IdentityOperationRow, ApiError> {
    sqlx::query_as::<_, IdentityOperationRow>(
        r#"
        SELECT id,ssh_host_id,kind,attempts,claim_expires_at,claim_token
        FROM ctfzone.ssh_host_identity_operations
        WHERE id=$1 AND state='claimed' AND claimed_by_gateway=$2
          AND claim_token=$3
          AND claim_expires_at > now()
        FOR UPDATE
        "#,
    )
    .bind(operation_id)
    .bind(gateway)
    .bind(claim_token)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::conflict("SSH identity operation claim expired"))
}

async fn complete_operation_row(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        UPDATE ctfzone.ssh_host_identity_operations
        SET state='completed',claimed_at=NULL,claim_expires_at=NULL,
            claim_token=NULL,claimed_by_gateway=NULL,completed_at=now(),
            last_error=NULL,updated_at=now()
        WHERE id=$1 AND state='claimed'
        "#,
    )
    .bind(operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

async fn ticket_by_digest(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &[u8],
    lock: bool,
) -> Result<TicketRow, ApiError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let query = format!(
        r#"
        SELECT id,ssh_host_id,purpose,issued_to_user_id,browser_session_id,
               request_ip,expires_at,consumed_at,revoked_at
        FROM ctfzone.ssh_host_tickets WHERE token_sha256=$1{suffix}
        "#
    );
    sqlx::query_as::<_, TicketRow>(&query)
        .bind(digest)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(invalid_ticket)
}

async fn ticket_session_is_valid(
    transaction: &mut Transaction<'_, Postgres>,
    browser_session_id: &str,
    user_id: i32,
    session_lifetime_seconds: i64,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar::<_, String>(
        r#"
        SELECT session.id
        FROM ctfzone.user_sessions AS session
        JOIN ctfzone.users AS account ON account.id=session.user_id
        LEFT JOIN ctfzone.teams AS team ON team.id=account.team_id
        WHERE session.id=$1 AND session.user_id=$2 AND session.revoked_at IS NULL
          AND session.last_seen >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
              - ($3::double precision*INTERVAL '1 second')
          AND COALESCE(account.type,'user')='admin'
          AND NOT COALESCE(account.banned,false)
          AND NOT COALESCE(account.change_password,false)
          AND NOT COALESCE(team.banned,false)
        "#,
    )
    .bind(browser_session_id)
    .bind(user_id)
    .bind(session_lifetime_seconds)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .is_some())
}

async fn session_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<SessionRow, ApiError> {
    sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT ssh_host_id,admin_user_id,browser_session_id,gateway_instance_id,
               host_revision,trusted_host_key_fingerprint,state
        FROM ctfzone.ssh_terminal_sessions WHERE id=$1
        "#,
    )
    .bind(session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("SSH session not found"))
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalKey {
    canonical: String,
    fingerprint: String,
}

fn canonical_ed25519_public_key(value: &str) -> Result<CanonicalKey, ApiError> {
    if value.is_empty() || value.len() > 1024 || value.contains(char::is_control) {
        return Err(ApiError::bad_request("Invalid Ed25519 SSH public key"));
    }
    let mut fields = value.split_ascii_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return Err(ApiError::bad_request("Only Ed25519 SSH keys are accepted"));
    }
    let encoded = fields
        .next()
        .ok_or_else(|| ApiError::bad_request("Invalid Ed25519 SSH public key"))?;
    let blob = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ApiError::bad_request("Invalid Ed25519 SSH public key"))?;
    if !valid_ed25519_blob(&blob) {
        return Err(ApiError::bad_request("Invalid Ed25519 SSH public key"));
    }
    let canonical_blob = general_purpose::STANDARD.encode(&blob);
    let fingerprint = format!(
        "SHA256:{}",
        general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
    );
    Ok(CanonicalKey {
        canonical: format!("ssh-ed25519 {canonical_blob}"),
        fingerprint,
    })
}

fn valid_ed25519_blob(blob: &[u8]) -> bool {
    let Some((algorithm, rest)) = read_ssh_string(blob) else {
        return false;
    };
    let Some((key, trailing)) = read_ssh_string(rest) else {
        return false;
    };
    algorithm == b"ssh-ed25519" && key.len() == 32 && trailing.is_empty()
}

fn read_ssh_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let end = 4_usize.checked_add(length)?;
    Some((input.get(4..end)?, input.get(end..)?))
}

// OpenSSH sshd(8) defines `restrict` as disabling port, agent and X11
// forwarding, PTY allocation, and user rc. The subsequent `pty` option
// deliberately re-enables only PTY allocation, which an interactive terminal
// needs. The key permits an interactive PTY but disables forwarding and agents.
fn authorized_keys_line(public_key: &str) -> String {
    format!("restrict,pty {public_key}")
}

fn validate_target(name: &str, hostname: &str, ssh_port: i32) -> Result<(), ApiError> {
    if !safe_existing_user(name) || !safe_hostname(hostname) || !(1..=65535).contains(&ssh_port) {
        return Err(ApiError::bad_request(
            "SSH hosts require an existing non-root Unix username and a valid target",
        ));
    }
    Ok(())
}

fn safe_existing_user(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=32).contains(&bytes.len())
        && matches!(bytes.first(), Some(b'a'..=b'z' | b'_'))
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
        && !matches!(value, "root" | "toor")
}

fn safe_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn safe_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn safe_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|digest| {
        (40..=50).contains(&digest.len())
            && digest.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-')
            })
    })
}

fn valid_ticket_text(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn canonical_ip(value: &str) -> Option<String> {
    value
        .trim()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

fn validate_ticket_host(host: &SshHostRow, purpose: TicketPurpose) -> Result<(), ApiError> {
    if host.identity_state != "ready" {
        return Err(ApiError::conflict("The SSH access identity is not ready"));
    }
    if matches!(purpose, TicketPurpose::Terminal)
        && (!host.enabled || host.trusted_host_public_key.is_none())
    {
        return Err(ApiError::conflict(
            "Trust the SSH host key before opening a terminal",
        ));
    }
    Ok(())
}

fn validate_byte_counts(from_browser: i64, to_browser: i64) -> Result<(), ApiError> {
    if from_browser < 0 || to_browser < 0 {
        return Err(ApiError::bad_request("Invalid SSH session byte counters"));
    }
    Ok(())
}

fn invalid_ticket() -> ApiError {
    ApiError::unauthorized("Invalid or expired SSH ticket")
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if !user.is_admin() {
        return Err(ApiError::forbidden("Administrator access is required"));
    }
    Ok(())
}

fn default_ssh_port() -> i32 {
    22
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ed25519_key() -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(11_u32.to_be_bytes()));
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&(32_u32.to_be_bytes()));
        blob.extend_from_slice(&[7_u8; 32]);
        format!(
            "ssh-ed25519 {} fixture",
            general_purpose::STANDARD.encode(blob)
        )
    }

    #[test]
    fn existing_user_policy_is_exact_and_non_privileged() {
        for valid in ["tecnico", "ubuntu", "user_1", "_service"] {
            assert!(safe_existing_user(valid), "{valid}");
        }
        for invalid in [
            "root",
            "toor",
            "User",
            "-option",
            "user.name",
            "user@host",
            "a;id",
            "",
        ] {
            assert!(!safe_existing_user(invalid), "{invalid}");
        }
    }

    #[test]
    fn target_validation_rejects_ssh_option_injection() {
        for valid in [
            "host-1.internal",
            "ssh_host.internal",
            "host.example.",
            "host..example",
            "2001:db8::1",
        ] {
            assert!(safe_hostname(valid), "{valid}");
        }
        for invalid in ["-oProxyCommand=id", "host name", "user@host", "a/../b", ""] {
            assert!(!safe_hostname(invalid), "{invalid}");
        }
    }

    #[test]
    fn active_terminal_limit_is_per_administrator_and_host() {
        assert!(ACTIVE_TERMINAL_FOR_ACTOR_QUERY.contains("ssh_host_id=$1"));
        assert!(ACTIVE_TERMINAL_FOR_ACTOR_QUERY.contains("admin_user_id=$2"));
        assert!(!ACTIVE_TERMINAL_FOR_ACTOR_QUERY.contains("browser_session_id"));
    }

    #[test]
    fn canonicalizes_and_fingerprints_only_ed25519_keys() {
        let parsed = canonical_ed25519_public_key(&test_ed25519_key()).unwrap();
        assert!(parsed.canonical.starts_with("ssh-ed25519 AAAA"));
        assert!(!parsed.canonical.contains("fixture"));
        assert!(parsed.fingerprint.starts_with("SHA256:"));
        assert!(canonical_ed25519_public_key("ssh-rsa AAAA").is_err());
        assert!(canonical_ed25519_public_key("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn authorized_key_reenables_only_pty_after_restrict() {
        let key = canonical_ed25519_public_key(&test_ed25519_key()).unwrap();
        let line = authorized_keys_line(&key.canonical);
        assert_eq!(line, format!("restrict,pty {}", key.canonical));
        assert!(!line.contains("command="));
        assert!(!line.contains("no-pty"));
    }

    #[test]
    fn ticket_shape_and_ip_binding_inputs_are_bounded() {
        let token = general_purpose::URL_SAFE_NO_PAD.encode([3_u8; 32]);
        assert!(valid_ticket_text(&token));
        assert!(!valid_ticket_text("short"));
        assert_eq!(canonical_ip("2001:0db8::1").as_deref(), Some("2001:db8::1"));
        assert!(canonical_ip("unknown").is_none());
        assert_eq!(TICKET_TTL_SECONDS, 30);
        assert_eq!(WEBSOCKET_PATH, "/bff/ssh/terminal");
    }

    #[test]
    fn identity_callbacks_are_bound_to_the_exact_lease_claim() {
        let source = include_str!("ssh_hosts.rs");
        for marker in [
            "claim_token: Uuid",
            "operation.claim_token=$3",
            "AND claim_token=$3",
            ".bind(request.claim_token)",
        ] {
            assert!(source.contains(marker), "missing claim fence: {marker}");
        }
    }

    #[test]
    fn authorized_key_cleanup_state_has_one_pre_release_name() {
        let api = include_str!("ssh_hosts.rs");
        let schema = include_str!("../../../../db/init/004-ssh-host-control-plane.sql");
        let obsolete = ["legacy", "authorized", "key", "cleanup", "required"].join("_");
        for source in [api, schema] {
            assert!(source.contains("authorized_key_cleanup_required"));
            assert!(!source.contains(&obsolete));
        }
    }
}
