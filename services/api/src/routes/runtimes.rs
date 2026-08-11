use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

const COMMAND_CHANNEL: &str = "ctfzone_runtime_commands";
const SETTINGS_CHANNEL: &str = "ctfzone_settings_changed";
const CHALLENGE_CHANNEL: &str = "ctfzone_challenge_runtime_changed";

#[derive(Deserialize, Default)]
pub(super) struct EnsureRequest {
    ttl_seconds: Option<i64>,
    idempotency_key: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct ExtendRequest {
    additional_seconds: Option<i64>,
    idempotency_key: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct HistoryQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    challenge_id: Option<i32>,
    active: Option<bool>,
    owner_user_id: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct SettingPatch {
    enabled: bool,
}

#[derive(Deserialize)]
pub(super) struct RuntimeConfigInput {
    runtime_mode: String,
    enabled: bool,
    image_digest: Option<String>,
    protocol: String,
    container_port: Option<i32>,
    default_ttl_seconds: i32,
    maximum_ttl_seconds: i32,
    allow_extension: bool,
    maximum_extensions: i32,
    cpu_limit: Option<String>,
    memory_limit_bytes: Option<i64>,
    pid_limit: Option<i32>,
    storage_limit_bytes: Option<i64>,
    #[serde(default = "empty_object")]
    healthcheck: Value,
    remote_pool: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct RemoteServerCreate {
    name: String,
    hostname: String,
    #[serde(default = "default_ssh_port")]
    ssh_port: i32,
    ssh_user: String,
    #[serde(default = "default_helper_path")]
    helper_path: String,
    identity_file: Option<String>,
    host_key_alias: Option<String>,
    pool: Option<String>,
    #[serde(default = "default_capacity")]
    capacity: i32,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Deserialize, Default)]
pub(super) struct RemoteServerPatch {
    name: Option<String>,
    hostname: Option<String>,
    ssh_port: Option<i32>,
    ssh_user: Option<String>,
    helper_path: Option<String>,
    identity_file: Option<String>,
    host_key_alias: Option<String>,
    pool: Option<String>,
    capacity: Option<i32>,
    enabled: Option<bool>,
}

#[derive(FromRow)]
struct LaunchGate {
    challenge_state: String,
    setting_enabled: bool,
    setting_revision: i64,
    runtime_mode: String,
    runtime_enabled: bool,
    runtime_revision: i64,
    image_digest: Option<String>,
    protocol: String,
    container_port: Option<i32>,
    default_ttl_seconds: i32,
    maximum_ttl_seconds: i32,
    cpu_limit: Option<String>,
    memory_limit_bytes: Option<i64>,
    pid_limit: Option<i32>,
    storage_limit_bytes: Option<i64>,
    healthcheck: Value,
    remote_pool: Option<String>,
}

#[derive(Clone, FromRow, Serialize)]
pub(super) struct RuntimeInstanceView {
    id: Uuid,
    owner_user_id: i32,
    created_by_user_id: i32,
    team_id: Option<i32>,
    challenge_id: i32,
    active: bool,
    desired_state: String,
    observed_state: String,
    desired_expires_at: DateTime<Utc>,
    maximum_expires_at: DateTime<Utc>,
    observed_expires_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    remote_server_id: Option<Uuid>,
    remote_container_id: Option<String>,
    remote_ip: Option<String>,
    container_port: Option<i32>,
    published_ip: Option<String>,
    published_port: Option<i32>,
    protocol: Option<String>,
    public_hostname: Option<String>,
    endpoint_url: Option<String>,
    generation: i64,
    observed_generation: i64,
    extension_count: i32,
    created_at: DateTime<Utc>,
    activated_at: Option<DateTime<Utc>>,
    ready_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
    stopped_at: Option<DateTime<Utc>>,
    failure_code: Option<String>,
    failure_message: Option<String>,
}

#[derive(FromRow, Serialize)]
struct RuntimeEventView {
    sequence: i64,
    event_id: Uuid,
    instance_id: Uuid,
    event_type: String,
    source: String,
    actor_user_id: Option<i32>,
    payload: Value,
    created_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize)]
struct RuntimeSettingView {
    key: String,
    enabled: bool,
    revision: i64,
    updated_at: DateTime<Utc>,
    updated_by_user_id: Option<i32>,
}

#[derive(FromRow, Serialize)]
struct RuntimeConfigView {
    challenge_id: i32,
    runtime_mode: String,
    enabled: bool,
    image_digest: Option<String>,
    protocol: String,
    container_port: Option<i32>,
    default_ttl_seconds: i32,
    maximum_ttl_seconds: i32,
    allow_extension: bool,
    maximum_extensions: i32,
    cpu_limit: Option<String>,
    memory_limit_bytes: Option<i64>,
    pid_limit: Option<i32>,
    storage_limit_bytes: Option<i64>,
    healthcheck: Value,
    remote_pool: Option<String>,
    revision: i64,
    updated_at: DateTime<Utc>,
    updated_by_user_id: Option<i32>,
}

#[derive(Clone, FromRow, Serialize)]
struct RemoteServerView {
    id: Uuid,
    name: String,
    hostname: String,
    ssh_port: i32,
    ssh_user: String,
    helper_path: String,
    identity_file: Option<String>,
    host_key_alias: Option<String>,
    pool: Option<String>,
    capacity: i32,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ExtensionState {
    active: bool,
    desired_state: String,
    observed_state: String,
    desired_expires_at: DateTime<Utc>,
    maximum_expires_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    generation: i64,
    extension_count: i32,
    private_challenges_revision: i64,
    challenge_runtime_revision: i64,
    allow_extension: bool,
    maximum_extensions: i32,
    default_ttl_seconds: i32,
}

pub(super) async fn ensure_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
    headers: HeaderMap,
    Json(request): Json<EnsureRequest>,
) -> Result<Response, ApiError> {
    super::challenges::require_challenge_visibility(&state, Some(&user)).await?;
    super::challenges::require_ctf_time(&state, Some(&user)).await?;
    super::challenges::require_verified(&state, Some(&user)).await?;
    if super::challenges::is_team_mode(&state).await? && !user.is_admin() && user.team_id.is_none()
    {
        return Err(ApiError::forbidden(
            "Join a team before starting a challenge",
        ));
    }

    let gate = load_launch_gate(&state, challenge_id).await?;
    if !user.is_admin() && gate.challenge_state != "visible" {
        return Err(ApiError::not_found("Challenge not found"));
    }
    if !gate.setting_enabled || !gate.runtime_enabled || gate.runtime_mode != "managed" {
        return Err(ApiError::conflict(
            "This challenge does not currently provide a managed instance",
        ));
    }
    let ttl = request
        .ttl_seconds
        .unwrap_or(i64::from(gate.default_ttl_seconds));
    if ttl < 60 || ttl > i64::from(gate.maximum_ttl_seconds) {
        return Err(ApiError::bad_request(
            "Requested lifetime is outside the challenge limits",
        ));
    }
    let idempotency_key = idempotency_key(&headers, request.idempotency_key)?;
    let now = Utc::now();
    let desired_expires_at = now + Duration::seconds(ttl);
    let maximum_expires_at = now + Duration::seconds(i64::from(gate.maximum_ttl_seconds));

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    sqlx::query("SELECT id FROM ctfzone.users WHERE id=$1 FOR UPDATE")
        .bind(user.id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    if let Some(existing) = active_instance_for_user(&mut transaction, user.id).await? {
        transaction.commit().await.map_err(ApiError::database)?;
        if existing.challenge_id == challenge_id {
            return Ok(Json(Success::new(existing)).into_response());
        }
        return Err(ApiError::conflict(format!(
            "You already have an active instance for challenge {}",
            existing.challenge_id
        )));
    }

    let deployment_snapshot = json!({
        "image_digest": gate.image_digest,
        "protocol": gate.protocol,
        "container_port": gate.container_port,
        "cpu_limit": gate.cpu_limit,
        "memory_limit_bytes": gate.memory_limit_bytes,
        "pid_limit": gate.pid_limit,
        "storage_limit_bytes": gate.storage_limit_bytes,
        "healthcheck": gate.healthcheck,
        "remote_pool": gate.remote_pool,
    });
    let instance_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_instances (
            owner_user_id,created_by_user_id,team_id,challenge_id,
            private_challenges_revision,challenge_runtime_revision,
            deployment_snapshot,desired_expires_at,maximum_expires_at,
            expires_at,protocol
        ) VALUES ($1,$1,$2,$3,$4,$5,$6,$7,$8,$7,$9)
        RETURNING id
        "#,
    )
    .bind(user.id)
    .bind(user.team_id)
    .bind(challenge_id)
    .bind(gate.setting_revision)
    .bind(gate.runtime_revision)
    .bind(deployment_snapshot)
    .bind(desired_expires_at)
    .bind(maximum_expires_at)
    .bind(&gate.protocol)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_runtime_database_error)?;
    append_event(
        &mut transaction,
        instance_id,
        "instance.requested",
        Some(user.id),
        json!({"challenge_id": challenge_id, "request_ip": user.request_ip()}),
    )
    .await?;
    let command_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,
            challenge_runtime_revision,status,requested_by_user_id,idempotency_key
        ) VALUES ($1,'start',1,$2,$3,'pending',$4,$5)
        RETURNING id
        "#,
    )
    .bind(instance_id)
    .bind(gate.setting_revision)
    .bind(gate.runtime_revision)
    .bind(user.id)
    .bind(idempotency_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_runtime_database_error)?;
    notify(&mut transaction, COMMAND_CHANNEL, &command_id.to_string()).await?;
    let instance = instance_by_id_tx(&mut transaction, instance_id).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::ACCEPTED, Json(Success::new(instance))).into_response())
}

pub(super) async fn challenge_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    let instance = active_instance_for_user_pool(&state, user.id)
        .await?
        .filter(|instance| instance.challenge_id == challenge_id)
        .ok_or_else(|| ApiError::not_found("No active instance exists for this challenge"))?;
    Ok(Json(Success::new(instance)).into_response())
}

pub(super) async fn terminate_challenge_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    let instance = active_instance_for_user_pool(&state, user.id)
        .await?
        .filter(|instance| instance.challenge_id == challenge_id)
        .ok_or_else(|| ApiError::not_found("No active instance exists for this challenge"))?;
    request_termination(&state, &user, instance.id, "user_requested").await
}

pub(super) async fn terminate_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(instance_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    request_termination(&state, &user, instance_id, "user_requested").await
}

pub(super) async fn extend_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(instance_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ExtendRequest>,
) -> Result<Response, ApiError> {
    let idempotency_key = idempotency_key(&headers, request.idempotency_key)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let row = sqlx::query_as::<_, ExtensionState>(
        r#"
        SELECT i.active,i.desired_state,i.observed_state,i.desired_expires_at,
               i.maximum_expires_at,i.expires_at,i.generation,i.extension_count,
               i.private_challenges_revision,i.challenge_runtime_revision,
               COALESCE(r.allow_extension,false) AS allow_extension,
               COALESCE(r.maximum_extensions,0) AS maximum_extensions,
               COALESCE(r.default_ttl_seconds,900) AS default_ttl_seconds
        FROM ctfzone.runtime_instances i
        LEFT JOIN ctfzone.challenge_runtime_configs r ON r.challenge_id=i.challenge_id
        WHERE i.id=$1
        FOR UPDATE OF i
        "#,
    )
    .bind(instance_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Instance not found"))?;
    authorize_instance(&user, instance_id, &mut transaction).await?;
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(existing_instance_id) = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT instance_id FROM ctfzone.runtime_commands
            WHERE requested_by_user_id=$1 AND idempotency_key=$2 AND kind='extend'
            "#,
        )
        .bind(user.id)
        .bind(key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        {
            if existing_instance_id != instance_id {
                return Err(ApiError::conflict(
                    "Idempotency key was already used for another instance",
                ));
            }
            let instance = instance_by_id_tx(&mut transaction, instance_id).await?;
            transaction.commit().await.map_err(ApiError::database)?;
            return Ok(Json(Success::new(instance)).into_response());
        }
    }
    if !row.active
        || row.desired_state != "running"
        || row.observed_state != "ready"
        || row.expires_at <= Utc::now()
    {
        return Err(ApiError::conflict("This instance cannot be extended"));
    }
    if !row.allow_extension || row.extension_count >= row.maximum_extensions {
        return Err(ApiError::forbidden("No instance extensions remain"));
    }
    let additional = request
        .additional_seconds
        .unwrap_or(i64::from(row.default_ttl_seconds));
    if !(60..=86400).contains(&additional) {
        return Err(ApiError::bad_request(
            "Extension must be between 60 seconds and 24 hours",
        ));
    }
    let proposed = row.desired_expires_at + Duration::seconds(additional);
    let new_expires_at = proposed.min(row.maximum_expires_at);
    if new_expires_at <= row.desired_expires_at {
        return Err(ApiError::conflict(
            "The instance has reached its maximum lifetime",
        ));
    }
    let generation = row.generation + 1;
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET desired_expires_at=$1,
            generation=$2,extension_count=extension_count+1
        WHERE id=$3
        "#,
    )
    .bind(new_expires_at)
    .bind(generation)
    .bind(instance_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let command_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,challenge_runtime_revision,
            payload,status,requested_by_user_id,idempotency_key
        ) VALUES ($1,'extend',$2,$3,$4,$5,'pending',$6,$7)
        RETURNING id
        "#,
    )
    .bind(instance_id)
    .bind(generation)
    .bind(row.private_challenges_revision)
    .bind(row.challenge_runtime_revision)
    .bind(json!({"requested_expires_at": new_expires_at}))
    .bind(user.id)
    .bind(idempotency_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_runtime_database_error)?;
    append_event(
        &mut transaction,
        instance_id,
        "instance.extension_requested",
        Some(user.id),
        json!({"command_id": command_id, "requested_expires_at": new_expires_at}),
    )
    .await?;
    notify(&mut transaction, COMMAND_CHANNEL, &command_id.to_string()).await?;
    let instance = instance_by_id_tx(&mut transaction, instance_id).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::ACCEPTED, Json(Success::new(instance))).into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(instance_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let instance = instance_by_id_pool(&state, instance_id).await?;
    if !user.is_admin() && instance.owner_user_id != user.id {
        return Err(ApiError::not_found("Instance not found"));
    }
    Ok(Json(Success::new(instance)).into_response())
}

pub(super) async fn events(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(instance_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let instance = instance_by_id_pool(&state, instance_id).await?;
    if !user.is_admin() && instance.owner_user_id != user.id {
        return Err(ApiError::not_found("Instance not found"));
    }
    let events = sqlx::query_as::<_, RuntimeEventView>(
        r#"
        SELECT sequence,event_id,instance_id,event_type,source,actor_user_id,payload,created_at
        FROM ctfzone.runtime_instance_events WHERE instance_id=$1 ORDER BY sequence
        "#,
    )
    .bind(instance_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(events)).into_response())
}

pub(super) async fn history(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, ApiError> {
    list_instances(&state, Some(user.id), query).await
}

pub(super) async fn admin_instances(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    list_instances(&state, query.owner_user_id, query).await
}

pub(super) async fn challenge_runtime_summary(
    state: &AppState,
    user_id: Option<i32>,
    challenge_id: i32,
) -> Result<Value, ApiError> {
    let config = load_runtime_config(state, challenge_id).await?;
    let setting = load_setting(state).await?;
    let active_instance = if let Some(user_id) = user_id {
        active_instance_for_user_pool(state, user_id).await?
    } else {
        None
    };
    let instance = active_instance
        .as_ref()
        .filter(|instance| instance.challenge_id == challenge_id);
    let blocking_instance = active_instance
        .as_ref()
        .filter(|instance| instance.challenge_id != challenge_id);
    let available = setting.enabled
        && config
            .as_ref()
            .is_some_and(|config| config.enabled && config.runtime_mode == "managed");
    Ok(json!({
        "available": available,
        "authenticated": user_id.is_some(),
        "setting_revision": setting.revision,
        "config": config.map(|config| json!({
            "runtime_mode": config.runtime_mode,
            "enabled": config.enabled,
            "protocol": config.protocol,
            "container_port": config.container_port,
            "default_ttl_seconds": config.default_ttl_seconds,
            "maximum_ttl_seconds": config.maximum_ttl_seconds,
            "allow_extension": config.allow_extension,
            "maximum_extensions": config.maximum_extensions,
            "revision": config.revision,
        })),
        "instance": instance,
        "blocking_instance": blocking_instance.map(|instance| json!({
            "id": instance.id,
            "challenge_id": instance.challenge_id,
            "observed_state": instance.observed_state,
            "expires_at": instance.expires_at,
        })),
        "activation_url": format!("/api/v1/challenges/{challenge_id}/instance"),
    }))
}

pub(super) async fn get_private_challenges_setting(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let setting = load_setting(&state).await?;
    Ok(Json(Success::new(setting)).into_response())
}

pub(super) async fn update_private_challenges_setting(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<SettingPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let setting = sqlx::query_as::<_, RuntimeSettingView>(
        r#"
        UPDATE ctfzone.runtime_settings
        SET enabled=$1,revision=revision+1,updated_at=now(),updated_by_user_id=$2
        WHERE key='private_challenges'
        RETURNING key,enabled,revision,updated_at,updated_by_user_id
        "#,
    )
    .bind(request.enabled)
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    notify(
        &mut transaction,
        SETTINGS_CHANNEL,
        &setting.revision.to_string(),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(setting)).into_response())
}

pub(super) async fn get_challenge_runtime(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let config = load_runtime_config(&state, challenge_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Challenge runtime configuration not found"))?;
    Ok(Json(Success::new(config)).into_response())
}

pub(super) async fn put_challenge_runtime(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
    Json(request): Json<RuntimeConfigInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_runtime_config(&request)?;
    let challenge_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.challenges WHERE id=$1)",
    )
    .bind(challenge_id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    if !challenge_exists {
        return Err(ApiError::not_found("Challenge not found"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let config = sqlx::query_as::<_, RuntimeConfigView>(
        r#"
        INSERT INTO ctfzone.challenge_runtime_configs (
            challenge_id,runtime_mode,enabled,image_digest,protocol,container_port,
            default_ttl_seconds,maximum_ttl_seconds,allow_extension,maximum_extensions,
            cpu_limit,memory_limit_bytes,pid_limit,storage_limit_bytes,healthcheck,
            remote_pool,revision,updated_at,updated_by_user_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,1,now(),$17)
        ON CONFLICT (challenge_id) DO UPDATE SET
            runtime_mode=EXCLUDED.runtime_mode,enabled=EXCLUDED.enabled,
            image_digest=EXCLUDED.image_digest,protocol=EXCLUDED.protocol,
            container_port=EXCLUDED.container_port,
            default_ttl_seconds=EXCLUDED.default_ttl_seconds,
            maximum_ttl_seconds=EXCLUDED.maximum_ttl_seconds,
            allow_extension=EXCLUDED.allow_extension,
            maximum_extensions=EXCLUDED.maximum_extensions,cpu_limit=EXCLUDED.cpu_limit,
            memory_limit_bytes=EXCLUDED.memory_limit_bytes,pid_limit=EXCLUDED.pid_limit,
            storage_limit_bytes=EXCLUDED.storage_limit_bytes,healthcheck=EXCLUDED.healthcheck,
            remote_pool=EXCLUDED.remote_pool,revision=ctfzone.challenge_runtime_configs.revision+1,
            updated_at=now(),updated_by_user_id=EXCLUDED.updated_by_user_id
        RETURNING challenge_id,runtime_mode,enabled,image_digest,protocol,container_port,
                  default_ttl_seconds,maximum_ttl_seconds,allow_extension,maximum_extensions,
                  cpu_limit,memory_limit_bytes,pid_limit,storage_limit_bytes,healthcheck,
                  remote_pool,revision,updated_at,updated_by_user_id
        "#,
    )
    .bind(challenge_id)
    .bind(&request.runtime_mode)
    .bind(request.enabled)
    .bind(normalize_optional(request.image_digest))
    .bind(&request.protocol)
    .bind(request.container_port)
    .bind(request.default_ttl_seconds)
    .bind(request.maximum_ttl_seconds)
    .bind(request.allow_extension)
    .bind(request.maximum_extensions)
    .bind(normalize_optional(request.cpu_limit))
    .bind(request.memory_limit_bytes)
    .bind(request.pid_limit)
    .bind(request.storage_limit_bytes)
    .bind(request.healthcheck)
    .bind(normalize_optional(request.remote_pool))
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    notify(
        &mut transaction,
        CHALLENGE_CHANNEL,
        &challenge_id.to_string(),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(config)).into_response())
}

pub(super) async fn list_remote_servers(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let servers = sqlx::query_as::<_, RemoteServerView>(&remote_server_select("ORDER BY name"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(servers)).into_response())
}

pub(super) async fn create_remote_server(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<RemoteServerCreate>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_remote_server(
        &request.name,
        &request.hostname,
        request.ssh_port,
        &request.ssh_user,
        &request.helper_path,
        request.capacity,
        request.host_key_alias.as_deref(),
    )?;
    let server = sqlx::query_as::<_, RemoteServerView>(
        r#"
        INSERT INTO ctfzone.remote_servers (
            name,hostname,ssh_port,ssh_user,helper_path,identity_file,
            host_key_alias,pool,capacity,enabled
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING id,name,hostname,ssh_port,ssh_user,helper_path,identity_file,
                  host_key_alias,pool,capacity,enabled,created_at,updated_at
        "#,
    )
    .bind(request.name.trim())
    .bind(request.hostname.trim())
    .bind(request.ssh_port)
    .bind(request.ssh_user.trim())
    .bind(request.helper_path.trim())
    .bind(normalize_optional(request.identity_file))
    .bind(normalize_optional(request.host_key_alias))
    .bind(normalize_optional(request.pool))
    .bind(request.capacity)
    .bind(request.enabled)
    .fetch_one(&state.database)
    .await
    .map_err(map_runtime_database_error)?;
    Ok((StatusCode::CREATED, Json(Success::new(server))).into_response())
}

pub(super) async fn get_remote_server(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let server = remote_server_by_id(&state, server_id).await?;
    Ok(Json(Success::new(server)).into_response())
}

pub(super) async fn update_remote_server(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(request): Json<RemoteServerPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let current = remote_server_by_id(&state, server_id).await?;
    let name = request.name.unwrap_or(current.name);
    let hostname = request.hostname.unwrap_or(current.hostname);
    let ssh_port = request.ssh_port.unwrap_or(current.ssh_port);
    let ssh_user = request.ssh_user.unwrap_or(current.ssh_user);
    let helper_path = request.helper_path.unwrap_or(current.helper_path);
    let capacity = request.capacity.unwrap_or(current.capacity);
    let host_key_alias = request.host_key_alias.or(current.host_key_alias);
    validate_remote_server(
        &name,
        &hostname,
        ssh_port,
        &ssh_user,
        &helper_path,
        capacity,
        host_key_alias.as_deref(),
    )?;
    let server = sqlx::query_as::<_, RemoteServerView>(
        r#"
        UPDATE ctfzone.remote_servers SET name=$1,hostname=$2,ssh_port=$3,ssh_user=$4,
            helper_path=$5,identity_file=$6,host_key_alias=$7,pool=$8,capacity=$9,
            enabled=$10,updated_at=now()
        WHERE id=$11
        RETURNING id,name,hostname,ssh_port,ssh_user,helper_path,identity_file,
                  host_key_alias,pool,capacity,enabled,created_at,updated_at
        "#,
    )
    .bind(name.trim())
    .bind(hostname.trim())
    .bind(ssh_port)
    .bind(ssh_user.trim())
    .bind(helper_path.trim())
    .bind(request.identity_file.or(current.identity_file))
    .bind(host_key_alias)
    .bind(request.pool.or(current.pool))
    .bind(capacity)
    .bind(request.enabled.unwrap_or(current.enabled))
    .bind(server_id)
    .fetch_one(&state.database)
    .await
    .map_err(map_runtime_database_error)?;
    Ok(Json(Success::new(server)).into_response())
}

pub(super) async fn disable_remote_server(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let server = sqlx::query_as::<_, RemoteServerView>(
        r#"
        UPDATE ctfzone.remote_servers SET enabled=false,updated_at=now() WHERE id=$1
        RETURNING id,name,hostname,ssh_port,ssh_user,helper_path,identity_file,
                  host_key_alias,pool,capacity,enabled,created_at,updated_at
        "#,
    )
    .bind(server_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Remote server not found"))?;
    Ok(Json(Success::new(server)).into_response())
}

pub(super) async fn reconcile_instance(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(instance_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let instance = instance_by_id_tx_locked(&mut transaction, instance_id).await?;
    if instance.remote_server_id.is_none() {
        return Err(ApiError::conflict("Instance has no assigned remote server"));
    }
    let (setting_revision, runtime_revision) =
        instance_revisions(&mut transaction, instance_id).await?;
    let command_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,challenge_runtime_revision,
            payload,status,requested_by_user_id
        ) VALUES ($1,'reconcile',$2,$3,$4,'{}','pending',$5)
        ON CONFLICT DO NOTHING RETURNING id
        "#,
    )
    .bind(instance_id)
    .bind(instance.generation)
    .bind(setting_revision)
    .bind(runtime_revision)
    .bind(user.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if let Some(command_id) = command_id {
        append_event(
            &mut transaction,
            instance_id,
            "instance.reconciliation_requested",
            Some(user.id),
            json!({"command_id": command_id}),
        )
        .await?;
        notify(&mut transaction, COMMAND_CHANNEL, &command_id.to_string()).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::ACCEPTED, Json(Success::new(instance))).into_response())
}

async fn request_termination(
    state: &AppState,
    user: &CurrentUser,
    instance_id: Uuid,
    reason: &str,
) -> Result<Response, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let instance = instance_by_id_tx_locked(&mut transaction, instance_id).await?;
    if !user.is_admin() && instance.owner_user_id != user.id {
        return Err(ApiError::not_found("Instance not found"));
    }
    if !instance.active || instance.desired_state == "stopped" {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(Json(Success::new(instance)).into_response());
    }
    let (setting_revision, runtime_revision) =
        instance_revisions(&mut transaction, instance_id).await?;
    let generation = instance.generation + 1;
    sqlx::query(
        "UPDATE ctfzone.runtime_instances SET desired_state='stopped',generation=$1 WHERE id=$2",
    )
    .bind(generation)
    .bind(instance_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let command_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,challenge_runtime_revision,
            payload,status,requested_by_user_id
        ) VALUES ($1,'terminate',$2,$3,$4,$5,'pending',$6)
        RETURNING id
        "#,
    )
    .bind(instance_id)
    .bind(generation)
    .bind(setting_revision)
    .bind(runtime_revision)
    .bind(json!({"reason": reason}))
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_runtime_database_error)?;
    append_event(
        &mut transaction,
        instance_id,
        "instance.termination_requested",
        Some(user.id),
        json!({"command_id": command_id, "reason": reason}),
    )
    .await?;
    notify(&mut transaction, COMMAND_CHANNEL, &command_id.to_string()).await?;
    let updated = instance_by_id_tx(&mut transaction, instance_id).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::ACCEPTED, Json(Success::new(updated))).into_response())
}

async fn list_instances(
    state: &AppState,
    owner_user_id: Option<i32>,
    query: HistoryQuery,
) -> Result<Response, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
    let rows = sqlx::query_as::<_, RuntimeInstanceView>(&format!(
        "{} WHERE ($1::integer IS NULL OR owner_user_id=$1) AND ($2::integer IS NULL OR challenge_id=$2) AND ($3::boolean IS NULL OR active=$3) ORDER BY created_at DESC LIMIT $4 OFFSET $5",
        instance_select()
    ))
    .bind(owner_user_id)
    .bind(query.challenge_id)
    .bind(query.active)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let total = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM ctfzone.runtime_instances
        WHERE ($1::integer IS NULL OR owner_user_id=$1)
          AND ($2::integer IS NULL OR challenge_id=$2)
          AND ($3::boolean IS NULL OR active=$3)
        "#,
    )
    .bind(owner_user_id)
    .bind(query.challenge_id)
    .bind(query.active)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({
        "items": rows,
        "pagination": {"page": page, "per_page": per_page, "total": total}
    })))
    .into_response())
}

async fn load_launch_gate(state: &AppState, challenge_id: i32) -> Result<LaunchGate, ApiError> {
    sqlx::query_as::<_, LaunchGate>(
        r#"
        SELECT COALESCE(c.state,'hidden') AS challenge_state,
               COALESCE(s.enabled,false) AS setting_enabled,
               COALESCE(s.revision,0) AS setting_revision,
               COALESCE(r.runtime_mode,'static') AS runtime_mode,
               COALESCE(r.enabled,false) AS runtime_enabled,
               COALESCE(r.revision,0) AS runtime_revision,r.image_digest,
               COALESCE(r.protocol,'tcp') AS protocol,r.container_port,
               COALESCE(r.default_ttl_seconds,1800) AS default_ttl_seconds,
               COALESCE(r.maximum_ttl_seconds,3600) AS maximum_ttl_seconds,
               r.cpu_limit,r.memory_limit_bytes,r.pid_limit,r.storage_limit_bytes,
               COALESCE(r.healthcheck,'{}'::jsonb) AS healthcheck,r.remote_pool
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.runtime_settings s ON s.key='private_challenges'
        LEFT JOIN ctfzone.challenge_runtime_configs r ON r.challenge_id=c.id
        WHERE c.id=$1
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))
}

async fn load_setting(state: &AppState) -> Result<RuntimeSettingView, ApiError> {
    sqlx::query_as::<_, RuntimeSettingView>(
        "SELECT key,enabled,revision,updated_at,updated_by_user_id FROM ctfzone.runtime_settings WHERE key='private_challenges'",
    )
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn load_runtime_config(
    state: &AppState,
    challenge_id: i32,
) -> Result<Option<RuntimeConfigView>, ApiError> {
    sqlx::query_as::<_, RuntimeConfigView>(
        r#"
        SELECT challenge_id,runtime_mode,enabled,image_digest,protocol,container_port,
               default_ttl_seconds,maximum_ttl_seconds,allow_extension,maximum_extensions,
               cpu_limit,memory_limit_bytes,pid_limit,storage_limit_bytes,healthcheck,
               remote_pool,revision,updated_at,updated_by_user_id
        FROM ctfzone.challenge_runtime_configs WHERE challenge_id=$1
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn active_instance_for_user_pool(
    state: &AppState,
    user_id: i32,
) -> Result<Option<RuntimeInstanceView>, ApiError> {
    sqlx::query_as::<_, RuntimeInstanceView>(&format!(
        "{} WHERE owner_user_id=$1 AND active",
        instance_select()
    ))
    .bind(user_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn active_instance_for_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
) -> Result<Option<RuntimeInstanceView>, ApiError> {
    sqlx::query_as::<_, RuntimeInstanceView>(&format!(
        "{} WHERE owner_user_id=$1 AND active FOR UPDATE",
        instance_select()
    ))
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn instance_by_id_pool(
    state: &AppState,
    instance_id: Uuid,
) -> Result<RuntimeInstanceView, ApiError> {
    sqlx::query_as::<_, RuntimeInstanceView>(&format!("{} WHERE id=$1", instance_select()))
        .bind(instance_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Instance not found"))
}

async fn instance_by_id_tx(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
) -> Result<RuntimeInstanceView, ApiError> {
    sqlx::query_as::<_, RuntimeInstanceView>(&format!("{} WHERE id=$1", instance_select()))
        .bind(instance_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Instance not found"))
}

async fn instance_by_id_tx_locked(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
) -> Result<RuntimeInstanceView, ApiError> {
    sqlx::query_as::<_, RuntimeInstanceView>(&format!(
        "{} WHERE id=$1 FOR UPDATE",
        instance_select()
    ))
    .bind(instance_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Instance not found"))
}

async fn authorize_instance(
    user: &CurrentUser,
    instance_id: Uuid,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    let owner = sqlx::query_scalar::<_, i32>(
        "SELECT owner_user_id FROM ctfzone.runtime_instances WHERE id=$1",
    )
    .bind(instance_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if !user.is_admin() && owner != user.id {
        return Err(ApiError::not_found("Instance not found"));
    }
    Ok(())
}

async fn instance_revisions(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
) -> Result<(i64, i64), ApiError> {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT private_challenges_revision,challenge_runtime_revision FROM ctfzone.runtime_instances WHERE id=$1",
    )
    .bind(instance_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
    event_type: &str,
    actor_user_id: Option<i32>,
    payload: Value,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.runtime_instance_events
            (instance_id,event_type,source,actor_user_id,payload)
        VALUES ($1,$2,'api',$3,$4)
        "#,
    )
    .bind(instance_id)
    .bind(event_type)
    .bind(actor_user_id)
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

async fn notify(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &str,
    payload: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_notify($1,$2)")
        .bind(channel)
        .bind(payload)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

fn instance_select() -> &'static str {
    r#"
    SELECT id,owner_user_id,created_by_user_id,team_id,challenge_id,active,
           desired_state,observed_state,desired_expires_at,maximum_expires_at,
           observed_expires_at,expires_at,remote_server_id,remote_container_id,
           host(remote_ip) AS remote_ip,container_port,host(published_ip) AS published_ip,
           published_port,protocol,public_hostname,endpoint_url,generation,
           observed_generation,extension_count,created_at,activated_at,ready_at,
           last_observed_at,stopped_at,failure_code,failure_message
    FROM ctfzone.runtime_instances
    "#
}

fn remote_server_select(suffix: &str) -> String {
    format!(
        "SELECT id,name,hostname,ssh_port,ssh_user,helper_path,identity_file,host_key_alias,pool,capacity,enabled,created_at,updated_at FROM ctfzone.remote_servers {suffix}"
    )
}

async fn remote_server_by_id(
    state: &AppState,
    server_id: Uuid,
) -> Result<RemoteServerView, ApiError> {
    sqlx::query_as::<_, RemoteServerView>(&remote_server_select("WHERE id=$1"))
        .bind(server_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Remote server not found"))
}

fn validate_runtime_config(request: &RuntimeConfigInput) -> Result<(), ApiError> {
    if !matches!(request.runtime_mode.as_str(), "static" | "managed") {
        return Err(ApiError::bad_request("Unsupported runtime mode"));
    }
    if !matches!(request.protocol.as_str(), "tcp" | "http" | "https") {
        return Err(ApiError::bad_request("Unsupported runtime protocol"));
    }
    if request.runtime_mode == "managed"
        && (request
            .image_digest
            .as_deref()
            .is_none_or(|value| !valid_image_digest(value.trim()))
            || request.container_port.is_none())
    {
        return Err(ApiError::bad_request(
            "Managed runtimes require an image digest and container port",
        ));
    }
    if request
        .container_port
        .is_some_and(|port| !(1..=65535).contains(&port))
        || !(60..=86400).contains(&request.default_ttl_seconds)
        || request.maximum_ttl_seconds < request.default_ttl_seconds
        || request.maximum_ttl_seconds > 604800
        || request.maximum_extensions < 0
        || request.memory_limit_bytes.is_some_and(|value| value <= 0)
        || request.pid_limit.is_some_and(|value| value <= 0)
        || request.storage_limit_bytes.is_some_and(|value| value <= 0)
    {
        return Err(ApiError::bad_request(
            "Invalid runtime resource or lifetime limit",
        ));
    }
    if !request.healthcheck.is_object() {
        return Err(ApiError::bad_request("Healthcheck must be a JSON object"));
    }
    Ok(())
}

fn valid_image_digest(value: &str) -> bool {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !repository.starts_with('-')
        && repository
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:/-".contains(character))
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

#[allow(clippy::too_many_arguments)]
fn validate_remote_server(
    name: &str,
    hostname: &str,
    ssh_port: i32,
    ssh_user: &str,
    helper_path: &str,
    capacity: i32,
    host_key_alias: Option<&str>,
) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 100 || capacity <= 0 {
        return Err(ApiError::bad_request(
            "Invalid remote server name or capacity",
        ));
    }
    if !(1..=65535).contains(&ssh_port)
        || !safe_host_component(hostname.trim())
        || !safe_user(ssh_user.trim())
        || host_key_alias.is_some_and(|value| !safe_host_component(value))
    {
        return Err(ApiError::bad_request("Invalid remote SSH target"));
    }
    if !helper_path.starts_with('/')
        || !helper_path
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._-".contains(character))
    {
        return Err(ApiError::bad_request("Invalid remote helper path"));
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

fn idempotency_key(
    headers: &HeaderMap,
    body_value: Option<String>,
) -> Result<Option<String>, ApiError> {
    let header_value = headers
        .get("idempotency-key")
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::bad_request("Invalid Idempotency-Key header"))
        })
        .transpose()?;
    let value = header_value
        .or(body_value)
        .map(|value| value.trim().to_owned());
    if value.as_deref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.contains(char::is_control)
    }) {
        return Err(ApiError::bad_request("Invalid idempotency key"));
    }
    Ok(value)
}

fn map_runtime_database_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database_error) = &error {
        if matches!(
            database_error.constraint(),
            Some("runtime_instances_one_active_per_user")
                | Some("runtime_commands_idempotency")
                | Some("remote_servers_name_key")
        ) {
            return ApiError::conflict("The runtime request conflicts with existing state");
        }
    }
    ApiError::database(error)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
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

fn default_helper_path() -> String {
    "/usr/local/libexec/ctfzone-runtime-helper".to_owned()
}

fn default_capacity() -> i32 {
    100
}

fn default_true() -> bool {
    true
}

fn empty_object() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ssh_target_components() {
        assert!(safe_host_component("runtime-1.internal"));
        assert!(!safe_host_component("-oProxyCommand=bad"));
        assert!(safe_user("ctfzone_runtime"));
        assert!(!safe_user("root@host"));
    }

    #[test]
    fn rejects_invalid_runtime_limits() {
        let invalid = RuntimeConfigInput {
            runtime_mode: "managed".to_owned(),
            enabled: true,
            image_digest: None,
            protocol: "tcp".to_owned(),
            container_port: Some(31337),
            default_ttl_seconds: 1800,
            maximum_ttl_seconds: 3600,
            allow_extension: true,
            maximum_extensions: 1,
            cpu_limit: None,
            memory_limit_bytes: None,
            pid_limit: None,
            storage_limit_bytes: None,
            healthcheck: json!({}),
            remote_pool: None,
        };
        assert!(validate_runtime_config(&invalid).is_err());
    }

    #[test]
    fn requires_immutable_container_image_digest() {
        assert!(valid_image_digest(
            "registry.example/ctf/challenge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!valid_image_digest("registry.example/ctf/challenge:latest"));
        assert!(!valid_image_digest("sha256:aaaaaaaa"));
    }
}
