use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

pub(super) const MAX_UPLOAD_BODY_BYTES: usize = 64 * 1024;
const STORAGE_QUOTA_LOCK_NAMESPACE: i32 = 0x4354_465a;

#[derive(Clone, FromRow)]
struct StoredObject {
    id: Uuid,
    object_key: String,
    upload_key: String,
    purpose: String,
    status: String,
    authorization_scope: String,
    owner_user_id: Option<i32>,
    owner_team_id: Option<i32>,
    challenge_id: Option<i32>,
    page_id: Option<i32>,
    solution_id: Option<i32>,
    original_filename: String,
    content_type: String,
    expected_size: i64,
    actual_size: Option<i64>,
    expected_checksum: String,
    actual_checksum: Option<String>,
    upload_expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    ready_at: Option<DateTime<Utc>>,
    revision: i64,
}

#[derive(FromRow)]
struct MutationIdentity {
    user_type: String,
    team_id: Option<i32>,
    banned: bool,
    team_banned: bool,
}

#[derive(Serialize)]
struct ObjectView {
    id: Uuid,
    purpose: String,
    status: String,
    filename: String,
    content_type: String,
    expected_size: i64,
    actual_size: Option<i64>,
    sha256: Option<String>,
    challenge_id: Option<i32>,
    page_id: Option<i32>,
    solution_id: Option<i32>,
    upload_expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    ready_at: Option<DateTime<Utc>>,
}

impl From<&StoredObject> for ObjectView {
    fn from(object: &StoredObject) -> Self {
        Self {
            id: object.id,
            purpose: object.purpose.clone(),
            status: object.status.clone(),
            filename: object.original_filename.clone(),
            content_type: object.content_type.clone(),
            expected_size: object.expected_size,
            actual_size: object.actual_size,
            sha256: Some(
                object
                    .actual_checksum
                    .clone()
                    .unwrap_or_else(|| object.expected_checksum.clone()),
            ),
            challenge_id: object.challenge_id,
            page_id: object.page_id,
            solution_id: object.solution_id,
            upload_expires_at: object.upload_expires_at,
            created_at: object.created_at,
            ready_at: object.ready_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UploadRequest {
    purpose: String,
    filename: String,
    #[serde(default = "default_content_type")]
    content_type: String,
    size: i64,
    sha256: String,
    #[serde(default)]
    challenge_id: Option<i32>,
    #[serde(default)]
    page_id: Option<i32>,
    #[serde(default)]
    solution_id: Option<i32>,
}

#[derive(Serialize)]
struct UploadGrant {
    object: ObjectView,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<UploadInstructions>,
    complete_path: String,
}

#[derive(Serialize)]
struct UploadInstructions {
    method: &'static str,
    url: String,
    headers: BTreeMap<String, String>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
enum Purpose {
    ChallengeAsset,
    PageAsset,
    SolutionAsset,
    Submission,
    Patch,
    Program,
}

impl Purpose {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "challenge_asset" => Ok(Self::ChallengeAsset),
            "page_asset" => Ok(Self::PageAsset),
            "solution_asset" => Ok(Self::SolutionAsset),
            "submission" => Ok(Self::Submission),
            "patch" => Ok(Self::Patch),
            "program" => Ok(Self::Program),
            _ => Err(ApiError::bad_request("Unsupported object purpose")),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeAsset => "challenge_asset",
            Self::PageAsset => "page_asset",
            Self::SolutionAsset => "solution_asset",
            Self::Submission => "submission",
            Self::Patch => "patch",
            Self::Program => "program",
        }
    }

    const fn is_asset(self) -> bool {
        matches!(
            self,
            Self::ChallengeAsset | Self::PageAsset | Self::SolutionAsset
        )
    }
}

fn is_competition_purpose(value: &str) -> bool {
    matches!(
        value,
        "submission" | "patch" | "program" | "pcap" | "result"
    )
}

struct ValidatedTarget {
    challenge_id: Option<i32>,
    page_id: Option<i32>,
    solution_id: Option<i32>,
}

struct HeadMetadata {
    content_type: Option<String>,
    etag: Option<String>,
    length: i64,
}

#[derive(Clone, Copy)]
enum AuthorizationPrincipal {
    Target,
    User(i32),
    Team(i32),
}

impl AuthorizationPrincipal {
    const fn scope(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::User(_) => "user",
            Self::Team(_) => "team",
        }
    }

    const fn quota_id(self) -> Option<i32> {
        match self {
            Self::Target => None,
            Self::User(id) | Self::Team(id) => Some(id),
        }
    }
}

pub(super) async fn initiate_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(request): Json<UploadRequest>,
) -> Result<Response, ApiError> {
    let purpose = Purpose::parse(request.purpose.trim())?;
    if purpose.is_asset() {
        require_admin(&user)?;
    }
    let filename = safe_filename(&request.filename)?;
    let content_type = safe_content_type(&request.content_type)?;
    if request.size < 0 || request.size > state.object_storage.max_upload_bytes() {
        return Err(ApiError::bad_request(
            "Object size is outside the upload limit",
        ));
    }
    let expected_checksum = validate_sha256(&request.sha256)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let target = validate_target(&state, &user, purpose, &request).await?;
    let object_id = Uuid::new_v4();
    let now = Utc::now();
    let upload_expires_at = now
        + ChronoDuration::from_std(state.object_storage.presign_ttl())
            .map_err(|_| ApiError::upstream("Upload expiry is invalid"))?;
    let object_key = format!(
        "objects/{}/{}/{}/{object_id}/{filename}",
        purpose.as_str(),
        now.format("%Y"),
        now.format("%m")
    );
    let upload_key = format!("uploads/{object_id}");

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if !purpose.is_asset() {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
    }
    let user_mode = super::user_mode_transition::transaction_user_mode(&mut transaction).await?;
    let principal =
        authorization_principal_in_transaction(&mut transaction, &user, purpose, &user_mode)
            .await?;
    if !lock_validated_target(&mut transaction, purpose, &target).await? {
        return Err(ApiError::not_found("Object target not found"));
    }
    if let Some(challenge_id) = target.challenge_id {
        super::challenges::require_full_challenge_access_in_transaction(
            &mut transaction,
            Some(&user),
            challenge_id,
        )
        .await?;
    }
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(STORAGE_QUOTA_LOCK_NAMESPACE)
        .bind(user.id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;

    if let Some(existing) =
        load_idempotent_object(&mut transaction, user.id, &idempotency_key).await?
    {
        require_same_upload(
            &existing,
            purpose,
            principal,
            &target,
            &filename,
            &content_type,
            request.size,
            &expected_checksum,
        )?;
        if !matches!(existing.status.as_str(), "pending" | "ready") {
            return Err(ApiError::conflict(
                "The idempotent upload is no longer available",
            ));
        }
        let grant = build_upload_grant(&state, &existing)?;
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok((StatusCode::OK, Json(Success::new(grant))).into_response());
    }

    if !user.is_admin() {
        enforce_storage_quota(&state, &mut transaction, principal, request.size).await?;
    }

    let owner_team_id = match principal {
        AuthorizationPrincipal::Team(team_id) => Some(team_id),
        AuthorizationPrincipal::Target | AuthorizationPrincipal::User(_) => None,
    };
    let object = sqlx::query_as::<_, StoredObject>(
        r#"
        INSERT INTO ctfzone.stored_objects
            (id,bucket,object_key,upload_key,purpose,status,authorization_scope,
             owner_user_id,owner_team_id,idempotency_key,challenge_id,page_id,
             solution_id,original_filename,content_type,
             expected_size,checksum_algorithm,expected_checksum,retention_class,
             upload_expires_at)
        VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                'sha256',$16,'standard',$17)
        RETURNING id,object_key,upload_key,purpose,status,authorization_scope,
                  owner_user_id,owner_team_id,
                  challenge_id,page_id,solution_id,original_filename,content_type,
                  expected_size,actual_size,expected_checksum,actual_checksum,
                  upload_expires_at,created_at,ready_at,revision
        "#,
    )
    .bind(object_id)
    .bind(state.object_storage.bucket_name())
    .bind(&object_key)
    .bind(&upload_key)
    .bind(purpose.as_str())
    .bind(principal.scope())
    .bind(user.id)
    .bind(owner_team_id)
    .bind(&idempotency_key)
    .bind(target.challenge_id)
    .bind(target.page_id)
    .bind(target.solution_id)
    .bind(&filename)
    .bind(&content_type)
    .bind(request.size)
    .bind(&expected_checksum)
    .bind(upload_expires_at)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    insert_event(
        &mut transaction,
        object.id,
        "upload_created",
        "api",
        Some(user.id),
        json!({"purpose": purpose.as_str(), "expected_size": request.size}),
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO ctfzone.object_operations
            (object_id,operation,object_revision,status,available_at)
        VALUES ($1,'reconcile',1,'pending',$2)
        "#,
    )
    .bind(object.id)
    .bind(upload_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;

    let grant = build_upload_grant(&state, &object)?;
    Ok((StatusCode::CREATED, Json(Success::new(grant))).into_response())
}

pub(super) async fn complete_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let object = load_object(&state, object_id).await?;
    authorize_change(&state, user.id, &object).await?;
    if object.status == "ready" {
        return Ok(Json(Success::new(ObjectView::from(&object))).into_response());
    }
    if object.status != "pending" {
        return Err(ApiError::conflict("Object upload is no longer pending"));
    }
    if object.upload_expires_at < Utc::now() {
        fail_upload(&state, &object, &user, "upload_expired").await?;
        return Err(ApiError::conflict("Object upload has expired"));
    }

    let staging_metadata = head_object(&state, &object.upload_key).await?;
    let invalid_reason = if staging_metadata.length != object.expected_size {
        Some("size_mismatch")
    } else if staging_metadata.content_type.as_deref() != Some(object.content_type.as_str()) {
        Some("content_type_mismatch")
    } else {
        None
    };
    if let Some(reason) = invalid_reason {
        fail_upload(&state, &object, &user, reason).await?;
        return Err(ApiError::conflict(
            "Uploaded object metadata does not match the grant",
        ));
    }

    let purpose = Purpose::parse(&object.purpose)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if !purpose.is_asset() {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
    }
    let user_mode = super::user_mode_transition::transaction_user_mode(&mut transaction).await?;
    if !lock_target(&mut transaction, &object).await? {
        transaction.rollback().await.map_err(ApiError::database)?;
        fail_upload(&state, &object, &user, "target_removed").await?;
        return Err(ApiError::conflict("The upload target no longer exists"));
    }
    let current = load_object_for_update(&mut transaction, object.id).await?;
    authorize_change_in_transaction(&mut transaction, user.id, &current).await?;
    let principal =
        authorization_principal_in_transaction(&mut transaction, &user, purpose, &user_mode)
            .await?;
    require_current_upload_principal(&current, principal, user.id)?;
    if current.status == "ready" {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(Json(Success::new(ObjectView::from(&current))).into_response());
    }
    if current.status != "pending" {
        return Err(ApiError::conflict("Object upload is no longer pending"));
    }
    if current.upload_expires_at < Utc::now() {
        transaction.rollback().await.map_err(ApiError::database)?;
        fail_upload(&state, &current, &user, "upload_expired").await?;
        return Err(ApiError::conflict("Object upload has expired"));
    }
    copy_to_final_key(&state, &current).await?;
    let final_metadata = head_object(&state, &current.object_key).await?;
    if final_metadata.length != current.expected_size
        || final_metadata.content_type.as_deref() != Some(current.content_type.as_str())
    {
        return Err(ApiError::upstream(
            "Object storage did not preserve the promoted object metadata",
        ));
    }

    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.stored_objects
        SET status='ready',actual_size=$2,actual_checksum=$3,etag=$4,
            ready_at=now(),revision=revision+1
        WHERE id=$1 AND status='pending' AND revision=$5
        RETURNING revision
        "#,
    )
    .bind(current.id)
    .bind(final_metadata.length)
    .bind(&current.expected_checksum)
    .bind(&final_metadata.etag)
    .bind(current.revision)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        "UPDATE ctfzone.object_operations SET status='cancelled',completed_at=now() WHERE object_id=$1 AND operation='reconcile' AND status IN ('pending','claimed')",
    )
    .bind(current.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    enqueue_operation(
        &mut transaction,
        current.id,
        "delete_upload",
        revision,
        staging_cleanup_at(current.upload_expires_at),
    )
    .await?;
    insert_event(
        &mut transaction,
        current.id,
        "upload_completed",
        "api",
        Some(user.id),
        json!({
            "actual_size": final_metadata.length,
            "etag": final_metadata.etag,
            "sha256": current.expected_checksum,
        }),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let object = load_object(&state, current.id).await?;
    Ok(Json(Success::new(ObjectView::from(&object))).into_response())
}

pub(super) async fn object_detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let object = load_object_for_update(&mut transaction, object_id).await?;
    authorize_change_in_transaction(&mut transaction, user.id, &object).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(ObjectView::from(&object))).into_response())
}

pub(super) async fn download_grant(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    if let Some(current) = user.as_ref() {
        crate::auth::revalidate_current_credential(
            &mut transaction,
            current,
            state.auth.session_lifetime_seconds,
        )
        .await?;
    }
    let user_mode = super::user_mode_transition::transaction_user_mode(&mut transaction).await?;
    let mut effective_user = user.clone();
    let current_team_id = if user_mode == "teams"
        && effective_user
            .as_ref()
            .is_some_and(|current| !current.is_admin())
    {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
        let current = effective_user.as_ref().expect("checked above");
        let team_id = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT team_id FROM ctfzone.users WHERE id=$1 AND type='user'",
        )
        .bind(current.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .flatten();
        effective_user.as_mut().expect("checked above").team_id = team_id;
        team_id
    } else {
        None
    };
    let authorized_object = load_object_in_transaction(&mut transaction, object_id).await?;
    if is_competition_purpose(&authorized_object.purpose) {
        let current = effective_user
            .as_ref()
            .ok_or_else(|| ApiError::not_found("Object not found"))?;
        if !current.is_admin() {
            let authorized = match authorized_object.authorization_scope.as_str() {
                "user" if user_mode == "users" => {
                    authorized_object.owner_user_id == Some(current.id)
                }
                "team" if user_mode == "teams" => {
                    authorized_object.owner_team_id.is_some()
                        && authorized_object.owner_team_id == current_team_id
                }
                _ => false,
            };
            if !authorized {
                return Err(ApiError::not_found("Object not found"));
            }
        }
    } else {
        authorize_download_in_transaction(
            &mut transaction,
            effective_user.as_ref(),
            &authorized_object,
            &user_mode,
        )
        .await?;
    }
    let object = load_object_for_update(&mut transaction, object_id).await?;
    if !same_download_identity(&authorized_object, &object) || object.status != "ready" {
        return Err(ApiError::not_found("Object not found"));
    }
    let url = state.object_storage.get_url(
        &object.object_key,
        &object.original_filename,
        &object.content_type,
    );
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.object_storage.presign_ttl())
            .map_err(|_| ApiError::upstream("Download expiry is invalid"))?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({
        "method": "GET",
        "url": url,
        "expires_at": expires_at,
    })))
    .into_response())
}

pub(super) async fn delete_object(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let object = load_object(&state, object_id).await?;
    authorize_change(&state, user.id, &object).await?;
    schedule_delete(&state, &object, &user).await?;
    Ok(Json(Success::new(json!({"status": "deleting"}))).into_response())
}

async fn validate_target(
    state: &AppState,
    user: &CurrentUser,
    purpose: Purpose,
    request: &UploadRequest,
) -> Result<ValidatedTarget, ApiError> {
    let supplied = [request.challenge_id, request.page_id, request.solution_id]
        .into_iter()
        .flatten()
        .count();
    if supplied != 1 {
        return Err(ApiError::bad_request(
            "Exactly one challenge, page, or solution target is required",
        ));
    }
    match purpose {
        Purpose::ChallengeAsset => {
            let challenge_id = request
                .challenge_id
                .ok_or_else(|| ApiError::bad_request("challenge_asset requires challenge_id"))?;
            super::challenges::require_full_challenge_access(state, Some(user), challenge_id)
                .await?;
            Ok(ValidatedTarget {
                challenge_id: Some(challenge_id),
                page_id: None,
                solution_id: None,
            })
        }
        Purpose::PageAsset => {
            let page_id = request
                .page_id
                .ok_or_else(|| ApiError::bad_request("page_asset requires page_id"))?;
            require_row(state, "pages", page_id).await?;
            Ok(ValidatedTarget {
                challenge_id: None,
                page_id: Some(page_id),
                solution_id: None,
            })
        }
        Purpose::SolutionAsset => {
            let solution_id = request
                .solution_id
                .ok_or_else(|| ApiError::bad_request("solution_asset requires solution_id"))?;
            let challenge_id = sqlx::query_scalar::<_, i32>(
                "SELECT challenge_id FROM ctfzone.solutions WHERE id=$1",
            )
            .bind(solution_id)
            .fetch_optional(&state.database)
            .await
            .map_err(ApiError::database)?
            .ok_or_else(|| ApiError::not_found("Solution not found"))?;
            super::challenges::require_full_challenge_access(state, Some(user), challenge_id)
                .await?;
            Ok(ValidatedTarget {
                challenge_id: Some(challenge_id),
                page_id: None,
                solution_id: Some(solution_id),
            })
        }
        Purpose::Submission | Purpose::Patch | Purpose::Program => {
            let challenge_id = request
                .challenge_id
                .ok_or_else(|| ApiError::bad_request("Submission objects require challenge_id"))?;
            super::challenges::require_full_challenge_access(state, Some(user), challenge_id)
                .await?;
            Ok(ValidatedTarget {
                challenge_id: Some(challenge_id),
                page_id: None,
                solution_id: None,
            })
        }
    }
}

async fn require_row(state: &AppState, table: &str, id: i32) -> Result<(), ApiError> {
    let query = format!("SELECT EXISTS(SELECT 1 FROM ctfzone.{table} WHERE id=$1)");
    let exists = sqlx::query_scalar::<_, bool>(&query)
        .bind(id)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::not_found("Object target not found"))
    }
}

async fn authorization_principal_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: &CurrentUser,
    purpose: Purpose,
    user_mode: &str,
) -> Result<AuthorizationPrincipal, ApiError> {
    if purpose.is_asset() {
        return Ok(AuthorizationPrincipal::Target);
    }
    if user_mode == "teams" {
        let team_id =
            sqlx::query_scalar::<_, Option<i32>>("SELECT team_id FROM ctfzone.users WHERE id=$1")
                .bind(user.id)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(ApiError::database)?
                .flatten();
        if let Some(team_id) = team_id {
            Ok(AuthorizationPrincipal::Team(team_id))
        } else if user.is_admin() {
            Ok(AuthorizationPrincipal::User(user.id))
        } else {
            Err(ApiError::forbidden(
                "Join a team before uploading challenge data",
            ))
        }
    } else {
        Ok(AuthorizationPrincipal::User(user.id))
    }
}

fn require_current_upload_principal(
    object: &StoredObject,
    principal: AuthorizationPrincipal,
    actor_user_id: i32,
) -> Result<(), ApiError> {
    let current = match principal {
        AuthorizationPrincipal::Target => object.authorization_scope == "target",
        AuthorizationPrincipal::User(user_id) => {
            object.authorization_scope == "user" && object.owner_user_id == Some(user_id)
        }
        AuthorizationPrincipal::Team(team_id) => {
            object.authorization_scope == "team"
                && object.owner_user_id == Some(actor_user_id)
                && object.owner_team_id == Some(team_id)
        }
    };
    if current {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "The upload was created for a previous competition mode",
        ))
    }
}

async fn lock_validated_target(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    purpose: Purpose,
    target: &ValidatedTarget,
) -> Result<bool, ApiError> {
    match purpose {
        Purpose::ChallengeAsset | Purpose::Submission | Purpose::Patch | Purpose::Program => {
            let Some(challenge_id) = target.challenge_id else {
                return Ok(false);
            };
            let exists = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
            )
            .bind(challenge_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
            Ok(exists)
        }
        Purpose::PageAsset => {
            let Some(page_id) = target.page_id else {
                return Ok(false);
            };
            let exists = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.pages WHERE id=$1 FOR KEY SHARE",
            )
            .bind(page_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
            Ok(exists)
        }
        Purpose::SolutionAsset => {
            let (Some(challenge_id), Some(solution_id)) = (target.challenge_id, target.solution_id)
            else {
                return Ok(false);
            };
            let challenge_exists = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
            )
            .bind(challenge_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
            if !challenge_exists {
                return Ok(false);
            }
            let solution_exists = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.solutions WHERE id=$1 AND challenge_id=$2 FOR KEY SHARE",
            )
            .bind(solution_id)
            .bind(challenge_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
            Ok(solution_exists)
        }
    }
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get("idempotency-key")
        .ok_or_else(|| ApiError::bad_request("Idempotency-Key header is required"))?
        .to_str()
        .map_err(|_| ApiError::bad_request("Invalid Idempotency-Key header"))?
        .trim();
    if value.is_empty() || value.len() > 128 || value.contains(char::is_control) {
        return Err(ApiError::bad_request("Invalid Idempotency-Key header"));
    }
    Ok(value.to_owned())
}

async fn load_idempotent_object(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: i32,
    idempotency_key: &str,
) -> Result<Option<StoredObject>, ApiError> {
    sqlx::query_as::<_, StoredObject>(
        r#"
        SELECT id,object_key,upload_key,purpose,status,authorization_scope,
               owner_user_id,owner_team_id,challenge_id,page_id,solution_id,
               original_filename,content_type,expected_size,actual_size,
               expected_checksum,actual_checksum,upload_expires_at,created_at,
               ready_at,revision
        FROM ctfzone.stored_objects
        WHERE owner_user_id=$1 AND idempotency_key=$2
        FOR UPDATE
        "#,
    )
    .bind(user_id)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

#[allow(clippy::too_many_arguments)]
fn require_same_upload(
    object: &StoredObject,
    purpose: Purpose,
    principal: AuthorizationPrincipal,
    target: &ValidatedTarget,
    filename: &str,
    content_type: &str,
    size: i64,
    checksum: &str,
) -> Result<(), ApiError> {
    let owner_matches = match principal {
        AuthorizationPrincipal::Target | AuthorizationPrincipal::User(_) => {
            object.owner_team_id.is_none()
        }
        AuthorizationPrincipal::Team(team_id) => object.owner_team_id == Some(team_id),
    };
    if object.purpose != purpose.as_str()
        || object.authorization_scope != principal.scope()
        || !owner_matches
        || object.challenge_id != target.challenge_id
        || object.page_id != target.page_id
        || object.solution_id != target.solution_id
        || object.original_filename != filename
        || object.content_type != content_type
        || object.expected_size != size
        || object.expected_checksum != checksum
    {
        return Err(ApiError::conflict(
            "Idempotency-Key was already used for a different upload",
        ));
    }
    Ok(())
}

fn build_upload_grant(state: &AppState, object: &StoredObject) -> Result<UploadGrant, ApiError> {
    let upload = if object.status == "ready" {
        None
    } else {
        let remaining = (object.upload_expires_at - Utc::now())
            .to_std()
            .map_err(|_| ApiError::conflict("The upload grant has expired"))?;
        if remaining.is_zero() {
            return Err(ApiError::conflict("The upload grant has expired"));
        }
        let (url, checksum) = state
            .object_storage
            .put_url(
                &object.upload_key,
                &object.content_type,
                object.expected_size,
                &object.expected_checksum,
                remaining,
            )
            .map_err(|_| ApiError::upstream("Could not authorize object upload"))?;
        Some(UploadInstructions {
            method: "PUT",
            url,
            headers: BTreeMap::from([
                ("Content-Type".to_owned(), object.content_type.clone()),
                ("x-amz-checksum-sha256".to_owned(), checksum),
            ]),
            expires_at: object.upload_expires_at,
        })
    };
    Ok(UploadGrant {
        complete_path: format!("/bff/api/v1/storage/objects/{}/complete", object.id),
        object: ObjectView::from(object),
        upload,
    })
}

async fn enforce_storage_quota(
    state: &AppState,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: AuthorizationPrincipal,
    requested_size: i64,
) -> Result<(), ApiError> {
    let Some(principal_id) = principal.quota_id() else {
        return Ok(());
    };
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(STORAGE_QUOTA_LOCK_NAMESPACE ^ 0x5354_4f52)
        .bind(principal_id)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    let (pending_objects, pending_bytes, retained_bytes, uploads_last_hour) =
        sqlx::query_as::<_, (i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status='pending')::bigint,
                COALESCE(SUM(expected_size) FILTER (WHERE status='pending'),0)::bigint,
                COALESCE(SUM(COALESCE(actual_size,expected_size))
                    FILTER (WHERE status IN ('pending','ready','deleting')
                        OR (status='failed' AND EXISTS (
                            SELECT 1 FROM ctfzone.object_operations op
                            WHERE op.object_id=stored_objects.id
                              AND op.status IN ('pending','claimed')
                        ))),0)::bigint,
                COUNT(*) FILTER (WHERE created_at >= now() - interval '1 hour')::bigint
            FROM ctfzone.stored_objects
            WHERE authorization_scope=$1
              AND (($1='user' AND owner_user_id=$2)
                   OR ($1='team' AND owner_team_id=$2))
            "#,
        )
        .bind(principal.scope())
        .bind(principal_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)?;

    let quota = &state.object_storage;
    if pending_objects >= quota.max_pending_objects_per_principal()
        || pending_bytes.saturating_add(requested_size) > quota.max_pending_bytes_per_principal()
        || retained_bytes.saturating_add(requested_size) > quota.max_retained_bytes_per_principal()
    {
        return Err(ApiError::conflict("Object storage quota exceeded"));
    }
    if uploads_last_hour >= quota.max_uploads_per_hour_per_principal() {
        return Err(ApiError::too_many_requests(
            "Object upload rate limit exceeded",
        ));
    }
    Ok(())
}

async fn lock_target(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object: &StoredObject,
) -> Result<bool, ApiError> {
    let exists = match object.purpose.as_str() {
        "challenge_asset" | "submission" | "patch" | "program" => {
            let Some(id) = object.challenge_id else {
                return Ok(false);
            };
            sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
            )
            .bind(id)
            .fetch_optional(&mut **transaction)
            .await
            .map(|row| row.is_some())
        }
        "page_asset" => {
            let Some(id) = object.page_id else {
                return Ok(false);
            };
            sqlx::query_scalar::<_, i32>("SELECT id FROM ctfzone.pages WHERE id=$1 FOR KEY SHARE")
                .bind(id)
                .fetch_optional(&mut **transaction)
                .await
                .map(|row| row.is_some())
        }
        "solution_asset" => {
            let (Some(solution_id), Some(challenge_id)) = (object.solution_id, object.challenge_id)
            else {
                return Ok(false);
            };
            let challenge_exists = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
            )
            .bind(challenge_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
            if !challenge_exists {
                return Ok(false);
            }
            sqlx::query_scalar::<_, i32>(
                "SELECT id FROM ctfzone.solutions WHERE id=$1 AND challenge_id=$2 FOR KEY SHARE",
            )
            .bind(solution_id)
            .bind(challenge_id)
            .fetch_optional(&mut **transaction)
            .await
            .map(|row| row.is_some())
        }
        _ => return Ok(true),
    }
    .map_err(ApiError::database)?;
    Ok(exists)
}

async fn head_object(state: &AppState, object_key: &str) -> Result<HeadMetadata, ApiError> {
    let response = state
        .http
        .head(state.object_storage.internal_head_url(object_key))
        .send()
        .await
        .map_err(|_| ApiError::upstream("Object storage is unavailable"))?;
    if response.status() == StatusCode::NOT_FOUND {
        return Err(ApiError::conflict("The uploaded object is not present"));
    }
    if !response.status().is_success() {
        return Err(ApiError::upstream(
            "Object storage rejected upload verification",
        ));
    }
    let headers = response.headers();
    let length = required_i64_header(headers, CONTENT_LENGTH)?;
    Ok(HeadMetadata {
        content_type: string_header(headers, CONTENT_TYPE),
        etag: string_header(headers, ETAG).map(|value| value.trim_matches('"').to_owned()),
        length,
    })
}

async fn copy_to_final_key(state: &AppState, object: &StoredObject) -> Result<(), ApiError> {
    let (url, copy_source) = state
        .object_storage
        .internal_copy_request(&object.upload_key, &object.object_key);
    let response = state
        .http
        .put(url)
        .header("x-amz-copy-source", copy_source)
        .body(Vec::new())
        .send()
        .await
        .map_err(|_| ApiError::upstream("Object storage promotion is unavailable"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(ApiError::upstream(
            "Object storage rejected object promotion",
        ))
    }
}

async fn fail_upload(
    state: &AppState,
    object: &StoredObject,
    user: &CurrentUser,
    reason: &str,
) -> Result<(), ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if is_competition_purpose(&object.purpose) {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
    }
    let current = load_object_for_update(&mut transaction, object.id).await?;
    authorize_change_in_transaction(&mut transaction, user.id, &current).await?;
    if current.status != "pending" {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(());
    }
    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.stored_objects
        SET status='failed',revision=revision+1
        WHERE id=$1 AND status='pending' AND revision=$2
        RETURNING revision
        "#,
    )
    .bind(current.id)
    .bind(current.revision)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        "UPDATE ctfzone.object_operations SET status='cancelled',completed_at=now() WHERE object_id=$1 AND status IN ('pending','claimed')",
    )
    .bind(current.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    enqueue_operation(&mut transaction, current.id, "delete", revision, Utc::now()).await?;
    enqueue_operation(
        &mut transaction,
        current.id,
        "delete_upload",
        revision,
        staging_cleanup_at(current.upload_expires_at),
    )
    .await?;
    insert_event(
        &mut transaction,
        current.id,
        "upload_failed",
        "api",
        Some(user.id),
        json!({"reason": reason}),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)
}

async fn schedule_delete(
    state: &AppState,
    object: &StoredObject,
    user: &CurrentUser,
) -> Result<(), ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if is_competition_purpose(&object.purpose) {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
    }
    let current = load_object_for_update(&mut transaction, object.id).await?;
    authorize_change_in_transaction(&mut transaction, user.id, &current).await?;
    if current.status == "deleted" || current.status == "deleting" {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(());
    }
    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.stored_objects
        SET status='deleting',revision=revision+1
        WHERE id=$1 AND revision=$2
        RETURNING revision
        "#,
    )
    .bind(current.id)
    .bind(current.revision)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        "UPDATE ctfzone.object_operations SET status='cancelled',completed_at=now() WHERE object_id=$1 AND status IN ('pending','claimed')",
    )
    .bind(current.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    enqueue_operation(
        &mut transaction,
        current.id,
        "delete_upload",
        revision,
        staging_cleanup_at(current.upload_expires_at),
    )
    .await?;
    enqueue_operation(&mut transaction, current.id, "delete", revision, Utc::now()).await?;
    insert_event(
        &mut transaction,
        current.id,
        "delete_requested",
        "api",
        Some(user.id),
        json!({}),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)
}

async fn enqueue_operation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_id: Uuid,
    operation: &str,
    object_revision: i64,
    available_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.object_operations
            (object_id,operation,object_revision,status,available_at)
        SELECT $1,$2,$3,'pending',$4
        WHERE NOT EXISTS (
            SELECT 1 FROM ctfzone.object_operations
            WHERE object_id=$1 AND operation=$2 AND status IN ('pending','claimed')
        )
        "#,
    )
    .bind(object_id)
    .bind(operation)
    .bind(object_revision)
    .bind(available_at)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

fn staging_cleanup_at(upload_expires_at: DateTime<Utc>) -> DateTime<Utc> {
    upload_expires_at + ChronoDuration::seconds(5)
}

async fn insert_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_id: Uuid,
    event_type: &str,
    source: &str,
    actor_user_id: Option<i32>,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.stored_object_events
            (object_id,event_type,source,actor_user_id,details)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(object_id)
    .bind(event_type)
    .bind(source)
    .bind(actor_user_id)
    .bind(details)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

async fn load_object(state: &AppState, object_id: Uuid) -> Result<StoredObject, ApiError> {
    sqlx::query_as::<_, StoredObject>(
        r#"
        SELECT id,object_key,upload_key,purpose,status,authorization_scope,
               owner_user_id,owner_team_id,
               challenge_id,page_id,solution_id,original_filename,content_type,
               expected_size,actual_size,expected_checksum,actual_checksum,
               upload_expires_at,created_at,ready_at,revision
        FROM ctfzone.stored_objects WHERE id=$1
        "#,
    )
    .bind(object_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Object not found"))
}

async fn load_object_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_id: Uuid,
) -> Result<StoredObject, ApiError> {
    sqlx::query_as::<_, StoredObject>(
        r#"
        SELECT id,object_key,upload_key,purpose,status,authorization_scope,
               owner_user_id,owner_team_id,
               challenge_id,page_id,solution_id,original_filename,content_type,
               expected_size,actual_size,expected_checksum,actual_checksum,
               upload_expires_at,created_at,ready_at,revision
        FROM ctfzone.stored_objects WHERE id=$1 FOR UPDATE
        "#,
    )
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Object not found"))
}

async fn load_object_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_id: Uuid,
) -> Result<StoredObject, ApiError> {
    sqlx::query_as::<_, StoredObject>(
        r#"
        SELECT id,object_key,upload_key,purpose,status,authorization_scope,
               owner_user_id,owner_team_id,
               challenge_id,page_id,solution_id,original_filename,content_type,
               expected_size,actual_size,expected_checksum,actual_checksum,
               upload_expires_at,created_at,ready_at,revision
        FROM ctfzone.stored_objects WHERE id=$1
        "#,
    )
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Object not found"))
}

async fn authorize_download_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Option<&CurrentUser>,
    object: &StoredObject,
    user_mode: &str,
) -> Result<(), ApiError> {
    match object.purpose.as_str() {
        "challenge_asset" => {
            let challenge_id = object
                .challenge_id
                .ok_or_else(|| ApiError::not_found("Object not found"))?;
            lock_download_challenge(transaction, challenge_id).await?;
            super::challenges::require_full_challenge_access_in_transaction(
                transaction,
                user,
                challenge_id,
            )
            .await
        }
        "page_asset" => {
            let page_id = object
                .page_id
                .ok_or_else(|| ApiError::not_found("Object not found"))?;
            let (draft, hidden, auth_required) = sqlx::query_as::<_, (bool, bool, bool)>(
                "SELECT COALESCE(draft,false),COALESCE(hidden,false),COALESCE(auth_required,false) FROM ctfzone.pages WHERE id=$1 FOR KEY SHARE",
            )
            .bind(page_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .ok_or_else(|| ApiError::not_found("Object not found"))?;
            if user.is_some_and(CurrentUser::is_admin) {
                return Ok(());
            }
            if draft || hidden || (auth_required && user.is_none()) {
                Err(ApiError::not_found("Object not found"))
            } else {
                Ok(())
            }
        }
        "solution_asset" => {
            authorize_solution_download_in_transaction(transaction, user, object, user_mode).await
        }
        "submission" | "patch" | "program" | "pcap" | "result" => {
            let Some(user) = user else {
                return Err(ApiError::not_found("Object not found"));
            };
            if user.is_admin() {
                return Ok(());
            }
            let authorized = match object.authorization_scope.as_str() {
                "user" => object.owner_user_id == Some(user.id),
                "team" => object
                    .owner_team_id
                    .is_some_and(|team_id| user.team_id == Some(team_id)),
                _ => false,
            };
            if authorized {
                Ok(())
            } else {
                Err(ApiError::not_found("Object not found"))
            }
        }
        _ => Err(ApiError::not_found("Object not found")),
    }
}

async fn authorize_solution_download_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Option<&CurrentUser>,
    object: &StoredObject,
    user_mode: &str,
) -> Result<(), ApiError> {
    let solution_id = object
        .solution_id
        .ok_or_else(|| ApiError::not_found("Object not found"))?;
    let expected_challenge_id = object
        .challenge_id
        .ok_or_else(|| ApiError::not_found("Object not found"))?;
    lock_download_challenge(transaction, expected_challenge_id).await?;
    let (challenge_id, solution_state) = sqlx::query_as::<_, (i32, String)>(
        "SELECT challenge_id,state FROM ctfzone.solutions WHERE id=$1 AND challenge_id=$2 FOR KEY SHARE",
    )
    .bind(solution_id)
    .bind(expected_challenge_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Object not found"))?;
    super::challenges::require_full_challenge_access_in_transaction(
        transaction,
        user,
        challenge_id,
    )
    .await?;
    let Some(user) = user else {
        return Err(ApiError::not_found("Object not found"));
    };
    if user.is_admin() {
        return Ok(());
    }
    if solution_state == "visible" {
        return Ok(());
    }
    let team_mode = user_mode == "teams";
    let solved = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM ctfzone.submissions s
            JOIN ctfzone.solves solved ON solved.id=s.id
            WHERE s.challenge_id=$1
              AND (($2 AND s.team_id=$3) OR (NOT $2 AND s.user_id=$4)))
        "#,
    )
    .bind(challenge_id)
    .bind(team_mode)
    .bind(user.team_id)
    .bind(user.id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if solution_state == "solved" && solved {
        Ok(())
    } else {
        Err(ApiError::not_found("Object not found"))
    }
}

async fn lock_download_challenge(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_id: i32,
) -> Result<(), ApiError> {
    sqlx::query_scalar::<_, i32>("SELECT id FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE")
        .bind(challenge_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Object not found"))?;
    Ok(())
}

fn same_download_identity(left: &StoredObject, right: &StoredObject) -> bool {
    left.id == right.id
        && left.object_key == right.object_key
        && left.purpose == right.purpose
        && left.authorization_scope == right.authorization_scope
        && left.owner_user_id == right.owner_user_id
        && left.owner_team_id == right.owner_team_id
        && left.challenge_id == right.challenge_id
        && left.page_id == right.page_id
        && left.solution_id == right.solution_id
        && left.original_filename == right.original_filename
        && left.content_type == right.content_type
}

async fn authorize_change(
    state: &AppState,
    actor_user_id: i32,
    object: &StoredObject,
) -> Result<(), ApiError> {
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    authorize_change_on(&mut connection, actor_user_id, object).await
}

async fn authorize_change_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_user_id: i32,
    object: &StoredObject,
) -> Result<(), ApiError> {
    authorize_change_on(transaction, actor_user_id, object).await
}

async fn authorize_change_on(
    connection: &mut PgConnection,
    actor_user_id: i32,
    object: &StoredObject,
) -> Result<(), ApiError> {
    let identity = sqlx::query_as::<_, MutationIdentity>(
        r#"
        SELECT users.type AS user_type,users.team_id,
               COALESCE(users.banned,false) AS banned,
               COALESCE(teams.banned,false) AS team_banned
        FROM ctfzone.users
        LEFT JOIN ctfzone.teams ON teams.id=users.team_id
        WHERE users.id=$1
        "#,
    )
    .bind(actor_user_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::database)?;
    if identity.as_ref().is_some_and(|identity| {
        mutation_scope_authorized(
            &object.authorization_scope,
            actor_user_id,
            identity,
            object.owner_user_id,
            object.owner_team_id,
        )
    }) {
        Ok(())
    } else {
        Err(ApiError::not_found("Object not found"))
    }
}

fn mutation_scope_authorized(
    authorization_scope: &str,
    actor_user_id: i32,
    identity: &MutationIdentity,
    owner_user_id: Option<i32>,
    owner_team_id: Option<i32>,
) -> bool {
    if identity.banned || identity.team_banned {
        return false;
    }
    match authorization_scope {
        "target" => identity.user_type == "admin",
        "user" => owner_user_id == Some(actor_user_id),
        "team" => {
            owner_user_id == Some(actor_user_id)
                && owner_team_id.is_some()
                && owner_team_id == identity.team_id
        }
        _ => false,
    }
}

fn default_content_type() -> String {
    "application/octet-stream".to_owned()
}

fn safe_filename(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
        || matches!(value, "." | "..")
    {
        return Err(ApiError::bad_request("Filename is invalid"));
    }
    Ok(value.to_owned())
}

fn safe_content_type(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || !value.contains('/')
        || value.chars().any(char::is_control)
        || value.parse::<reqwest::header::HeaderValue>().is_err()
    {
        return Err(ApiError::bad_request("Content type is invalid"));
    }
    Ok(value.to_owned())
}

fn validate_sha256(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("SHA-256 checksum is invalid"));
    }
    Ok(value)
}

fn required_i64_header(
    headers: &HeaderMap,
    name: reqwest::header::HeaderName,
) -> Result<i64, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ApiError::upstream("Object storage returned incomplete metadata"))
}

fn string_header(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_cannot_be_paths_or_headers() {
        for invalid in ["", ".", "..", "a/b", "a\\b", "a\r\nb"] {
            assert!(safe_filename(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(
            safe_filename("challenge.tar.gz").unwrap(),
            "challenge.tar.gz"
        );
    }

    #[test]
    fn checksums_are_normalized_and_validated() {
        let uppercase = "A".repeat(64);
        assert_eq!(validate_sha256(&uppercase).unwrap(), "a".repeat(64));
        assert!(validate_sha256(&"g".repeat(64)).is_err());
        assert!(validate_sha256("abc").is_err());
    }

    #[test]
    fn upload_idempotency_key_is_required_and_bounded() {
        let mut headers = HeaderMap::new();
        assert!(required_idempotency_key(&headers).is_err());
        headers.insert("idempotency-key", "upload-123".parse().unwrap());
        assert_eq!(required_idempotency_key(&headers).unwrap(), "upload-123");
        headers.insert(
            "idempotency-key",
            "x".repeat(129).parse().expect("header value"),
        );
        assert!(required_idempotency_key(&headers).is_err());
    }

    #[test]
    fn object_mutations_follow_current_scope_role_and_membership() {
        let admin = mutation_identity("admin", None);
        let demoted = mutation_identity("user", None);
        assert!(mutation_scope_authorized(
            "target",
            7,
            &admin,
            Some(7),
            None
        ));
        assert!(!mutation_scope_authorized(
            "target",
            7,
            &demoted,
            Some(7),
            None
        ));

        assert!(mutation_scope_authorized(
            "user",
            7,
            &demoted,
            Some(7),
            None
        ));
        assert!(!mutation_scope_authorized(
            "user",
            8,
            &mutation_identity("admin", None),
            Some(7),
            None
        ));

        let creator_on_team = mutation_identity("user", Some(11));
        assert!(mutation_scope_authorized(
            "team",
            7,
            &creator_on_team,
            Some(7),
            Some(11)
        ));
        assert!(!mutation_scope_authorized(
            "team",
            7,
            &mutation_identity("user", None),
            Some(7),
            Some(11)
        ));
        assert!(!mutation_scope_authorized(
            "team",
            8,
            &mutation_identity("user", Some(11)),
            Some(7),
            Some(11)
        ));
    }

    #[test]
    fn banned_principals_cannot_mutate_objects() {
        let mut identity = mutation_identity("admin", None);
        identity.banned = true;
        assert!(!mutation_scope_authorized(
            "target",
            7,
            &identity,
            Some(7),
            None
        ));
        let mut identity = mutation_identity("user", Some(11));
        identity.team_banned = true;
        assert!(!mutation_scope_authorized(
            "team",
            7,
            &identity,
            Some(7),
            Some(11)
        ));
    }

    fn mutation_identity(user_type: &str, team_id: Option<i32>) -> MutationIdentity {
        MutationIdentity {
            user_type: user_type.to_owned(),
            team_id,
            banned: false,
            team_banned: false,
        }
    }
}
