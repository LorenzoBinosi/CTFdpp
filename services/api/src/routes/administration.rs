use std::collections::HashSet;

use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

const SETTINGS_CHANNEL: &str = "ctfzone_settings_changed";

#[derive(Deserialize, Default)]
pub(super) struct AdminQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    challenge_id: Option<i32>,
    user_id: Option<i32>,
    team_id: Option<i32>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    target_id: Option<i32>,
}

#[derive(Deserialize, Default)]
pub(super) struct RegistrationEmailQuery {
    q: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct ConfigInput {
    key: String,
    value: Value,
}

#[derive(Deserialize)]
pub(super) struct ConfigValueInput {
    value: Value,
}

#[derive(Deserialize)]
pub(super) struct EmailInput {
    email: String,
}

#[derive(Deserialize)]
pub(super) struct FieldInput {
    name: String,
    #[serde(rename = "type")]
    field_owner_type: String,
    field_type: String,
    description: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    editable: bool,
}

#[derive(Deserialize, Default)]
pub(super) struct FieldPatch {
    name: Option<String>,
    #[serde(rename = "type")]
    field_owner_type: Option<String>,
    field_type: Option<String>,
    description: Option<String>,
    required: Option<bool>,
    public: Option<bool>,
    editable: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct PageInput {
    title: String,
    route: String,
    content: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    auth_required: bool,
    #[serde(default = "default_markdown")]
    format: String,
    link_target: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct PagePatch {
    title: Option<String>,
    route: Option<String>,
    content: Option<String>,
    draft: Option<bool>,
    hidden: Option<bool>,
    auth_required: Option<bool>,
    format: Option<String>,
    link_target: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct BracketInput {
    name: String,
    description: Option<String>,
    #[serde(rename = "type")]
    bracket_type: String,
}

#[derive(Deserialize)]
pub(super) struct FlagInput {
    challenge_id: i32,
    #[serde(rename = "type")]
    flag_type: String,
    content: String,
    data: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct FlagPatch {
    challenge_id: Option<i32>,
    #[serde(rename = "type")]
    flag_type: Option<String>,
    content: Option<String>,
    data: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TagInput {
    challenge_id: i32,
    value: String,
}

#[derive(Deserialize)]
pub(super) struct TopicRelationInput {
    value: Option<String>,
    topic_id: Option<i32>,
    #[serde(rename = "type")]
    topic_type: String,
    challenge_id: i32,
}

#[derive(Deserialize)]
pub(super) struct AwardInput {
    user_id: i32,
    team_id: Option<i32>,
    #[serde(rename = "type")]
    award_type: Option<String>,
    name: String,
    description: Option<String>,
    value: i32,
    category: Option<String>,
    icon: Option<String>,
    requirements: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct CommentInput {
    content: String,
    challenge_id: Option<i32>,
    user_id: Option<i32>,
    team_id: Option<i32>,
    page_id: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct SubmissionInput {
    challenge_id: i32,
    user_id: i32,
    team_id: Option<i32>,
    ip: Option<String>,
    provided: String,
    #[serde(rename = "type")]
    submission_type: String,
    date: Option<NaiveDateTime>,
}

#[derive(Deserialize, Default)]
pub(super) struct SubmissionPatch {
    #[serde(rename = "type")]
    submission_type: Option<String>,
    provided: Option<String>,
}

#[derive(FromRow, Serialize)]
struct FieldView {
    id: i32,
    name: Option<String>,
    #[serde(rename = "type")]
    field_owner_type: Option<String>,
    field_type: Option<String>,
    description: Option<String>,
    required: Option<bool>,
    public: Option<bool>,
    editable: Option<bool>,
}

#[derive(FromRow, Serialize)]
struct PageView {
    id: i32,
    title: Option<String>,
    route: Option<String>,
    content: Option<String>,
    draft: Option<bool>,
    hidden: Option<bool>,
    auth_required: Option<bool>,
    format: Option<String>,
    link_target: Option<String>,
}

#[derive(FromRow, Serialize)]
struct PublicPageView {
    id: i32,
    title: Option<String>,
    route: String,
    content: String,
    format: String,
    link_target: Option<String>,
    auth_required: bool,
}

#[derive(FromRow, Serialize)]
struct BracketView {
    id: i32,
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "type")]
    bracket_type: Option<String>,
}

#[derive(FromRow, Serialize)]
struct FlagView {
    id: i32,
    challenge_id: Option<i32>,
    #[serde(rename = "type")]
    flag_type: Option<String>,
    content: Option<String>,
    data: Option<String>,
}

#[derive(FromRow, Serialize)]
struct TagView {
    id: i32,
    challenge_id: Option<i32>,
    value: Option<String>,
}

#[derive(FromRow, Serialize)]
struct TopicView {
    id: i32,
    value: Option<String>,
}

#[derive(FromRow, Serialize)]
struct AwardView {
    id: i32,
    user_id: Option<i32>,
    team_id: Option<i32>,
    #[serde(rename = "type")]
    award_type: Option<String>,
    name: Option<String>,
    description: Option<String>,
    date: Option<NaiveDateTime>,
    value: Option<i32>,
    category: Option<String>,
    icon: Option<String>,
    requirements: Option<Value>,
}

#[derive(FromRow, Serialize)]
struct CommentView {
    id: i32,
    #[serde(rename = "type")]
    comment_type: Option<String>,
    content: Option<String>,
    date: Option<NaiveDateTime>,
    author_id: Option<i32>,
    challenge_id: Option<i32>,
    user_id: Option<i32>,
    team_id: Option<i32>,
    page_id: Option<i32>,
}

#[derive(Clone, FromRow, Serialize)]
struct SubmissionView {
    id: i32,
    challenge_id: Option<i32>,
    user_id: Option<i32>,
    team_id: Option<i32>,
    ip: Option<String>,
    provided: Option<String>,
    #[serde(rename = "type")]
    submission_type: Option<String>,
    date: Option<NaiveDateTime>,
}

pub(super) async fn list_configs(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let configs = sqlx::query_as::<_, super::configuration::StoredConfig>(
        "SELECT id,key,value FROM ctfzone.config ORDER BY key,id",
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(
        configs
            .into_iter()
            .filter(|config| config.key.as_deref() != Some(crate::setup::COMPLETED_MARKER_KEY))
            .map(super::configuration::PublicConfig::from)
            .collect::<Vec<_>>(),
    ))
    .into_response())
}

pub(super) async fn create_config(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<ConfigInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.key == "private_challenges" {
        return set_private_challenges(&state, &user, value_bool(&request.value)?).await;
    }
    let key = request.key;
    let values = Map::from_iter([(key.clone(), request.value)]);
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let stored_value = super::configuration::normalize_mutations(&mut transaction, &values)
        .await?
        .into_iter()
        .next()
        .map(|(_, value)| value)
        .ok_or_else(|| ApiError::bad_request("Configuration mutation is empty"))?;
    let config = sqlx::query_as::<_, super::configuration::StoredConfig>(
        "INSERT INTO ctfzone.config (key,value) VALUES ($1,$2) RETURNING id,key,value",
    )
    .bind(key)
    .bind(stored_value)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_admin_database_error)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((
        StatusCode::CREATED,
        Json(Success::new(super::configuration::PublicConfig::from(
            config,
        ))),
    )
        .into_response())
}

pub(super) async fn patch_configs(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(mut request): Json<Map<String, Value>>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    request.remove("clear_registration_access_modes");
    let private_value = request.remove("private_challenges");
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let normalized = super::configuration::normalize_mutations(&mut transaction, &request).await?;
    for (key, value) in normalized {
        super::configuration::upsert_normalized(&mut transaction, &key, value).await?;
    }
    if let Some(value) = private_value {
        let enabled = value_bool(&value)?;
        let revision = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE ctfzone.runtime_settings SET enabled=$1,revision=revision+1,
                updated_at=now(),updated_by_user_id=$2 WHERE key='private_challenges'
            RETURNING revision
            "#,
        )
        .bind(enabled)
        .bind(user.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        notify(&mut transaction, SETTINGS_CHANNEL, &revision.to_string()).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn get_config(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(config_key): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if config_key == "private_challenges" {
        let (enabled, revision) = sqlx::query_as::<_, (bool, i64)>(
            "SELECT enabled,revision FROM ctfzone.runtime_settings WHERE key='private_challenges'",
        )
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
        return Ok(Json(Success::new(super::configuration::PublicConfig::from(
            super::configuration::StoredConfig {
                id: i32::try_from(revision).unwrap_or(i32::MAX),
                key: Some(config_key),
                value: Some(enabled.to_string()),
            },
        )))
        .into_response());
    }
    let config = load_config(&state, &config_key).await?;
    Ok(Json(Success::new(super::configuration::PublicConfig::from(
        config,
    )))
    .into_response())
}

pub(super) async fn update_config(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(config_key): Path<String>,
    Json(request): Json<ConfigValueInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if config_key == "private_challenges" {
        return set_private_challenges(&state, &user, value_bool(&request.value)?).await;
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let values = Map::from_iter([(config_key.clone(), request.value)]);
    let stored_value = super::configuration::normalize_mutations(&mut transaction, &values)
        .await?
        .into_iter()
        .next()
        .map(|(_, value)| value)
        .ok_or_else(|| ApiError::bad_request("Configuration mutation is empty"))?;
    let config = upsert_config(&mut transaction, &config_key, stored_value).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(super::configuration::PublicConfig::from(
        config,
    )))
    .into_response())
}

pub(super) async fn delete_config(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(config_key): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if config_key == crate::setup::COMPLETED_MARKER_KEY {
        return Err(ApiError::bad_request(
            "The setup completion marker cannot be deleted",
        ));
    }
    if config_key == "private_challenges" {
        return Err(ApiError::bad_request(
            "The private challenge setting cannot be deleted",
        ));
    }
    if config_key == "player_frontend" || config_key == "ctf_name" {
        return Err(ApiError::bad_request(
            "Required site identity settings cannot be deleted",
        ));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let deleted = super::configuration::delete_legacy(&mut transaction, &config_key).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    if deleted == 0 {
        return Err(ApiError::not_found("Configuration not found"));
    }
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn list_registration_emails(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<RegistrationEmailQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let page = query.page.unwrap_or(1).clamp(1, 1_000_000);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let search = query.q.unwrap_or_default();
    if search.len() > 254 || search.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Email search is invalid"));
    }
    let pattern = format!("%{}%", escape_like(search.trim()));
    let total = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM ctfzone.registration_email_allowlist WHERE email ILIKE $1 ESCAPE '\'"#,
    )
    .bind(&pattern)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let rows = sqlx::query_as::<_, (i32, String, bool)>(
        r#"
        SELECT a.id,a.email,EXISTS(SELECT 1 FROM ctfzone.users u WHERE lower(u.email)=lower(a.email))
        FROM ctfzone.registration_email_allowlist a
        WHERE a.email ILIKE $1 ESCAPE '\'
        ORDER BY a.email LIMIT $2 OFFSET $3
        "#,
    )
    .bind(pattern)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|(id, email, registered)| json!({"id": id, "email": email, "registered": registered}))
    .collect::<Vec<_>>();
    let pages = if total == 0 {
        0
    } else {
        (total + per_page - 1) / per_page
    };
    Ok(Json(Success::new(json!({
        "items": rows,
        "pagination": {"page": page, "per_page": per_page, "pages": pages, "total": total}
    })))
    .into_response())
}

pub(super) async fn create_registration_email(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<EmailInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let email = request.email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(ApiError::bad_request("Enter a valid email address"));
    }
    let admin_email = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE lower(email)=lower($1) AND type='admin')",
    )
    .bind(&email)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    if admin_email {
        return Err(ApiError::conflict(
            "Administrator emails cannot be added to the allowlist",
        ));
    }
    let id = sqlx::query_scalar::<_, i32>(
        "INSERT INTO ctfzone.registration_email_allowlist (email,created) VALUES ($1,timezone('utc',now())) RETURNING id",
    )
    .bind(&email)
    .fetch_one(&state.database)
    .await
    .map_err(map_admin_database_error)?;
    Ok((
        StatusCode::CREATED,
        Json(Success::new(
            json!({"id": id, "email": email, "registered": false}),
        )),
    )
        .into_response())
}

pub(super) async fn import_registration_emails(
    State(state): State<AppState>,
    user: CurrentUser,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut upload = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("The uploaded file is not valid multipart data"))?
    {
        if field.name() == Some("file") {
            upload = Some(
                field
                    .bytes()
                    .await
                    .map_err(|_| ApiError::bad_request("Unable to read the uploaded CSV"))?,
            );
            break;
        }
    }
    let upload = upload.ok_or_else(|| ApiError::bad_request("Choose a CSV file to import"))?;
    if upload.len() > 5 * 1024 * 1024 {
        return Err(ApiError::bad_request("CSV files must be 5 MB or smaller"));
    }
    let decoded = if let Ok(value) = std::str::from_utf8(&upload) {
        value.trim_start_matches('\u{feff}').to_owned()
    } else {
        let (value, _, _) = encoding_rs::WINDOWS_1252.decode(&upload);
        value.into_owned()
    };
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(decoded.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| ApiError::bad_request("The uploaded file is not valid CSV"))?
        .clone();
    let email_column = headers
        .iter()
        .position(|header| header.trim().eq_ignore_ascii_case("email"))
        .ok_or_else(|| ApiError::bad_request("The CSV must contain a column named email"))?;
    let mut addresses = HashSet::new();
    let mut invalid_rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let record =
            record.map_err(|_| ApiError::bad_request("The uploaded file is not valid CSV"))?;
        let address = record
            .get(email_column)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if valid_email(&address) {
            addresses.insert(address);
        } else {
            invalid_rows.push(index + 2);
        }
    }
    if !invalid_rows.is_empty() {
        let rows = invalid_rows
            .iter()
            .take(10)
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if invalid_rows.len() > 10 { "..." } else { "" };
        return Err(ApiError::bad_request(format!(
            "Invalid email address on CSV row(s): {rows}{suffix}"
        )));
    }
    let mut sorted = addresses.into_iter().collect::<Vec<_>>();
    sorted.sort();
    let existing = sqlx::query_scalar::<_, String>(
        "SELECT lower(email) FROM ctfzone.registration_email_allowlist WHERE lower(email)=ANY($1)",
    )
    .bind(&sorted)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .collect::<HashSet<_>>();
    let administrators = sqlx::query_scalar::<_, String>(
        "SELECT lower(email) FROM ctfzone.users WHERE type='admin' AND lower(email)=ANY($1)",
    )
    .bind(&sorted)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .collect::<HashSet<_>>();
    let new_addresses = sorted
        .iter()
        .filter(|email| !existing.contains(*email) && !administrators.contains(*email))
        .cloned()
        .collect::<Vec<_>>();
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    for email in &new_addresses {
        sqlx::query(
            "INSERT INTO ctfzone.registration_email_allowlist (email,created) VALUES ($1,timezone('utc',now()))",
        )
        .bind(email)
        .execute(&mut *transaction)
        .await
        .map_err(map_admin_database_error)?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    let mut data = json!({
        "added": new_addresses.len(),
        "skipped": sorted.len() - new_addresses.len(),
    });
    if !administrators.is_empty() {
        data["skipped_administrators"] = json!(administrators.len());
    }
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn delete_registration_email(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(entry_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let email = sqlx::query_scalar::<_, String>(
        r#"
        SELECT email
        FROM ctfzone.registration_email_allowlist
        WHERE id=$1
        FOR UPDATE
        "#,
    )
    .bind(entry_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let registered = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ctfzone.users WHERE lower(email)=lower($1)
        )
        "#,
    )
    .bind(&email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if registered {
        return Err(ApiError::conflict(
            "Delete the registered user before removing this allowlist entry",
        ));
    }
    sqlx::query("DELETE FROM ctfzone.registration_email_allowlist WHERE id=$1")
        .bind(entry_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn list_fields(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let fields = sqlx::query_as::<_, FieldView>(&field_select("ORDER BY id"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(fields)).into_response())
}

pub(super) async fn get_field(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(field_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let field = load_field(&state, field_id).await?;
    Ok(Json(Success::new(field)).into_response())
}

pub(super) async fn create_field(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<FieldInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_field(
        &request.field_owner_type,
        &request.field_type,
        &request.name,
    )?;
    let field = sqlx::query_as::<_, FieldView>(
        r#"
        INSERT INTO ctfzone.fields (name,type,field_type,description,required,public,editable)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING id,name,type AS field_owner_type,field_type,description,required,public,editable
        "#,
    )
    .bind(request.name)
    .bind(request.field_owner_type)
    .bind(request.field_type)
    .bind(request.description)
    .bind(request.required)
    .bind(request.public)
    .bind(request.editable)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(field))).into_response())
}

pub(super) async fn update_field(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(field_id): Path<i32>,
    Json(request): Json<FieldPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let current = load_field(&state, field_id).await?;
    let name = request.name.or(current.name).unwrap_or_default();
    let owner_type = request
        .field_owner_type
        .or(current.field_owner_type)
        .unwrap_or_else(|| "user".to_owned());
    let field_type = request
        .field_type
        .or(current.field_type)
        .unwrap_or_else(|| "text".to_owned());
    validate_field(&owner_type, &field_type, &name)?;
    let field = sqlx::query_as::<_, FieldView>(
        r#"
        UPDATE ctfzone.fields SET name=$1,type=$2,field_type=$3,
            description=COALESCE($4,description),required=COALESCE($5,required),
            public=COALESCE($6,public),editable=COALESCE($7,editable)
        WHERE id=$8
        RETURNING id,name,type AS field_owner_type,field_type,description,required,public,editable
        "#,
    )
    .bind(name)
    .bind(owner_type)
    .bind(field_type)
    .bind(request.description)
    .bind(request.required)
    .bind(request.public)
    .bind(request.editable)
    .bind(field_id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(field)).into_response())
}

pub(super) async fn delete_field(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(field_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "fields", field_id).await
}

pub(super) async fn list_pages(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let pages = sqlx::query_as::<_, PageView>(&page_select("ORDER BY id"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(pages)).into_response())
}

pub(super) async fn get_page_by_route(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(route): Path<String>,
) -> Result<Response, ApiError> {
    let route = validate_public_page_route(&route)?;
    let page = sqlx::query_as::<_, PublicPageView>(
        r#"
        SELECT id,title,route,COALESCE(content,'') AS content,
               COALESCE(format,'markdown') AS format,link_target,
               COALESCE(auth_required,false) AS auth_required
        FROM ctfzone.pages
        WHERE route=$1
          AND NOT COALESCE(draft,false)
          AND NOT COALESCE(hidden,false)
        "#,
    )
    .bind(route)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Page not found"))?;
    if page.auth_required && user.is_none() {
        return Err(ApiError::forbidden("Authentication required"));
    }
    Ok(Json(Success::new(page)).into_response())
}

pub(super) async fn get_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(page_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_page(&state, page_id).await?)).into_response())
}

pub(super) async fn create_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<PageInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_page(&request.route, &request.format)?;
    let page = sqlx::query_as::<_, PageView>(
        r#"
        INSERT INTO ctfzone.pages
            (title,route,content,draft,hidden,auth_required,format,link_target)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING id,title,route,content,draft,hidden,auth_required,format,link_target
        "#,
    )
    .bind(request.title)
    .bind(normalize_route(&request.route))
    .bind(request.content)
    .bind(request.draft)
    .bind(request.hidden)
    .bind(request.auth_required)
    .bind(request.format)
    .bind(request.link_target)
    .fetch_one(&state.database)
    .await
    .map_err(map_admin_database_error)?;
    Ok((StatusCode::CREATED, Json(Success::new(page))).into_response())
}

pub(super) async fn update_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(page_id): Path<i32>,
    Json(request): Json<PagePatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if let Some(route) = request.route.as_deref() {
        validate_page(route, request.format.as_deref().unwrap_or("markdown"))?;
    }
    if request
        .format
        .as_deref()
        .is_some_and(|format| !matches!(format, "markdown" | "html"))
    {
        return Err(ApiError::bad_request("Unsupported page format"));
    }
    let page = sqlx::query_as::<_, PageView>(
        r#"
        UPDATE ctfzone.pages SET title=COALESCE($1,title),route=COALESCE($2,route),
            content=COALESCE($3,content),draft=COALESCE($4,draft),hidden=COALESCE($5,hidden),
            auth_required=COALESCE($6,auth_required),format=COALESCE($7,format),
            link_target=COALESCE($8,link_target)
        WHERE id=$9
        RETURNING id,title,route,content,draft,hidden,auth_required,format,link_target
        "#,
    )
    .bind(request.title)
    .bind(request.route.map(|route| normalize_route(&route)))
    .bind(request.content)
    .bind(request.draft)
    .bind(request.hidden)
    .bind(request.auth_required)
    .bind(request.format)
    .bind(request.link_target)
    .bind(page_id)
    .fetch_optional(&state.database)
    .await
    .map_err(map_admin_database_error)?
    .ok_or_else(|| ApiError::not_found("Page not found"))?;
    Ok(Json(Success::new(page)).into_response())
}

pub(super) async fn delete_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(page_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "pages", page_id).await
}

pub(super) async fn list_brackets(State(state): State<AppState>) -> Result<Response, ApiError> {
    let rows = sqlx::query_as::<_, BracketView>(&bracket_select("ORDER BY id"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn create_bracket(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<BracketInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_bracket(&request)?;
    let row = sqlx::query_as::<_, BracketView>(
        "INSERT INTO ctfzone.brackets (name,description,type) VALUES ($1,$2,$3) RETURNING id,name,description,type AS bracket_type",
    )
    .bind(request.name)
    .bind(request.description)
    .bind(request.bracket_type)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(row))).into_response())
}

pub(super) async fn update_bracket(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bracket_id): Path<i32>,
    Json(request): Json<BracketInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_bracket(&request)?;
    let row = sqlx::query_as::<_, BracketView>(
        "UPDATE ctfzone.brackets SET name=$1,description=$2,type=$3 WHERE id=$4 RETURNING id,name,description,type AS bracket_type",
    )
    .bind(request.name)
    .bind(request.description)
    .bind(request.bracket_type)
    .bind(bracket_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Bracket not found"))?;
    Ok(Json(Success::new(row)).into_response())
}

pub(super) async fn delete_bracket(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bracket_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "brackets", bracket_id).await
}

pub(super) async fn flag_types(user: CurrentUser) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(flag_types_value())).into_response())
}

pub(super) async fn flag_type(
    user: CurrentUser,
    Path(type_name): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let types = flag_types_value();
    let value = types
        .get(&type_name)
        .cloned()
        .ok_or_else(|| ApiError::not_found("Flag type not found"))?;
    Ok(Json(Success::new(value)).into_response())
}

pub(super) async fn list_flags(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let flags = sqlx::query_as::<_, FlagView>(
        "SELECT id,challenge_id,type AS flag_type,content,data FROM ctfzone.flags WHERE ($1::integer IS NULL OR challenge_id=$1) ORDER BY id",
    )
    .bind(query.challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(flags)).into_response())
}

pub(super) async fn get_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(flag_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_flag(&state, flag_id).await?)).into_response())
}

pub(super) async fn create_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(mut request): Json<FlagInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_flag(&request.flag_type, &request.content)?;
    if matches!(request.flag_type.as_str(), "static" | "regex") {
        request.content = request.content.trim().to_owned();
    }
    let flag = sqlx::query_as::<_, FlagView>(
        "INSERT INTO ctfzone.flags (challenge_id,type,content,data) VALUES ($1,$2,$3,$4) RETURNING id,challenge_id,type AS flag_type,content,data",
    )
    .bind(request.challenge_id)
    .bind(request.flag_type)
    .bind(request.content)
    .bind(request.data)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(flag))).into_response())
}

pub(super) async fn update_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(flag_id): Path<i32>,
    Json(mut request): Json<FlagPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if let Some(content) = request.content.as_mut() {
        *content = content.trim().to_owned();
    }
    let flag = sqlx::query_as::<_, FlagView>(
        r#"
        UPDATE ctfzone.flags SET challenge_id=COALESCE($1,challenge_id),type=COALESCE($2,type),
            content=COALESCE($3,content),data=COALESCE($4,data) WHERE id=$5
        RETURNING id,challenge_id,type AS flag_type,content,data
        "#,
    )
    .bind(request.challenge_id)
    .bind(request.flag_type)
    .bind(request.content)
    .bind(request.data)
    .bind(flag_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Flag not found"))?;
    Ok(Json(Success::new(flag)).into_response())
}

pub(super) async fn delete_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(flag_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "flags", flag_id).await
}

pub(super) async fn list_tags(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, TagView>(
        "SELECT id,challenge_id,value FROM ctfzone.tags WHERE ($1::integer IS NULL OR challenge_id=$1) ORDER BY id",
    )
    .bind(query.challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(tag_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_tag(&state, tag_id).await?)).into_response())
}

pub(super) async fn create_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<TagInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let value = validate_short_text(&request.value, "Tag")?;
    let row = sqlx::query_as::<_, TagView>(
        "INSERT INTO ctfzone.tags (challenge_id,value) VALUES ($1,$2) RETURNING id,challenge_id,value",
    )
    .bind(request.challenge_id)
    .bind(value)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(row))).into_response())
}

pub(super) async fn update_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(tag_id): Path<i32>,
    Json(request): Json<TagInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let value = validate_short_text(&request.value, "Tag")?;
    let row = sqlx::query_as::<_, TagView>(
        "UPDATE ctfzone.tags SET challenge_id=$1,value=$2 WHERE id=$3 RETURNING id,challenge_id,value",
    )
    .bind(request.challenge_id)
    .bind(value)
    .bind(tag_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Tag not found"))?;
    Ok(Json(Success::new(row)).into_response())
}

pub(super) async fn delete_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(tag_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "tags", tag_id).await
}

pub(super) async fn list_topics(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, TopicView>("SELECT id,value FROM ctfzone.topics ORDER BY value")
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_topic(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(topic_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let topic = load_topic(&state, topic_id).await?;
    Ok(Json(Success::new(topic)).into_response())
}

pub(super) async fn create_topic_relation(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<TopicRelationInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.topic_type != "challenge" {
        return Err(ApiError::bad_request("Unsupported topic relation type"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let topic_id = if let Some(value) = request.value {
        let value = validate_short_text(&value, "Topic")?;
        sqlx::query_scalar::<_, i32>(
            "INSERT INTO ctfzone.topics (value) VALUES ($1) ON CONFLICT (value) DO UPDATE SET value=EXCLUDED.value RETURNING id",
        )
        .bind(value)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?
    } else {
        request
            .topic_id
            .ok_or_else(|| ApiError::bad_request("A topic ID or value is required"))?
    };
    let relation_id = sqlx::query_scalar::<_, i32>(
        "INSERT INTO ctfzone.challenge_topics (challenge_id,topic_id) VALUES ($1,$2) RETURNING id",
    )
    .bind(request.challenge_id)
    .bind(topic_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_admin_database_error)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(json!({
        "id": relation_id, "challenge_id": request.challenge_id, "topic_id": topic_id, "type": "challenge"
    })))).into_response())
}

pub(super) async fn delete_topic_relation(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if query.record_type.as_deref() != Some("challenge") {
        return Err(ApiError::bad_request("Unsupported topic relation type"));
    }
    let id = query
        .target_id
        .ok_or_else(|| ApiError::bad_request("target_id is required"))?;
    delete_integer_id(&state, "challenge_topics", id).await
}

pub(super) async fn delete_topic(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(topic_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "topics", topic_id).await
}

pub(super) async fn list_awards(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, AwardView>(&award_select(
        "WHERE ($1::integer IS NULL OR user_id=$1) AND ($2::integer IS NULL OR team_id=$2) ORDER BY id DESC",
    ))
    .bind(query.user_id)
    .bind(query.team_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_award(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(award_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_award(&state, award_id).await?)).into_response())
}

pub(super) async fn create_award(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(mut request): Json<AwardInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if super::challenges::is_team_mode(&state).await? && request.team_id.is_none() {
        request.team_id =
            sqlx::query_scalar::<_, Option<i32>>("SELECT team_id FROM ctfzone.users WHERE id=$1")
                .bind(request.user_id)
                .fetch_one(&state.database)
                .await
                .map_err(ApiError::database)?;
        if request.team_id.is_none() {
            return Err(ApiError::bad_request(
                "The award user does not belong to a team",
            ));
        }
    }
    let award = sqlx::query_as::<_, AwardView>(
        r#"
        INSERT INTO ctfzone.awards
            (user_id,team_id,type,name,description,date,value,category,icon,requirements)
        VALUES ($1,$2,$3,$4,$5,timezone('utc',now()),$6,$7,$8,$9)
        RETURNING id,user_id,team_id,type AS award_type,name,description,date,value,category,icon,requirements
        "#,
    )
    .bind(request.user_id)
    .bind(request.team_id)
    .bind(request.award_type.unwrap_or_else(|| "standard".to_owned()))
    .bind(request.name)
    .bind(request.description)
    .bind(request.value)
    .bind(request.category)
    .bind(request.icon)
    .bind(request.requirements)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(award))).into_response())
}

pub(super) async fn delete_award(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(award_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "awards", award_id).await
}

pub(super) async fn list_comments(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
    let comments = sqlx::query_as::<_, CommentView>(
        r#"
        SELECT id,type AS comment_type,content,date,author_id,challenge_id,user_id,team_id,page_id
        FROM ctfzone.comments
        WHERE ($1::integer IS NULL OR challenge_id=$1)
          AND ($2::integer IS NULL OR user_id=$2)
          AND ($3::integer IS NULL OR team_id=$3)
        ORDER BY id DESC LIMIT $4 OFFSET $5
        "#,
    )
    .bind(query.challenge_id)
    .bind(query.user_id)
    .bind(query.team_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(comments)).into_response())
}

pub(super) async fn create_comment(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<CommentInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let target_count = [
        request.challenge_id,
        request.user_id,
        request.team_id,
        request.page_id,
    ]
    .into_iter()
    .flatten()
    .count();
    if target_count > 1 || request.content.trim().is_empty() {
        return Err(ApiError::bad_request(
            "A comment must have at most one target",
        ));
    }
    let comment_type = if request.challenge_id.is_some() {
        "challenge"
    } else if request.user_id.is_some() {
        "user"
    } else if request.team_id.is_some() {
        "team"
    } else if request.page_id.is_some() {
        "page"
    } else {
        "standard"
    };
    let comment = sqlx::query_as::<_, CommentView>(
        r#"
        INSERT INTO ctfzone.comments
            (type,content,date,author_id,challenge_id,user_id,team_id,page_id)
        VALUES ($1,$2,timezone('utc',now()),$3,$4,$5,$6,$7)
        RETURNING id,type AS comment_type,content,date,author_id,challenge_id,user_id,team_id,page_id
        "#,
    )
    .bind(comment_type)
    .bind(request.content)
    .bind(user.id)
    .bind(request.challenge_id)
    .bind(request.user_id)
    .bind(request.team_id)
    .bind(request.page_id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(comment))).into_response())
}

pub(super) async fn delete_comment(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(comment_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "comments", comment_id).await
}

pub(super) async fn list_submissions(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AdminQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
    let mut builder = QueryBuilder::<Postgres>::new(submission_select());
    builder.push(" WHERE TRUE");
    if let Some(challenge_id) = query.challenge_id {
        builder.push(" AND challenge_id=").push_bind(challenge_id);
    }
    if let Some(user_id) = query.user_id {
        builder.push(" AND user_id=").push_bind(user_id);
    }
    if let Some(team_id) = query.team_id {
        builder.push(" AND team_id=").push_bind(team_id);
    }
    if let Some(record_type) = query.record_type {
        builder.push(" AND type=").push_bind(record_type);
    }
    builder
        .push(" ORDER BY id DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind((page - 1) * per_page);
    let rows = builder
        .build_query_as::<SubmissionView>()
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_submission(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(submission_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_submission(&state, submission_id).await?)).into_response())
}

pub(super) async fn create_submission(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<SubmissionInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_submission_type(&request.submission_type)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let id = insert_submission(&mut transaction, &request).await?;
    if request.submission_type == "correct" {
        sqlx::query(
            "INSERT INTO ctfzone.solves (id,challenge_id,user_id,team_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(request.challenge_id)
        .bind(request.user_id)
        .bind(request.team_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_admin_database_error)?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((
        StatusCode::CREATED,
        Json(Success::new(load_submission(&state, id).await?)),
    )
        .into_response())
}

pub(super) async fn update_submission(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(submission_id): Path<i32>,
    Json(request): Json<SubmissionPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let current = load_submission(&state, submission_id).await?;
    let requested_type = request
        .submission_type
        .unwrap_or_else(|| current.submission_type.clone().unwrap_or_default());
    validate_submission_type(&requested_type)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    if current.submission_type.as_deref() != Some("correct") && requested_type == "correct" {
        let input = SubmissionInput {
            challenge_id: current.challenge_id.unwrap_or_default(),
            user_id: current.user_id.unwrap_or_default(),
            team_id: current.team_id,
            ip: current.ip,
            provided: request.provided.or(current.provided).unwrap_or_default(),
            submission_type: "correct".to_owned(),
            date: current.date,
        };
        let solve_id = insert_submission(&mut transaction, &input).await?;
        sqlx::query(
            "INSERT INTO ctfzone.solves (id,challenge_id,user_id,team_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(solve_id)
        .bind(input.challenge_id)
        .bind(input.user_id)
        .bind(input.team_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_admin_database_error)?;
        sqlx::query("UPDATE ctfzone.submissions SET type='discard' WHERE id=$1")
            .bind(submission_id)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(Json(Success::new(load_submission(&state, solve_id).await?)).into_response());
    }
    if current.submission_type.as_deref() == Some("correct") && requested_type != "correct" {
        sqlx::query("DELETE FROM ctfzone.solves WHERE id=$1")
            .bind(submission_id)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
    }
    sqlx::query(
        "UPDATE ctfzone.submissions SET type=$1,provided=COALESCE($2,provided) WHERE id=$3",
    )
    .bind(requested_type)
    .bind(request.provided)
    .bind(submission_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(load_submission(&state, submission_id).await?)).into_response())
}

pub(super) async fn delete_submission(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(submission_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, "submissions", submission_id).await
}

async fn set_private_challenges(
    state: &AppState,
    user: &CurrentUser,
    enabled: bool,
) -> Result<Response, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.runtime_settings SET enabled=$1,revision=revision+1,
            updated_at=now(),updated_by_user_id=$2 WHERE key='private_challenges'
        RETURNING revision
        "#,
    )
    .bind(enabled)
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    notify(&mut transaction, SETTINGS_CHANNEL, &revision.to_string()).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(super::configuration::PublicConfig::from(
        super::configuration::StoredConfig {
            id: i32::try_from(revision).unwrap_or(i32::MAX),
            key: Some("private_challenges".to_owned()),
            value: Some(enabled.to_string()),
        },
    )))
    .into_response())
}

async fn upsert_config(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    value: String,
) -> Result<super::configuration::StoredConfig, ApiError> {
    sqlx::query_as::<_, super::configuration::StoredConfig>(
        r#"
        INSERT INTO ctfzone.config (key,value) VALUES ($1,$2)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        RETURNING id,key,value
        "#,
    )
    .bind(key)
    .bind(value)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn load_config(
    state: &AppState,
    key: &str,
) -> Result<super::configuration::StoredConfig, ApiError> {
    sqlx::query_as::<_, super::configuration::StoredConfig>(
        "SELECT id,key,value FROM ctfzone.config WHERE key=$1",
    )
    .bind(key)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Configuration not found"))
}

async fn load_field(state: &AppState, id: i32) -> Result<FieldView, ApiError> {
    sqlx::query_as::<_, FieldView>(&field_select("WHERE id=$1"))
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Field not found"))
}

async fn load_page(state: &AppState, id: i32) -> Result<PageView, ApiError> {
    sqlx::query_as::<_, PageView>(&page_select("WHERE id=$1"))
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Page not found"))
}

async fn load_flag(state: &AppState, id: i32) -> Result<FlagView, ApiError> {
    sqlx::query_as::<_, FlagView>(
        "SELECT id,challenge_id,type AS flag_type,content,data FROM ctfzone.flags WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Flag not found"))
}

async fn load_tag(state: &AppState, id: i32) -> Result<TagView, ApiError> {
    sqlx::query_as::<_, TagView>("SELECT id,challenge_id,value FROM ctfzone.tags WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Tag not found"))
}

async fn load_topic(state: &AppState, id: i32) -> Result<TopicView, ApiError> {
    sqlx::query_as::<_, TopicView>("SELECT id,value FROM ctfzone.topics WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Topic not found"))
}

async fn load_award(state: &AppState, id: i32) -> Result<AwardView, ApiError> {
    sqlx::query_as::<_, AwardView>(&award_select("WHERE id=$1"))
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Award not found"))
}

async fn load_submission(state: &AppState, id: i32) -> Result<SubmissionView, ApiError> {
    sqlx::query_as::<_, SubmissionView>(&format!("{} WHERE id=$1", submission_select()))
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Submission not found"))
}

async fn insert_submission(
    transaction: &mut Transaction<'_, Postgres>,
    request: &SubmissionInput,
) -> Result<i32, ApiError> {
    sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.submissions
            (challenge_id,user_id,team_id,ip,provided,type,date)
        VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7,timezone('utc',now())))
        RETURNING id
        "#,
    )
    .bind(request.challenge_id)
    .bind(request.user_id)
    .bind(request.team_id)
    .bind(&request.ip)
    .bind(&request.provided)
    .bind(&request.submission_type)
    .bind(request.date)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn delete_integer_id(state: &AppState, table: &str, id: i32) -> Result<Response, ApiError> {
    let allowed = [
        "registration_email_allowlist",
        "fields",
        "pages",
        "brackets",
        "flags",
        "tags",
        "topics",
        "challenge_topics",
        "awards",
        "comments",
        "submissions",
    ];
    if !allowed.contains(&table) {
        return Err(ApiError::bad_request(
            "Unsupported administrative content type",
        ));
    }
    let result = sqlx::query(&format!("DELETE FROM ctfzone.{table} WHERE id=$1"))
        .bind(id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Record not found"));
    }
    Ok(Json(json!({"success": true})).into_response())
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

fn field_select(suffix: &str) -> String {
    format!(
        "SELECT id,name,type AS field_owner_type,field_type,description,required,public,editable FROM ctfzone.fields {suffix}"
    )
}

fn page_select(suffix: &str) -> String {
    format!(
        "SELECT id,title,route,content,draft,hidden,auth_required,format,link_target FROM ctfzone.pages {suffix}"
    )
}

fn bracket_select(suffix: &str) -> String {
    format!("SELECT id,name,description,type AS bracket_type FROM ctfzone.brackets {suffix}")
}

fn award_select(suffix: &str) -> String {
    format!(
        "SELECT id,user_id,team_id,type AS award_type,name,description,date,value,category,icon,requirements FROM ctfzone.awards {suffix}"
    )
}

fn submission_select() -> &'static str {
    "SELECT id,challenge_id,user_id,team_id,ip,provided,type AS submission_type,date FROM ctfzone.submissions"
}

fn flag_types_value() -> Value {
    json!({
        "static": {"name": "static", "templates": {}},
        "regex": {"name": "regex", "templates": {}}
    })
}

fn value_bool(value: &Value) -> Result<bool, ApiError> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(ApiError::bad_request("Setting must be a boolean")),
        },
        _ => Err(ApiError::bad_request("Setting must be a boolean")),
    }
}

fn validate_field(owner_type: &str, field_type: &str, name: &str) -> Result<(), ApiError> {
    if !matches!(owner_type, "user" | "team")
        || !matches!(
            field_type,
            "text" | "boolean" | "select" | "email" | "number"
        )
        || name.trim().is_empty()
    {
        return Err(ApiError::bad_request("Field definition is invalid"));
    }
    Ok(())
}

fn validate_page(route: &str, format: &str) -> Result<(), ApiError> {
    let route = normalize_route(route);
    if route.is_empty()
        || route.len() > 128
        || route.contains("..")
        || !route
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_-".contains(character))
        || !matches!(format, "markdown" | "html")
    {
        return Err(ApiError::bad_request("Page route or format is invalid"));
    }
    Ok(())
}

fn normalize_route(route: &str) -> String {
    route.trim().trim_start_matches('/').to_owned()
}

fn validate_public_page_route(route: &str) -> Result<String, ApiError> {
    let route = normalize_route(route);
    if route.is_empty()
        || route.len() > 128
        || route.contains("..")
        || route.contains('/')
        || !route
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        return Err(ApiError::bad_request("Page route is invalid"));
    }
    Ok(route)
}

fn validate_bracket(request: &BracketInput) -> Result<(), ApiError> {
    if request.name.trim().is_empty() || !matches!(request.bracket_type.as_str(), "users" | "teams")
    {
        return Err(ApiError::bad_request("Bracket definition is invalid"));
    }
    Ok(())
}

fn validate_flag(flag_type: &str, content: &str) -> Result<(), ApiError> {
    if !matches!(flag_type, "static" | "regex") || content.trim().is_empty() {
        return Err(ApiError::bad_request("Flag definition is invalid"));
    }
    Ok(())
}

fn validate_submission_type(value: &str) -> Result<(), ApiError> {
    if matches!(
        value,
        "correct" | "incorrect" | "partial" | "discard" | "ratelimited"
    ) {
        Ok(())
    } else {
        Err(ApiError::bad_request("Submission type is invalid"))
    }
}

fn validate_short_text(value: &str, label: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 255 {
        return Err(ApiError::bad_request(format!("{label} value is invalid")));
    }
    Ok(value.to_owned())
}

fn valid_email(value: &str) -> bool {
    value.len() <= 128
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        })
        && !value.chars().any(char::is_whitespace)
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn default_markdown() -> String {
    "markdown".to_owned()
}

fn map_admin_database_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.is_unique_violation() {
            return ApiError::conflict("A record with these values already exists");
        }
    }
    ApiError::database(error)
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
    fn validates_public_page_slugs() {
        assert_eq!(validate_public_page_route(" rules ").unwrap(), "rules");
        assert_eq!(
            validate_public_page_route("event_rules-2026").unwrap(),
            "event_rules-2026"
        );
        assert!(validate_public_page_route("").is_err());
        assert!(validate_public_page_route("../rules").is_err());
        assert!(validate_public_page_route("nested/rules").is_err());
        assert!(validate_public_page_route("https://example.test").is_err());
    }

    #[test]
    fn escapes_allowlist_search_wildcards_as_literals() {
        assert_eq!(escape_like("100%_\\example"), "100\\%\\_\\\\example");
    }
}
