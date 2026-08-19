use std::collections::HashSet;

use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

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
#[serde(deny_unknown_fields)]
pub(super) struct PageInput {
    label: String,
    endpoint: String,
    content: String,
    visibility: String,
    navigation_order: i32,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct PagePatch {
    label: Option<String>,
    endpoint: Option<String>,
    content: Option<String>,
    visibility: Option<String>,
    navigation_order: Option<i32>,
    revision: i64,
}

#[derive(Deserialize)]
pub(super) struct BracketInput {
    name: String,
    description: Option<String>,
    #[serde(rename = "type")]
    bracket_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChallengeCategoryInput {
    name: String,
    #[serde(default)]
    logo_key: Option<String>,
    #[serde(default)]
    logo_color: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ChallengeCategoryPatch {
    name: Option<Value>,
    logo_key: Option<Value>,
    logo_color: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct FlagInput {
    challenge_id: i32,
    #[serde(rename = "type")]
    flag_type: String,
    content: String,
    #[serde(default)]
    data: Value,
}

#[derive(Deserialize, Default)]
pub(super) struct FlagPatch {
    challenge_id: Option<i32>,
    #[serde(rename = "type")]
    flag_type: Option<String>,
    content: Option<String>,
    data: Option<Value>,
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
    label: String,
    endpoint: String,
    content: String,
    page_type: String,
    system_key: Option<String>,
    visibility: String,
    navigation_order: i32,
    revision: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(FromRow, Serialize)]
struct PublicPageView {
    id: i32,
    label: String,
    endpoint: String,
    content: String,
    page_type: String,
    system_key: Option<String>,
    visibility: String,
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
struct ChallengeCategoryView {
    id: i32,
    name: String,
    logo_key: Option<String>,
    logo_color: Option<String>,
    icon_object_id: Option<Uuid>,
    challenge_count: i64,
}

#[derive(FromRow, Serialize)]
struct FlagView {
    id: i32,
    challenge_id: i32,
    #[serde(rename = "type")]
    flag_type: String,
    content: String,
    data: Value,
    revision: i64,
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
            .filter(|config| {
                config
                    .key
                    .as_deref()
                    .is_some_and(super::configuration::is_known_setting)
            })
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
    if request.key == "user_mode" {
        return Err(direct_user_mode_change_error());
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
    Json(request): Json<Map<String, Value>>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let normalized = super::configuration::normalize_mutations(&mut transaction, &request).await?;
    reject_direct_user_mode_change(&mut transaction, &normalized).await?;
    for (key, value) in normalized {
        super::configuration::upsert_normalized(&mut transaction, &key, value).await?;
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
    if !super::configuration::is_known_setting(&config_key) {
        return Err(ApiError::not_found("Configuration setting not found"));
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let values = Map::from_iter([(config_key.clone(), request.value)]);
    let normalized = super::configuration::normalize_mutations(&mut transaction, &values).await?;
    reject_direct_user_mode_change(&mut transaction, &normalized).await?;
    let stored_value = normalized
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
    delete_integer_id(&state, &user, "fields", field_id).await
}

pub(super) async fn list_pages(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let pages =
        sqlx::query_as::<_, PageView>(&page_select("ORDER BY navigation_order, lower(label), id"))
            .fetch_all(&state.database)
            .await
            .map_err(ApiError::database)?;
    Ok(Json(Success::new(pages)).into_response())
}

pub(super) async fn get_root_page(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
) -> Result<Response, ApiError> {
    public_page_response(&state, user.as_ref(), "").await
}

pub(super) async fn get_page_by_route(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(route): Path<String>,
) -> Result<Response, ApiError> {
    let route = validate_custom_page_endpoint(&route)?;
    public_page_response(&state, user.as_ref(), &route).await
}

async fn public_page_response(
    state: &AppState,
    user: Option<&CurrentUser>,
    endpoint: &str,
) -> Result<Response, ApiError> {
    let page = sqlx::query_as::<_, PublicPageView>(
        r#"
        SELECT id,label,endpoint,content,page_type,system_key,visibility
        FROM ctfzone.pages
        WHERE endpoint=$1
        "#,
    )
    .bind(endpoint)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Page not found"))?;
    match page.visibility.as_str() {
        "public" => {}
        "private" if user.is_some() => {}
        "private" => return Err(ApiError::forbidden("Authentication required")),
        "invisible" if user.is_some_and(CurrentUser::is_admin) => {}
        "invisible" => return Err(ApiError::not_found("Page not found")),
        _ => return Err(ApiError::not_found("Page not found")),
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
    headers: HeaderMap,
    Json(request): Json<PageInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let label = validate_page_label(&request.label)?;
    let endpoint = validate_custom_page_endpoint(&request.endpoint)?;
    let content = validate_page_content(&request.content)?;
    let visibility = validate_page_visibility(&request.visibility)?;
    let navigation_order = validate_page_navigation_order(request.navigation_order, false)?;
    let request_data = json!({
        "label": &label,
        "endpoint": &endpoint,
        "content": &content,
        "visibility": &visibility,
        "navigation_order": navigation_order,
    });
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let (idempotency, replay) = super::create_idempotency::CreateRequest::lock_and_replay(
        &mut transaction,
        &headers,
        user.id,
        super::create_idempotency::PAGE_CREATE,
        &request_data,
    )
    .await?;
    if let Some(response_data) = replay {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response());
    }
    let page = sqlx::query_as::<_, PageView>(
        r#"
        INSERT INTO ctfzone.pages
            (label,endpoint,content,page_type,system_key,visibility,navigation_order)
        VALUES ($1,$2,$3,'custom',NULL,$4,$5)
        RETURNING id,label,endpoint,content,page_type,system_key,visibility,
                  navigation_order,revision,created_at,updated_at
        "#,
    )
    .bind(label)
    .bind(endpoint)
    .bind(content)
    .bind(visibility)
    .bind(navigation_order)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_admin_database_error)?;
    let response_data = json!(&page);
    idempotency
        .complete(&mut transaction, page.id, &response_data)
        .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response())
}

pub(super) async fn update_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(page_id): Path<i32>,
    Json(request): Json<PagePatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.revision < 1 {
        return Err(ApiError::bad_request("Page revision is invalid"));
    }
    if request.label.is_none()
        && request.endpoint.is_none()
        && request.content.is_none()
        && request.visibility.is_none()
        && request.navigation_order.is_none()
    {
        return Err(ApiError::bad_request("No page changes were supplied"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let current = sqlx::query_as::<_, PageView>(&page_select("WHERE id=$1 FOR UPDATE"))
        .bind(page_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Page not found"))?;
    if current.revision != request.revision {
        return Err(ApiError::conflict(
            "This page changed since it was loaded; refresh before saving",
        ));
    }
    match current.page_type.as_str() {
        "home" => {
            if request.endpoint.is_some()
                || request.visibility.is_some()
                || request.navigation_order.is_some()
            {
                return Err(ApiError::bad_request(
                    "The root endpoint, visibility, and order are fixed",
                ));
            }
        }
        "system" => {
            if request.label.is_some() || request.endpoint.is_some() || request.content.is_some() {
                return Err(ApiError::bad_request(
                    "System page labels, endpoints, and content cannot be changed",
                ));
            }
        }
        "custom" => {}
        _ => return Err(ApiError::conflict("Page type is invalid")),
    }

    let label = match request.label {
        Some(value) => validate_page_label(&value)?,
        None => current.label.clone(),
    };
    let endpoint = match request.endpoint {
        Some(value) if current.page_type == "custom" => validate_custom_page_endpoint(&value)?,
        Some(_) => return Err(ApiError::bad_request("Page endpoint cannot be changed")),
        None => current.endpoint.clone(),
    };
    let content = match request.content {
        Some(value) => validate_page_content(&value)?,
        None => current.content.clone(),
    };
    let visibility = match request.visibility {
        Some(value) => validate_page_visibility(&value)?,
        None => current.visibility.clone(),
    };
    let navigation_order = validate_page_navigation_order(
        request.navigation_order.unwrap_or(current.navigation_order),
        current.page_type == "home",
    )?;

    let page = sqlx::query_as::<_, PageView>(
        r#"
        UPDATE ctfzone.pages
        SET label=$1,endpoint=$2,content=$3,visibility=$4,navigation_order=$5,
            revision=revision+1,updated_at=now()
        WHERE id=$6 AND revision=$7
        RETURNING id,label,endpoint,content,page_type,system_key,visibility,
                  navigation_order,revision,created_at,updated_at
        "#,
    )
    .bind(label)
    .bind(endpoint)
    .bind(content)
    .bind(&visibility)
    .bind(navigation_order)
    .bind(page_id)
    .bind(current.revision)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_admin_database_error)?
    .ok_or_else(|| ApiError::conflict("Page revision changed while saving"))?;
    if let Some(system_key) = page.system_key.as_deref() {
        sync_system_page_visibility(&mut transaction, system_key, &visibility).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(page)).into_response())
}

pub(super) async fn delete_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(page_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let page = sqlx::query_as::<_, PageView>(&page_select("WHERE id=$1 FOR UPDATE"))
        .bind(page_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Page not found"))?;
    if page.page_type != "custom" {
        return Err(ApiError::conflict("Built-in pages cannot be deleted"));
    }
    sqlx::query("DELETE FROM ctfzone.pages WHERE id=$1")
        .bind(page_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    super::create_idempotency::forget_resource(
        &mut transaction,
        super::create_idempotency::PAGE_CREATE,
        page_id,
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn list_brackets(State(state): State<AppState>) -> Result<Response, ApiError> {
    let rows = sqlx::query_as::<_, BracketView>(&bracket_select("ORDER BY id"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn list_challenge_categories(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, ChallengeCategoryView>(
        r#"
        SELECT category.id,category.name,category.logo_key,category.logo_color,category.icon_object_id,
               COUNT(challenge.id)::bigint AS challenge_count
        FROM ctfzone.challenge_categories category
        LEFT JOIN ctfzone.challenges challenge ON challenge.category_id=category.id
        GROUP BY category.id
        ORDER BY lower(category.name),category.id
        "#,
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_challenge_category(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(category_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let row = load_challenge_category(&state, category_id).await?;
    Ok(Json(Success::new(row)).into_response())
}

pub(super) async fn create_challenge_category(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(request): Json<ChallengeCategoryInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let name = validate_challenge_category_name(&request.name)?;
    let logo_key = validate_challenge_category_logo_key(request.logo_key.as_deref())?;
    let logo_color =
        validate_challenge_category_logo_color(request.logo_color.as_deref(), logo_key.as_deref())?;
    let request_data = json!({"name": &name, "logo_key": &logo_key, "logo_color": &logo_color});
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let (idempotency, replay) = super::create_idempotency::CreateRequest::lock_and_replay(
        &mut transaction,
        &headers,
        user.id,
        super::create_idempotency::CATEGORY_CREATE,
        &request_data,
    )
    .await?;
    if let Some(response_data) = replay {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response());
    }
    let row = sqlx::query_as::<_, ChallengeCategoryView>(
        r#"
        INSERT INTO ctfzone.challenge_categories (name,logo_key,logo_color)
        VALUES ($1,$2,$3)
        RETURNING id,name,logo_key,logo_color,icon_object_id,0::bigint AS challenge_count
        "#,
    )
    .bind(name)
    .bind(logo_key)
    .bind(logo_color)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| ApiError::conflict_or_database(error, "Challenge category already exists"))?;
    let response_data = json!({
        "id": row.id,
        "name": row.name,
        "logo_key": row.logo_key,
        "logo_color": row.logo_color,
        "icon_object_id": row.icon_object_id,
        "challenge_count": row.challenge_count,
    });
    idempotency
        .complete(&mut transaction, row.id, &response_data)
        .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response())
}

pub(super) async fn update_challenge_category(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(category_id): Path<i32>,
    Json(request): Json<ChallengeCategoryPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let current = sqlx::query_as::<_, ChallengeCategoryView>(
        r#"
        SELECT category.id,category.name,category.logo_key,category.logo_color,category.icon_object_id,
               (SELECT COUNT(*)::bigint FROM ctfzone.challenges challenge
                WHERE challenge.category_id=category.id) AS challenge_count
        FROM ctfzone.challenge_categories category
        WHERE category.id=$1
        FOR UPDATE OF category
        "#,
    )
    .bind(category_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge category not found"))?;

    let name = match request.name.as_ref() {
        None => current.name,
        Some(Value::String(value)) => validate_challenge_category_name(value)?,
        Some(_) => return Err(ApiError::bad_request("Category name must be a string")),
    };
    let logo_key = match request.logo_key.as_ref() {
        None => current.logo_key,
        Some(Value::Null) => None,
        Some(Value::String(value)) => validate_challenge_category_logo_key(Some(value))?,
        Some(_) => {
            return Err(ApiError::bad_request(
                "Category logo_key must be a string or null",
            ));
        }
    };
    let requested_logo_color = match request.logo_color.as_ref() {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Some(Some(value.as_str())),
        Some(_) => {
            return Err(ApiError::bad_request(
                "Category logo_color must be a string or null",
            ));
        }
    };
    let logo_color = if logo_key.is_none() {
        if requested_logo_color.is_some_and(|value| value.is_some()) {
            return Err(ApiError::bad_request(
                "Category logo_color requires a built-in logo",
            ));
        }
        None
    } else {
        let requested = match requested_logo_color {
            None => current.logo_color.as_deref(),
            Some(value) => value,
        };
        validate_challenge_category_logo_color(requested, logo_key.as_deref())?
    };
    let row = sqlx::query_as::<_, ChallengeCategoryView>(
        r#"
        UPDATE ctfzone.challenge_categories
        SET name=$1,logo_key=$2,logo_color=$3
        WHERE id=$4
        RETURNING id,name,logo_key,logo_color,icon_object_id,$5::bigint AS challenge_count
        "#,
    )
    .bind(name)
    .bind(logo_key)
    .bind(logo_color)
    .bind(category_id)
    .bind(current.challenge_count)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| ApiError::conflict_or_database(error, "Challenge category already exists"))?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(row)).into_response())
}

pub(super) async fn delete_challenge_category(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(category_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM ctfzone.challenge_categories WHERE id=$1 FOR UPDATE",
    )
    .bind(category_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .is_some();
    if !exists {
        return Err(ApiError::not_found("Challenge category not found"));
    }
    let in_use = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.challenges WHERE category_id=$1)",
    )
    .bind(category_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if in_use {
        return Err(ApiError::conflict(
            "Challenge category is still used by a challenge",
        ));
    }
    sqlx::query("DELETE FROM ctfzone.challenge_categories WHERE id=$1")
        .bind(category_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    super::create_idempotency::forget_resource(
        &mut transaction,
        super::create_idempotency::CATEGORY_CREATE,
        category_id,
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(StatusCode::NO_CONTENT.into_response())
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
    delete_integer_id(&state, &user, "brackets", bracket_id).await
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
        "SELECT id,challenge_id,type AS flag_type,content,data,revision FROM ctfzone.flags WHERE ($1::integer IS NULL OR challenge_id=$1) ORDER BY id",
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
    Json(request): Json<FlagInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::flag_policy::lock_challenge_definition(&mut transaction, request.challenge_id).await?;
    let exposure = sqlx::query_scalar::<_, String>(
        "SELECT exposure FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
    )
    .bind(request.challenge_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))?;
    if challenge_has_active_runtime(&mut transaction, request.challenge_id).await? {
        return Err(ApiError::conflict(
            "Stop the active challenge instances before changing flags",
        ));
    }
    let (flag_type, content, data) = super::flag_policy::normalize_definition(
        &request.flag_type,
        &request.content,
        request.data,
        &exposure,
    )?;
    let flag = sqlx::query_as::<_, FlagView>(
        "INSERT INTO ctfzone.flags (challenge_id,type,content,data) VALUES ($1,$2,$3,$4) RETURNING id,challenge_id,type AS flag_type,content,data,revision",
    )
    .bind(request.challenge_id)
    .bind(flag_type)
    .bind(content)
    .bind(data)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| {
        ApiError::conflict_or_database(error, "The challenge already has a generated flag")
    })?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(flag))).into_response())
}

pub(super) async fn update_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(flag_id): Path<i32>,
    Json(request): Json<FlagPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let initial_challenge_id =
        sqlx::query_scalar::<_, i32>("SELECT challenge_id FROM ctfzone.flags WHERE id=$1")
            .bind(flag_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .ok_or_else(|| ApiError::not_found("Flag not found"))?;
    let requested_challenge_id = request.challenge_id.unwrap_or(initial_challenge_id);
    for challenge_id in if initial_challenge_id == requested_challenge_id {
        vec![initial_challenge_id]
    } else {
        let mut ids = vec![initial_challenge_id, requested_challenge_id];
        ids.sort_unstable();
        ids
    } {
        super::flag_policy::lock_challenge_definition(&mut transaction, challenge_id).await?;
    }
    let current = sqlx::query_as::<_, FlagView>(
        "SELECT id,challenge_id,type AS flag_type,content,data,revision FROM ctfzone.flags WHERE id=$1 FOR UPDATE",
    )
    .bind(flag_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Flag not found"))?;
    if current.challenge_id != initial_challenge_id {
        return Err(ApiError::conflict(
            "The flag changed concurrently; reload it and try again",
        ));
    }
    let challenge_id = request.challenge_id.unwrap_or(current.challenge_id);
    let flag_type = request
        .flag_type
        .unwrap_or_else(|| current.flag_type.clone());
    let content = request.content.unwrap_or_else(|| current.content.clone());
    let data = request.data.unwrap_or_else(|| current.data.clone());
    let exposure = sqlx::query_scalar::<_, String>(
        "SELECT exposure FROM ctfzone.challenges WHERE id=$1 FOR KEY SHARE",
    )
    .bind(challenge_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))?;
    let (flag_type, content, data) =
        super::flag_policy::normalize_definition(&flag_type, &content, data, &exposure)?;
    let changed = challenge_id != current.challenge_id
        || flag_type != current.flag_type
        || content != current.content
        || data != current.data;
    if changed {
        if challenge_id != current.challenge_id {
            let source_flag_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM ctfzone.flags WHERE challenge_id=$1",
            )
            .bind(current.challenge_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
            if source_flag_count <= 1 {
                return Err(ApiError::conflict(
                    "A challenge must retain at least one flag definition",
                ));
            }
        }
        let assignments = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.user_challenge_flags WHERE flag_id=$1)",
        )
        .bind(flag_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if assignments {
            return Err(ApiError::conflict(
                "Generated flag definitions cannot change after allocation",
            ));
        }
        if challenge_has_active_runtime(&mut transaction, current.challenge_id).await?
            || (challenge_id != current.challenge_id
                && challenge_has_active_runtime(&mut transaction, challenge_id).await?)
        {
            return Err(ApiError::conflict(
                "Stop the active challenge instances before changing flags",
            ));
        }
    }
    let flag = sqlx::query_as::<_, FlagView>(
        r#"
        UPDATE ctfzone.flags SET challenge_id=$1,type=$2,content=$3,data=$4,
            revision=CASE WHEN challenge_id IS DISTINCT FROM $1 OR type IS DISTINCT FROM $2
                OR content IS DISTINCT FROM $3 OR data IS DISTINCT FROM $4
                THEN revision+1 ELSE revision END
        WHERE id=$5
        RETURNING id,challenge_id,type AS flag_type,content,data,revision
        "#,
    )
    .bind(challenge_id)
    .bind(flag_type)
    .bind(content)
    .bind(data)
    .bind(flag_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| {
        ApiError::conflict_or_database(error, "The challenge already has a generated flag")
    })?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(flag)).into_response())
}

pub(super) async fn delete_flag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(flag_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let initial_challenge_id =
        sqlx::query_scalar::<_, i32>("SELECT challenge_id FROM ctfzone.flags WHERE id=$1")
            .bind(flag_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .ok_or_else(|| ApiError::not_found("Flag not found"))?;
    super::flag_policy::lock_challenge_definition(&mut transaction, initial_challenge_id).await?;
    let challenge_id = sqlx::query_scalar::<_, i32>(
        "SELECT challenge_id FROM ctfzone.flags WHERE id=$1 FOR UPDATE",
    )
    .bind(flag_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Flag not found"))?;
    if challenge_id != initial_challenge_id {
        return Err(ApiError::conflict(
            "The flag changed concurrently; reload it and try again",
        ));
    }
    let assignments = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.user_challenge_flags WHERE flag_id=$1)",
    )
    .bind(flag_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if assignments {
        return Err(ApiError::conflict(
            "Generated flags cannot be deleted after allocation",
        ));
    }
    let flag_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ctfzone.flags WHERE challenge_id=$1")
            .bind(challenge_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
    if flag_count <= 1 {
        return Err(ApiError::conflict(
            "A challenge must retain at least one flag definition",
        ));
    }
    if challenge_has_active_runtime(&mut transaction, challenge_id).await? {
        return Err(ApiError::conflict(
            "Stop the active challenge instances before changing flags",
        ));
    }
    sqlx::query("DELETE FROM ctfzone.flags WHERE id=$1")
        .bind(flag_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(StatusCode::NO_CONTENT.into_response())
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
    delete_integer_id(&state, &user, "tags", tag_id).await
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
    delete_integer_id(&state, &user, "challenge_topics", id).await
}

pub(super) async fn delete_topic(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(topic_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, &user, "topics", topic_id).await
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    super::team_accounts::lock_team_membership(&mut transaction).await?;
    request.team_id =
        canonical_account_team_id(&mut transaction, request.user_id, request.team_id, "award")
            .await?;
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
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(award))).into_response())
}

pub(super) async fn delete_award(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(award_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, &user, "awards", award_id).await
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    if let Some(team_id) = request.team_id {
        if super::user_mode_transition::transaction_user_mode(&mut transaction).await? != "teams" {
            return Err(ApiError::bad_request(
                "Team comments are only available in team mode",
            ));
        }
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM ctfzone.teams WHERE id=$1)")
                .bind(team_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(ApiError::database)?;
        if !exists {
            return Err(ApiError::bad_request("Comment team does not exist"));
        }
    }
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
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(comment))).into_response())
}

pub(super) async fn delete_comment(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(comment_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_integer_id(&state, &user, "comments", comment_id).await
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
    Json(mut request): Json<SubmissionInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_submission_type(&request.submission_type)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    super::team_accounts::lock_team_membership(&mut transaction).await?;
    request.team_id = canonical_account_team_id(
        &mut transaction,
        request.user_id,
        request.team_id,
        "submission",
    )
    .await?;
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    super::team_accounts::lock_team_membership(&mut transaction).await?;
    let current = sqlx::query_as::<_, SubmissionView>(&format!(
        "{} WHERE id=$1 FOR UPDATE",
        submission_select()
    ))
    .bind(submission_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Submission not found"))?;
    let requested_type = request
        .submission_type
        .unwrap_or_else(|| current.submission_type.clone().unwrap_or_default());
    validate_submission_type(&requested_type)?;
    let canonical_team_id = canonical_account_team_id(
        &mut transaction,
        current.user_id.unwrap_or_default(),
        current.team_id,
        "submission",
    )
    .await?;
    if current.submission_type.as_deref() != Some("correct") && requested_type == "correct" {
        let input = SubmissionInput {
            challenge_id: current.challenge_id.unwrap_or_default(),
            user_id: current.user_id.unwrap_or_default(),
            team_id: canonical_team_id,
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
    delete_integer_id(&state, &user, "submissions", submission_id).await
}

async fn reject_direct_user_mode_change(
    transaction: &mut Transaction<'_, Postgres>,
    normalized: &[(String, String)],
) -> Result<(), ApiError> {
    let Some((_, requested)) = normalized.iter().find(|(key, _)| key == "user_mode") else {
        return Ok(());
    };
    let current = super::user_mode_transition::transaction_user_mode(transaction).await?;
    if requested == &current {
        Ok(())
    } else {
        Err(direct_user_mode_change_error())
    }
}

fn direct_user_mode_change_error() -> ApiError {
    ApiError::conflict(
        "Competition mode must be changed through the account-mode transition endpoint",
    )
}

async fn canonical_account_team_id(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
    requested_team_id: Option<i32>,
    record_kind: &str,
) -> Result<Option<i32>, ApiError> {
    if super::user_mode_transition::transaction_user_mode(transaction).await? == "users" {
        if requested_team_id.is_some() {
            return Err(ApiError::bad_request(format!(
                "A {record_kind} cannot target a team while competition mode is users"
            )));
        }
        let participant_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE id=$1 AND type='user')",
        )
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
        if !participant_exists {
            return Err(ApiError::bad_request(format!(
                "The {record_kind} user is not a participant"
            )));
        }
        return Ok(None);
    }

    let assigned_team_id = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT team_id FROM ctfzone.users WHERE id=$1 AND type='user'",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .flatten()
    .ok_or_else(|| {
        ApiError::bad_request(format!("The {record_kind} user does not belong to a team"))
    })?;
    if requested_team_id.is_some_and(|team_id| team_id != assigned_team_id) {
        return Err(ApiError::bad_request(format!(
            "The {record_kind} team does not match the user's current team"
        )));
    }
    Ok(Some(assigned_team_id))
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

async fn load_challenge_category(
    state: &AppState,
    category_id: i32,
) -> Result<ChallengeCategoryView, ApiError> {
    sqlx::query_as::<_, ChallengeCategoryView>(
        r#"
        SELECT category.id,category.name,category.logo_key,category.logo_color,category.icon_object_id,
               (SELECT COUNT(*)::bigint FROM ctfzone.challenges challenge
                WHERE challenge.category_id=category.id) AS challenge_count
        FROM ctfzone.challenge_categories category
        WHERE category.id=$1
        "#,
    )
    .bind(category_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge category not found"))
}

async fn load_flag(state: &AppState, id: i32) -> Result<FlagView, ApiError> {
    sqlx::query_as::<_, FlagView>(
        "SELECT id,challenge_id,type AS flag_type,content,data,revision FROM ctfzone.flags WHERE id=$1",
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

async fn delete_integer_id(
    state: &AppState,
    user: &CurrentUser,
    table: &str,
    id: i32,
) -> Result<Response, ApiError> {
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let result = sqlx::query(&format!("DELETE FROM ctfzone.{table} WHERE id=$1"))
        .bind(id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Record not found"));
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(json!({"success": true})).into_response())
}

fn field_select(suffix: &str) -> String {
    format!(
        "SELECT id,name,type AS field_owner_type,field_type,description,required,public,editable FROM ctfzone.fields {suffix}"
    )
}

fn page_select(suffix: &str) -> String {
    format!(
        "SELECT id,label,endpoint,content,page_type,system_key,visibility,navigation_order,revision,created_at,updated_at FROM ctfzone.pages {suffix}"
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
        "static": {"name": "static", "personalized": false},
        "regex": {"name": "regex", "personalized": false},
        "generated": {
            "name": "generated",
            "personalized": true,
            "private_only": true,
            "random_token_placeholder": super::flag_policy::RANDOM_TOKEN_PLACEHOLDER
        }
    })
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

fn validate_page_label(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 80
        || value
            .chars()
            .any(|character| character.is_control() || is_bidi_control(character))
    {
        return Err(ApiError::bad_request("Page label is invalid"));
    }
    Ok(value.to_owned())
}

fn validate_page_content(value: &str) -> Result<String, ApiError> {
    let value = value.replace("\r\n", "\n").replace('\r', "\n");
    if value.len() > 262_144 || value.contains('\0') {
        return Err(ApiError::bad_request(
            "Page HTML must be no larger than 256 KiB and cannot contain NUL bytes",
        ));
    }
    Ok(value)
}

fn validate_custom_page_endpoint(value: &str) -> Result<String, ApiError> {
    let endpoint = value.trim().trim_matches('/').to_ascii_lowercase();
    let valid = !endpoint.is_empty()
        && endpoint.len() <= 128
        && !endpoint.contains("..")
        && endpoint.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                })
        });
    let first = endpoint.split('/').next().unwrap_or_default();
    let reserved = matches!(
        first,
        "admin"
            | "api"
            | "assets"
            | "bff"
            | "category-icons"
            | "challenges"
            | "confirm"
            | "downloads"
            | "healthz"
            | "login"
            | "logout"
            | "profile"
            | "register"
            | "scoreboard"
            | "settings"
            | "setup"
            | "team"
            | "teams"
            | "users"
    );
    if !valid || reserved {
        return Err(ApiError::bad_request(
            "Page endpoint is invalid or reserved",
        ));
    }
    Ok(endpoint)
}

fn validate_page_visibility(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "public" | "private" | "invisible") {
        Ok(value)
    } else {
        Err(ApiError::bad_request("Page visibility is invalid"))
    }
}

fn validate_page_navigation_order(value: i32, home: bool) -> Result<i32, ApiError> {
    if (home && value == 0) || (!home && (1..=10_000).contains(&value)) {
        Ok(value)
    } else {
        Err(ApiError::bad_request("Page navigation order is invalid"))
    }
}

async fn sync_system_page_visibility(
    transaction: &mut Transaction<'_, Postgres>,
    system_key: &str,
    visibility: &str,
) -> Result<(), ApiError> {
    let config_key = match system_key {
        "challenges" => "challenge_visibility",
        "scoreboard" => "score_visibility",
        "home" => return Ok(()),
        _ => return Err(ApiError::conflict("System page key is invalid")),
    };
    let config_value = if visibility == "invisible" {
        "admins"
    } else {
        visibility
    };
    let result = sqlx::query("UPDATE ctfzone.config SET value=$1 WHERE key=$2")
        .bind(config_value)
        .bind(config_key)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "System visibility configuration is unavailable",
        ));
    }
    Ok(())
}

fn validate_bracket(request: &BracketInput) -> Result<(), ApiError> {
    if request.name.trim().is_empty() || !matches!(request.bracket_type.as_str(), "users" | "teams")
    {
        return Err(ApiError::bad_request("Bracket definition is invalid"));
    }
    Ok(())
}

fn validate_challenge_category_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 80
        || value
            .chars()
            .any(|character| character.is_control() || is_bidi_control(character))
    {
        return Err(ApiError::bad_request("Category value is invalid"));
    }
    Ok(value.to_owned())
}

fn validate_challenge_category_logo_key(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if matches!(
        value,
        "web" | "pwn" | "crypto" | "rev" | "misc" | "coding" | "forensics"
    ) {
        Ok(Some(value.to_owned()))
    } else {
        Err(ApiError::bad_request("Category logo_key is not supported"))
    }
}

const DEFAULT_CATEGORY_LOGO_COLOR: &str = "#34689c";

fn validate_challenge_category_logo_color(
    value: Option<&str>,
    logo_key: Option<&str>,
) -> Result<Option<String>, ApiError> {
    if logo_key.is_none() {
        return if value.is_none() {
            Ok(None)
        } else {
            Err(ApiError::bad_request(
                "Category logo_color requires a built-in logo",
            ))
        };
    }
    let value = value
        .unwrap_or(DEFAULT_CATEGORY_LOGO_COLOR)
        .to_ascii_lowercase();
    if value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(Some(value))
    } else {
        Err(ApiError::bad_request(
            "Category logo_color must be a six-digit hexadecimal color",
        ))
    }
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

async fn challenge_has_active_runtime(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.runtime_instances WHERE challenge_id=$1 AND active)",
    )
    .bind(challenge_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
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

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing source marker: {start}"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("missing source marker: {end}"))
            .0
    }

    fn assert_source_order(source: &str, markers: &[&str]) {
        let mut remaining = source;
        for marker in markers {
            remaining = remaining
                .split_once(marker)
                .unwrap_or_else(|| panic!("missing or out-of-order source marker: {marker}"))
                .1;
        }
    }

    #[test]
    fn validates_custom_page_contract() {
        assert_eq!(validate_custom_page_endpoint(" /rules/ ").unwrap(), "rules");
        assert_eq!(
            validate_custom_page_endpoint("event_rules-2026").unwrap(),
            "event_rules-2026"
        );
        assert_eq!(
            validate_custom_page_endpoint("guides/beginners").unwrap(),
            "guides/beginners"
        );
        assert!(validate_custom_page_endpoint("").is_err());
        assert!(validate_custom_page_endpoint("../rules").is_err());
        assert!(validate_custom_page_endpoint("challenges").is_err());
        assert!(validate_custom_page_endpoint("admin/preview").is_err());
        assert!(validate_custom_page_endpoint("team").is_err());
        assert!(validate_custom_page_endpoint("downloads/example").is_err());
        assert!(validate_custom_page_endpoint("https://example.test").is_err());
        assert_eq!(validate_page_visibility(" PRIVATE ").unwrap(), "private");
        assert!(validate_page_visibility("hidden").is_err());
        assert_eq!(validate_page_navigation_order(1, false).unwrap(), 1);
        assert!(validate_page_navigation_order(0, false).is_err());
        assert_eq!(validate_page_navigation_order(0, true).unwrap(), 0);
        assert!(validate_page_content(&"x".repeat(262_145)).is_err());
        assert!(validate_page_content("<p>ok</p>\0").is_err());
    }

    #[test]
    fn escapes_allowlist_search_wildcards_as_literals() {
        assert_eq!(escape_like("100%_\\example"), "100\\%\\_\\\\example");
    }

    #[test]
    fn challenge_category_names_are_bounded_and_safe() {
        assert_eq!(
            validate_challenge_category_name(" Hardware ").unwrap(),
            "Hardware"
        );
        assert!(validate_challenge_category_name("").is_err());
        assert!(validate_challenge_category_name(&"x".repeat(81)).is_err());
        assert!(validate_challenge_category_name(&"🦕".repeat(20)).is_ok());
        assert!(validate_challenge_category_name(&"🦕".repeat(21)).is_err());
        assert!(validate_challenge_category_name("safe\u{202e}txt").is_err());
        assert!(validate_challenge_category_name("safe\u{2066}txt").is_err());
        assert!(validate_challenge_category_name("safe\u{0007}txt").is_err());
        assert!(validate_challenge_category_name("safe\u{0085}txt").is_err());
    }

    #[test]
    fn challenge_category_logos_are_semantic_and_bounded() {
        for key in ["web", "pwn", "crypto", "rev", "misc", "coding", "forensics"] {
            assert_eq!(
                validate_challenge_category_logo_key(Some(key)).unwrap(),
                Some(key.to_owned())
            );
        }
        assert_eq!(validate_challenge_category_logo_key(None).unwrap(), None);
        assert!(validate_challenge_category_logo_key(Some("dinosaur")).is_err());
        assert!(validate_challenge_category_logo_key(Some("WEB")).is_err());
        assert!(validate_challenge_category_logo_key(Some("")).is_err());
        assert_eq!(
            validate_challenge_category_logo_color(None, Some("web")).unwrap(),
            Some(DEFAULT_CATEGORY_LOGO_COLOR.to_owned())
        );
        assert_eq!(
            validate_challenge_category_logo_color(Some("#A1B2C3"), Some("web")).unwrap(),
            Some("#a1b2c3".to_owned())
        );
        assert!(validate_challenge_category_logo_color(Some("red"), Some("web")).is_err());
        assert!(validate_challenge_category_logo_color(Some("#123abc"), None).is_err());
    }

    #[test]
    fn score_and_unlock_writers_hold_the_shared_mode_fence() {
        let challenges = include_str!("challenges.rs");
        assert_source_order(
            source_between(
                challenges,
                "pub(super) async fn attempt(",
                "async fn challenge_detail_by_id(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "pg_advisory_xact_lock",
                "insert_submission(",
                "INSERT INTO ctfzone.solves",
            ],
        );

        let content = include_str!("content.rs");
        assert_source_order(
            source_between(
                content,
                "pub(super) async fn rate_challenge(",
                "pub(super) async fn challenge_solution(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "lock_team_membership",
                "require_full_challenge_access_in_transaction",
                "user_solved_challenge_in_transaction",
                "INSERT INTO ctfzone.ratings",
            ],
        );
        assert_source_order(
            source_between(
                content,
                "pub(super) async fn unlock(",
                "pub(super) async fn list_notifications(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "CONTENT_UNLOCK_LOCK_NAMESPACE",
                "INSERT INTO ctfzone.awards",
                "INSERT INTO ctfzone.unlocks",
            ],
        );

        let administration = include_str!("administration.rs");
        for (start, end, final_write) in [
            (
                "pub(super) async fn create_award(",
                "pub(super) async fn delete_award(",
                "INSERT INTO ctfzone.awards",
            ),
            (
                "pub(super) async fn create_submission(",
                "pub(super) async fn update_submission(",
                "insert_submission(",
            ),
            (
                "pub(super) async fn update_submission(",
                "pub(super) async fn delete_submission(",
                "INSERT INTO ctfzone.solves",
            ),
        ] {
            assert_source_order(
                source_between(administration, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    "canonical_account_team_id",
                    final_write,
                ],
            );
        }
    }

    #[test]
    fn upload_token_and_team_writers_hold_the_shared_mode_fence() {
        let objects = include_str!("objects.rs");
        for (start, end, final_write) in [
            (
                "pub(super) async fn initiate_upload(",
                "pub(super) async fn complete_upload(",
                "INSERT INTO ctfzone.stored_objects",
            ),
            (
                "pub(super) async fn complete_upload(",
                "pub(super) async fn object_detail(",
                "UPDATE ctfzone.stored_objects",
            ),
        ] {
            assert_source_order(
                source_between(objects, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    "transaction_user_mode",
                    "authorization_principal_in_transaction",
                    final_write,
                ],
            );
        }

        let tokens = include_str!("participant_tokens.rs");
        assert_source_order(
            source_between(
                tokens,
                "pub(super) async fn get(",
                "pub(super) async fn rotate(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "lock_team_membership",
                "current_account_in_transaction",
                "load_token_in_transaction",
            ],
        );
        assert_source_order(
            source_between(
                tokens,
                "pub(super) async fn rotate(",
                "async fn current_account_in_transaction(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "current_account_in_transaction",
                "UPDATE ctfzone.users",
                "UPDATE ctfzone.teams",
            ],
        );

        let teams = include_str!("team_accounts.rs");
        for (start, end, final_write) in [
            (
                "pub(super) async fn create_current(",
                "pub(super) async fn join_current(",
                "INSERT INTO ctfzone.teams",
            ),
            (
                "pub(super) async fn join_current(",
                "pub(super) async fn detail(",
                "UPDATE ctfzone.users SET team_id",
            ),
            (
                "pub(super) async fn add_member(",
                "pub(super) async fn current_invite(",
                "UPDATE ctfzone.users SET team_id",
            ),
            (
                "pub(super) async fn remove_member(",
                "async fn update(",
                "UPDATE ctfzone.users SET team_id = NULL",
            ),
            (
                "async fn delete_team(",
                "async fn load_team(",
                "DELETE FROM ctfzone.teams",
            ),
        ] {
            assert_source_order(
                source_between(teams, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    "require_team_mode_in_transaction",
                    final_write,
                ],
            );
        }

        let api_tokens = include_str!("tokens.rs");
        for (start, end, final_write) in [
            (
                "pub(super) async fn create_token(",
                "pub(super) async fn get_token(",
                "INSERT INTO ctfzone.tokens",
            ),
            (
                "pub(super) async fn delete_token(",
                "async fn find_visible_token(",
                "DELETE FROM ctfzone.tokens",
            ),
        ] {
            assert_source_order(
                source_between(api_tokens, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    final_write,
                ],
            );
        }
    }

    #[test]
    fn exact_snapshot_metadata_writers_hold_the_shared_mode_fence() {
        let challenges = include_str!("challenges.rs");
        for (start, end, final_write) in [
            (
                "pub(super) async fn create(",
                "pub(super) async fn detail(",
                "INSERT INTO ctfzone.challenges",
            ),
            (
                "pub(super) async fn delete_challenge(",
                "pub(super) async fn attempt(",
                "DELETE FROM ctfzone.challenges",
            ),
        ] {
            assert_source_order(
                source_between(challenges, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    final_write,
                ],
            );
        }
        assert_source_order(
            source_between(
                challenges,
                "pub(super) async fn update(",
                "pub(super) async fn delete_challenge(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "challenge_detail_by_id_for_update",
                "transaction_user_mode",
                "UPDATE ctfzone.challenges",
            ],
        );

        let content = include_str!("content.rs");
        assert_source_order(
            source_between(
                content,
                "pub(super) async fn create_notification(",
                "pub(super) async fn delete_notification(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "INSERT INTO ctfzone.notifications",
            ],
        );

        let objects = include_str!("objects.rs");
        assert_source_order(
            source_between(
                objects,
                "pub(super) async fn download_grant(",
                "pub(super) async fn delete_object(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "lock_team_membership",
                "load_object_for_update",
                "get_url",
            ],
        );

        assert_source_order(
            source_between(
                challenges,
                "if let Some(current) = user.as_ref().filter(|current| !current.is_admin()) {",
                "pub(super) async fn update(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "INSERT INTO ctfzone.tracking",
            ],
        );

        let administration = include_str!("administration.rs");
        assert_source_order(
            source_between(
                administration,
                "pub(super) async fn create_comment(",
                "pub(super) async fn delete_comment(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "transaction_user_mode",
                "INSERT INTO ctfzone.comments",
            ],
        );
        assert_source_order(
            source_between(
                administration,
                "async fn delete_integer_id(",
                "fn field_select(",
            ),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "DELETE FROM ctfzone.",
            ],
        );
    }

    #[test]
    fn session_creation_and_revocation_hold_the_shared_mode_fence() {
        let browser = include_str!("../browser_auth.rs");
        assert_source_order(
            source_between(browser, "async fn login(", "async fn logout("),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "SELECT u.id",
                "insert_session(",
            ],
        );
        assert_source_order(
            source_between(browser, "async fn logout(", "fn session_id_from_headers("),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "UPDATE ctfzone.user_sessions",
            ],
        );

        let sessions = include_str!("sessions.rs");
        for (start, end) in [
            (
                "pub(super) async fn revoke_all(",
                "pub(super) async fn revoke_user(",
            ),
            (
                "pub(super) async fn revoke_user(",
                "pub(super) async fn revoke_one(",
            ),
            (
                "pub(super) async fn revoke_one(",
                "fn current_session_matches(",
            ),
        ] {
            assert_source_order(
                source_between(sessions, start, end),
                &[
                    "state.database.begin()",
                    "lock_configuration_shared",
                    "revalidate_current_credential",
                    "UPDATE ctfzone.user_sessions",
                ],
            );
        }

        let users = include_str!("user_accounts.rs");
        assert_source_order(
            source_between(users, "async fn update(", "async fn load_user("),
            &[
                "state.database.begin()",
                "lock_configuration_shared",
                "revalidate_current_credential",
                "UPDATE ctfzone.user_sessions",
            ],
        );
    }

    #[test]
    fn flag_mutations_cannot_leave_a_challenge_without_a_definition() {
        let source = include_str!("administration.rs");
        let update = source_between(
            source,
            "pub(super) async fn update_flag(",
            "pub(super) async fn delete_flag(",
        );
        let delete = source_between(
            source,
            "pub(super) async fn delete_flag(",
            "pub(super) async fn list_tags(",
        );
        for segment in [update, delete] {
            assert!(segment.contains("SELECT COUNT(*) FROM ctfzone.flags WHERE challenge_id=$1"));
            assert!(segment.contains("A challenge must retain at least one flag definition"));
        }
    }
}
