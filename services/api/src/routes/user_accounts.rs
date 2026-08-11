use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    passwords::{hash_password, verify_password},
    routes::Success,
};

#[derive(Deserialize, Default)]
pub(super) struct UserListQuery {
    affiliation: Option<String>,
    country: Option<String>,
    bracket: Option<i32>,
    q: Option<String>,
    field: Option<String>,
    view: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct CreateUser {
    name: String,
    email: String,
    password: String,
    #[serde(rename = "type")]
    user_type: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    language: Option<String>,
    bracket_id: Option<i32>,
    hidden: Option<bool>,
    banned: Option<bool>,
    verified: Option<bool>,
    change_password: Option<bool>,
    fields: Option<Vec<FieldInput>>,
}

#[derive(Deserialize, Default)]
pub(super) struct PatchUser {
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
    confirm: Option<String>,
    #[serde(rename = "type")]
    user_type: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    website: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    affiliation: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    country: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    language: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    bracket_id: Option<Option<i32>>,
    hidden: Option<bool>,
    banned: Option<bool>,
    verified: Option<bool>,
    change_password: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    team_id: Option<Option<i32>>,
    fields: Option<Vec<FieldInput>>,
}

#[derive(Clone, Deserialize)]
struct FieldInput {
    field_id: i32,
    value: Option<Value>,
}

#[derive(FromRow)]
struct UserRecord {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
    user_type: Option<String>,
    secret: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    hidden: Option<bool>,
    banned: Option<bool>,
    verified: Option<bool>,
    language: Option<String>,
    change_password: Option<bool>,
    team_id: Option<i32>,
    created: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct UserListRecord {
    id: i32,
    name: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    team_id: Option<i32>,
    total_count: i64,
}

#[derive(FromRow, Serialize)]
struct FieldEntry {
    field_id: i32,
    value: Option<Value>,
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<String>,
}

#[derive(Clone, Copy)]
enum UserView {
    Public,
    SelfView,
    Admin,
}

pub(super) async fn list(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<UserListQuery>,
) -> Result<Response, ApiError> {
    require_account_visibility(&state, user.as_ref()).await?;
    let admin_view =
        user.as_ref().is_some_and(CurrentUser::is_admin) && query.view.as_deref() == Some("admin");
    if query.field.as_deref() == Some("email") && !admin_view {
        return Err(ApiError::bad_request(
            "Emails can only be queried by admins",
        ));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
    let mut builder = QueryBuilder::<Postgres>::new(
        r#"
        SELECT
            id,
            name,
            website,
            affiliation,
            country,
            bracket_id,
            team_id,
            COUNT(*) OVER() AS total_count
        FROM ctfzone.users
        WHERE TRUE
        "#,
    );
    if !admin_view {
        builder.push(" AND COALESCE(banned, false) = false AND COALESCE(hidden, false) = false");
    }
    if let Some(affiliation) = query.affiliation {
        builder.push(" AND affiliation = ").push_bind(affiliation);
    }
    if let Some(country) = query.country {
        builder.push(" AND country = ").push_bind(country);
    }
    if let Some(bracket) = query.bracket {
        builder.push(" AND bracket_id = ").push_bind(bracket);
    }
    if let Some(search) = query.q.filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", search.trim());
        match query.field.as_deref().unwrap_or("name") {
            "name" => {
                builder.push(" AND name ILIKE ").push_bind(pattern);
            }
            "website" => {
                builder.push(" AND website ILIKE ").push_bind(pattern);
            }
            "country" => {
                builder.push(" AND country ILIKE ").push_bind(pattern);
            }
            "affiliation" => {
                builder.push(" AND affiliation ILIKE ").push_bind(pattern);
            }
            "email" => {
                builder.push(" AND email ILIKE ").push_bind(pattern);
            }
            "bracket" => {
                let bracket = search
                    .parse::<i32>()
                    .map_err(|_| ApiError::bad_request("bracket search must be an integer"))?;
                builder.push(" AND bracket_id = ").push_bind(bracket);
            }
            _ => return Err(ApiError::bad_request("Unsupported user search field")),
        }
    }
    builder
        .push(" ORDER BY created DESC NULLS LAST, id DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind((page - 1) * per_page);

    let rows = builder
        .build_query_as::<UserListRecord>()
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let total = rows.first().map_or(0, |row| row.total_count);
    let pages = if total == 0 {
        0
    } else {
        (total + per_page - 1) / per_page
    };
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let fields = fields_for_user(&state, row.id, UserView::Public).await?;
        data.push(json!({
            "website": row.website,
            "name": row.name,
            "country": row.country,
            "affiliation": row.affiliation,
            "bracket_id": row.bracket_id,
            "id": row.id,
            "fields": fields,
            "team_id": row.team_id,
        }));
    }

    Ok(Json(json!({
        "meta": {"pagination": {
            "page": page,
            "next": (page < pages).then_some(page + 1),
            "prev": (page > 1 && page <= pages + 1).then_some(page - 1),
            "pages": pages,
            "per_page": per_page,
            "total": total,
        }},
        "success": true,
        "data": data,
    }))
    .into_response())
}

pub(super) async fn create(
    State(state): State<AppState>,
    admin: CurrentUser,
    Json(request): Json<CreateUser>,
) -> Result<Response, ApiError> {
    require_admin(&admin)?;
    let name = validate_name(&request.name)?;
    let email = validate_email(&request.email)?;
    if request.password.is_empty() {
        return Err(ApiError::bad_request("Password must not be empty"));
    }
    let user_type = request.user_type.as_deref().unwrap_or("user");
    validate_user_type(user_type)?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let password = hash_password(&mut transaction, &request.password)
        .await
        .map_err(ApiError::database)?;
    reject_duplicate_identity(&mut transaction, None, &name, &email).await?;
    validate_user_bracket(&mut transaction, request.bracket_id).await?;

    let record = sqlx::query_as::<_, UserRecord>(
        r#"
        INSERT INTO ctfzone.users (
            name, email, password, type, participant_token, website, affiliation,
            country, language, bracket_id, hidden, banned, verified, change_password,
            created
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
            CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
        )
        RETURNING
            id, name, email, password, type AS user_type, secret, website,
            affiliation, country, bracket_id, hidden, banned, verified, language,
            change_password, team_id, created
        "#,
    )
    .bind(name)
    .bind(email)
    .bind(password)
    .bind(user_type)
    .bind(Uuid::new_v4().to_string())
    .bind(request.website)
    .bind(request.affiliation)
    .bind(request.country)
    .bind(request.language)
    .bind(request.bracket_id)
    .bind(request.hidden.unwrap_or(false))
    .bind(request.banned.unwrap_or(false))
    .bind(request.verified.unwrap_or(false))
    .bind(request.change_password.unwrap_or(false))
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;

    if user_type == "user" {
        add_allowlist_email(
            &mut transaction,
            record.email.as_deref().unwrap_or_default(),
        )
        .await?;
    }
    if let Some(fields) = request.fields {
        update_fields(&mut transaction, record.id, &fields, true).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;

    Ok(Json(Success::new(
        serialize_user(&state, record, UserView::Admin, false).await?,
    ))
    .into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_account_visibility(&state, current.as_ref()).await?;
    let record = load_user(&state, user_id).await?;
    if !current.as_ref().is_some_and(CurrentUser::is_admin)
        && (record.banned.unwrap_or(false) || record.hidden.unwrap_or(false))
    {
        return Err(ApiError::not_found("User not found"));
    }
    let view = if current.as_ref().is_some_and(CurrentUser::is_admin) {
        UserView::Admin
    } else {
        UserView::Public
    };
    let include_scores = scores_visible(&state, current.as_ref()).await?;

    Ok(Json(Success::new(
        serialize_user(&state, record, view, include_scores).await?,
    ))
    .into_response())
}

pub(super) async fn update_admin(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(user_id): Path<i32>,
    Json(request): Json<PatchUser>,
) -> Result<Response, ApiError> {
    require_admin(&admin)?;
    if admin.id == user_id && request.banned == Some(true) {
        return Err(ApiError::bad_request("You cannot ban yourself"));
    }
    update(&state, &admin, user_id, request, true).await
}

pub(super) async fn update_self(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(mut request): Json<PatchUser>,
) -> Result<Response, ApiError> {
    request.user_type = None;
    request.hidden = None;
    request.banned = None;
    request.verified = None;
    request.change_password = None;
    request.team_id = None;
    update(&state, &user, user.id, request, false).await
}

pub(super) async fn delete(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&admin)?;
    if admin.id == user_id {
        return Err(ApiError::bad_request("You cannot delete yourself"));
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::setup::guard_admin_delete(&mut transaction, user_id).await?;
    let email =
        sqlx::query_scalar::<_, Option<String>>("SELECT email FROM ctfzone.users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .flatten();
    if let Some(email) = email {
        sqlx::query("DELETE FROM ctfzone.registration_email_allowlist WHERE email = lower($1)")
            .bind(email)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
    }

    for table in [
        "notifications",
        "awards",
        "unlocks",
        "submissions",
        "tracking",
        "session_activity",
        "user_sessions",
    ] {
        let statement = format!("DELETE FROM ctfzone.{table} WHERE user_id = $1");
        sqlx::query(&statement)
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
    }
    let deleted = sqlx::query("DELETE FROM ctfzone.users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .rows_affected();
    transaction.commit().await.map_err(ApiError::database)?;
    if deleted == 0 {
        return Err(ApiError::not_found("User not found"));
    }

    Ok(Json(json!({"success": true})).into_response())
}

async fn update(
    state: &AppState,
    actor: &CurrentUser,
    user_id: i32,
    request: PatchUser,
    admin: bool,
) -> Result<Response, ApiError> {
    let previous = load_user(state, user_id).await?;
    let name = request.name.as_deref().map(validate_name).transpose()?;
    let email = request.email.as_deref().map(validate_email).transpose()?;
    if let Some(user_type) = request.user_type.as_deref() {
        validate_user_type(user_type)?;
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    if admin {
        crate::setup::guard_admin_update(
            &mut transaction,
            user_id,
            request.user_type.as_deref(),
            request.banned,
        )
        .await?;
    }

    if !admin {
        if name.as_deref() != previous.name.as_deref() && name.is_some() {
            let enabled = config_bool(state, "name_changes", true).await?;
            if !enabled {
                return Err(ApiError::forbidden("Name changes are disabled"));
            }
        }
        if email.as_deref() != previous.email.as_deref() || request.password.is_some() {
            let confirm = request
                .confirm
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("Please confirm your current password"))?;
            let previous_password = previous.password.as_deref().unwrap_or_default();
            if !verify_password(&mut transaction, confirm, previous_password)
                .await
                .map_err(ApiError::database)?
            {
                return Err(ApiError::bad_request("Your previous password is incorrect"));
            }
        }
        if let Some(password) = request.password.as_deref() {
            let minimum = config_i64(state, "password_min_length", 0).await?;
            if password.chars().count() < minimum as usize {
                return Err(ApiError::bad_request(format!(
                    "Password must be at least {minimum} characters"
                )));
            }
        }
    }

    let password = if let Some(password) = request.password.as_deref() {
        Some(
            hash_password(&mut transaction, password)
                .await
                .map_err(ApiError::database)?,
        )
    } else {
        None
    };
    let password_changed = password.is_some();
    let new_type = request
        .user_type
        .clone()
        .or_else(|| previous.user_type.clone())
        .unwrap_or_else(|| "user".to_owned());
    let new_email = email
        .clone()
        .or_else(|| previous.email.clone())
        .unwrap_or_default();

    reject_duplicate_identity(
        &mut transaction,
        Some(user_id),
        name.as_deref()
            .or(previous.name.as_deref())
            .unwrap_or_default(),
        &new_email,
    )
    .await?;
    if let Some(bracket_id) = request.bracket_id {
        if !admin && previous.bracket_id.is_some() && bracket_id != previous.bracket_id {
            return Err(ApiError::forbidden(
                "Please contact an admin to change your bracket",
            ));
        }
        validate_user_bracket(&mut transaction, bracket_id).await?;
    }

    let record = sqlx::query_as::<_, UserRecord>(
        r#"
        UPDATE ctfzone.users
        SET
            name = COALESCE($2, name),
            email = COALESCE($3, email),
            password = COALESCE($4, password),
            type = COALESCE($5, type),
            website = CASE WHEN $6 THEN $7 ELSE website END,
            affiliation = CASE WHEN $8 THEN $9 ELSE affiliation END,
            country = CASE WHEN $10 THEN $11 ELSE country END,
            language = CASE WHEN $12 THEN $13 ELSE language END,
            bracket_id = CASE WHEN $14 THEN $15 ELSE bracket_id END,
            hidden = COALESCE($16, hidden),
            banned = COALESCE($17, banned),
            verified = CASE
                WHEN $3::text IS NOT NULL AND $3::text <> email AND $22 THEN false
                ELSE COALESCE($18, verified)
            END,
            change_password = COALESCE($19, change_password),
            team_id = CASE WHEN $20 THEN $21 ELSE team_id END
        WHERE id = $1
        RETURNING
            id, name, email, password, type AS user_type, secret, website,
            affiliation, country, bracket_id, hidden, banned, verified, language,
            change_password, team_id, created
        "#,
    )
    .bind(user_id)
    .bind(name)
    .bind(email)
    .bind(password)
    .bind(request.user_type)
    .bind(request.website.is_some())
    .bind(request.website.flatten())
    .bind(request.affiliation.is_some())
    .bind(request.affiliation.flatten())
    .bind(request.country.is_some())
    .bind(request.country.flatten())
    .bind(request.language.is_some())
    .bind(request.language.flatten())
    .bind(request.bracket_id.is_some())
    .bind(request.bracket_id.flatten())
    .bind(request.hidden)
    .bind(request.banned)
    .bind(request.verified)
    .bind(request.change_password)
    .bind(request.team_id.is_some())
    .bind(request.team_id.flatten())
    .bind(config_bool(state, "verify_emails", false).await?)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    sync_allowlist(
        &mut transaction,
        previous.email.as_deref().unwrap_or_default(),
        &new_email,
        previous.user_type.as_deref().unwrap_or("user"),
        &new_type,
    )
    .await?;
    if let Some(fields) = request.fields {
        update_fields(&mut transaction, user_id, &fields, admin).await?;
    }
    if password_changed || (!previous.banned.unwrap_or(false) && record.banned.unwrap_or(false)) {
        sqlx::query(
            r#"
            UPDATE ctfzone.user_sessions
            SET revoked_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
                revoked_by_user_id = $1
            WHERE user_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(actor.id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    transaction.commit().await.map_err(ApiError::database)?;

    let view = if admin {
        UserView::Admin
    } else {
        UserView::SelfView
    };
    Ok(Json(Success::new(
        serialize_user(state, record, view, false).await?,
    ))
    .into_response())
}

async fn load_user(state: &AppState, user_id: i32) -> Result<UserRecord, ApiError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT
            id, name, email, password, type AS user_type, secret, website,
            affiliation, country, bracket_id, hidden, banned, verified, language,
            change_password, team_id, created
        FROM ctfzone.users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("User not found"))
}

async fn serialize_user(
    state: &AppState,
    user: UserRecord,
    view: UserView,
    include_scores: bool,
) -> Result<Value, ApiError> {
    let fields = fields_for_user(state, user.id, view).await?;
    let mut data = match view {
        UserView::Public => json!({
            "website": user.website,
            "name": user.name,
            "country": user.country,
            "affiliation": user.affiliation,
            "bracket_id": user.bracket_id,
            "id": user.id,
            "fields": fields,
            "team_id": user.team_id,
        }),
        UserView::SelfView => json!({
            "website": user.website,
            "name": user.name,
            "email": user.email,
            "language": user.language,
            "country": user.country,
            "affiliation": user.affiliation,
            "bracket_id": user.bracket_id,
            "id": user.id,
            "fields": fields,
            "team_id": user.team_id,
        }),
        UserView::Admin => json!({
            "website": user.website,
            "name": user.name,
            "created": user.created,
            "country": user.country,
            "banned": user.banned,
            "email": user.email,
            "language": user.language,
            "affiliation": user.affiliation,
            "secret": user.secret,
            "bracket_id": user.bracket_id,
            "hidden": user.hidden,
            "id": user.id,
            "type": user.user_type,
            "verified": user.verified,
            "change_password": user.change_password,
            "fields": fields,
            "team_id": user.team_id,
        }),
    };
    if include_scores {
        let (score, place) = score_and_place(state, user.id).await?;
        data["score"] = json!(score);
        data["place"] = json!(place);
    } else if matches!(view, UserView::Public | UserView::Admin) {
        data["score"] = Value::Null;
        data["place"] = Value::Null;
    }
    Ok(data)
}

async fn fields_for_user(
    state: &AppState,
    user_id: i32,
    view: UserView,
) -> Result<Vec<FieldEntry>, ApiError> {
    sqlx::query_as::<_, FieldEntry>(
        r#"
        SELECT
            field_entries.field_id,
            field_entries.value,
            fields.name,
            fields.description,
            fields.field_type
        FROM ctfzone.field_entries
        JOIN ctfzone.fields ON fields.id = field_entries.field_id
        WHERE field_entries.user_id = $1
          AND (
              $2 = 'admin'
              OR ($2 = 'self' AND (COALESCE(fields.editable, false) OR COALESCE(fields.public, false)))
              OR ($2 = 'public' AND COALESCE(fields.public, false))
          )
        ORDER BY field_entries.id
        "#,
    )
    .bind(user_id)
    .bind(match view {
        UserView::Public => "public",
        UserView::SelfView => "self",
        UserView::Admin => "admin",
    })
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn update_fields(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
    fields: &[FieldInput],
    admin: bool,
) -> Result<(), ApiError> {
    let mut provided = HashSet::new();
    for input in fields {
        if !provided.insert(input.field_id) {
            return Err(ApiError::bad_request("A field was provided more than once"));
        }
        let field = sqlx::query_as::<_, (bool, bool)>(
            r#"
            SELECT COALESCE(required, false), COALESCE(editable, false)
            FROM ctfzone.fields
            WHERE id = $1
            "#,
        )
        .bind(input.field_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::bad_request("A user field does not exist"))?;

        let existing = sqlx::query_scalar::<_, i32>(
            "SELECT id FROM ctfzone.field_entries WHERE user_id = $1 AND field_id = $2 LIMIT 1",
        )
        .bind(user_id)
        .bind(input.field_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
        if !admin && existing.is_some() && !field.1 {
            return Err(ApiError::forbidden("This field cannot be edited"));
        }
        if field.0 && value_is_empty(input.value.as_ref()) {
            return Err(ApiError::bad_request("A required field cannot be empty"));
        }

        if let Some(entry_id) = existing {
            sqlx::query("UPDATE ctfzone.field_entries SET value = $1 WHERE id = $2")
                .bind(&input.value)
                .bind(entry_id)
                .execute(&mut **transaction)
                .await
                .map_err(ApiError::database)?;
        } else {
            sqlx::query(
                r#"
                INSERT INTO ctfzone.field_entries (type, value, field_id, user_id)
                VALUES ('user', $1, $2, $3)
                "#,
            )
            .bind(&input.value)
            .bind(input.field_id)
            .bind(user_id)
            .execute(&mut **transaction)
            .await
            .map_err(ApiError::database)?;
        }
    }
    Ok(())
}

async fn reject_duplicate_identity(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Option<i32>,
    name: &str,
    email: &str,
) -> Result<(), ApiError> {
    let duplicate = sqlx::query_as::<_, (bool, bool)>(
        r#"
        SELECT
            EXISTS(SELECT 1 FROM ctfzone.users WHERE name = $1 AND ($3::int IS NULL OR id <> $3)),
            EXISTS(SELECT 1 FROM ctfzone.users WHERE lower(email) = lower($2) AND ($3::int IS NULL OR id <> $3))
        "#,
    )
    .bind(name)
    .bind(email)
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if duplicate.0 {
        return Err(ApiError::conflict("User name has already been taken"));
    }
    if duplicate.1 {
        return Err(ApiError::conflict("Email address has already been used"));
    }
    Ok(())
}

async fn validate_user_bracket(
    transaction: &mut Transaction<'_, Postgres>,
    bracket_id: Option<i32>,
) -> Result<(), ApiError> {
    let Some(bracket_id) = bracket_id else {
        return Ok(());
    };
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.brackets WHERE id = $1 AND type = 'users')",
    )
    .bind(bracket_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::bad_request("Please provide a valid bracket id"))
    }
}

async fn add_allowlist_email(
    transaction: &mut Transaction<'_, Postgres>,
    email: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.registration_email_allowlist (email, created)
        VALUES (lower($1), CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
        ON CONFLICT (email) DO NOTHING
        "#,
    )
    .bind(email)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

async fn sync_allowlist(
    transaction: &mut Transaction<'_, Postgres>,
    previous_email: &str,
    current_email: &str,
    previous_type: &str,
    current_type: &str,
) -> Result<(), ApiError> {
    if previous_type == "user" {
        sqlx::query("DELETE FROM ctfzone.registration_email_allowlist WHERE email = lower($1)")
            .bind(previous_email)
            .execute(&mut **transaction)
            .await
            .map_err(ApiError::database)?;
    }
    if current_type == "user" {
        add_allowlist_email(transaction, current_email).await?;
    }
    Ok(())
}

async fn require_account_visibility(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    let visibility = config_string(state, "account_visibility").await?;
    match visibility.as_deref().unwrap_or("public") {
        "public" => Ok(()),
        "private" if user.is_some() => Ok(()),
        "private" => Err(ApiError::forbidden("Authentication required")),
        "admins" if user.is_some_and(CurrentUser::is_admin) => Ok(()),
        "admins" => Err(ApiError::not_found("Accounts are not available")),
        _ => Ok(()),
    }
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

async fn scores_visible(state: &AppState, user: Option<&CurrentUser>) -> Result<bool, ApiError> {
    let visibility = config_string(state, "score_visibility").await?;
    Ok(match visibility.as_deref().unwrap_or("public") {
        "public" => true,
        "private" => user.is_some(),
        "admins" => user.is_some_and(CurrentUser::is_admin),
        "hidden" => false,
        _ => true,
    })
}

async fn score_and_place(
    state: &AppState,
    user_id: i32,
) -> Result<(i64, Option<String>), ApiError> {
    let freeze = config_string(state, "freeze")
        .await?
        .and_then(|value| value.parse::<i64>().ok());
    let score = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT
            COALESCE((
                SELECT SUM(challenges.value)::bigint
                FROM ctfzone.solves
                JOIN ctfzone.challenges ON challenges.id = solves.challenge_id
                JOIN ctfzone.submissions ON submissions.id = solves.id
                WHERE solves.user_id = $1
                  AND ($2::bigint IS NULL OR submissions.date < (to_timestamp($2::double precision) AT TIME ZONE 'UTC'))
            ), 0)
            +
            COALESCE((
                SELECT SUM(awards.value)::bigint
                FROM ctfzone.awards
                WHERE awards.user_id = $1
                  AND ($2::bigint IS NULL OR awards.date < (to_timestamp($2::double precision) AT TIME ZONE 'UTC'))
            ), 0)
        "#,
    )
    .bind(user_id)
    .bind(freeze)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;

    let place = super::users::user_place(state, user_id, freeze)
        .await?
        .map(super::users::ordinalize);
    Ok((score, place))
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key = $1 LIMIT 1",
    )
    .bind(key)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)
    .map(Option::flatten)
}

async fn config_bool(state: &AppState, key: &str, default: bool) -> Result<bool, ApiError> {
    Ok(config_string(state, key)
        .await?
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default))
}

async fn config_i64(state: &AppState, key: &str, default: i64) -> Result<i64, ApiError> {
    Ok(config_string(state, key)
        .await?
        .and_then(|value| value.parse().ok())
        .unwrap_or(default))
}

fn validate_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 128 {
        return Err(ApiError::bad_request("User names must not be empty"));
    }
    Ok(value.to_owned())
}

fn validate_email(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    let valid = value.len() <= 128
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if !valid {
        return Err(ApiError::bad_request(
            "Emails must be a properly formatted email address",
        ));
    }
    Ok(value.to_owned())
}

fn validate_user_type(value: &str) -> Result<(), ApiError> {
    if matches!(value, "user" | "admin") {
        Ok(())
    } else {
        Err(ApiError::bad_request("User type must be user or admin"))
    }
}

fn value_is_empty(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
        || value
            .and_then(Value::as_str)
            .is_some_and(|value| value.trim().is_empty())
}

fn deserialize_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
