use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::NaiveDateTime;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

const TEAM_CAPACITY_LOCK: i64 = 0x4354_465B;
const TEAM_MEMBERSHIP_LOCK: i64 = 0x4354_465C;
const TEAM_INVITE_MAX_AGE_SECONDS: i64 = 86_400;
const TEAM_INVITE_MAX_LENGTH: usize = 4_096;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    passwords::{hash_password, verify_password},
    routes::Success,
};

#[derive(Deserialize, Default)]
pub(super) struct TeamListQuery {
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
pub(super) struct CreateTeam {
    name: String,
    email: String,
    password: String,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    hidden: Option<bool>,
    banned: Option<bool>,
    captain_id: Option<i32>,
    fields: Option<Vec<FieldInput>>,
}

#[derive(Deserialize)]
pub(super) struct CreateCurrentTeam {
    name: String,
}

#[derive(Deserialize)]
pub(super) struct JoinCurrentTeam {
    code: String,
}

#[derive(Deserialize)]
struct InvitePayload {
    id: i32,
    v: String,
}

struct VerifiedInvite {
    team_id: i32,
    team_verification: Vec<u8>,
}

#[derive(Deserialize, Default)]
pub(super) struct PatchTeam {
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
    confirm: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    website: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    affiliation: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    country: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    bracket_id: Option<Option<i32>>,
    hidden: Option<bool>,
    banned: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    captain_id: Option<Option<i32>>,
    fields: Option<Vec<FieldInput>>,
}

#[derive(Clone, Deserialize)]
struct FieldInput {
    field_id: i32,
    value: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct MemberMutation {
    user_id: i32,
}

#[derive(FromRow)]
struct TeamRecord {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
    secret: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    hidden: Option<bool>,
    banned: Option<bool>,
    captain_id: Option<i32>,
    created: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct TeamListRecord {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    hidden: Option<bool>,
    banned: Option<bool>,
    captain_id: Option<i32>,
    created: Option<NaiveDateTime>,
    total_count: i64,
}

#[derive(FromRow, Serialize)]
pub(super) struct Member {
    id: i32,
    name: Option<String>,
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

#[derive(FromRow)]
struct TeamFieldEntry {
    team_id: i32,
    field_id: i32,
    value: Option<Value>,
    name: Option<String>,
    description: Option<String>,
    field_type: Option<String>,
}

#[derive(Clone, Copy)]
enum TeamView {
    Public,
    SelfView,
    Admin,
}

pub(super) async fn list(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<TeamListQuery>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_account_visibility(&state, user.as_ref()).await?;
    let is_admin = user.as_ref().is_some_and(CurrentUser::is_admin);
    let unfiltered = is_admin && query.view.as_deref() == Some("admin");
    if query.field.as_deref() == Some("email") && !is_admin {
        return Err(ApiError::bad_request(
            "Emails can only be queried by admins",
        ));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
    let mut builder = QueryBuilder::<Postgres>::new(
        r#"
        SELECT
            id, name, email, website, affiliation, country, bracket_id, hidden,
            banned, captain_id, created, COUNT(*) OVER() AS total_count
        FROM ctfzone.teams
        WHERE TRUE
        "#,
    );
    if !unfiltered {
        builder.push(" AND COALESCE(hidden, false) = false AND COALESCE(banned, false) = false");
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
            "name" => builder.push(" AND name ILIKE ").push_bind(pattern),
            "website" => builder.push(" AND website ILIKE ").push_bind(pattern),
            "country" => builder.push(" AND country ILIKE ").push_bind(pattern),
            "affiliation" => builder.push(" AND affiliation ILIKE ").push_bind(pattern),
            "email" => builder.push(" AND email ILIKE ").push_bind(pattern),
            "bracket" => {
                let bracket = search
                    .parse::<i32>()
                    .map_err(|_| ApiError::bad_request("bracket search must be an integer"))?;
                builder.push(" AND bracket_id = ").push_bind(bracket)
            }
            _ => return Err(ApiError::bad_request("Unsupported team search field")),
        };
    }
    builder
        .push(" ORDER BY created DESC NULLS LAST, id DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind((page - 1) * per_page);
    let rows = builder
        .build_query_as::<TeamListRecord>()
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let total = rows.first().map_or(0, |row| row.total_count);
    let pages = if total == 0 {
        0
    } else {
        (total + per_page - 1) / per_page
    };
    let team_ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
    let mut fields_by_team = fields_for_teams(
        &state,
        &team_ids,
        if is_admin {
            TeamView::Admin
        } else {
            TeamView::Public
        },
    )
    .await?;
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        let fields = fields_by_team.remove(&row.id).unwrap_or_default();
        data.push(if is_admin {
            json!({
                "website": row.website, "name": row.name, "created": row.created,
                "country": row.country, "banned": row.banned, "email": row.email,
                "affiliation": row.affiliation, "bracket_id": row.bracket_id,
                "hidden": row.hidden, "id": row.id, "captain_id": row.captain_id,
                "fields": fields,
            })
        } else {
            json!({
                "website": row.website, "name": row.name, "country": row.country,
                "affiliation": row.affiliation, "bracket_id": row.bracket_id,
                "id": row.id, "captain_id": row.captain_id, "fields": fields,
            })
        });
    }
    Ok(Json(json!({
        "meta": {"pagination": {
            "page": page,
            "next": (page < pages).then_some(page + 1),
            "prev": (page > 1 && page <= pages + 1).then_some(page - 1),
            "pages": pages, "per_page": per_page, "total": total,
        }},
        "success": true, "data": data,
    }))
    .into_response())
}

pub(super) async fn create(
    State(state): State<AppState>,
    admin: CurrentUser,
    Json(request): Json<CreateTeam>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    let name = validate_name(&request.name)?;
    let email = validate_email(&request.email)?;
    if request.password.is_empty() {
        return Err(ApiError::bad_request("Password must not be empty"));
    }
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &admin,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    reject_duplicate(&mut transaction, None, &name, &email).await?;
    validate_bracket(&mut transaction, request.bracket_id).await?;
    if request.captain_id.is_some() {
        return Err(ApiError::bad_request(
            "A new team cannot have a captain before it has members",
        ));
    }
    let password = hash_password(&mut transaction, &request.password)
        .await
        .map_err(ApiError::database)?;
    // Administrators may bypass the configured limit, but their inserts still
    // serialize with participant capacity checks so those checks see a stable
    // team count.
    lock_team_capacity(&mut transaction).await?;
    let record = sqlx::query_as::<_, TeamRecord>(
        r#"
        INSERT INTO ctfzone.teams (
            name, email, password, participant_token, website, affiliation,
            country, bracket_id, hidden, banned, captain_id, created
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
        RETURNING id,name,email,password,secret,website,affiliation,country,
                  bracket_id,hidden,banned,captain_id,created
        "#,
    )
    .bind(name)
    .bind(email)
    .bind(password)
    .bind(Uuid::new_v4().to_string())
    .bind(request.website)
    .bind(request.affiliation)
    .bind(request.country)
    .bind(request.bracket_id)
    .bind(request.hidden.unwrap_or(false))
    .bind(request.banned.unwrap_or(false))
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| {
        ApiError::conflict_or_database(error, "The team name or email is already in use")
    })?;
    if let Some(fields) = request.fields {
        update_fields(&mut transaction, record.id, &fields, true).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(
        serialize_team(&state, record, TeamView::Admin, false).await?,
    ))
    .into_response())
}

pub(super) async fn create_current(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<CreateCurrentTeam>,
) -> Result<Response, ApiError> {
    require_participant(&user)?;
    rate_limit_team_action(&state, &user, "team-create", 5, Duration::from_secs(60)).await?;
    let name = validate_name(&request.name)?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    lock_team_capacity(&mut transaction).await?;
    lock_team_membership(&mut transaction).await?;
    let current_team_id = lock_participant(&mut transaction, user.id).await?;
    if current_team_id.is_some() {
        return Err(ApiError::conflict("You have already joined a team"));
    }
    if !transaction_config_bool(&mut transaction, "team_creation", true).await? {
        return Err(ApiError::forbidden(
            "Participant team creation is currently disabled; join an existing team instead",
        ));
    }
    let maximum_teams = transaction_config_i64(&mut transaction, "num_teams", 0).await?;
    if maximum_teams > 0 {
        let active_teams = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ctfzone.teams WHERE NOT COALESCE(banned,false) AND NOT COALESCE(hidden,false)",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if active_teams >= maximum_teams {
            return Err(ApiError::conflict(format!(
                "The maximum number of teams ({maximum_teams}) has been reached"
            )));
        }
    }

    let record = sqlx::query_as::<_, TeamRecord>(
        r#"
        INSERT INTO ctfzone.teams (
            name,email,password,participant_token,hidden,banned,captain_id,created
        )
        VALUES ($1,NULL,NULL,$2,false,false,$3,CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
        RETURNING id,name,email,password,secret,website,affiliation,country,
                  bracket_id,hidden,banned,captain_id,created
        "#,
    )
    .bind(name)
    .bind(Uuid::new_v4().to_string())
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| ApiError::conflict_or_database(error, "The team name is already in use"))?;
    let assigned = sqlx::query(
        "UPDATE ctfzone.users SET team_id=$1 WHERE id=$2 AND team_id IS NULL AND type='user'",
    )
    .bind(record.id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if assigned.rows_affected() != 1 {
        return Err(ApiError::conflict("You have already joined a team"));
    }
    transaction.commit().await.map_err(ApiError::database)?;

    let response = Json(Success::new(
        serialize_team(&state, record, TeamView::SelfView, true).await?,
    ));
    Ok((StatusCode::CREATED, response).into_response())
}

pub(super) async fn join_current(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<JoinCurrentTeam>,
) -> Result<Response, ApiError> {
    require_participant(&user)?;
    rate_limit_team_action(&state, &user, "team-join", 10, Duration::from_secs(5)).await?;
    let invite = verify_invite_envelope(&state, &request.code)?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    lock_team_membership(&mut transaction).await?;
    let current_team_id = lock_participant(&mut transaction, user.id).await?;
    if current_team_id.is_some() {
        return Err(ApiError::conflict("You have already joined a team"));
    }
    let record = load_team_for_update(&mut transaction, invite.team_id)
        .await?
        .ok_or_else(invalid_team_invite)?;
    if record.banned.unwrap_or(false) {
        return Err(invalid_team_invite());
    }
    verify_team_invite(&state, &record, &invite.team_verification)?;

    let maximum_members = transaction_config_i64(&mut transaction, "team_size", 0).await?;
    if maximum_members > 0 {
        let member_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ctfzone.users WHERE team_id=$1")
                .bind(record.id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(ApiError::database)?;
        if member_count >= maximum_members {
            return Err(ApiError::conflict(format!(
                "This team has reached its maximum size of {maximum_members}"
            )));
        }
    }
    let assigned = sqlx::query(
        "UPDATE ctfzone.users SET team_id=$1 WHERE id=$2 AND team_id IS NULL AND type='user'",
    )
    .bind(record.id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if assigned.rows_affected() != 1 {
        return Err(ApiError::conflict("You have already joined a team"));
    }
    transaction.commit().await.map_err(ApiError::database)?;

    Ok(Json(Success::new(
        serialize_team(&state, record, TeamView::SelfView, true).await?,
    ))
    .into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_account_visibility(&state, current.as_ref()).await?;
    let record = load_team(&state, team_id).await?;
    let is_admin = current.as_ref().is_some_and(CurrentUser::is_admin);
    if !is_admin && (record.hidden.unwrap_or(false) || record.banned.unwrap_or(false)) {
        return Err(ApiError::not_found("Team not found"));
    }
    let scores = scores_visible(&state, current.as_ref()).await?;
    Ok(Json(Success::new(
        serialize_team(
            &state,
            record,
            if is_admin {
                TeamView::Admin
            } else {
                TeamView::Public
            },
            scores,
        )
        .await?,
    ))
    .into_response())
}

pub(super) async fn current(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    let team_id = user
        .team_id
        .ok_or_else(|| ApiError::forbidden("You are not a member of a team"))?;
    let record = load_team(&state, team_id).await?;
    Ok(Json(Success::new(
        serialize_team(&state, record, TeamView::SelfView, true).await?,
    ))
    .into_response())
}

pub(super) async fn update_admin(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(team_id): Path<i32>,
    Json(request): Json<PatchTeam>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    update(&state, &admin, team_id, request, true).await
}

pub(super) async fn update_current(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(mut request): Json<PatchTeam>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    let team_id = user
        .team_id
        .ok_or_else(|| ApiError::forbidden("You are not a member of a team"))?;
    request.hidden = None;
    request.banned = None;
    update(&state, &user, team_id, request, false).await
}

pub(super) async fn delete_admin(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    delete_team(&state, &admin, team_id, None).await
}

pub(super) async fn delete_current(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    let team_id = user
        .team_id
        .ok_or_else(|| ApiError::forbidden("You are not a member of a team"))?;
    delete_team(&state, &user, team_id, Some(user.id)).await
}

pub(super) async fn list_members(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    load_team(&state, team_id).await?;
    Ok(Json(Success::new(members(&state, team_id).await?)).into_response())
}

pub(super) async fn add_member(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(team_id): Path<i32>,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    if body.is_empty() {
        let team = load_team(&state, team_id).await?;
        return Ok(Json(Success::new(json!({
            "code": invite_code(&state, &team)?,
        })))
        .into_response());
    }
    let request: MemberMutation = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("A valid user_id is required"))?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &admin,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    lock_team_membership(&mut transaction).await?;
    let participant = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
        "SELECT type,team_id FROM ctfzone.users WHERE id=$1 FOR UPDATE",
    )
    .bind(request.user_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("User not found"))?;
    if participant.0.as_deref() != Some("user") {
        return Err(ApiError::bad_request(
            "Only participant accounts can be team members",
        ));
    }
    if participant.1.is_some() {
        return Err(ApiError::conflict("User has already joined a team"));
    }
    load_team_for_update(&mut transaction, team_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))?;
    sqlx::query("UPDATE ctfzone.users SET team_id=$1 WHERE id=$2")
        .bind(team_id)
        .bind(request.user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(members(&state, team_id).await?)).into_response())
}

pub(super) async fn current_invite(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    rate_limit_team_action(&state, &user, "team-invite", 10, Duration::from_secs(60)).await?;
    let team_id = user
        .team_id
        .ok_or_else(|| ApiError::forbidden("You are not a member of a team"))?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    lock_team_membership(&mut transaction).await?;
    if lock_participant(&mut transaction, user.id).await? != Some(team_id) {
        return Err(ApiError::forbidden("You are not a member of this team"));
    }
    require_team_mode_in_transaction(&mut transaction).await?;
    let team = load_team_for_update(&mut transaction, team_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))?;
    if team.captain_id != Some(user.id) {
        return Err(ApiError::forbidden(
            "Only team captains can generate invite codes",
        ));
    }
    let code = invite_code(&state, &team)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({
        "code": code,
    })))
    .into_response())
}

pub(super) async fn remove_member(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(team_id): Path<i32>,
    Json(request): Json<MemberMutation>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_admin(&admin)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &admin,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    lock_team_membership(&mut transaction).await?;
    let member_team_id = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT team_id FROM ctfzone.users WHERE id=$1 FOR UPDATE",
    )
    .bind(request.user_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .flatten();
    load_team_for_update(&mut transaction, team_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))?;
    if member_team_id != Some(team_id) {
        return Err(ApiError::bad_request("User is not part of this team"));
    }
    sqlx::query("UPDATE ctfzone.users SET team_id = NULL WHERE id = $1")
        .bind(request.user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    sqlx::query("UPDATE ctfzone.teams SET captain_id = NULL WHERE id = $1 AND captain_id = $2")
        .bind(team_id)
        .bind(request.user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    for table in ["submissions", "awards", "unlocks"] {
        let statement = format!("DELETE FROM ctfzone.{table} WHERE user_id = $1");
        sqlx::query(&statement)
            .bind(request.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(members(&state, team_id).await?)).into_response())
}

async fn update(
    state: &AppState,
    actor: &CurrentUser,
    team_id: i32,
    request: PatchTeam,
    admin: bool,
) -> Result<Response, ApiError> {
    let mut previous = load_team(state, team_id).await?;
    let name = request.name.as_deref().map(validate_name).transpose()?;
    let email = request.email.as_deref().map(validate_email).transpose()?;
    let mut name_changes_enabled = true;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        actor,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    if !admin {
        lock_team_membership(&mut transaction).await?;
        if lock_participant(&mut transaction, actor.id).await? != Some(team_id) {
            return Err(ApiError::forbidden("You are not a member of this team"));
        }
        let locked_team = load_team_for_update(&mut transaction, team_id)
            .await?
            .ok_or_else(|| ApiError::not_found("Team not found"))?;
        if locked_team.captain_id != Some(actor.id) {
            return Err(ApiError::forbidden(
                "Only team captains can edit team information",
            ));
        }
        previous = locked_team;
        name_changes_enabled =
            transaction_config_bool(&mut transaction, "name_changes", true).await?;
    }

    if !admin {
        if name.as_deref() != previous.name.as_deref() && name.is_some() && !name_changes_enabled {
            return Err(ApiError::forbidden("Name changes are disabled"));
        }
        if request.password.is_some() {
            let confirm = request
                .confirm
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("Please confirm your current password"))?;
            let team_valid = verify_password(
                &mut transaction,
                confirm,
                previous.password.as_deref().unwrap_or_default(),
            )
            .await
            .map_err(ApiError::database)?;
            let captain_password = sqlx::query_scalar::<_, Option<String>>(
                "SELECT password FROM ctfzone.users WHERE id = $1",
            )
            .bind(actor.id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .flatten();
            let captain_valid = if let Some(captain_password) = captain_password {
                verify_password(&mut transaction, confirm, &captain_password)
                    .await
                    .map_err(ApiError::database)?
            } else {
                false
            };
            if !team_valid && !captain_valid {
                return Err(ApiError::bad_request("Your previous password is incorrect"));
            }
        }
    }
    reject_duplicate(
        &mut transaction,
        Some(team_id),
        name.as_deref()
            .or(previous.name.as_deref())
            .unwrap_or_default(),
        email
            .as_deref()
            .or(previous.email.as_deref())
            .unwrap_or_default(),
    )
    .await?;
    if let Some(bracket_id) = request.bracket_id {
        if !admin && previous.bracket_id.is_some() && bracket_id != previous.bracket_id {
            return Err(ApiError::forbidden(
                "Please contact an admin to change your bracket",
            ));
        }
        validate_bracket(&mut transaction, bracket_id).await?;
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
    if request.hidden.is_some() || request.banned.is_some() {
        // Visibility and ban changes alter the active-team capacity count.
        lock_team_capacity(&mut transaction).await?;
    }
    if request.captain_id.is_some() {
        // Captain selection depends on membership and must not race a join or
        // removal. Capacity is always acquired first when both are needed.
        lock_team_membership(&mut transaction).await?;
    }
    if let Some(Some(captain_id)) = request.captain_id {
        let member = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE id=$1 AND team_id=$2)",
        )
        .bind(captain_id)
        .bind(team_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if !member {
            return Err(ApiError::bad_request("Only team members can be captain"));
        }
    }
    let record = sqlx::query_as::<_, TeamRecord>(
        r#"
        UPDATE ctfzone.teams
        SET
            name = COALESCE($2, name),
            email = COALESCE($3, email),
            password = COALESCE($4, password),
            website = CASE WHEN $5 THEN $6 ELSE website END,
            affiliation = CASE WHEN $7 THEN $8 ELSE affiliation END,
            country = CASE WHEN $9 THEN $10 ELSE country END,
            bracket_id = CASE WHEN $11 THEN $12 ELSE bracket_id END,
            hidden = COALESCE($13, hidden),
            banned = COALESCE($14, banned),
            captain_id = CASE WHEN $15 THEN $16 ELSE captain_id END
        WHERE id = $1
        RETURNING id,name,email,password,secret,website,affiliation,country,
                  bracket_id,hidden,banned,captain_id,created
        "#,
    )
    .bind(team_id)
    .bind(name)
    .bind(email)
    .bind(password)
    .bind(request.website.is_some())
    .bind(request.website.flatten())
    .bind(request.affiliation.is_some())
    .bind(request.affiliation.flatten())
    .bind(request.country.is_some())
    .bind(request.country.flatten())
    .bind(request.bracket_id.is_some())
    .bind(request.bracket_id.flatten())
    .bind(request.hidden)
    .bind(request.banned)
    .bind(request.captain_id.is_some())
    .bind(request.captain_id.flatten())
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if let Some(fields) = request.fields {
        update_fields(&mut transaction, team_id, &fields, admin).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(
        serialize_team(
            state,
            record,
            if admin {
                TeamView::Admin
            } else {
                TeamView::SelfView
            },
            false,
        )
        .await?,
    ))
    .into_response())
}

async fn delete_team(
    state: &AppState,
    actor: &CurrentUser,
    team_id: i32,
    participant_actor: Option<i32>,
) -> Result<Response, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        actor,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    require_team_mode_in_transaction(&mut transaction).await?;
    lock_team_capacity(&mut transaction).await?;
    lock_team_membership(&mut transaction).await?;
    if let Some(actor_id) = participant_actor {
        let actor_team_id = lock_participant(&mut transaction, actor_id).await?;
        if actor_team_id != Some(team_id) {
            return Err(ApiError::forbidden("You are not a member of this team"));
        }
    }
    let team = load_team_for_update(&mut transaction, team_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))?;
    if let Some(actor_id) = participant_actor {
        if team.captain_id != Some(actor_id) {
            return Err(ApiError::forbidden(
                "Only team captains can disband their team",
            ));
        }
        if transaction_config_string(&mut transaction, "team_disbanding")
            .await?
            .as_deref()
            == Some("disabled")
        {
            return Err(ApiError::forbidden("Team disbanding is currently disabled"));
        }
        let performed_actions = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT
                EXISTS(SELECT 1 FROM ctfzone.submissions WHERE team_id=$1)
                OR EXISTS(SELECT 1 FROM ctfzone.awards WHERE team_id=$1)
                OR EXISTS(SELECT 1 FROM ctfzone.unlocks WHERE team_id=$1)
            "#,
        )
        .bind(team_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if performed_actions {
            return Err(ApiError::forbidden(
                "You cannot disband a team that has participated in the event",
            ));
        }
    }
    sqlx::query("UPDATE ctfzone.users SET team_id = NULL WHERE team_id = $1")
        .bind(team_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    let deleted = sqlx::query("DELETE FROM ctfzone.teams WHERE id = $1")
        .bind(team_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .rows_affected();
    transaction.commit().await.map_err(ApiError::database)?;
    debug_assert_eq!(deleted, 1);
    Ok(Json(json!({"success": true})).into_response())
}

async fn load_team(state: &AppState, team_id: i32) -> Result<TeamRecord, ApiError> {
    sqlx::query_as::<_, TeamRecord>(
        r#"
        SELECT id,name,email,password,secret,website,affiliation,country,
               bracket_id,hidden,banned,captain_id,created
        FROM ctfzone.teams WHERE id = $1
        "#,
    )
    .bind(team_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Team not found"))
}

async fn load_team_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    team_id: i32,
) -> Result<Option<TeamRecord>, ApiError> {
    sqlx::query_as::<_, TeamRecord>(
        r#"
        SELECT id,name,email,password,secret,website,affiliation,country,
               bracket_id,hidden,banned,captain_id,created
        FROM ctfzone.teams WHERE id=$1 FOR UPDATE
        "#,
    )
    .bind(team_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn rate_limit_team_action(
    state: &AppState,
    user: &CurrentUser,
    operation: &str,
    limit: u32,
    interval: Duration,
) -> Result<(), ApiError> {
    let user_subject = user.id.to_string();
    let user_allowed = state
        .rate_limiter
        .allow(operation, &user_subject, limit, interval)
        .await;
    let ip_operation = format!("{operation}-ip");
    let ip_allowed = state
        .rate_limiter
        .allow(
            &ip_operation,
            user.request_ip(),
            limit.saturating_mul(4),
            interval,
        )
        .await;
    if user_allowed && ip_allowed {
        Ok(())
    } else {
        Err(ApiError::too_many_requests(
            "Too many team requests; try again shortly",
        ))
    }
}

pub(super) async fn lock_configuration_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    super::user_mode_transition::lock_configuration_shared(transaction).await
}

async fn lock_team_capacity(transaction: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(TEAM_CAPACITY_LOCK)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(ApiError::database)
}

pub(super) async fn lock_team_membership(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(TEAM_MEMBERSHIP_LOCK)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(ApiError::database)
}

async fn lock_participant(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
) -> Result<Option<i32>, ApiError> {
    let row = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
        "SELECT type,team_id FROM ctfzone.users WHERE id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::unauthorized("The authenticated account no longer exists"))?;
    if row.0.as_deref() != Some("user") {
        return Err(ApiError::forbidden(
            "Only participant accounts can create or join teams",
        ));
    }
    Ok(row.1)
}

async fn transaction_config_string(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key=$1 ORDER BY id LIMIT 1",
    )
    .bind(key)
    .fetch_optional(&mut **transaction)
    .await
    .map(|value| value.flatten())
    .map_err(ApiError::database)
}

async fn transaction_config_bool(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    default: bool,
) -> Result<bool, ApiError> {
    Ok(transaction_config_string(transaction, key)
        .await?
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default))
}

async fn transaction_config_i64(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    default: i64,
) -> Result<i64, ApiError> {
    Ok(transaction_config_string(transaction, key)
        .await?
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .unwrap_or(default))
}

async fn require_team_mode_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    if super::user_mode_transition::transaction_user_mode(transaction).await? == "teams" {
        Ok(())
    } else {
        Err(ApiError::not_found("Team mode is disabled"))
    }
}

fn verify_invite_envelope(state: &AppState, code: &str) -> Result<VerifiedInvite, ApiError> {
    verify_invite_envelope_at(&state.auth.secret_key, code, chrono::Utc::now().timestamp())
}

fn verify_invite_envelope_at(
    secret_key: &str,
    code: &str,
    now: i64,
) -> Result<VerifiedInvite, ApiError> {
    let code = code.trim();
    if code.is_empty() || code.len() > TEAM_INVITE_MAX_LENGTH {
        return Err(invalid_team_invite());
    }
    let mut parts = code.split('.');
    let (Some(payload), Some(timestamp), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid_team_invite());
    };
    let supplied_signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| invalid_team_invite())?;
    let mut outer_signature = HmacSha1::new_from_slice(&invite_signing_key(secret_key))
        .map_err(|_| invalid_team_invite())?;
    outer_signature.update(format!("{payload}.{timestamp}").as_bytes());
    outer_signature
        .verify_slice(&supplied_signature)
        .map_err(|_| invalid_team_invite())?;

    let timestamp_bytes = URL_SAFE_NO_PAD
        .decode(timestamp)
        .map_err(|_| invalid_team_invite())?;
    if timestamp_bytes.is_empty() || timestamp_bytes.len() > 8 {
        return Err(invalid_team_invite());
    }
    let mut padded_timestamp = [0_u8; 8];
    padded_timestamp[8 - timestamp_bytes.len()..].copy_from_slice(&timestamp_bytes);
    let issued_at =
        i64::try_from(u64::from_be_bytes(padded_timestamp)).map_err(|_| invalid_team_invite())?;
    if issued_at > now || now.saturating_sub(issued_at) > TEAM_INVITE_MAX_AGE_SECONDS {
        return Err(invalid_team_invite());
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_team_invite())?;
    let payload: InvitePayload =
        serde_json::from_slice(&payload).map_err(|_| invalid_team_invite())?;
    if payload.id <= 0 {
        return Err(invalid_team_invite());
    }
    let team_verification = hex::decode(payload.v).map_err(|_| invalid_team_invite())?;
    if team_verification.len() != 20 {
        return Err(invalid_team_invite());
    }
    Ok(VerifiedInvite {
        team_id: payload.id,
        team_verification,
    })
}

fn invite_signing_key(secret_key: &str) -> Vec<u8> {
    let mut derived_key = Sha1::new();
    derived_key.update(b"itsdangerous");
    derived_key.update(b"signer");
    derived_key.update(secret_key.as_bytes());
    derived_key.finalize().to_vec()
}

fn verify_team_invite(
    state: &AppState,
    team: &TeamRecord,
    supplied_verification: &[u8],
) -> Result<(), ApiError> {
    verify_team_invite_with_secret(&state.auth.secret_key, team, supplied_verification)
}

fn verify_team_invite_with_secret(
    secret_key: &str,
    team: &TeamRecord,
    supplied_verification: &[u8],
) -> Result<(), ApiError> {
    let mut verification_secret = secret_key.as_bytes().to_vec();
    if let Some(password) = &team.password {
        verification_secret.extend_from_slice(password.as_bytes());
    }
    let mut verification =
        HmacSha1::new_from_slice(&verification_secret).map_err(|_| invalid_team_invite())?;
    verification.update(team.id.to_string().as_bytes());
    verification
        .verify_slice(supplied_verification)
        .map_err(|_| invalid_team_invite())
}

fn invalid_team_invite() -> ApiError {
    ApiError::bad_request("The team invite is invalid or has expired")
}

fn invite_code(state: &AppState, team: &TeamRecord) -> Result<String, ApiError> {
    invite_code_at(&state.auth.secret_key, team, chrono::Utc::now().timestamp())
}

fn invite_code_at(secret_key: &str, team: &TeamRecord, timestamp: i64) -> Result<String, ApiError> {
    let mut verification_secret = secret_key.as_bytes().to_vec();
    if let Some(password) = &team.password {
        verification_secret.extend_from_slice(password.as_bytes());
    }
    let mut verification = HmacSha1::new_from_slice(&verification_secret)
        .map_err(|_| ApiError::bad_request("Unable to create an invite code"))?;
    verification.update(team.id.to_string().as_bytes());
    let verification = hex::encode(verification.finalize().into_bytes());
    let payload = serde_json::to_vec(&json!({"id": team.id, "v": verification}))
        .map_err(|_| ApiError::bad_request("Unable to create an invite code"))?;
    let payload = URL_SAFE_NO_PAD.encode(payload);

    let timestamp = u64::try_from(timestamp)
        .map_err(|_| ApiError::bad_request("Unable to create an invite code"))?;
    let timestamp_bytes = timestamp.to_be_bytes();
    let first_nonzero = timestamp_bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(timestamp_bytes.len() - 1);
    let timestamp = URL_SAFE_NO_PAD.encode(&timestamp_bytes[first_nonzero..]);
    let unsigned = format!("{payload}.{timestamp}");

    let mut signature = HmacSha1::new_from_slice(&invite_signing_key(secret_key))
        .map_err(|_| ApiError::bad_request("Unable to create an invite code"))?;
    signature.update(unsigned.as_bytes());
    Ok(format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(signature.finalize().into_bytes())
    ))
}

async fn serialize_team(
    state: &AppState,
    team: TeamRecord,
    view: TeamView,
    include_scores: bool,
) -> Result<Value, ApiError> {
    let fields = fields_for_team(state, team.id, view).await?;
    let members = members(state, team.id).await?;
    let mut data = match view {
        TeamView::Public => json!({
            "website": team.website, "name": team.name, "country": team.country,
            "affiliation": team.affiliation, "bracket_id": team.bracket_id,
            "members": members, "id": team.id, "captain_id": team.captain_id,
            "fields": fields,
        }),
        TeamView::SelfView => json!({
            "website": team.website, "name": team.name, "email": team.email,
            "country": team.country, "affiliation": team.affiliation,
            "bracket_id": team.bracket_id, "members": members, "id": team.id,
            "captain_id": team.captain_id, "fields": fields,
        }),
        TeamView::Admin => json!({
            "website": team.website, "name": team.name, "created": team.created,
            "country": team.country, "banned": team.banned, "email": team.email,
            "affiliation": team.affiliation, "secret": team.secret,
            "bracket_id": team.bracket_id, "members": members, "hidden": team.hidden,
            "id": team.id, "captain_id": team.captain_id, "fields": fields,
        }),
    };
    if include_scores {
        let (score, place) =
            score_and_place(state, team.id, matches!(view, TeamView::SelfView)).await?;
        data["score"] = json!(score);
        data["place"] = json!(place);
    } else if matches!(view, TeamView::Public | TeamView::Admin) {
        data["score"] = Value::Null;
        data["place"] = Value::Null;
    }
    Ok(data)
}

async fn members(state: &AppState, team_id: i32) -> Result<Vec<Member>, ApiError> {
    sqlx::query_as::<_, Member>("SELECT id, name FROM ctfzone.users WHERE team_id = $1 ORDER BY id")
        .bind(team_id)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)
}

async fn fields_for_team(
    state: &AppState,
    team_id: i32,
    view: TeamView,
) -> Result<Vec<FieldEntry>, ApiError> {
    sqlx::query_as::<_, FieldEntry>(
        r#"
        SELECT field_entries.field_id,field_entries.value,fields.name,
               fields.description,fields.field_type
        FROM ctfzone.field_entries
        JOIN ctfzone.fields ON fields.id = field_entries.field_id
        WHERE field_entries.team_id = $1
          AND ($2 = 'admin'
            OR ($2 = 'self' AND (COALESCE(fields.editable,false) OR COALESCE(fields.public,false)))
            OR ($2 = 'public' AND COALESCE(fields.public,false)))
        ORDER BY field_entries.id
        "#,
    )
    .bind(team_id)
    .bind(match view {
        TeamView::Public => "public",
        TeamView::SelfView => "self",
        TeamView::Admin => "admin",
    })
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn fields_for_teams(
    state: &AppState,
    team_ids: &[i32],
    view: TeamView,
) -> Result<HashMap<i32, Vec<FieldEntry>>, ApiError> {
    if team_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, TeamFieldEntry>(
        r#"
        SELECT field_entries.team_id,field_entries.field_id,field_entries.value,
               fields.name,fields.description,fields.field_type
        FROM ctfzone.field_entries
        JOIN ctfzone.fields ON fields.id=field_entries.field_id
        WHERE field_entries.team_id=ANY($1)
          AND ($2='admin'
            OR ($2='self' AND (COALESCE(fields.editable,false) OR COALESCE(fields.public,false)))
            OR ($2='public' AND COALESCE(fields.public,false)))
        ORDER BY field_entries.team_id,field_entries.id
        "#,
    )
    .bind(team_ids)
    .bind(match view {
        TeamView::Public => "public",
        TeamView::SelfView => "self",
        TeamView::Admin => "admin",
    })
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut grouped = HashMap::<i32, Vec<FieldEntry>>::new();
    for row in rows {
        grouped.entry(row.team_id).or_default().push(FieldEntry {
            field_id: row.field_id,
            value: row.value,
            name: row.name,
            description: row.description,
            field_type: row.field_type,
        });
    }
    Ok(grouped)
}

async fn update_fields(
    transaction: &mut Transaction<'_, Postgres>,
    team_id: i32,
    fields: &[FieldInput],
    admin: bool,
) -> Result<(), ApiError> {
    let mut provided = HashSet::new();
    for input in fields {
        if !provided.insert(input.field_id) {
            return Err(ApiError::bad_request("A field was provided more than once"));
        }
        let field = sqlx::query_as::<_, (bool, bool)>(
            "SELECT COALESCE(required,false),COALESCE(editable,false) FROM ctfzone.fields WHERE id=$1 AND type='team'",
        )
        .bind(input.field_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::bad_request("A team field does not exist"))?;
        let existing = sqlx::query_scalar::<_, i32>(
            "SELECT id FROM ctfzone.field_entries WHERE team_id=$1 AND field_id=$2 LIMIT 1",
        )
        .bind(team_id)
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
            sqlx::query("UPDATE ctfzone.field_entries SET value=$1 WHERE id=$2")
                .bind(&input.value)
                .bind(entry_id)
                .execute(&mut **transaction)
                .await
                .map_err(ApiError::database)?;
        } else {
            sqlx::query("INSERT INTO ctfzone.field_entries (type,value,field_id,team_id) VALUES ('team',$1,$2,$3)")
                .bind(&input.value)
                .bind(input.field_id)
                .bind(team_id)
                .execute(&mut **transaction)
                .await
                .map_err(ApiError::database)?;
        }
    }
    Ok(())
}

async fn reject_duplicate(
    transaction: &mut Transaction<'_, Postgres>,
    team_id: Option<i32>,
    name: &str,
    email: &str,
) -> Result<(), ApiError> {
    let duplicate = sqlx::query_as::<_, (bool, bool)>(
        r#"
        SELECT
          EXISTS(SELECT 1 FROM ctfzone.teams WHERE name=$1 AND ($3::int IS NULL OR id<>$3)),
          EXISTS(SELECT 1 FROM ctfzone.teams WHERE lower(email)=lower($2) AND ($3::int IS NULL OR id<>$3))
        "#,
    )
    .bind(name).bind(email).bind(team_id)
    .fetch_one(&mut **transaction).await.map_err(ApiError::database)?;
    if duplicate.0 {
        return Err(ApiError::conflict("Team name has already been taken"));
    }
    if duplicate.1 {
        return Err(ApiError::conflict("Email address has already been used"));
    }
    Ok(())
}

async fn validate_bracket(
    transaction: &mut Transaction<'_, Postgres>,
    bracket_id: Option<i32>,
) -> Result<(), ApiError> {
    let Some(bracket_id) = bracket_id else {
        return Ok(());
    };
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.brackets WHERE id=$1 AND type='teams')",
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

async fn score_and_place(
    state: &AppState,
    team_id: i32,
    current_team: bool,
) -> Result<(i64, Option<String>), ApiError> {
    let freeze = config_string(state, "freeze")
        .await?
        .and_then(|value| value.parse::<i64>().ok());
    let score_freeze = if current_team { None } else { freeze };
    let score = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE((
          SELECT SUM(challenges.value)::bigint FROM ctfzone.solves
          JOIN ctfzone.challenges ON challenges.id=solves.challenge_id
          JOIN ctfzone.submissions ON submissions.id=solves.id
          WHERE solves.team_id=$1 AND ($2::bigint IS NULL OR submissions.date < (to_timestamp($2::double precision) AT TIME ZONE 'UTC'))
        ),0) + COALESCE((
          SELECT SUM(awards.value)::bigint FROM ctfzone.awards
          WHERE awards.team_id=$1 AND ($2::bigint IS NULL OR awards.date < (to_timestamp($2::double precision) AT TIME ZONE 'UTC'))
        ),0)
        "#,
    )
    .bind(team_id).bind(score_freeze).fetch_one(&state.database).await.map_err(ApiError::database)?;
    let place = sqlx::query_scalar::<_, i64>(
        r#"
        WITH events AS (
          SELECT solves.team_id account_id,SUM(challenges.value)::bigint score,
                 MAX(solves.id) event_id,MAX(submissions.date) event_date
          FROM ctfzone.solves JOIN ctfzone.challenges ON challenges.id=solves.challenge_id
          JOIN ctfzone.submissions ON submissions.id=solves.id
          WHERE solves.team_id IS NOT NULL AND challenges.value<>0
            AND ($1::bigint IS NULL OR submissions.date < (to_timestamp($1::double precision) AT TIME ZONE 'UTC'))
          GROUP BY solves.team_id
          UNION ALL
          SELECT awards.team_id,SUM(awards.value)::bigint,MAX(awards.id),MAX(awards.date)
          FROM ctfzone.awards WHERE awards.team_id IS NOT NULL AND awards.value<>0
            AND ($1::bigint IS NULL OR awards.date < (to_timestamp($1::double precision) AT TIME ZONE 'UTC'))
          GROUP BY awards.team_id
        ), totals AS (
          SELECT account_id,SUM(score)::bigint score,MAX(event_id) event_id,MAX(event_date) event_date
          FROM events GROUP BY account_id
        ), ranked AS (
          SELECT teams.id,ROW_NUMBER() OVER (ORDER BY totals.score DESC,totals.event_date ASC,totals.event_id ASC) place
          FROM totals JOIN ctfzone.teams ON teams.id=totals.account_id
          WHERE COALESCE(teams.banned,false)=false AND COALESCE(teams.hidden,false)=false
        ) SELECT place FROM ranked WHERE id=$2
        "#,
    )
    .bind(freeze).bind(team_id).fetch_optional(&state.database).await.map_err(ApiError::database)?;
    Ok((score, place.map(super::users::ordinalize)))
}

async fn require_team_mode(state: &AppState) -> Result<(), ApiError> {
    if config_string(state, "user_mode").await?.as_deref() == Some("teams") {
        Ok(())
    } else {
        Err(ApiError::not_found("Team mode is disabled"))
    }
}

async fn require_account_visibility(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    match config_string(state, "account_visibility")
        .await?
        .as_deref()
        .unwrap_or("public")
    {
        "public" => Ok(()),
        "private" if user.is_some() => Ok(()),
        "private" => Err(ApiError::forbidden("Authentication required")),
        "admins" if user.is_some_and(CurrentUser::is_admin) => Ok(()),
        "admins" => Err(ApiError::not_found("Accounts are not available")),
        _ => Ok(()),
    }
}

async fn scores_visible(state: &AppState, user: Option<&CurrentUser>) -> Result<bool, ApiError> {
    Ok(
        match config_string(state, "score_visibility")
            .await?
            .as_deref()
            .unwrap_or("public")
        {
            "public" => true,
            "private" => user.is_some(),
            "admins" => user.is_some_and(CurrentUser::is_admin),
            "hidden" => false,
            _ => true,
        },
    )
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1 LIMIT 1")
        .bind(key)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)
        .map(Option::flatten)
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

fn require_participant(user: &CurrentUser) -> Result<(), ApiError> {
    if user.user_type == "user" {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "Only participant accounts can create or join teams",
        ))
    }
}

fn validate_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        Err(ApiError::bad_request(
            "Team names must contain 1 to 128 printable characters",
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn validate_email(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.len() <= 128
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
    {
        Ok(value.to_owned())
    } else {
        Err(ApiError::bad_request(
            "Emails must be a properly formatted email address",
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const TEST_TIME: i64 = 1_700_000_000;

    fn team(password: Option<&str>) -> TeamRecord {
        TeamRecord {
            id: 42,
            name: Some("Blue Team".to_owned()),
            email: None,
            password: password.map(str::to_owned),
            secret: None,
            website: None,
            affiliation: None,
            country: None,
            bracket_id: None,
            hidden: Some(false),
            banned: Some(false),
            captain_id: Some(7),
            created: None,
        }
    }

    #[test]
    fn invite_round_trip_preserves_team_and_verification() {
        let team = team(Some("stored-password-hash"));
        let code = invite_code_at(TEST_SECRET, &team, TEST_TIME).expect("invite code");
        let verified =
            verify_invite_envelope_at(TEST_SECRET, &code, TEST_TIME + 60).expect("valid envelope");
        assert_eq!(verified.team_id, team.id);
        assert!(
            verify_team_invite_with_secret(TEST_SECRET, &team, &verified.team_verification).is_ok()
        );
    }

    #[test]
    fn invite_rejects_tampering_and_wrong_team_password() {
        let original = team(Some("old-password-hash"));
        let code = invite_code_at(TEST_SECRET, &original, TEST_TIME).expect("invite code");
        let replacement = if code.starts_with('A') { 'B' } else { 'A' };
        let tampered = format!("{replacement}{}", &code[1..]);
        assert!(verify_invite_envelope_at(TEST_SECRET, &tampered, TEST_TIME).is_err());

        let verified =
            verify_invite_envelope_at(TEST_SECRET, &code, TEST_TIME).expect("valid envelope");
        let changed = team(Some("new-password-hash"));
        assert!(
            verify_team_invite_with_secret(TEST_SECRET, &changed, &verified.team_verification)
                .is_err()
        );
    }

    #[test]
    fn invite_enforces_issuance_window_and_input_bounds() {
        let code = invite_code_at(TEST_SECRET, &team(None), TEST_TIME).expect("invite code");
        assert!(verify_invite_envelope_at(TEST_SECRET, &code, TEST_TIME - 1).is_err());
        assert!(
            verify_invite_envelope_at(
                TEST_SECRET,
                &code,
                TEST_TIME + TEAM_INVITE_MAX_AGE_SECONDS + 1,
            )
            .is_err()
        );
        assert!(verify_invite_envelope_at(TEST_SECRET, "not-an-invite", TEST_TIME).is_err());
        assert!(
            verify_invite_envelope_at(
                TEST_SECRET,
                &"x".repeat(TEAM_INVITE_MAX_LENGTH + 1),
                TEST_TIME,
            )
            .is_err()
        );
    }

    #[test]
    fn team_name_rejects_controls_and_enforces_length() {
        assert_eq!(validate_name("  Blue Team  ").unwrap(), "Blue Team");
        assert!(validate_name("").is_err());
        assert!(validate_name("Blue\nTeam").is_err());
        assert!(validate_name(&"x".repeat(129)).is_err());
    }
}
