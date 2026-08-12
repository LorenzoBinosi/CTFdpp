use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
};

#[derive(Deserialize, Default)]
pub(super) struct SubmissionQuery {
    challenge_id: Option<i32>,
}

#[derive(Clone, Copy)]
enum Account {
    User(i32),
    Team(i32),
}

#[derive(Clone, Copy)]
enum SubmissionKind {
    All,
    Solves,
    Fails,
}

#[derive(FromRow, Serialize)]
struct SubmissionRow {
    id: i32,
    challenge_id: Option<i32>,
    #[serde(rename = "type")]
    submission_type: Option<String>,
    date: Option<NaiveDateTime>,
    provided: Option<String>,
    ip: Option<String>,
    challenge_name: Option<String>,
    challenge_category: Option<String>,
    challenge_value: Option<i32>,
    user_id: Option<i32>,
    user_name: Option<String>,
    team_id: Option<i32>,
    team_name: Option<String>,
}

#[derive(FromRow, Serialize)]
struct AwardRow {
    id: i32,
    category: Option<String>,
    user_id: Option<i32>,
    team_id: Option<i32>,
    name: Option<String>,
    description: Option<String>,
    value: Option<i32>,
    date: Option<NaiveDateTime>,
    requirements: Option<Value>,
    icon: Option<String>,
}

pub(super) async fn user_me_submissions(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<SubmissionQuery>,
) -> Result<Response, ApiError> {
    if !config_bool(&state, "view_self_submissions", false).await? {
        return Err(ApiError::forbidden("Viewing your submissions is disabled"));
    }
    submissions_response(
        &state,
        Account::User(user.id),
        SubmissionKind::All,
        query.challenge_id,
        true,
        user.is_admin(),
        false,
    )
    .await
}

pub(super) async fn user_me_solves(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    submissions_response(
        &state,
        Account::User(user.id),
        SubmissionKind::Solves,
        None,
        false,
        user.is_admin(),
        false,
    )
    .await
}

pub(super) async fn user_me_fails(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    submissions_response(
        &state,
        Account::User(user.id),
        SubmissionKind::Fails,
        None,
        false,
        user.is_admin(),
        false,
    )
    .await
}

pub(super) async fn user_me_awards(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    awards_response(&state, Account::User(user.id), true, user.is_admin()).await
}

pub(super) async fn user_solves(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Response, ApiError> {
    public_submission_response(
        &state,
        current.as_ref(),
        Account::User(user_id),
        SubmissionKind::Solves,
    )
    .await
}

pub(super) async fn user_fails(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Response, ApiError> {
    public_submission_response(
        &state,
        current.as_ref(),
        Account::User(user_id),
        SubmissionKind::Fails,
    )
    .await
}

pub(super) async fn user_awards(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_public_account_access(&state, current.as_ref(), Account::User(user_id)).await?;
    require_score_visibility(&state, current.as_ref()).await?;
    awards_response(
        &state,
        Account::User(user_id),
        false,
        current.as_ref().is_some_and(CurrentUser::is_admin),
    )
    .await
}

pub(super) async fn team_me_solves(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    let team_id = require_team(&user)?;
    submissions_response(
        &state,
        Account::Team(team_id),
        SubmissionKind::Solves,
        None,
        false,
        user.is_admin(),
        false,
    )
    .await
}

pub(super) async fn team_me_fails(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    let team_id = require_team(&user)?;
    submissions_response(
        &state,
        Account::Team(team_id),
        SubmissionKind::Fails,
        None,
        false,
        user.is_admin(),
        false,
    )
    .await
}

pub(super) async fn team_me_awards(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    awards_response(
        &state,
        Account::Team(require_team(&user)?),
        true,
        user.is_admin(),
    )
    .await
}

pub(super) async fn team_solves(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    public_submission_response(
        &state,
        current.as_ref(),
        Account::Team(team_id),
        SubmissionKind::Solves,
    )
    .await
}

pub(super) async fn team_fails(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    public_submission_response(
        &state,
        current.as_ref(),
        Account::Team(team_id),
        SubmissionKind::Fails,
    )
    .await
}

pub(super) async fn team_awards(
    State(state): State<AppState>,
    OptionalCurrentUser(current): OptionalCurrentUser,
    Path(team_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_team_mode(&state).await?;
    require_public_account_access(&state, current.as_ref(), Account::Team(team_id)).await?;
    require_score_visibility(&state, current.as_ref()).await?;
    awards_response(
        &state,
        Account::Team(team_id),
        false,
        current.as_ref().is_some_and(CurrentUser::is_admin),
    )
    .await
}

async fn public_submission_response(
    state: &AppState,
    current: Option<&CurrentUser>,
    account: Account,
    kind: SubmissionKind,
) -> Result<Response, ApiError> {
    require_public_account_access(state, current, account).await?;
    require_score_visibility(state, current).await?;
    submissions_response(
        state,
        account,
        kind,
        None,
        false,
        current.is_some_and(CurrentUser::is_admin),
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn submissions_response(
    state: &AppState,
    account: Account,
    kind: SubmissionKind,
    challenge_id: Option<i32>,
    self_view: bool,
    admin: bool,
    apply_freeze: bool,
) -> Result<Response, ApiError> {
    let (user_id, team_id) = match account {
        Account::User(id) => (Some(id), None),
        Account::Team(id) => (None, Some(id)),
    };
    let kind_value = match kind {
        SubmissionKind::All => None,
        SubmissionKind::Solves => Some("correct"),
        SubmissionKind::Fails => Some("incorrect"),
    };
    let freeze = if apply_freeze && !admin {
        config_string(state, "freeze")
            .await?
            .and_then(|value| value.parse::<i64>().ok())
    } else {
        None
    };
    let rows = sqlx::query_as::<_, SubmissionRow>(
        r#"
        SELECT
            submissions.id,
            submissions.challenge_id,
            submissions.type AS submission_type,
            submissions.date,
            submissions.provided,
            submissions.ip,
            challenges.name AS challenge_name,
            challenges.category AS challenge_category,
            challenges.value AS challenge_value,
            submissions.user_id,
            users.name AS user_name,
            submissions.team_id,
            teams.name AS team_name
        FROM ctfzone.submissions
        LEFT JOIN ctfzone.challenges ON challenges.id = submissions.challenge_id
        LEFT JOIN ctfzone.users ON users.id = submissions.user_id
        LEFT JOIN ctfzone.teams ON teams.id = submissions.team_id
        WHERE ($1::int IS NULL OR submissions.user_id = $1)
          AND ($2::int IS NULL OR submissions.team_id = $2)
          AND ($3::text IS NULL OR submissions.type = $3)
          AND ($4::int IS NULL OR submissions.challenge_id = $4)
          AND ($5::bigint IS NULL OR submissions.date < (to_timestamp($5::double precision) AT TIME ZONE 'UTC'))
        ORDER BY submissions.date DESC NULLS LAST, submissions.id DESC
        "#,
    )
    .bind(user_id)
    .bind(team_id)
    .bind(kind_value)
    .bind(challenge_id)
    .bind(freeze)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;

    let count = rows.len();
    let hide_fail_details = matches!(kind, SubmissionKind::Fails) && !admin;
    let data = if hide_fail_details {
        Vec::new()
    } else {
        rows.into_iter()
            .map(|row| serialize_submission(row, self_view, admin))
            .collect()
    };
    Ok(Json(json!({
        "success": true,
        "data": data,
        "meta": {"count": count},
    }))
    .into_response())
}

fn serialize_submission(row: SubmissionRow, self_view: bool, admin: bool) -> Value {
    let mut data = json!({
        "challenge_id": row.challenge_id,
        "challenge": {
            "id": row.challenge_id,
            "name": row.challenge_name,
            "category": row.challenge_category,
            "value": row.challenge_value,
        },
        "user": row.user_id.map(|id| json!({"id": id, "name": row.user_name})),
        "team": row.team_id.map(|id| json!({"id": id, "name": row.team_name})),
        "date": row.date,
        "type": row.submission_type,
        "id": row.id,
    });
    if self_view || admin {
        data["provided"] = json!(row.provided);
    }
    if admin {
        data["ip"] = json!(row.ip);
    }
    data
}

async fn awards_response(
    state: &AppState,
    account: Account,
    current_account: bool,
    admin: bool,
) -> Result<Response, ApiError> {
    let (user_id, team_id) = match account {
        Account::User(id) => (Some(id), None),
        Account::Team(id) => (None, Some(id)),
    };
    let freeze = if current_account || admin {
        None
    } else {
        config_string(state, "freeze")
            .await?
            .and_then(|value| value.parse::<i64>().ok())
    };
    let rows = sqlx::query_as::<_, AwardRow>(
        r#"
        SELECT id,category,user_id,team_id,name,description,value,date,requirements,icon
        FROM ctfzone.awards
        WHERE ($1::int IS NULL OR user_id = $1)
          AND ($2::int IS NULL OR team_id = $2)
          AND ($3::bigint IS NULL OR date < (to_timestamp($3::double precision) AT TIME ZONE 'UTC'))
        ORDER BY date DESC NULLS LAST, id DESC
        "#,
    )
    .bind(user_id)
    .bind(team_id)
    .bind(freeze)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let count = rows.len();
    let data: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let mut data = json!({
                "category": row.category, "user_id": row.user_id, "name": row.name,
                "description": row.description, "value": row.value, "team_id": row.team_id,
                "date": row.date, "id": row.id, "icon": row.icon,
            });
            if admin {
                data["requirements"] = json!(row.requirements);
            }
            data
        })
        .collect();
    Ok(Json(json!({"success": true, "data": data, "meta": {"count": count}})).into_response())
}

async fn require_public_account_access(
    state: &AppState,
    current: Option<&CurrentUser>,
    account: Account,
) -> Result<(), ApiError> {
    match config_string(state, "account_visibility")
        .await?
        .as_deref()
        .unwrap_or("public")
    {
        "private" if current.is_none() => {
            return Err(ApiError::forbidden("Authentication required"));
        }
        "admins" if !current.is_some_and(CurrentUser::is_admin) => {
            return Err(ApiError::not_found("Account not found"));
        }
        _ => {}
    }
    let (table, id) = match account {
        Account::User(id) => ("users", id),
        Account::Team(id) => ("teams", id),
    };
    let statement = format!(
        "SELECT COALESCE(banned,false),COALESCE(hidden,false) FROM ctfzone.{table} WHERE id=$1"
    );
    let flags = sqlx::query_as::<_, (bool, bool)>(&statement)
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Account not found"))?;
    if !current.is_some_and(CurrentUser::is_admin) && (flags.0 || flags.1) {
        return Err(ApiError::not_found("Account not found"));
    }
    Ok(())
}

async fn require_score_visibility(
    state: &AppState,
    current: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    match config_string(state, "score_visibility")
        .await?
        .as_deref()
        .unwrap_or("public")
    {
        "private" if current.is_none() => Err(ApiError::forbidden("Authentication required")),
        "hidden" if !current.is_some_and(CurrentUser::is_admin) => {
            Err(ApiError::forbidden("Scores are currently hidden"))
        }
        "admins" if !current.is_some_and(CurrentUser::is_admin) => {
            Err(ApiError::not_found("Scores are not available"))
        }
        _ => Ok(()),
    }
}

fn require_team(user: &CurrentUser) -> Result<i32, ApiError> {
    user.team_id
        .ok_or_else(|| ApiError::forbidden("You are not a member of a team"))
}

async fn require_team_mode(state: &AppState) -> Result<(), ApiError> {
    if config_string(state, "user_mode").await?.as_deref() == Some("teams") {
        Ok(())
    } else {
        Err(ApiError::not_found("Team mode is disabled"))
    }
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1 LIMIT 1")
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
