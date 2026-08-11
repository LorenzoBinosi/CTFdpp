use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, NaiveDateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

#[derive(Clone, Copy)]
enum Account {
    User(i32),
    Team(i32),
}

#[derive(FromRow)]
struct ParticipantTokenRow {
    participant_token: String,
    participant_token_last_rotated: Option<NaiveDateTime>,
}

#[derive(Serialize)]
pub(super) struct ParticipantTokenData {
    value: String,
    last_rotated: Option<String>,
}

pub(super) async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Success<ParticipantTokenData>>, ApiError> {
    let account = current_account(&state, &user).await?;
    let token = load_token(&state, account).await?;
    Ok(Json(Success::new(serialize(token))))
}

pub(super) async fn rotate(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    let account = current_account(&state, &user).await?;
    if let Account::Team(team_id) = account {
        let captain_id = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT captain_id FROM ctfzone.teams WHERE id = $1",
        )
        .bind(team_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .flatten();
        if captain_id != Some(user.id) {
            return Err(ApiError::forbidden(
                "Only the team captain can rotate the team token",
            ));
        }
    }

    let value = Uuid::new_v4().to_string();
    let cutoff = Utc::now().naive_utc() - Duration::minutes(1);
    let rotated = match account {
        Account::User(user_id) => sqlx::query_as::<_, ParticipantTokenRow>(
            r#"
                UPDATE ctfzone.users
                SET participant_token = $1,
                    participant_token_last_rotated = CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
                WHERE id = $2
                  AND (
                      participant_token_last_rotated IS NULL
                      OR participant_token_last_rotated <= $3
                  )
                RETURNING participant_token, participant_token_last_rotated
                "#,
        )
        .bind(&value)
        .bind(user_id)
        .bind(cutoff)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?,
        Account::Team(team_id) => sqlx::query_as::<_, ParticipantTokenRow>(
            r#"
                UPDATE ctfzone.teams
                SET participant_token = $1,
                    participant_token_last_rotated = CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
                WHERE id = $2
                  AND (
                      participant_token_last_rotated IS NULL
                      OR participant_token_last_rotated <= $3
                  )
                RETURNING participant_token, participant_token_last_rotated
                "#,
        )
        .bind(&value)
        .bind(team_id)
        .bind(cutoff)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?,
    };

    if let Some(rotated) = rotated {
        return Ok(Json(Success::new(serialize(rotated))).into_response());
    }

    let current = load_token(&state, account).await?;
    Ok((
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "success": false,
            "errors": {"": ["This token can only be rotated once per minute"]},
            "data": {
                "last_rotated": current.participant_token_last_rotated.map(utc_iso),
            },
        })),
    )
        .into_response())
}

async fn current_account(state: &AppState, user: &CurrentUser) -> Result<Account, ApiError> {
    let mode = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key = 'user_mode' LIMIT 1",
    )
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .flatten();

    if mode.as_deref() == Some("teams") {
        user.team_id
            .map(Account::Team)
            .ok_or_else(|| ApiError::forbidden("Join or create a team before using a team token"))
    } else {
        Ok(Account::User(user.id))
    }
}

async fn load_token(state: &AppState, account: Account) -> Result<ParticipantTokenRow, ApiError> {
    let token = match account {
        Account::User(user_id) => sqlx::query_as::<_, ParticipantTokenRow>(
            r#"
                SELECT participant_token, participant_token_last_rotated
                FROM ctfzone.users
                WHERE id = $1
                "#,
        )
        .bind(user_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?,
        Account::Team(team_id) => sqlx::query_as::<_, ParticipantTokenRow>(
            r#"
                SELECT participant_token, participant_token_last_rotated
                FROM ctfzone.teams
                WHERE id = $1
                "#,
        )
        .bind(team_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?,
    };
    token.ok_or_else(|| ApiError::not_found("Participant account not found"))
}

fn serialize(token: ParticipantTokenRow) -> ParticipantTokenData {
    ParticipantTokenData {
        value: token.participant_token,
        last_rotated: token.participant_token_last_rotated.map(utc_iso),
    }
}

fn utc_iso(value: NaiveDateTime) -> String {
    DateTime::<Utc>::from_naive_utc_and_offset(value, Utc)
        .to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
