use std::collections::HashMap;

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
    routes::Success,
};

#[derive(Deserialize, Default)]
pub(super) struct ScoreboardQuery {
    bracket_id: Option<i32>,
}

#[derive(Clone, FromRow, Serialize)]
pub(super) struct Standing {
    pub(super) account_id: i32,
    pub(super) name: Option<String>,
    pub(super) score: i64,
    pub(super) bracket_id: Option<i32>,
    pub(super) bracket_name: Option<String>,
}

#[derive(Clone, FromRow, Serialize)]
struct MemberScore {
    id: i32,
    name: Option<String>,
    score: i64,
    bracket_id: Option<i32>,
    bracket_name: Option<String>,
    team_id: i32,
}

#[derive(FromRow, Serialize)]
struct ScoreEvent {
    challenge_id: Option<i32>,
    account_id: i32,
    team_id: Option<i32>,
    user_id: Option<i32>,
    value: i32,
    date: NaiveDateTime,
}

pub(super) async fn list(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<ScoreboardQuery>,
) -> Result<Response, ApiError> {
    require_visible(&state, user.as_ref()).await?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let standings = load_standings(&state, team_mode, query.bracket_id, None, false).await?;
    let members = if team_mode {
        team_members(&state).await?
    } else {
        HashMap::new()
    };
    let data = standings
        .into_iter()
        .enumerate()
        .map(|(index, standing)| {
            let account_id = standing.account_id;
            let mut value = json!({
                "pos": index + 1,
                "account_id": account_id,
                "account_url": account_url(team_mode, account_id),
                "account_type": if team_mode { "team" } else { "user" },
                "name": standing.name,
                "score": standing.score,
                "bracket_id": standing.bracket_id,
                "bracket_name": standing.bracket_name,
            });
            if team_mode {
                value["members"] = json!(members.get(&account_id).cloned().unwrap_or_default());
            }
            value
        })
        .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn top(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(count): Path<i64>,
    Query(query): Query<ScoreboardQuery>,
) -> Result<Response, ApiError> {
    require_visible(&state, user.as_ref()).await?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let standings = load_standings(
        &state,
        team_mode,
        query.bracket_id,
        Some(count.clamp(1, 50)),
        false,
    )
    .await?;
    let account_ids = standings
        .iter()
        .map(|standing| standing.account_id)
        .collect::<Vec<_>>();
    let events = score_events(&state, team_mode, &account_ids).await?;
    let mut mapped: HashMap<i32, Vec<ScoreEvent>> = HashMap::new();
    for event in events {
        mapped.entry(event.account_id).or_default().push(event);
    }
    let mut data = serde_json::Map::new();
    for (index, standing) in standings.into_iter().enumerate() {
        let account_id = standing.account_id;
        data.insert(
            (index + 1).to_string(),
            json!({
                "id": account_id,
                "account_url": account_url(team_mode, account_id),
                "name": standing.name,
                "score": standing.score,
                "bracket_id": standing.bracket_id,
                "bracket_name": standing.bracket_name,
                "solves": mapped.remove(&account_id).unwrap_or_default(),
            }),
        );
    }
    Ok(Json(Success::new(Value::Object(data))).into_response())
}

pub(super) async fn load_standings(
    state: &AppState,
    team_mode: bool,
    bracket_id: Option<i32>,
    limit: Option<i64>,
    admin: bool,
) -> Result<Vec<Standing>, ApiError> {
    let account_column = if team_mode { "team_id" } else { "user_id" };
    let account_table = if team_mode { "teams" } else { "users" };
    let visibility = if admin {
        "TRUE"
    } else {
        "NOT COALESCE(a.banned,false) AND NOT COALESCE(a.hidden,false)"
    };
    let sql = format!(
        r#"
        WITH freeze_config AS (
            SELECT NULLIF(value,'')::double precision AS epoch
            FROM ctfzone.config WHERE key='freeze' LIMIT 1
        ), score_events AS (
            SELECT s.{account_column} AS account_id,c.value::bigint AS value,s.id,s.date
            FROM ctfzone.submissions s
            JOIN ctfzone.solves solved ON solved.id=s.id
            JOIN ctfzone.challenges c ON c.id=s.challenge_id
            WHERE s.{account_column} IS NOT NULL AND c.value <> 0
              AND ($3 OR (SELECT epoch FROM freeze_config) IS NULL
                   OR s.date < to_timestamp((SELECT epoch FROM freeze_config)) AT TIME ZONE 'UTC')
            UNION ALL
            SELECT aw.{account_column},aw.value::bigint,aw.id,aw.date
            FROM ctfzone.awards aw
            WHERE aw.{account_column} IS NOT NULL AND aw.value <> 0
              AND ($3 OR (SELECT epoch FROM freeze_config) IS NULL
                   OR aw.date < to_timestamp((SELECT epoch FROM freeze_config)) AT TIME ZONE 'UTC')
        ), totals AS (
            SELECT account_id,SUM(value)::bigint AS score,MAX(date) AS last_date,MAX(id) AS last_id
            FROM score_events GROUP BY account_id
        )
        SELECT a.id AS account_id,a.name,totals.score,a.bracket_id,b.name AS bracket_name
        FROM ctfzone.{account_table} a
        JOIN totals ON totals.account_id=a.id
        LEFT JOIN ctfzone.brackets b ON b.id=a.bracket_id
        WHERE {visibility} AND ($1::integer IS NULL OR a.bracket_id=$1)
        ORDER BY totals.score DESC,totals.last_date,totals.last_id
        LIMIT $2
        "#,
    );
    sqlx::query_as::<_, Standing>(&sql)
        .bind(bracket_id)
        .bind(limit.unwrap_or(i64::MAX))
        .bind(admin)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)
}

async fn team_members(state: &AppState) -> Result<HashMap<i32, Vec<MemberScore>>, ApiError> {
    let rows = sqlx::query_as::<_, MemberScore>(
        r#"
        SELECT u.id,u.name,COALESCE(SUM(c.value),0)::bigint AS score,
               u.bracket_id,b.name AS bracket_name,u.team_id
        FROM ctfzone.users u
        LEFT JOIN ctfzone.submissions s ON s.user_id=u.id
        LEFT JOIN ctfzone.solves solved ON solved.id=s.id
        LEFT JOIN ctfzone.challenges c ON c.id=s.challenge_id AND solved.id IS NOT NULL
        LEFT JOIN ctfzone.brackets b ON b.id=u.bracket_id
        WHERE u.team_id IS NOT NULL AND NOT COALESCE(u.hidden,false) AND NOT COALESCE(u.banned,false)
        GROUP BY u.id,b.name ORDER BY u.id
        "#,
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut members: HashMap<i32, Vec<MemberScore>> = HashMap::new();
    for row in rows {
        members.entry(row.team_id).or_default().push(row);
    }
    Ok(members)
}

async fn score_events(
    state: &AppState,
    team_mode: bool,
    account_ids: &[i32],
) -> Result<Vec<ScoreEvent>, ApiError> {
    if account_ids.is_empty() {
        return Ok(Vec::new());
    }
    let account_expression = if team_mode { "s.team_id" } else { "s.user_id" };
    let award_expression = if team_mode {
        "aw.team_id"
    } else {
        "aw.user_id"
    };
    let sql = format!(
        r#"
        WITH freeze_config AS (
            SELECT NULLIF(value,'')::double precision AS epoch
            FROM ctfzone.config WHERE key='freeze' LIMIT 1
        )
        SELECT s.challenge_id,{account_expression} AS account_id,s.team_id,s.user_id,
               c.value,s.date
        FROM ctfzone.submissions s
        JOIN ctfzone.solves solved ON solved.id=s.id
        JOIN ctfzone.challenges c ON c.id=s.challenge_id
        WHERE {account_expression}=ANY($1)
          AND ((SELECT epoch FROM freeze_config) IS NULL
               OR s.date < to_timestamp((SELECT epoch FROM freeze_config)) AT TIME ZONE 'UTC')
        UNION ALL
        SELECT NULL::integer,{award_expression},aw.team_id,aw.user_id,aw.value,aw.date
        FROM ctfzone.awards aw WHERE {award_expression}=ANY($1)
          AND ((SELECT epoch FROM freeze_config) IS NULL
               OR aw.date < to_timestamp((SELECT epoch FROM freeze_config)) AT TIME ZONE 'UTC')
        ORDER BY date
        "#,
    );
    sqlx::query_as::<_, ScoreEvent>(&sql)
        .bind(account_ids)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)
}

async fn require_visible(state: &AppState, user: Option<&CurrentUser>) -> Result<(), ApiError> {
    if super::challenges::scores_and_accounts_visible(state, user).await? {
        Ok(())
    } else {
        Err(ApiError::forbidden("The scoreboard is not available"))
    }
}

fn account_url(team_mode: bool, account_id: i32) -> String {
    format!(
        "/{}/{}",
        if team_mode { "teams" } else { "users" },
        account_id
    )
}
