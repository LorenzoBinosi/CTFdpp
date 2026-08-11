use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

#[derive(Deserialize, Default)]
pub(super) struct AggregateQuery {
    function: Option<String>,
    target: Option<String>,
}

pub(super) async fn users(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let (registered, confirmed) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*)::bigint,COUNT(*) FILTER (WHERE COALESCE(verified,false))::bigint FROM ctfzone.users",
    )
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({
        "registered": registered,
        "confirmed": confirmed
    })))
    .into_response())
}

pub(super) async fn teams(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let registered = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ctfzone.teams")
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({"registered": registered}))).into_response())
}

pub(super) async fn user_property(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(column): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    grouped_property(
        &state,
        "users",
        &column,
        &[
            "type",
            "country",
            "affiliation",
            "bracket_id",
            "hidden",
            "banned",
            "verified",
            "language",
            "team_id",
        ],
    )
    .await
}

pub(super) async fn submission_property(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(column): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    grouped_property(
        &state,
        "submissions",
        &column,
        &["challenge_id", "user_id", "team_id", "ip", "type"],
    )
    .await
}

pub(super) async fn challenge_property(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(column): Path<String>,
    Query(query): Query<AggregateQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let allowed = [
        "name",
        "max_attempts",
        "value",
        "category",
        "type",
        "state",
        "logic",
        "position",
        "function",
    ];
    if !allowed.contains(&column.as_str()) {
        return Err(ApiError::not_found("Challenge property not found"));
    }
    let target = query.target.unwrap_or_else(|| "category".to_owned());
    if !allowed.contains(&target.as_str()) {
        return Err(ApiError::bad_request("Invalid aggregate target"));
    }
    let aggregate = match query.function.as_deref().unwrap_or("count") {
        "count" => format!("COUNT(\"{target}\")"),
        "sum" => format!("COALESCE(SUM(\"{target}\"::bigint),0)"),
        _ => return Err(ApiError::bad_request("Unsupported aggregate function")),
    };
    grouped_query(
        &state,
        &format!(
            "SELECT \"{column}\"::text AS key,{aggregate}::bigint AS count FROM ctfzone.challenges GROUP BY \"{column}\""
        ),
    )
    .await
}

pub(super) async fn challenge_solves(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let account = if team_mode { "team_id" } else { "user_id" };
    let account_table = if team_mode { "teams" } else { "users" };
    let sql = format!(
        r#"
        SELECT c.id,c.name,
               COUNT(DISTINCT s.{account}) FILTER (
                   WHERE solved.id IS NOT NULL
                     AND NOT COALESCE(a.banned,false)
                     AND NOT COALESCE(a.hidden,false)
               )::bigint AS solves
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.submissions s ON s.challenge_id=c.id
        LEFT JOIN ctfzone.solves solved ON solved.id=s.id
        LEFT JOIN ctfzone.{account_table} a ON a.id=s.{account}
        WHERE c.state NOT IN ('hidden','locked')
        GROUP BY c.id ORDER BY c.value,c.id
        "#,
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let data = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<i32,_>("id"),
                "name": row.get::<Option<String>,_>("name"),
                "solves": row.get::<i64,_>("solves"),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn challenge_solve_percentages(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let account = if team_mode { "team_id" } else { "user_id" };
    let total = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(DISTINCT {account}) FROM ctfzone.submissions WHERE type='correct' AND {account} IS NOT NULL"
    ))
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let rows = sqlx::query(&format!(
        "SELECT c.id,c.name,COUNT(DISTINCT s.{account})::bigint AS solves FROM ctfzone.challenges c LEFT JOIN ctfzone.submissions s ON s.challenge_id=c.id AND s.type='correct' GROUP BY c.id ORDER BY solves DESC,c.id"
    ))
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let data = rows
        .into_iter()
        .map(|row| {
            let solves = row.get::<i64, _>("solves");
            json!({
                "id": row.get::<i32,_>("id"),
                "name": row.get::<Option<String>,_>("name"),
                "percentage": if total == 0 { 0.0 } else { solves as f64 / total as f64 },
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn score_distribution(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let standings = super::scoreboard::load_standings(&state, team_mode, None, None, true).await?;
    let (challenge_count, total_points) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT GREATEST(COUNT(*),1)::bigint,COALESCE(SUM(value) FILTER (WHERE state='visible'),0)::bigint FROM ctfzone.challenges",
    )
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let bracket_size = (total_points / challenge_count).max(1);
    let mut brackets: HashMap<i64, i64> = HashMap::new();
    for standing in standings {
        let ceiling = if standing.score <= 0 {
            bracket_size
        } else {
            ((standing.score + bracket_size - 1) / bracket_size) * bracket_size
        };
        *brackets.entry(ceiling).or_default() += 1;
    }
    Ok(Json(Success::new(json!({"brackets": brackets}))).into_response())
}

pub(super) async fn progression_matrix(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let standings =
        super::scoreboard::load_standings(&state, team_mode, None, Some(100), true).await?;
    let account_ids = standings
        .iter()
        .map(|standing| standing.account_id)
        .collect::<Vec<_>>();
    let account_column = if team_mode { "team_id" } else { "user_id" };
    let account_table = if team_mode { "teams" } else { "users" };

    let mut solves: HashMap<i32, HashSet<i32>> = HashMap::new();
    let mut attempts: HashMap<i32, HashSet<i32>> = HashMap::new();
    let mut opens: HashMap<i32, HashSet<i32>> = HashMap::new();
    if !account_ids.is_empty() {
        let solve_sql = format!(
            r#"
            SELECT s.{account_column} AS account_id,s.challenge_id
            FROM ctfzone.submissions s
            JOIN ctfzone.solves solved ON solved.id=s.id
            JOIN ctfzone.challenges c ON c.id=s.challenge_id
            JOIN ctfzone.{account_table} a ON a.id=s.{account_column}
            WHERE s.{account_column}=ANY($1) AND c.state='visible'
              AND NOT COALESCE(a.banned,false) AND NOT COALESCE(a.hidden,false)
            "#,
        );
        for row in sqlx::query(&solve_sql)
            .bind(&account_ids)
            .fetch_all(&state.database)
            .await
            .map_err(ApiError::database)?
        {
            solves
                .entry(row.get("account_id"))
                .or_default()
                .insert(row.get("challenge_id"));
        }

        let attempt_sql = format!(
            r#"
            SELECT s.{account_column} AS account_id,s.challenge_id
            FROM ctfzone.submissions s
            JOIN ctfzone.challenges c ON c.id=s.challenge_id
            JOIN ctfzone.{account_table} a ON a.id=s.{account_column}
            WHERE s.{account_column}=ANY($1) AND s.type='incorrect' AND c.state='visible'
              AND NOT COALESCE(a.banned,false) AND NOT COALESCE(a.hidden,false)
            "#,
        );
        for row in sqlx::query(&attempt_sql)
            .bind(&account_ids)
            .fetch_all(&state.database)
            .await
            .map_err(ApiError::database)?
        {
            attempts
                .entry(row.get("account_id"))
                .or_default()
                .insert(row.get("challenge_id"));
        }

        let open_sql = if team_mode {
            r#"
            SELECT DISTINCT u.team_id AS account_id,t.target::integer AS challenge_id
            FROM ctfzone.tracking t
            JOIN ctfzone.users u ON u.id=t.user_id
            JOIN ctfzone.teams team ON team.id=u.team_id
            JOIN ctfzone.challenges c ON c.id=t.target
            WHERE u.team_id=ANY($1) AND t.type='challenges.open'
              AND NOT COALESCE(u.banned,false) AND NOT COALESCE(u.hidden,false)
              AND NOT COALESCE(team.banned,false) AND NOT COALESCE(team.hidden,false)
              AND c.state='visible'
            "#
        } else {
            r#"
            SELECT DISTINCT t.user_id AS account_id,t.target::integer AS challenge_id
            FROM ctfzone.tracking t
            JOIN ctfzone.users u ON u.id=t.user_id
            JOIN ctfzone.challenges c ON c.id=t.target
            WHERE t.user_id=ANY($1) AND t.type='challenges.open'
              AND NOT COALESCE(u.banned,false) AND NOT COALESCE(u.hidden,false)
              AND c.state='visible'
            "#
        };
        for row in sqlx::query(open_sql)
            .bind(&account_ids)
            .fetch_all(&state.database)
            .await
            .map_err(ApiError::database)?
        {
            opens
                .entry(row.get("account_id"))
                .or_default()
                .insert(row.get("challenge_id"));
        }
    }

    let scoreboard = standings
        .into_iter()
        .enumerate()
        .map(|(index, standing)| {
            let id = standing.account_id;
            json!({
                "id": id,
                "name": standing.name,
                "score": standing.score,
                "place": index + 1,
                "url": format!("/admin/{}/{id}", if team_mode { "teams" } else { "users" }),
                "bracket_id": standing.bracket_id,
                "bracket_name": standing.bracket_name,
                "solves": sorted_ids(solves.remove(&id)),
                "attempts": sorted_ids(attempts.remove(&id)),
                "opens": sorted_ids(opens.remove(&id)),
            })
        })
        .collect::<Vec<_>>();

    let challenges = sqlx::query(
        r#"
        SELECT id,name,value,position,category FROM ctfzone.challenges
        WHERE state='visible'
        ORDER BY (position=0),position,value,category,id
        "#,
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|row| {
        let id = row.get::<i32, _>("id");
        json!({
            "id": id,
            "name": row.get::<Option<String>,_>("name"),
            "value": row.get::<Option<i32>,_>("value"),
            "position": row.get::<i32,_>("position"),
            "category": row.get::<Option<String>,_>("category"),
            "url": format!("/admin/challenges/{id}"),
        })
    })
    .collect::<Vec<_>>();

    let brackets = sqlx::query("SELECT id,name,description,type FROM ctfzone.brackets ORDER BY id")
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<i32,_>("id"),
                "name": row.get::<Option<String>,_>("name"),
                "description": row.get::<Option<String>,_>("description"),
                "type": row.get::<Option<String>,_>("type"),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(Success::new(json!({
        "scoreboard": scoreboard,
        "challenges": challenges,
        "brackets": brackets,
    })))
    .into_response())
}

fn sorted_ids(values: Option<HashSet<i32>>) -> Vec<i32> {
    let mut values = values.unwrap_or_default().into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values
}

async fn grouped_property(
    state: &AppState,
    table: &str,
    column: &str,
    allowed: &[&str],
) -> Result<Response, ApiError> {
    if !allowed.contains(&column) {
        return Err(ApiError::not_found("Property not found"));
    }
    grouped_query(
        state,
        &format!(
            "SELECT \"{column}\"::text AS key,COUNT(\"{column}\")::bigint AS count FROM ctfzone.{table} GROUP BY \"{column}\""
        ),
    )
    .await
}

async fn grouped_query(state: &AppState, sql: &str) -> Result<Response, ApiError> {
    let rows = sqlx::query(sql)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let mut data = Map::new();
    for row in rows {
        let key = row
            .get::<Option<String>, _>("key")
            .unwrap_or_else(|| "null".to_owned());
        data.insert(key, Value::from(row.get::<i64, _>("count")));
    }
    Ok(Json(Success::new(Value::Object(data))).into_response())
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}
