use axum::{Json, extract::State};
use serde::Serialize;
use serde_json::Value;
use sqlx::FromRow;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

#[derive(FromRow)]
struct UserRow {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    website: Option<String>,
    affiliation: Option<String>,
    country: Option<String>,
    bracket_id: Option<i32>,
    language: Option<String>,
    team_id: Option<i32>,
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

#[derive(Serialize)]
pub(super) struct CurrentUserData {
    website: Option<String>,
    name: Option<String>,
    email: Option<String>,
    language: Option<String>,
    country: Option<String>,
    affiliation: Option<String>,
    bracket_id: Option<i32>,
    id: i32,
    fields: Vec<FieldEntry>,
    team_id: Option<i32>,
    place: Option<String>,
    score: i64,
}

pub(super) async fn current_user(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Success<CurrentUserData>>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, name, email, website, affiliation, country, bracket_id, language, team_id
        FROM ctfzone.users
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    let fields = sqlx::query_as::<_, FieldEntry>(
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
          AND (COALESCE(fields.editable, false) OR COALESCE(fields.public, false))
        ORDER BY field_entries.id
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;

    let score = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT
            COALESCE((
                SELECT SUM(challenges.value)::bigint
                FROM ctfzone.solves
                JOIN ctfzone.challenges ON challenges.id = solves.challenge_id
                WHERE solves.user_id = $1
            ), 0)
            +
            COALESCE((
                SELECT SUM(awards.value)::bigint
                FROM ctfzone.awards
                WHERE awards.user_id = $1
            ), 0)
        "#,
    )
    .bind(user.id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;

    let freeze = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key = 'freeze' LIMIT 1",
    )
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .flatten()
    .and_then(|value| value.parse::<i64>().ok());

    let place = user_place(&state, user.id, freeze).await?;

    Ok(Json(Success::new(CurrentUserData {
        website: row.website,
        name: row.name,
        email: row.email,
        language: row.language,
        country: row.country,
        affiliation: row.affiliation,
        bracket_id: row.bracket_id,
        id: row.id,
        fields,
        team_id: row.team_id,
        place: place.map(ordinalize),
        score,
    })))
}

pub(super) async fn user_place(
    state: &AppState,
    user_id: i32,
    freeze: Option<i64>,
) -> Result<Option<i64>, ApiError> {
    sqlx::query_scalar::<_, i64>(
        r#"
        WITH score_events AS (
            SELECT
                solves.user_id AS account_id,
                SUM(challenges.value)::bigint AS score,
                MAX(solves.id) AS event_id,
                MAX(submissions.date) AS event_date
            FROM ctfzone.solves
            JOIN ctfzone.challenges ON challenges.id = solves.challenge_id
            JOIN ctfzone.submissions ON submissions.id = solves.id
            WHERE challenges.value <> 0
              AND solves.user_id IS NOT NULL
              AND (
                  $1::bigint IS NULL
                  OR submissions.date < (to_timestamp($1::double precision) AT TIME ZONE 'UTC')
              )
            GROUP BY solves.user_id

            UNION ALL

            SELECT
                awards.user_id AS account_id,
                SUM(awards.value)::bigint AS score,
                MAX(awards.id) AS event_id,
                MAX(awards.date) AS event_date
            FROM ctfzone.awards
            WHERE awards.value <> 0
              AND awards.user_id IS NOT NULL
              AND (
                  $1::bigint IS NULL
                  OR awards.date < (to_timestamp($1::double precision) AT TIME ZONE 'UTC')
              )
            GROUP BY awards.user_id
        ), totals AS (
            SELECT
                account_id,
                SUM(score)::bigint AS score,
                MAX(event_id) AS event_id,
                MAX(event_date) AS event_date
            FROM score_events
            GROUP BY account_id
        ), ranked AS (
            SELECT
                users.id,
                ROW_NUMBER() OVER (
                    ORDER BY totals.score DESC, totals.event_date ASC, totals.event_id ASC
                ) AS place
            FROM totals
            JOIN ctfzone.users ON users.id = totals.account_id
            WHERE COALESCE(users.banned, false) = false
              AND COALESCE(users.hidden, false) = false
        )
        SELECT place
        FROM ranked
        WHERE id = $2
        "#,
    )
    .bind(freeze)
    .bind(user_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)
}

pub(super) fn ordinalize(value: i64) -> String {
    let suffix = if (11..=13).contains(&(value % 100)) {
        "th"
    } else {
        match value % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        }
    };
    format!("{value}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinalizes_scoreboard_places() {
        assert_eq!(ordinalize(1), "1st");
        assert_eq!(ordinalize(2), "2nd");
        assert_eq!(ordinalize(3), "3rd");
        assert_eq!(ordinalize(11), "11th");
        assert_eq!(ordinalize(21), "21st");
    }
}
