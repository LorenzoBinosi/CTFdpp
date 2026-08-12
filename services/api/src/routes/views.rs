use axum::{
    Json,
    extract::{Query, State},
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

#[derive(Default, Deserialize)]
pub(super) struct ChallengeViewQuery {
    selected: Option<i32>,
}

#[derive(FromRow, Serialize)]
struct RecentSubmission {
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

#[derive(FromRow, Serialize)]
struct OverviewCounts {
    challenges: i64,
    users: i64,
    teams: i64,
    instances: i64,
    active_instances: i64,
    ready_instances: i64,
    pending_instances: i64,
    failed_instances: i64,
}

pub(super) async fn challenges(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<ChallengeViewQuery>,
) -> Result<Response, ApiError> {
    let bootstrap = super::bootstrap::data(&state, user.clone()).await?;
    let challenges = super::challenges::list_data(
        state.clone(),
        user.clone(),
        super::challenges::ChallengeListQuery::default(),
    )
    .await?;
    let selected_id = selected_challenge_id(query.selected, &challenges);
    let selected = if let Some(challenge_id) = selected_id {
        Some(super::challenges::detail_data(state, user, challenge_id).await?)
    } else {
        None
    };

    Ok(Json(Success::new(json!({
        "bootstrap": bootstrap,
        "challenges": challenges,
        "selected": selected,
    })))
    .into_response())
}

fn selected_challenge_id(requested: Option<i32>, challenges: &[Value]) -> Option<i32> {
    let selectable = challenges.iter().filter_map(|challenge| {
        if challenge.get("type").and_then(Value::as_str) == Some("hidden") {
            return None;
        }
        challenge
            .get("id")
            .and_then(Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
    });
    let ids = selectable.collect::<Vec<_>>();
    requested
        .filter(|requested| ids.contains(requested))
        .or_else(|| ids.first().copied())
}

pub(super) async fn admin_overview(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    if !user.is_admin() {
        return Err(ApiError::forbidden("Administrator access is required"));
    }
    let bootstrap = super::bootstrap::data(&state, Some(user)).await?;
    let counts = sqlx::query_as::<_, OverviewCounts>(
        r#"
        SELECT
          (SELECT COUNT(*) FROM ctfzone.challenges) AS challenges,
          (SELECT COUNT(*) FROM ctfzone.users) AS users,
          (SELECT COUNT(*) FROM ctfzone.teams) AS teams,
          (SELECT COUNT(*) FROM ctfzone.runtime_instances) AS instances,
          (SELECT COUNT(*) FROM ctfzone.runtime_instances WHERE active) AS active_instances,
          (SELECT COUNT(*) FROM ctfzone.runtime_instances WHERE observed_state='ready') AS ready_instances,
          (SELECT COUNT(*) FROM ctfzone.runtime_instances
             WHERE active AND observed_state IN ('requested','starting','stopping','cleanup_pending','unknown'))
             AS pending_instances,
          (SELECT COUNT(*) FROM ctfzone.runtime_instances WHERE observed_state='failed')
             AS failed_instances
        "#,
    )
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let recent_submissions = sqlx::query_as::<_, RecentSubmission>(
        r#"
        SELECT id,challenge_id,user_id,team_id,ip,provided,type AS submission_type,date
        FROM ctfzone.submissions
        ORDER BY id DESC
        LIMIT 8
        "#,
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let stats = json!({
        "challenges": counts.challenges,
        "users": counts.users,
        "teams": counts.teams,
        "instances": counts.instances,
    });
    let runtime = json!({
        "total": counts.instances,
        "active": counts.active_instances,
        "ready": counts.ready_instances,
        "pending": counts.pending_instances,
        "failed": counts.failed_instances,
    });

    Ok(Json(Success::new(json!({
        "bootstrap": bootstrap,
        "stats": stats,
        "runtime": runtime,
        "recent_submissions": recent_submissions,
    })))
    .into_response())
}

pub(super) async fn admin_configuration(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    if !user.is_admin() {
        return Err(ApiError::forbidden("Administrator access is required"));
    }
    Ok(Json(Success::new(
        super::configuration::catalog(&state.database).await?,
    ))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_or_hidden_selection_falls_back_without_loading_it() {
        let challenges = vec![
            json!({"id": 1, "type": "hidden"}),
            json!({"id": 2, "type": "standard"}),
            json!({"id": 3, "type": "dynamic"}),
        ];
        assert_eq!(selected_challenge_id(Some(99), &challenges), Some(2));
        assert_eq!(selected_challenge_id(Some(1), &challenges), Some(2));
        assert_eq!(selected_challenge_id(Some(3), &challenges), Some(3));
        assert_eq!(selected_challenge_id(None, &challenges), Some(2));
        assert_eq!(
            selected_challenge_id(Some(1), &[json!({"id": 1, "type": "hidden"})]),
            None
        );
    }
}
