use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::{
    AppState,
    auth::{Credential, CurrentUser},
    error::ApiError,
    routes::Success,
};

const MAX_ACTIVITY_EVENTS: i64 = 10_000;
const SESSION_LIST_QUERY: &str = r#"
    SELECT id, management_id, created, last_seen, initial_ip, last_ip, revoked_at
    FROM ctfzone.user_sessions
    WHERE user_id = $1
      AND (revoked_at IS NULL OR (created <= $2 AND last_seen >= $3))
    ORDER BY created DESC, management_id DESC
"#;

#[derive(Deserialize, Default)]
pub(super) struct UserSearch {
    q: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SessionQuery {
    user_id: i32,
    start: Option<f64>,
    end: Option<f64>,
}

#[derive(FromRow, Serialize)]
pub(super) struct SessionUser {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    #[serde(serialize_with = "serialize_optional_utc")]
    created: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct BrowserSessionRow {
    id: String,
    management_id: uuid::Uuid,
    created: NaiveDateTime,
    last_seen: NaiveDateTime,
    initial_ip: String,
    last_ip: String,
    revoked_at: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct ActivityRow {
    session_id: Option<String>,
    api_token_id: Option<i32>,
    credential_type: String,
    credential_label: String,
    method: String,
    endpoint: String,
    status_code: i32,
    ip: String,
    ip_changed: bool,
    date: NaiveDateTime,
}

#[derive(Serialize)]
struct BrowserSessionData {
    fingerprint: String,
    management_id: uuid::Uuid,
    created: String,
    last_seen: String,
    initial_ip: String,
    last_ip: String,
    revoked_at: Option<String>,
    active: bool,
    current: bool,
}

#[derive(Serialize)]
struct ActivityData {
    date: String,
    credential_key: String,
    credential_label: String,
    credential_type: String,
    method: String,
    endpoint: String,
    status_code: i32,
    ip: String,
    ip_changed: bool,
}

#[derive(Serialize)]
struct TimeRange {
    start: String,
    end: String,
}

#[derive(Serialize)]
pub(super) struct SessionListData {
    user: SessionUser,
    range: TimeRange,
    sessions: Vec<BrowserSessionData>,
    activities: Vec<ActivityData>,
    truncated: bool,
    activity_count: i64,
}

#[derive(Serialize)]
pub(super) struct RevocationData {
    revoked: u64,
    current_session_revoked: bool,
}

pub(super) async fn users(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(search): Query<UserSearch>,
) -> Result<Json<Success<Vec<SessionUser>>>, ApiError> {
    require_admin(&user)?;
    let query = search.q.unwrap_or_default().trim().to_owned();
    let pattern = format!("%{query}%");

    let users = sqlx::query_as::<_, SessionUser>(
        r#"
        SELECT id, name, email, created
        FROM ctfzone.users
        WHERE $1 = '' OR name ILIKE $2 OR email ILIKE $2
        ORDER BY created DESC NULLS LAST
        LIMIT 20
        "#,
    )
    .bind(&query)
    .bind(pattern)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;

    Ok(Json(Success::new(users)))
}

pub(super) async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<SessionQuery>,
) -> Result<Json<Success<SessionListData>>, ApiError> {
    require_admin(&user)?;

    let now = Utc::now().naive_utc();
    let start = parse_timestamp(query.start, "start")?.unwrap_or(now - Duration::hours(1));
    let end = parse_timestamp(query.end, "end")?.unwrap_or(now);
    if start > end {
        return Err(ApiError::bad_request("start must be earlier than end"));
    }

    let selected_user = sqlx::query_as::<_, SessionUser>(
        "SELECT id, name, email, created FROM ctfzone.users WHERE id = $1",
    )
    .bind(query.user_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    let sessions = sqlx::query_as::<_, BrowserSessionRow>(SESSION_LIST_QUERY)
        .bind(query.user_id)
        .bind(end)
        .bind(start)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;

    let activity_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM ctfzone.session_activity
        WHERE user_id = $1 AND date >= $2 AND date <= $3
          AND endpoint <> 'browser.request'
        "#,
    )
    .bind(query.user_id)
    .bind(start)
    .bind(end)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;

    let activities = sqlx::query_as::<_, ActivityRow>(
        r#"
        SELECT
            session_id,
            api_token_id,
            credential_type,
            credential_label,
            method,
            endpoint,
            status_code,
            ip,
            ip_changed,
            date
        FROM ctfzone.session_activity
        WHERE user_id = $1 AND date >= $2 AND date <= $3
          AND endpoint <> 'browser.request'
        ORDER BY date DESC, id DESC
        LIMIT $4
        "#,
    )
    .bind(query.user_id)
    .bind(start)
    .bind(end)
    .bind(MAX_ACTIVITY_EVENTS)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;

    let active_cutoff = now - Duration::seconds(state.auth.session_lifetime_seconds);
    Ok(Json(Success::new(SessionListData {
        user: selected_user,
        range: TimeRange {
            start: utc_iso(start),
            end: utc_iso(end),
        },
        sessions: sessions
            .into_iter()
            .map(|session| BrowserSessionData {
                fingerprint: session.id.chars().take(12).collect(),
                management_id: session.management_id,
                created: utc_iso(session.created),
                last_seen: utc_iso(session.last_seen),
                initial_ip: session.initial_ip,
                last_ip: session.last_ip,
                revoked_at: session.revoked_at.map(utc_iso),
                active: session.revoked_at.is_none() && session.last_seen >= active_cutoff,
                current: matches!(
                    &user.credential,
                    Credential::InternalSession { session_id } if session_id == &session.id
                ),
            })
            .collect(),
        activities: activities.into_iter().map(serialize_activity).collect(),
        truncated: activity_count > MAX_ACTIVITY_EVENTS,
        activity_count,
    })))
}

pub(super) async fn revoke_all(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Success<RevocationData>>, ApiError> {
    require_admin(&user)?;
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.user_sessions
        SET revoked_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
            revoked_by_user_id = $1
        WHERE revoked_at IS NULL
        "#,
    )
    .bind(user.id)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;

    let revoked = result.rows_affected();
    Ok(Json(Success::new(RevocationData {
        revoked,
        current_session_revoked: revoked > 0 && current_session_matches(&user, None, None),
    })))
}

pub(super) async fn revoke_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Json<Success<RevocationData>>, ApiError> {
    require_admin(&user)?;
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&state.database)
            .await
            .map_err(ApiError::database)?;
    if !exists {
        return Err(ApiError::not_found("User not found"));
    }

    let result = sqlx::query(
        r#"
        UPDATE ctfzone.user_sessions
        SET revoked_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
            revoked_by_user_id = $1
        WHERE user_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(user.id)
    .bind(user_id)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;

    let revoked = result.rows_affected();
    Ok(Json(Success::new(RevocationData {
        revoked,
        current_session_revoked: revoked > 0 && current_session_matches(&user, Some(user_id), None),
    })))
}

pub(super) async fn revoke_one(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(management_id): Path<uuid::Uuid>,
) -> Result<Json<Success<RevocationData>>, ApiError> {
    require_admin(&user)?;
    let session = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT id, user_id
        FROM ctfzone.user_sessions
        WHERE management_id = $1
        "#,
    )
    .bind(management_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Session not found"))?;

    let result = sqlx::query(
        r#"
        UPDATE ctfzone.user_sessions
        SET revoked_at = CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
            revoked_by_user_id = $1
        WHERE management_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(user.id)
    .bind(management_id)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;
    let revoked = result.rows_affected();

    Ok(Json(Success::new(RevocationData {
        revoked,
        current_session_revoked: revoked > 0
            && current_session_matches(&user, Some(session.1), Some(&session.0)),
    })))
}

fn current_session_matches(
    user: &CurrentUser,
    target_user_id: Option<i32>,
    target_session_id: Option<&str>,
) -> bool {
    if target_user_id.is_some_and(|target_user_id| target_user_id != user.id) {
        return false;
    }
    match (user.internal_session_id(), target_session_id) {
        (Some(_), None) => true,
        (Some(session_id), Some(target)) => session_id == target,
        (None, _) => false,
    }
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

fn parse_timestamp(value: Option<f64>, label: &str) -> Result<Option<NaiveDateTime>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !value.is_finite() {
        return Err(ApiError::bad_request(format!(
            "{label} must be a Unix timestamp"
        )));
    }
    let milliseconds = (value * 1_000.0).round();
    if milliseconds < i64::MIN as f64 || milliseconds > i64::MAX as f64 {
        return Err(ApiError::bad_request(format!(
            "{label} must be a Unix timestamp"
        )));
    }
    DateTime::<Utc>::from_timestamp_millis(milliseconds as i64)
        .map(|value| Some(value.naive_utc()))
        .ok_or_else(|| ApiError::bad_request(format!("{label} must be a Unix timestamp")))
}

fn serialize_activity(activity: ActivityRow) -> ActivityData {
    let (credential_key, credential_label) = if activity.credential_type == "internal_session" {
        if let Some(session_id) = &activity.session_id {
            (
                format!(
                    "internal_session:{}",
                    session_id.chars().take(12).collect::<String>()
                ),
                format!("Session {}", session_id.chars().take(8).collect::<String>()),
            )
        } else {
            (
                activity.credential_type.clone(),
                activity.credential_label.clone(),
            )
        }
    } else if let Some(token_id) = activity.api_token_id {
        (
            format!("api_token:{token_id}"),
            activity.credential_label.clone(),
        )
    } else {
        (
            activity.credential_type.clone(),
            activity.credential_label.clone(),
        )
    };

    ActivityData {
        date: utc_iso(activity.date),
        credential_key,
        credential_label,
        credential_type: activity.credential_type,
        method: activity.method,
        endpoint: activity.endpoint,
        status_code: activity.status_code,
        ip: activity.ip,
        ip_changed: activity.ip_changed,
    }
}

fn utc_iso(value: NaiveDateTime) -> String {
    DateTime::<Utc>::from_naive_utc_and_offset(value, Utc).to_rfc3339()
}

fn serialize_optional_utc<S>(
    value: &Option<NaiveDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    value.map(utc_iso).serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fractional_unix_timestamp() {
        let value = parse_timestamp(Some(1_700_000_000.125), "start")
            .unwrap()
            .unwrap();
        assert_eq!(value.and_utc().timestamp_millis(), 1_700_000_000_125);
    }

    #[test]
    fn rejects_non_finite_timestamp() {
        assert!(parse_timestamp(Some(f64::NAN), "end").is_err());
    }

    #[test]
    fn serializes_internal_session_activity_as_a_session_credential() {
        let activity = serialize_activity(ActivityRow {
            session_id: Some("12345678-1234-4234-8234-123456789abc".to_owned()),
            api_token_id: None,
            credential_type: "internal_session".to_owned(),
            credential_label: "stored label".to_owned(),
            method: "GET".to_owned(),
            endpoint: "/api/v1/challenges".to_owned(),
            status_code: 200,
            ip: "127.0.0.1".to_owned(),
            ip_changed: false,
            date: DateTime::<Utc>::UNIX_EPOCH.naive_utc(),
        });

        assert_eq!(activity.credential_key, "internal_session:12345678-123");
        assert_eq!(activity.credential_label, "Session 12345678");
        assert_eq!(activity.credential_type, "internal_session");
    }

    #[test]
    fn session_management_data_never_serializes_the_bearer_id() {
        let management_id =
            uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("valid UUID");
        let value = serde_json::to_value(BrowserSessionData {
            fingerprint: "12345678-123".to_owned(),
            management_id,
            created: "1970-01-01T00:00:00+00:00".to_owned(),
            last_seen: "1970-01-01T00:00:00+00:00".to_owned(),
            initial_ip: "127.0.0.1".to_owned(),
            last_ip: "127.0.0.1".to_owned(),
            revoked_at: None,
            active: true,
            current: true,
        })
        .expect("session data serializes");

        assert_eq!(value["management_id"], management_id.to_string());
        assert_eq!(value["current"], true);
        assert!(value.get("id").is_none());
    }

    #[test]
    fn session_management_query_keeps_unrevoked_sessions_outside_activity_range() {
        assert!(SESSION_LIST_QUERY.contains("revoked_at IS NULL"));
        assert!(SESSION_LIST_QUERY.contains("created <= $2 AND last_seen >= $3"));
    }
}
