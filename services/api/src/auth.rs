use axum::{
    extract::{FromRequestParts, MatchedPath, Request, State},
    http::{header, request::Parts},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{FromRow, PgPool};
use tracing::error;
use uuid::Uuid;

use crate::{AppState, error::ApiError};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const BACKEND_TOKEN_HEADER: &str = "x-ctfzone-backend-token";
pub(crate) const SESSION_HEADER: &str = "x-ctfzone-session";
const SERVICE_TOKEN_COMPARISON_KEY: &[u8] =
    b"ctfzone/backend-service-token/constant-time-comparison/v1";

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) secret_key: String,
    pub(crate) session_lifetime_seconds: i64,
}

#[derive(Clone, Debug)]
pub(crate) enum Credential {
    ApiToken { token_id: i32, label: String },
    InternalSession { session_id: String },
}

#[derive(Clone, Debug)]
pub(crate) struct CurrentUser {
    pub(crate) id: i32,
    #[allow(dead_code)]
    pub(crate) name: Option<String>,
    #[allow(dead_code)]
    pub(crate) email: Option<String>,
    pub(crate) user_type: String,
    pub(crate) team_id: Option<i32>,
    pub(crate) verified: bool,
    pub(crate) credential: Credential,
    request_ip: String,
    ip_changed: bool,
}

impl CurrentUser {
    pub(crate) fn is_admin(&self) -> bool {
        self.user_type == "admin"
    }

    pub(crate) fn request_ip(&self) -> &str {
        &self.request_ip
    }

    pub(crate) fn internal_session_id(&self) -> Option<&str> {
        match &self.credential {
            Credential::InternalSession { session_id } => Some(session_id),
            Credential::ApiToken { .. } => None,
        }
    }
}

#[derive(FromRow)]
struct TokenAuthRow {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    user_type: String,
    team_id: Option<i32>,
    verified: bool,
    banned: bool,
    change_password: bool,
    team_banned: bool,
    token_id: i32,
    token_description: Option<String>,
    expiration: chrono::NaiveDateTime,
    previous_ip: Option<String>,
}

#[derive(FromRow)]
struct SessionAuthRow {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    user_type: String,
    team_id: Option<i32>,
    verified: bool,
    banned: bool,
    change_password: bool,
    team_banned: bool,
    session_id: String,
    last_ip: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get::<CurrentUser>() {
            return Ok(user.clone());
        }

        let user = authenticate_current_user(parts, state).await?;

        parts.extensions.insert(user.clone());
        Ok(user)
    }
}

pub(crate) struct OptionalCurrentUser(pub(crate) Option<CurrentUser>);

impl FromRequestParts<AppState> for OptionalCurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get::<CurrentUser>() {
            return Ok(Self(Some(user.clone())));
        }

        let has_credentials = parts.headers.contains_key(header::AUTHORIZATION)
            || parts.headers.contains_key(SESSION_HEADER);
        if !has_credentials {
            return Ok(Self(None));
        }

        let user = authenticate_current_user(parts, state).await?;
        parts.extensions.insert(user.clone());
        Ok(Self(Some(user)))
    }
}

async fn authenticate_current_user(
    parts: &mut Parts,
    state: &AppState,
) -> Result<CurrentUser, ApiError> {
    if let Some(authorization) = parts.headers.get(header::AUTHORIZATION) {
        authenticate_api_token(
            &state.database,
            authorization.to_str().unwrap_or_default(),
            parts,
        )
        .await
    } else {
        authenticate_internal_session(parts, state).await
    }
}

async fn authenticate_api_token(
    database: &PgPool,
    authorization: &str,
    parts: &Parts,
) -> Result<CurrentUser, ApiError> {
    let Some((_scheme, token)) = authorization.split_once(' ') else {
        return Err(ApiError::unauthorized("Invalid authorization header"));
    };
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized("Invalid authorization header"));
    }

    let row = sqlx::query_as::<_, TokenAuthRow>(
        r#"
        SELECT
            users.id,
            users.name,
            users.email,
            COALESCE(users.type, 'user') AS user_type,
            users.team_id,
            COALESCE(users.verified, false) AS verified,
            COALESCE(users.banned, false) AS banned,
            COALESCE(users.change_password, false) AS change_password,
            COALESCE(teams.banned, false) AS team_banned,
            tokens.id AS token_id,
            tokens.description AS token_description,
            tokens.expiration,
            (
                SELECT session_activity.ip
                FROM ctfzone.session_activity
                WHERE session_activity.user_id = users.id
                  AND session_activity.api_token_id = tokens.id
                ORDER BY session_activity.date DESC
                LIMIT 1
            ) AS previous_ip
        FROM ctfzone.tokens
        JOIN ctfzone.users ON users.id = tokens.user_id
        LEFT JOIN ctfzone.teams ON teams.id = users.team_id
        WHERE tokens.value = $1 AND tokens.type = 'user'
        "#,
    )
    .bind(token)
    .fetch_optional(database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::unauthorized("Your access token is invalid"))?;

    if row.expiration <= chrono::Utc::now().naive_utc() {
        return Err(ApiError::unauthorized("Your access token has expired"));
    }

    let request_ip = client_ip(parts).unwrap_or("unknown").to_owned();
    let ip_changed = row
        .previous_ip
        .as_deref()
        .is_some_and(|previous_ip| previous_ip != request_ip);
    let token_id = row.token_id;
    let token_label = row
        .token_description
        .unwrap_or_else(|| format!("API token #{token_id}"));

    authorize_identity(
        row.id,
        row.name,
        row.email,
        row.user_type,
        row.team_id,
        row.verified,
        row.banned,
        row.team_banned,
        row.change_password,
        Credential::ApiToken {
            token_id,
            label: token_label,
        },
        request_ip,
        ip_changed,
    )
}

async fn authenticate_internal_session(
    parts: &Parts,
    state: &AppState,
) -> Result<CurrentUser, ApiError> {
    let session_id = parts
        .headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| Uuid::parse_str(value).is_ok())
        .ok_or_else(|| ApiError::unauthorized("Invalid internal session"))?;

    let row = sqlx::query_as::<_, SessionAuthRow>(
        r#"
        SELECT
            users.id,
            users.name,
            users.email,
            COALESCE(users.type, 'user') AS user_type,
            users.team_id,
            COALESCE(users.verified, false) AS verified,
            COALESCE(users.banned, false) AS banned,
            COALESCE(users.change_password, false) AS change_password,
            COALESCE(teams.banned, false) AS team_banned,
            user_sessions.id AS session_id,
            user_sessions.last_ip
        FROM ctfzone.user_sessions
        JOIN ctfzone.users ON users.id = user_sessions.user_id
        LEFT JOIN ctfzone.teams ON teams.id = users.team_id
        WHERE user_sessions.id = $1
          AND user_sessions.revoked_at IS NULL
          AND user_sessions.last_seen >=
              (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
              - ($2::double precision * INTERVAL '1 second')
        "#,
    )
    .bind(session_id)
    .bind(state.auth.session_lifetime_seconds)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::unauthorized("This session has expired or been revoked"))?;

    let request_ip = client_ip(parts).unwrap_or("unknown").to_owned();
    let ip_changed = row.last_ip != request_ip;
    sqlx::query(
        r#"
        UPDATE ctfzone.user_sessions
        SET last_seen = CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
            last_ip = COALESCE($2, last_ip)
        WHERE id = $1
          AND (
              last_seen < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                  - (LEAST(60.0, GREATEST(1.0, $3::double precision / 2.0)) * INTERVAL '1 second')
              OR last_ip IS DISTINCT FROM $2
          )
        "#,
    )
    .bind(&row.session_id)
    .bind(&request_ip)
    .bind(state.auth.session_lifetime_seconds)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;

    authorize_identity(
        row.id,
        row.name,
        row.email,
        row.user_type,
        row.team_id,
        row.verified,
        row.banned,
        row.team_banned,
        row.change_password,
        Credential::InternalSession {
            session_id: row.session_id,
        },
        request_ip,
        ip_changed,
    )
}

#[allow(clippy::too_many_arguments)]
fn authorize_identity(
    id: i32,
    name: Option<String>,
    email: Option<String>,
    user_type: String,
    team_id: Option<i32>,
    verified: bool,
    banned: bool,
    team_banned: bool,
    change_password: bool,
    credential: Credential,
    request_ip: String,
    ip_changed: bool,
) -> Result<CurrentUser, ApiError> {
    if banned {
        return Err(ApiError::forbidden("You have been banned from this CTF"));
    }
    if team_banned {
        return Err(ApiError::forbidden(
            "Your team has been banned from this CTF",
        ));
    }
    if change_password {
        return Err(ApiError::forbidden("A password change is required"));
    }

    Ok(CurrentUser {
        id,
        name,
        email,
        user_type,
        team_id,
        verified,
        credential,
        request_ip,
        ip_changed,
    })
}

pub(crate) async fn optional_authenticated_activity(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    let has_credentials = parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(SESSION_HEADER);
    if !has_credentials {
        return Ok(next.run(Request::from_parts(parts, body)).await);
    }

    let user = authenticate_current_user(&mut parts, &state).await?;
    parts.extensions.insert(user.clone());

    let method = parts.method.as_str().to_owned();
    let endpoint = parts
        .extensions
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| parts.uri.path().to_owned());
    let response = next.run(Request::from_parts(parts, body)).await;

    if let Err(error) = record_activity(
        &state.database,
        &user,
        &method,
        &endpoint,
        i32::from(response.status().as_u16()),
    )
    .await
    {
        error!(%error, user_id = user.id, %method, %endpoint, "failed to record API activity");
    }

    Ok(response)
}

async fn record_activity(
    database: &PgPool,
    user: &CurrentUser,
    method: &str,
    endpoint: &str,
    status_code: i32,
) -> Result<(), sqlx::Error> {
    let (session_id, api_token_id, credential_type, credential_label) = match &user.credential {
        Credential::ApiToken { token_id, label } => {
            (None, Some(*token_id), "api_token", label.clone())
        }
        Credential::InternalSession { session_id } => (
            Some(session_id.as_str()),
            None,
            "internal_session",
            format!("Session {}", &session_id[..8]),
        ),
    };

    sqlx::query(
        r#"
        INSERT INTO ctfzone.session_activity (
            user_id,
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
        )
        VALUES (
            $1,
            $2,
            (SELECT id FROM ctfzone.tokens WHERE id = $3),
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
        )
        "#,
    )
    .bind(user.id)
    .bind(session_id)
    .bind(api_token_id)
    .bind(credential_type)
    .bind(credential_label)
    .bind(method)
    .bind(endpoint)
    .bind(status_code)
    .bind(&user.request_ip)
    .bind(user.ip_changed)
    .execute(database)
    .await?;

    Ok(())
}

pub(crate) async fn require_backend_service(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let provided = request
        .headers()
        .get(BACKEND_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !service_token_matches(&state.backend_service_token, provided) {
        return Err(ApiError::forbidden("Backend authentication failed"));
    }
    Ok(next.run(request).await)
}

fn service_token_matches(expected: &str, provided: &str) -> bool {
    let mut expected_mac = HmacSha256::new_from_slice(SERVICE_TOKEN_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    expected_mac.update(expected.as_bytes());
    let expected_tag = expected_mac.finalize().into_bytes();

    let mut provided_mac = HmacSha256::new_from_slice(SERVICE_TOKEN_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    provided_mac.update(provided.as_bytes());
    provided_mac.verify_slice(&expected_tag).is_ok()
}

fn client_ip(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 46)
}

pub(crate) async fn require_verified_email(
    database: &PgPool,
    user: &CurrentUser,
) -> Result<(), ApiError> {
    let value = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key = 'verify_emails' LIMIT 1",
    )
    .fetch_optional(database)
    .await
    .map_err(ApiError::database)?
    .flatten();

    let verification_enabled = value.as_deref().is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    });

    if verification_enabled && !user.is_admin() && !user.verified {
        return Err(ApiError::forbidden("Email verification is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_service_token_requires_an_exact_constant_time_match() {
        assert!(service_token_matches("backend-secret", "backend-secret"));
        assert!(!service_token_matches("backend-secret", ""));
        assert!(!service_token_matches("backend-secret", "backend-secret-x"));
    }
}
