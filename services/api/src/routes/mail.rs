use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use tracing::error;
use uuid::Uuid;

use std::time::Duration;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

const VERIFICATION_TOKEN_BYTES: usize = 32;
const MAIL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);
const VERIFICATION_RESEND_COOLDOWN_SECONDS: i64 = 60;
const VERIFICATION_SENDS_PER_USER_PER_HOUR: i64 = 5;
const VERIFICATION_SENDS_PER_IP_PER_HOUR: i64 = 25;

#[derive(Deserialize)]
pub(super) struct UserEmailInput {
    text: String,
}

#[derive(Deserialize)]
pub(super) struct ConfirmEmailInput {
    token: String,
}

#[derive(FromRow)]
struct VerificationTarget {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    verified: bool,
}

#[derive(FromRow)]
struct VerificationToken {
    id: Uuid,
    user_id: i32,
    email: String,
    used_at: Option<DateTime<Utc>>,
    invalidated_at: Option<DateTime<Utc>>,
}

pub(super) async fn email_user(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(user_id): Path<i32>,
    Json(request): Json<UserEmailInput>,
) -> Result<Response, ApiError> {
    if !admin.is_admin() {
        return Err(ApiError::forbidden("Administrator access is required"));
    }
    if !state
        .rate_limiter
        .allow(
            "admin_email",
            &admin.id.to_string(),
            10,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many email requests; try again shortly",
        ));
    }
    let text = request.text.trim();
    if text.is_empty() || text.len() > 100_000 {
        return Err(ApiError::bad_request(
            "Email text must contain between 1 and 100000 characters",
        ));
    }
    let recipient = sqlx::query_scalar::<_, String>("SELECT email FROM ctfzone.users WHERE id=$1")
        .bind(user_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let ctf_name = config_value(&state, "ctf_name")
        .await?
        .unwrap_or_else(|| "CTFZone".to_owned());
    let subject_template = config_value(&state, "user_creation_email_subject")
        .await?
        .unwrap_or_else(|| "Message from {ctf_name}".to_owned());
    let subject = subject_template.replace("{ctf_name}", &ctf_name);
    deliver_email(&state, &recipient, &subject, text).await?;
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn send_self_verification_email(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    let request_ip = user.request_ip().to_owned();
    if !state
        .rate_limiter
        .allow(
            "verification_email_user",
            &user.id.to_string(),
            10,
            Duration::from_secs(60),
        )
        .await
        || !state
            .rate_limiter
            .allow(
                "verification_email_ip",
                &request_ip,
                25,
                Duration::from_secs(60),
            )
            .await
    {
        return Err(ApiError::too_many_requests(
            "Too many verification email requests; try again shortly",
        ));
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    sqlx::query(
        r#"
        DELETE FROM ctfzone.email_verification_tokens
        WHERE id IN (
            SELECT id
            FROM ctfzone.email_verification_tokens
            WHERE created_at < now() - INTERVAL '30 days'
              AND (
                  used_at IS NOT NULL
                  OR invalidated_at IS NOT NULL
                  OR expires_at < now()
              )
            ORDER BY created_at
            LIMIT 1000
          )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let target = sqlx::query_as::<_, VerificationTarget>(
        r#"
        SELECT id,name,email,COALESCE(verified,false) AS verified
        FROM ctfzone.users
        WHERE id=$1
        FOR UPDATE
        "#,
    )
    .bind(user.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::unauthorized("Authenticated user no longer exists"))?;
    let recipient = target
        .email
        .as_deref()
        .filter(|email| !email.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("Your account does not have an email address"))?
        .to_owned();
    if target.verified {
        return Err(ApiError::conflict(
            "Your current email address is already verified",
        ));
    }

    let (last_created, user_hour_count) = sqlx::query_as::<_, (Option<DateTime<Utc>>, i64)>(
        r#"
        SELECT
            MAX(created_at),
            COUNT(*) FILTER (
                WHERE created_at > now() - INTERVAL '1 hour'
            )::bigint
        FROM ctfzone.email_verification_tokens
        WHERE user_id=$1
        "#,
    )
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let ip_hour_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::bigint
        FROM ctfzone.email_verification_tokens
        WHERE requested_by_ip=$1
          AND created_at > now() - INTERVAL '1 hour'
        "#,
    )
    .bind(&request_ip)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let now = Utc::now();
    if last_created.is_some_and(|created| {
        now.signed_duration_since(created).num_seconds() < VERIFICATION_RESEND_COOLDOWN_SECONDS
    }) || user_hour_count >= VERIFICATION_SENDS_PER_USER_PER_HOUR
        || ip_hour_count >= VERIFICATION_SENDS_PER_IP_PER_HOUR
    {
        return Err(ApiError::too_many_requests(
            "A verification email was sent recently; try again later",
        ));
    }

    let raw_token = new_verification_token();
    let token_hash = verification_token_hash(&raw_token)
        .expect("fresh verification tokens always have the required format");
    sqlx::query(
        r#"
        UPDATE ctfzone.email_verification_tokens
        SET invalidated_at=now()
        WHERE user_id=$1 AND used_at IS NULL AND invalidated_at IS NULL
        "#,
    )
    .bind(user.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    let expires_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        r#"
        INSERT INTO ctfzone.email_verification_tokens
            (token_hash,user_id,email,requested_by_user_id,requested_by_ip,expires_at)
        VALUES ($1,$2,$3,$4,$5,now() + ($6::double precision * INTERVAL '1 second'))
        RETURNING expires_at
        "#,
    )
    .bind(&token_hash)
    .bind(target.id)
    .bind(&recipient)
    .bind(user.id)
    .bind(&request_ip)
    .bind(state.email_verification_ttl_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;

    let ctf_name = config_value(&state, "ctf_name")
        .await?
        .unwrap_or_else(|| "CTFZone".to_owned());
    let subject = format!("Verify your email for {ctf_name}");
    let link = verification_link(state.site_url.as_str(), &raw_token);
    let greeting = target.name.as_deref().unwrap_or("participant");
    let body = format!(
        "Hello {greeting},\n\nVerify your email address for {ctf_name}:\n\n{link}\n\nThis single-use link expires in {} minutes. If you did not expect this message, you can ignore it.",
        state.email_verification_ttl_seconds / 60
    );
    if let Err(delivery_error) = deliver_email(&state, &recipient, &subject, &body).await {
        if let Err(invalidation_error) = sqlx::query(
            r#"
            UPDATE ctfzone.email_verification_tokens
            SET invalidated_at=now()
            WHERE token_hash=$1 AND used_at IS NULL AND invalidated_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .execute(&state.database)
        .await
        {
            error!(%invalidation_error, "failed to invalidate an undelivered verification token");
        }
        return Err(delivery_error);
    }

    Ok(Json(Success::new(json!({
        "sent": true,
        "expires_at": expires_at,
    })))
    .into_response())
}

pub(super) async fn confirm_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ConfirmEmailInput>,
) -> Result<Response, ApiError> {
    let request_ip = client_ip(&headers);
    if !state
        .rate_limiter
        .allow(
            "verification_email_confirm",
            &request_ip,
            20,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many verification attempts; try again shortly",
        ));
    }
    let token_hash =
        verification_token_hash(request.token.trim()).ok_or_else(invalid_verification_token)?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;

    // First discover the owning user without locking. All mutations lock the
    // user before the token, matching email edits and resends to avoid deadlocks.
    let token_owner = sqlx::query_scalar::<_, i32>(
        "SELECT user_id FROM ctfzone.email_verification_tokens WHERE token_hash=$1",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(invalid_verification_token)?;
    let current_email = sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM ctfzone.users WHERE id=$1 FOR UPDATE",
    )
    .bind(token_owner)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .flatten()
    .ok_or_else(invalid_verification_token)?;
    let token = sqlx::query_as::<_, VerificationToken>(
        r#"
        SELECT id,user_id,email,used_at,invalidated_at
        FROM ctfzone.email_verification_tokens
        WHERE token_hash=$1
        FOR UPDATE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(invalid_verification_token)?;
    if token.user_id != token_owner
        || token.email != current_email
        || token.used_at.is_some()
        || token.invalidated_at.is_some()
    {
        return Err(invalid_verification_token());
    }

    // Persist the consumed proof before promoting the account. The database
    // trigger requires this ordering and the surrounding transaction ensures
    // neither change can commit without the other.
    let consumed = sqlx::query_scalar::<_, DateTime<Utc>>(
        r#"
        WITH verification_time AS MATERIALIZED (
            SELECT clock_timestamp() AS consumed_at
        )
        UPDATE ctfzone.email_verification_tokens AS token
        SET used_at=verification_time.consumed_at
        FROM verification_time
        WHERE token.id=$1
          AND token.user_id=$2
          AND token.email=$3
          AND token.used_at IS NULL
          AND token.invalidated_at IS NULL
          AND verification_time.consumed_at >= token.created_at
          AND token.expires_at > verification_time.consumed_at
        RETURNING token.used_at
        "#,
    )
    .bind(token.id)
    .bind(token.user_id)
    .bind(&token.email)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if consumed.is_none() {
        return Err(invalid_verification_token());
    }
    let updated = sqlx::query("UPDATE ctfzone.users SET verified=true WHERE id=$1 AND email=$2")
        .bind(token.user_id)
        .bind(&token.email)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .rows_affected();
    if updated != 1 {
        return Err(invalid_verification_token());
    }
    sqlx::query(
        r#"
        UPDATE ctfzone.email_verification_tokens
        SET invalidated_at=now()
        WHERE user_id=$1 AND id<>$2 AND used_at IS NULL AND invalidated_at IS NULL
        "#,
    )
    .bind(token.user_id)
    .bind(token.id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;

    Ok(Json(Success::new(json!({"verified": true}))).into_response())
}

async fn deliver_email(
    state: &AppState,
    recipient: &str,
    subject: &str,
    text: &str,
) -> Result<(), ApiError> {
    let sender = config_value(state, "mailfrom_addr")
        .await?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("Email sender is not configured"))?;
    let provider = nonempty_config(state, "mail_provider").await?;
    let mailgun_base = nonempty_config(state, "mailgun_base_url").await?;
    let mailgun_key = nonempty_config(state, "mailgun_api_key").await?;
    let smtp_server = nonempty_config(state, "mail_server").await?;
    if provider.as_deref() == Some("disabled") {
        return Err(ApiError::bad_request("Email delivery is disabled"));
    }
    if provider.as_deref() == Some("mailgun")
        || (matches!(provider.as_deref(), None | Some("auto"))
            && mailgun_base.is_some()
            && mailgun_key.is_some())
    {
        let base = mailgun_base
            .ok_or_else(|| ApiError::bad_request("Mailgun base URL is not configured"))?;
        let key = mailgun_key
            .ok_or_else(|| ApiError::bad_request("Mailgun API key is not configured"))?;
        send_mailgun(state, &base, &key, &sender, recipient, subject, text).await?;
    } else if provider.as_deref() == Some("smtp")
        || (matches!(provider.as_deref(), None | Some("auto")) && smtp_server.is_some())
    {
        let server =
            smtp_server.ok_or_else(|| ApiError::bad_request("Email server is not configured"))?;
        let port = config_value(state, "mail_port")
            .await?
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(587);
        send_smtp(state, &server, port, &sender, recipient, subject, text).await?;
    } else {
        return Err(ApiError::bad_request("Email settings are not configured"));
    }
    Ok(())
}

fn new_verification_token() -> String {
    let mut random = [0_u8; VERIFICATION_TOKEN_BYTES];
    OsRng.fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

fn verification_token_hash(token: &str) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() != VERIFICATION_TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).to_vec())
}

fn verification_link(origin: &str, token: &str) -> String {
    format!("{}/confirm#{token}", origin.trim_end_matches('/'))
}

fn invalid_verification_token() -> ApiError {
    ApiError::bad_request("This verification link is invalid or has expired")
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 46)
        .unwrap_or("unknown")
        .to_owned()
}

async fn send_mailgun(
    state: &AppState,
    base: &str,
    key: &str,
    sender: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), ApiError> {
    let url = format!("{}/messages", base.trim_end_matches('/'));
    let form = reqwest::multipart::Form::new()
        .text("from", sender.to_owned())
        .text("to", recipient.to_owned())
        .text("subject", subject.to_owned())
        .text("text", body.to_owned());
    let response = state
        .http
        .post(url)
        .basic_auth("api", Some(key))
        .multipart(form)
        .send()
        .await
        .map_err(|error| {
            error!(%error, "Mailgun request failed");
            ApiError::upstream("Email provider is unavailable")
        })?;
    if !response.status().is_success() {
        error!(status = %response.status(), "Mailgun rejected an email");
        return Err(ApiError::upstream("Email provider rejected the message"));
    }
    Ok(())
}

async fn send_smtp(
    state: &AppState,
    server: &str,
    port: u16,
    sender: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), ApiError> {
    let message = Message::builder()
        .from(
            sender
                .parse()
                .map_err(|_| ApiError::bad_request("Email sender address is invalid"))?,
        )
        .to(recipient
            .parse()
            .map_err(|_| ApiError::bad_request("User email address is invalid"))?)
        .subject(subject)
        .body(body.to_owned())
        .map_err(|_| ApiError::bad_request("Unable to construct the email"))?;
    let ssl = config_bool(state, "mail_ssl").await?;
    let starttls = config_bool(state, "mail_tls").await?;
    if ssl && starttls {
        return Err(ApiError::bad_request(
            "Email cannot enable both implicit TLS and STARTTLS",
        ));
    }
    let mut builder = if ssl {
        AsyncSmtpTransport::<Tokio1Executor>::relay(server)
            .map_err(|_| ApiError::bad_request("Email server name is invalid"))?
    } else if starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(server)
            .map_err(|_| ApiError::bad_request("Email server name is invalid"))?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server)
    }
    .port(port)
    .timeout(Some(MAIL_DELIVERY_TIMEOUT));
    if let (Some(username), Some(password)) = (
        config_value(state, "mail_username").await?,
        config_value(state, "mail_password").await?,
    ) {
        if !username.is_empty() {
            builder = builder.credentials(Credentials::new(username, password));
        }
    }
    match tokio::time::timeout(MAIL_DELIVERY_TIMEOUT, builder.build().send(message)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => {
            error!(%error, "SMTP delivery failed");
            Err(ApiError::upstream("Email provider rejected the message"))
        }
        Err(_) => {
            error!(
                timeout_seconds = MAIL_DELIVERY_TIMEOUT.as_secs(),
                "SMTP delivery timed out"
            );
            Err(ApiError::upstream("Email provider is unavailable"))
        }
    }
}

async fn config_value(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM ctfzone.config WHERE key=$1 ORDER BY id DESC LIMIT 1",
    )
    .bind(key)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn nonempty_config(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    Ok(config_value(state, key)
        .await?
        .filter(|value| !value.trim().is_empty()))
}

async fn config_bool(state: &AppState, key: &str) -> Result<bool, ApiError> {
    Ok(config_value(state, key).await?.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_tokens_are_canonical_random_url_safe_values() {
        let first = new_verification_token();
        let second = new_verification_token();
        assert_eq!(first.len(), 43);
        assert_ne!(first, second);
        assert!(verification_token_hash(&first).is_some());
        assert!(
            !first
                .chars()
                .any(|character| matches!(character, '/' | '+' | '='))
        );
        assert!(verification_token_hash("").is_none());
        assert!(verification_token_hash(&format!("{first}=")).is_none());
        assert!(verification_token_hash(&"*".repeat(43)).is_none());
    }

    #[test]
    fn verification_hash_never_contains_the_bearer_token() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let hash = verification_token_hash(token).unwrap();
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, token.as_bytes());
        assert_eq!(hash, verification_token_hash(token).unwrap());
    }

    #[test]
    fn verification_link_uses_a_fragment_not_a_query() {
        let link = verification_link(
            "https://ctf.example.org/",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert_eq!(
            link,
            "https://ctf.example.org/confirm#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(!link.contains('?'));
    }
}
