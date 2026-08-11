use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use std::time::Duration;

use crate::{AppState, auth::CurrentUser, error::ApiError};

#[derive(Deserialize)]
pub(super) struct UserEmailInput {
    text: String,
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
    let sender = config_value(&state, "mailfrom_addr")
        .await?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("Email sender is not configured"))?;

    let mailgun_base = config_value(&state, "mailgun_base_url").await?;
    let mailgun_key = config_value(&state, "mailgun_api_key").await?;
    if let (Some(base), Some(key)) = (mailgun_base, mailgun_key) {
        send_mailgun(&state, &base, &key, &sender, &recipient, &subject, text).await?;
    } else if let Some(server) = config_value(&state, "mail_server").await? {
        let port = config_value(&state, "mail_port")
            .await?
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| ApiError::bad_request("Email server port is not configured"))?;
        send_smtp(&state, &server, port, &sender, &recipient, &subject, text).await?;
    } else {
        return Err(ApiError::bad_request("Email settings are not configured"));
    }
    Ok(Json(json!({"success": true})).into_response())
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
    .port(port);
    if let (Some(username), Some(password)) = (
        config_value(state, "mail_username").await?,
        config_value(state, "mail_password").await?,
    ) {
        if !username.is_empty() {
            builder = builder.credentials(Credentials::new(username, password));
        }
    }
    builder.build().send(message).await.map_err(|error| {
        error!(%error, "SMTP delivery failed");
        ApiError::upstream("Email provider rejected the message")
    })?;
    Ok(())
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

async fn config_bool(state: &AppState, key: &str) -> Result<bool, ApiError> {
    Ok(config_value(state, key).await?.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }))
}
