use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use std::time::Duration;

use crate::{AppState, auth, error::ApiError, passwords};

type SetupTokenMac = Hmac<Sha256>;

const SETUP_TOKEN_COMPARISON_KEY: &[u8] = b"ctfzone/setup-token/constant-time-comparison/v1";

#[derive(Deserialize)]
struct LoginForm {
    name: String,
    password: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SetupForm {
    name: String,
    email: String,
    password: String,
    #[serde(default)]
    setup_token: String,
}

#[derive(Deserialize, Default)]
struct LoginQuery {
    next: Option<String>,
}

#[derive(FromRow)]
struct LoginUser {
    id: i32,
    password: Option<String>,
    banned: bool,
    change_password: bool,
    team_banned: bool,
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/setup", post(setup))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/logout", get(logout).post(logout))
}

async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Result<Response, ApiError> {
    require_same_origin(&state, &headers)?;
    let request_ip = client_ip(&headers);
    if !state
        .rate_limiter
        .allow("setup", &request_ip, 5, Duration::from_secs(5))
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many setup attempts; try again shortly",
        ));
    }
    require_setup_token(&state.setup_token, &form.setup_token)?;

    let name = form.name.trim();
    let email = form.email.trim().to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 128
        || valid_email(name)
        || !valid_email(&email)
        || form.password.is_empty()
        || form.password.len() > 128
    {
        return Err(ApiError::bad_request(
            "A valid name, email address, and password are required",
        ));
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    // Serialize first-install attempts across all API replicas.
    crate::setup::lock_invariant(&mut transaction).await?;
    if crate::setup::is_complete_in_transaction(&mut transaction).await? {
        return Err(ApiError::conflict(
            "CTFZone setup has already been completed",
        ));
    }
    let duplicate_identity = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE name=$1 OR lower(email)=lower($2))",
    )
    .bind(name)
    .bind(&email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if duplicate_identity {
        return Err(ApiError::conflict(
            "The setup administrator name or email is already in use",
        ));
    }

    let password = passwords::hash_password(&mut transaction, &form.password)
        .await
        .map_err(ApiError::database)?;
    let user_id = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.users (
            name,email,password,type,participant_token,hidden,banned,verified,
            change_password,created
        ) VALUES ($1,$2,$3,'admin',$4,true,false,true,false,timezone('utc',now()))
        RETURNING id
        "#,
    )
    .bind(name)
    .bind(&email)
    .bind(password)
    .bind(Uuid::new_v4().to_string())
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;

    for (key, value) in [
        ("ctf_name", "CTFZone"),
        ("ctf_description", ""),
        ("user_mode", "users"),
        ("challenge_visibility", "private"),
        ("score_visibility", "public"),
        ("account_visibility", "public"),
        ("registration_visibility", "public"),
        ("registration_access_mode", "open"),
        ("verify_emails", "false"),
        ("social_shares", "false"),
        ("paused", "false"),
        ("start", ""),
        ("end", ""),
        ("freeze", ""),
    ] {
        upsert_setup_config(&mut transaction, key, value).await?;
    }
    sqlx::query(
        r#"
        INSERT INTO ctfzone.runtime_settings (key,enabled,revision,updated_by_user_id)
        VALUES ('private_challenges',false,1,$1)
        ON CONFLICT (key) DO NOTHING
        "#,
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    crate::setup::mark_complete(&mut transaction).await?;

    let session_id = Uuid::new_v4().to_string();
    let csrf_nonce = random_hex(32);
    insert_session(
        &mut transaction,
        &session_id,
        user_id,
        &csrf_nonce,
        &request_ip,
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let mut response = Redirect::to("/challenges").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&state, &session_id, false)?,
    );
    Ok(response)
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    require_same_origin(&state, &headers)?;
    if !crate::setup::is_complete(&state.database).await? {
        return Err(ApiError::conflict(
            "Complete CTFZone setup before registering users",
        ));
    }
    let request_ip = client_ip(&headers);
    if !state
        .rate_limiter
        .allow("register", &request_ip, 5, Duration::from_secs(5))
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many registration attempts; try again shortly",
        ));
    }
    if config_value(&state, "registration_visibility")
        .await?
        .as_deref()
        == Some("private")
    {
        return Err(ApiError::not_found("Registration is not available"));
    }
    let name = form.get("name").map_or("", String::as_str).trim();
    let email = form
        .get("email")
        .map_or("", String::as_str)
        .trim()
        .to_ascii_lowercase();
    let password = form.get("password").map_or("", String::as_str).trim();
    if name.is_empty()
        || name.len() > 128
        || valid_email(name)
        || !valid_email(&email)
        || password.is_empty()
        || password.len() > 128
    {
        return Ok(registration_error("invalid_input"));
    }
    let minimum_password_length = config_value(&state, "password_min_length")
        .await?
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if password.len() < minimum_password_length {
        return Ok(registration_error("password_too_short"));
    }
    let access_mode = registration_access_mode(&state).await?;
    if access_mode == "access_code" {
        let submitted = form.get("registration_code").map_or("", String::as_str);
        let configured = config_value(&state, "registration_code")
            .await?
            .unwrap_or_default();
        if configured.is_empty() || !submitted.eq_ignore_ascii_case(&configured) {
            return Ok(registration_error("invalid_registration_code"));
        }
    } else if access_mode == "email_allowlist" {
        let allowed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.registration_email_allowlist WHERE lower(email)=lower($1))",
        )
        .bind(&email)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
        if !allowed {
            return Ok(registration_error("email_not_allowed"));
        }
    } else if access_mode == "domain_rules" && !email_domain_allowed(&state, &email).await? {
        return Ok(registration_error("email_not_allowed"));
    }
    if access_mode != "email_allowlist" {
        let limit = config_value(&state, "num_users")
            .await?
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        if limit > 0 {
            let users = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM ctfzone.users WHERE NOT COALESCE(banned,false) AND NOT COALESCE(hidden,false)",
            )
            .fetch_one(&state.database)
            .await
            .map_err(ApiError::database)?;
            if users >= limit {
                return Ok(registration_error("user_limit_reached"));
            }
        }
    }

    let website = form
        .get("website")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    if website.is_some_and(|value| {
        value.len() > 128
            || value
                .parse::<Url>()
                .ok()
                .is_none_or(|url| !matches!(url.scheme(), "http" | "https"))
    }) {
        return Ok(registration_error("invalid_website"));
    }
    let affiliation = form
        .get("affiliation")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    if affiliation.is_some_and(|value| value.len() > 128) {
        return Ok(registration_error("invalid_affiliation"));
    }
    let country = form
        .get("country")
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty());
    if country.as_deref().is_some_and(|value| {
        value.len() != 2 || !value.chars().all(|char| char.is_ascii_uppercase())
    }) {
        return Ok(registration_error("invalid_country"));
    }
    let bracket_id = match form.get("bracket_id").map(|value| value.trim()) {
        Some("") | None => None,
        Some(value) => match value.parse::<i32>() {
            Ok(id) if id > 0 => Some(id),
            _ => return Ok(registration_error("invalid_bracket")),
        },
    };

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let duplicate = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE name=$1 OR lower(email)=lower($2))",
    )
    .bind(name)
    .bind(&email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if duplicate {
        return Ok(registration_error("identity_taken"));
    }
    if !valid_registration_bracket(&mut transaction, bracket_id).await? {
        return Ok(registration_error("invalid_bracket"));
    }
    let Some(field_values) = registration_fields(&mut transaction, &form).await? else {
        return Ok(registration_error("required_fields_missing"));
    };
    let encoded_password = passwords::hash_password(&mut transaction, password)
        .await
        .map_err(ApiError::database)?;
    let user_id = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.users
            (name,email,password,type,participant_token,website,affiliation,country,
             bracket_id,hidden,banned,verified,change_password,created)
        VALUES ($1,$2,$3,'user',$4,$5,$6,$7,$8,false,false,false,false,timezone('utc',now()))
        RETURNING id
        "#,
    )
    .bind(name)
    .bind(&email)
    .bind(encoded_password)
    .bind(Uuid::new_v4().to_string())
    .bind(website)
    .bind(affiliation)
    .bind(country)
    .bind(bracket_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    for (field_id, value) in field_values {
        sqlx::query(
            "INSERT INTO ctfzone.field_entries (type,value,field_id,user_id) VALUES ('user',$1,$2,$3)",
        )
        .bind(value)
        .bind(field_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    if access_mode == "email_allowlist" {
        sqlx::query(
            "INSERT INTO ctfzone.registration_email_allowlist (email,created) VALUES ($1,timezone('utc',now())) ON CONFLICT (email) DO NOTHING",
        )
        .bind(&email)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    let session_id = Uuid::new_v4().to_string();
    let csrf_nonce = random_hex(32);
    insert_session(
        &mut transaction,
        &session_id,
        user_id,
        &csrf_nonce,
        &request_ip,
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let team_mode = config_value(&state, "user_mode").await?.as_deref() == Some("teams");
    let verify_email = config_bool(&state, "verify_emails").await?;
    let destination = if verify_email {
        "/confirm"
    } else if team_mode {
        "/teams"
    } else {
        "/challenges"
    };
    let mut response = Redirect::to(destination).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&state, &session_id, false)?,
    );
    Ok(response)
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
    Form(form): Form<LoginForm>,
) -> Result<Response, ApiError> {
    require_same_origin(&state, &headers)?;
    let request_ip = client_ip(&headers);
    if !state
        .rate_limiter
        .allow("login", &request_ip, 10, Duration::from_secs(5))
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many login attempts; try again shortly",
        ));
    }
    let identity = form.name.trim();
    if identity.is_empty() || form.password.len() > 128 {
        return Ok(login_error("invalid_credentials"));
    }
    let user = sqlx::query_as::<_, LoginUser>(
        r#"
        SELECT u.id,u.password,COALESCE(u.banned,false) AS banned,
               COALESCE(u.change_password,false) AS change_password,
               COALESCE(t.banned,false) AS team_banned
        FROM ctfzone.users u LEFT JOIN ctfzone.teams t ON t.id=u.team_id
        WHERE lower(u.email)=lower($1) OR u.name=$1
        ORDER BY CASE WHEN lower(u.email)=lower($1) THEN 0 ELSE 1 END,u.id
        LIMIT 1
        "#,
    )
    .bind(identity)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?;
    let Some(user) = user else {
        return Ok(login_error("invalid_credentials"));
    };
    if user.banned || user.team_banned {
        return Ok(login_error("account_disabled"));
    }
    if user.change_password {
        return Ok(login_error("password_change_required"));
    }
    let Some(encoded_password) = user.password.as_deref() else {
        return Ok(login_error("external_account"));
    };
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    let matches = passwords::verify_password(&mut connection, &form.password, encoded_password)
        .await
        .map_err(ApiError::database)?;
    if !matches {
        return Ok(login_error("invalid_credentials"));
    }

    if let Some(session_id) = session_id_from_headers(&state, &headers) {
        sqlx::query(
            "UPDATE ctfzone.user_sessions SET revoked_at=timezone('utc',now()) WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    }
    let session_id = Uuid::new_v4().to_string();
    let csrf_nonce = random_hex(32);
    sqlx::query(
        r#"
        INSERT INTO ctfzone.user_sessions
            (id,user_id,created,last_seen,csrf_nonce,initial_ip,last_ip)
        VALUES ($1,$2,timezone('utc',now()),timezone('utc',now()),$3,$4,$4)
        "#,
    )
    .bind(&session_id)
    .bind(user.id)
    .bind(csrf_nonce)
    .bind(&request_ip)
    .execute(&state.database)
    .await
    .map_err(ApiError::database)?;

    let destination = query
        .next
        .as_deref()
        .filter(|value| safe_local_redirect(value))
        .unwrap_or("/challenges");
    let mut response = Redirect::to(destination).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&state, &session_id, false)?,
    );
    Ok(response)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !matches!(value, "same-origin" | "same-site" | "none"))
    {
        return Err(ApiError::forbidden("Cross-site logout is not allowed"));
    }
    if let Some(session_id) = session_id_from_headers(&state, &headers) {
        sqlx::query(
            "UPDATE ctfzone.user_sessions SET revoked_at=timezone('utc',now()) WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    }
    let mut response = Redirect::to("/").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&state, "", true)?);
    Ok(response)
}

fn require_same_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Url>().ok())
        .ok_or_else(|| ApiError::forbidden("A valid Origin header is required"))?;
    let expected = &state.public_base_url;
    if origin.scheme() != expected.scheme()
        || origin.host_str() != expected.host_str()
        || origin.port_or_known_default() != expected.port_or_known_default()
    {
        return Err(ApiError::forbidden(
            "Cross-origin form submission is not allowed",
        ));
    }
    Ok(())
}

fn session_id_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let signed = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().split_once('='))
        .find_map(|(name, value)| (name == state.auth.session_cookie_name).then_some(value))?;
    auth::verify_signed_session(signed, &state.auth.secret_key)
}

fn session_cookie(
    state: &AppState,
    session_id: &str,
    delete: bool,
) -> Result<HeaderValue, ApiError> {
    let value = if delete {
        String::new()
    } else {
        auth::sign_session(session_id, &state.auth.secret_key)
    };
    let mut cookie = format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax",
        state.auth.session_cookie_name
    );
    if state.public_base_url.scheme() == "https" {
        cookie.push_str("; Secure");
    }
    if delete {
        cookie.push_str("; Max-Age=0");
    } else {
        cookie.push_str(&format!(
            "; Max-Age={}",
            state.auth.session_lifetime_seconds
        ));
    }
    HeaderValue::from_str(&cookie)
        .map_err(|_| ApiError::upstream("Unable to create session cookie"))
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

async fn upsert_setup_config(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    value: &str,
) -> Result<(), ApiError> {
    let updated = sqlx::query("UPDATE ctfzone.config SET value=$2 WHERE key=$1")
        .bind(key)
        .bind(value)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    if updated.rows_affected() == 0 {
        sqlx::query("INSERT INTO ctfzone.config (key,value) VALUES ($1,$2)")
            .bind(key)
            .bind(value)
            .execute(&mut **transaction)
            .await
            .map_err(ApiError::database)?;
    }
    Ok(())
}

fn setup_token_matches(expected: &str, provided: &str) -> bool {
    let mut expected_mac = SetupTokenMac::new_from_slice(SETUP_TOKEN_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    expected_mac.update(expected.as_bytes());
    let expected_tag = expected_mac.finalize().into_bytes();

    let mut provided_mac = SetupTokenMac::new_from_slice(SETUP_TOKEN_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    provided_mac.update(provided.as_bytes());
    provided_mac.verify_slice(&expected_tag).is_ok()
}

fn require_setup_token(expected: &str, provided: &str) -> Result<(), ApiError> {
    if !setup_token_matches(expected, provided) {
        return Err(ApiError::forbidden("Setup authorization failed"));
    }
    Ok(())
}

async fn registration_access_mode(state: &AppState) -> Result<String, ApiError> {
    if let Some(mode) = config_value(state, "registration_access_mode").await? {
        if matches!(
            mode.as_str(),
            "open" | "domain_rules" | "access_code" | "email_allowlist"
        ) {
            return Ok(mode);
        }
    }
    if config_value(state, "registration_code")
        .await?
        .is_some_and(|value| !value.is_empty())
    {
        return Ok("access_code".to_owned());
    }
    if config_value(state, "domain_whitelist")
        .await?
        .is_some_and(|value| !value.is_empty())
        || config_value(state, "domain_blacklist")
            .await?
            .is_some_and(|value| !value.is_empty())
    {
        return Ok("domain_rules".to_owned());
    }
    Ok("open".to_owned())
}

async fn email_domain_allowed(state: &AppState, email: &str) -> Result<bool, ApiError> {
    let domain = email.rsplit_once('@').map_or("", |(_, domain)| domain);
    let whitelist = config_value(state, "domain_whitelist")
        .await?
        .unwrap_or_default();
    if !whitelist.trim().is_empty()
        && !whitelist
            .split(',')
            .map(str::trim)
            .any(|rule| domain_rule_matches(rule, domain))
    {
        return Ok(false);
    }
    let blacklist = config_value(state, "domain_blacklist")
        .await?
        .unwrap_or_default();
    Ok(!blacklist
        .split(',')
        .map(str::trim)
        .any(|rule| !rule.is_empty() && domain_rule_matches(rule, domain)))
}

fn domain_rule_matches(rule: &str, domain: &str) -> bool {
    let rule = rule.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    if let Some(suffix) = rule.strip_prefix('*') {
        !domain.contains('*') && domain.ends_with(suffix)
    } else {
        domain == rule
    }
}

async fn valid_registration_bracket(
    transaction: &mut Transaction<'_, Postgres>,
    bracket_id: Option<i32>,
) -> Result<bool, ApiError> {
    if let Some(bracket_id) = bracket_id {
        return sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.brackets WHERE id=$1 AND type='users')",
        )
        .bind(bracket_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database);
    }
    let user_brackets =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ctfzone.brackets WHERE type='users'")
            .fetch_one(&mut **transaction)
            .await
            .map_err(ApiError::database)?;
    Ok(user_brackets == 0)
}

async fn registration_fields(
    transaction: &mut Transaction<'_, Postgres>,
    form: &std::collections::HashMap<String, String>,
) -> Result<Option<Vec<(i32, Value)>>, ApiError> {
    let fields = sqlx::query_as::<_, (i32, bool, String)>(
        r#"
        SELECT id,COALESCE(required,false),COALESCE(field_type,'text')
        FROM ctfzone.fields WHERE type='user' ORDER BY id
        "#,
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let mut values = Vec::with_capacity(fields.len());
    for (field_id, required, field_type) in fields {
        let value = form
            .get(&format!("fields[{field_id}]"))
            .map(|value| value.trim())
            .unwrap_or_default();
        if required && value.is_empty() {
            return Ok(None);
        }
        let value = if field_type == "boolean" {
            json!(!value.is_empty())
        } else {
            json!(value)
        };
        values.push((field_id, value));
    }
    Ok(Some(values))
}

async fn insert_session(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: &str,
    user_id: i32,
    csrf_nonce: &str,
    request_ip: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.user_sessions
            (id,user_id,created,last_seen,csrf_nonce,initial_ip,last_ip)
        VALUES ($1,$2,timezone('utc',now()),timezone('utc',now()),$3,$4,$4)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(csrf_nonce)
    .bind(request_ip)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

fn valid_email(value: &str) -> bool {
    value.len() <= 128
        && !value.chars().any(char::is_whitespace)
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        })
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn safe_local_redirect(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\r', '\n'])
        && value.len() <= 2048
}

fn login_error(code: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, format!("/login?ctfzone_error={code}"))],
    )
        .into_response()
}

fn registration_error(code: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, format!("/register?ctfzone_error={code}"))],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_local_redirects() {
        assert!(safe_local_redirect("/challenges?category=web"));
        assert!(!safe_local_redirect("//example.org"));
        assert!(!safe_local_redirect("https://example.org"));
        assert!(!safe_local_redirect("/ok\r\nLocation: https://example.org"));
    }

    #[test]
    fn applies_exact_and_wildcard_domain_rules() {
        assert!(domain_rule_matches("example.org", "example.org"));
        assert!(!domain_rule_matches("example.org", "sub.example.org"));
        assert!(domain_rule_matches("*.example.org", "sub.example.org"));
        assert!(!domain_rule_matches("*.example.org", "example.org"));
    }

    #[test]
    fn setup_token_requires_an_exact_constant_time_tag_match() {
        assert!(setup_token_matches("operator-secret", "operator-secret"));
        assert!(!setup_token_matches("operator-secret", ""));
        assert!(!setup_token_matches("operator-secret", "operator-secre"));
        assert!(!setup_token_matches(
            "operator-secret",
            "operator-secret-extra"
        ));

        let response = require_setup_token("operator-secret", "wrong-secret")
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
