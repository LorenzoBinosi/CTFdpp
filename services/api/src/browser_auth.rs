use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use std::time::Duration;

use crate::{AppState, auth, error::ApiError, passwords, routes::Success};

type SetupTokenMac = Hmac<Sha256>;

const SETUP_TOKEN_COMPARISON_KEY: &[u8] = b"ctfzone/setup-token/constant-time-comparison/v1";
const REGISTRATION_CODE_COMPARISON_KEY: &[u8] =
    b"ctfzone/registration-code/constant-time-comparison/v1";
const REGISTRATION_CAPACITY_LOCK_KEY: i64 = 0x4354_465D_i64;
pub(crate) const DEFAULT_CTF_NAME: &str = "CTFZone";
pub(crate) const DEFAULT_PLAYER_FRONTEND: &str = "terminal";

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
    ctf_name: Option<String>,
    player_frontend: Option<String>,
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
        .route("/logout", post(logout))
}

async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Result<Response, ApiError> {
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
    let ctf_name = setup_ctf_name(form.ctf_name.as_deref())?;
    let player_frontend = setup_player_frontend(form.player_frontend.as_deref())?;
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
        ) VALUES ($1,$2,$3,'admin',$4,true,false,$5,false,timezone('utc',now()))
        RETURNING id
        "#,
    )
    .bind(name)
    .bind(&email)
    .bind(password)
    .bind(Uuid::new_v4().to_string())
    .bind(new_account_email_verified())
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;

    for (key, value) in [
        ("ctf_name", ctf_name.as_str()),
        ("player_frontend", player_frontend.as_str()),
        ("ctf_description", ""),
        ("user_mode", "users"),
        ("num_users", "0"),
        ("password_min_length", "0"),
        ("name_changes", "true"),
        ("team_creation", "true"),
        ("team_size", "0"),
        ("num_teams", "0"),
        ("team_disbanding", "inactive_only"),
        ("challenge_visibility", "private"),
        ("score_visibility", "public"),
        ("account_visibility", "public"),
        ("registration_visibility", "public"),
        ("registration_access_mode", "open"),
        ("verify_emails", "false"),
        ("paused", "false"),
        ("start", ""),
        ("end", ""),
        ("freeze", ""),
    ] {
        upsert_setup_config(&mut transaction, key, value).await?;
    }
    crate::setup::mark_complete(&mut transaction).await?;

    let session_id = Uuid::new_v4().to_string();
    insert_session(&mut transaction, &session_id, user_id, &request_ip).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(session_response(session_id, "/admin"))
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let policy = locked_registration_policy(&mut transaction).await?;
    if policy.registration_closed {
        return Err(ApiError::not_found("Registration is not available"));
    }
    let name = form.get("name").map_or("", String::as_str).trim();
    let email = form
        .get("email")
        .map_or("", String::as_str)
        .trim()
        .to_ascii_lowercase();
    let password = form.get("password").map_or("", String::as_str).trim();
    let password_length = password.chars().count();
    if name.is_empty()
        || name.len() > 128
        || valid_email(name)
        || !valid_email(&email)
        || password.is_empty()
        || password_length > 128
    {
        return Ok(registration_error("invalid_input"));
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

    if password_length < policy.minimum_password_length {
        return Ok(registration_error("password_too_short"));
    }
    if policy.access_mode == "access_code" {
        let submitted = form.get("registration_code").map_or("", String::as_str);
        if policy.registration_code.is_empty()
            || !registration_code_matches(&policy.registration_code, submitted)
        {
            return Ok(registration_error("invalid_registration_code"));
        }
    } else if policy.access_mode == "domain_rules"
        && !email_domain_allowed(&email, &policy.domain_whitelist, &policy.domain_blacklist)
    {
        return Ok(registration_error("email_not_allowed"));
    }
    if policy.access_mode == "email_allowlist"
        && !lock_registration_email(&mut transaction, &email).await?
    {
        return Ok(registration_error("email_not_allowed"));
    }
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
    if policy.access_mode != "email_allowlist" && policy.participant_limit > 0 {
        lock_registration_capacity(&mut transaction).await?;
        let users = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ctfzone.users WHERE NOT COALESCE(banned,false) AND NOT COALESCE(hidden,false)",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if users >= policy.participant_limit {
            return Ok(registration_error("user_limit_reached"));
        }
    }
    let user_id = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.users
            (name,email,password,type,participant_token,website,affiliation,country,
             bracket_id,hidden,banned,verified,change_password,created)
        VALUES ($1,$2,$3,'user',$4,$5,$6,$7,$8,false,false,$9,false,timezone('utc',now()))
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
    .bind(new_account_email_verified())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| {
        ApiError::conflict_or_database(error, "The user name or email is already in use")
    })?;
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
    let session_id = Uuid::new_v4().to_string();
    insert_session(&mut transaction, &session_id, user_id, &request_ip).await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let destination = if policy.team_mode {
        "/team"
    } else {
        "/challenges"
    };
    Ok(session_response(session_id, destination))
}

pub(crate) async fn lock_registration_capacity(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(REGISTRATION_CAPACITY_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(ApiError::database)
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
    Form(form): Form<LoginForm>,
) -> Result<Response, ApiError> {
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::routes::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
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
    .fetch_optional(&mut *transaction)
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
    let matches = passwords::verify_password(&mut transaction, &form.password, encoded_password)
        .await
        .map_err(ApiError::database)?;
    if !matches {
        return Ok(login_error("invalid_credentials"));
    }

    if let Some(session_id) = session_id_from_headers(&headers) {
        sqlx::query(
            "UPDATE ctfzone.user_sessions SET revoked_at=timezone('utc',now()) WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    let session_id = Uuid::new_v4().to_string();
    insert_session(&mut transaction, &session_id, user.id, &request_ip).await?;
    transaction.commit().await.map_err(ApiError::database)?;

    let destination = query
        .next
        .as_deref()
        .filter(|value| safe_local_redirect(value))
        .unwrap_or("/challenges");
    Ok(session_response(session_id, destination))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let session_id = session_id_from_headers(&headers)
        .ok_or_else(|| ApiError::unauthorized("An internal session is required"))?;
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    crate::routes::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    sqlx::query(
        "UPDATE ctfzone.user_sessions SET revoked_at=timezone('utc',now()) WHERE id=$1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(Success::new(json!({"revoked": true}))).into_response())
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(auth::SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| Uuid::parse_str(value).is_ok())
        .map(str::to_owned)
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

async fn upsert_setup_config(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    value: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO ctfzone.config (key,value) VALUES ($1,$2) \
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
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

fn registration_code_matches(expected: &str, provided: &str) -> bool {
    let mut expected_mac = SetupTokenMac::new_from_slice(REGISTRATION_CODE_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    expected_mac.update(expected.to_ascii_lowercase().as_bytes());
    let expected_tag = expected_mac.finalize().into_bytes();

    let mut provided_mac = SetupTokenMac::new_from_slice(REGISTRATION_CODE_COMPARISON_KEY)
        .expect("HMAC-SHA256 accepts comparison keys of every length");
    provided_mac.update(provided.to_ascii_lowercase().as_bytes());
    provided_mac.verify_slice(&expected_tag).is_ok()
}

fn require_setup_token(expected: &str, provided: &str) -> Result<(), ApiError> {
    if !setup_token_matches(expected, provided) {
        return Err(ApiError::forbidden("Setup authorization failed"));
    }
    Ok(())
}

fn new_account_email_verified() -> bool {
    false
}

struct RegistrationPolicy {
    registration_closed: bool,
    access_mode: String,
    registration_code: String,
    domain_whitelist: String,
    domain_blacklist: String,
    participant_limit: i64,
    minimum_password_length: usize,
    team_mode: bool,
}

async fn locked_registration_policy(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<RegistrationPolicy, ApiError> {
    // Configuration writes take the exclusive form of this lock. Holding its
    // shared form through account creation makes every admission decision use
    // one committed policy version and prevents a mid-registration mode swap.
    crate::routes::user_mode_transition::lock_configuration_shared(transaction).await?;
    let keys = [
        "user_mode",
        "registration_visibility",
        "registration_access_mode",
        "registration_code",
        "domain_whitelist",
        "domain_blacklist",
        "num_users",
        "password_min_length",
    ]
    .map(str::to_owned);
    let rows = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT key,value FROM ctfzone.config WHERE key=ANY($1) ORDER BY id",
    )
    .bind(keys.to_vec())
    .fetch_all(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let values = rows
        .into_iter()
        .map(|(key, value)| (key, value.unwrap_or_default()))
        .collect::<std::collections::HashMap<_, _>>();
    let value = |key: &str| values.get(key).map(String::as_str);
    let registration_code = value("registration_code").unwrap_or_default().to_owned();
    let domain_whitelist = value("domain_whitelist").unwrap_or_default().to_owned();
    let domain_blacklist = value("domain_blacklist").unwrap_or_default().to_owned();
    let access_mode =
        effective_registration_access_mode(value("registration_access_mode")).to_owned();
    Ok(RegistrationPolicy {
        registration_closed: value("registration_visibility") == Some("private"),
        access_mode,
        registration_code,
        domain_whitelist,
        domain_blacklist,
        participant_limit: value("num_users")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0),
        minimum_password_length: value("password_min_length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0),
        team_mode: value("user_mode") == Some("teams"),
    })
}

pub(crate) fn effective_registration_access_mode(explicit: Option<&str>) -> &'static str {
    match explicit {
        Some("domain_rules") => "domain_rules",
        Some("access_code") => "access_code",
        Some("email_allowlist") => "email_allowlist",
        Some("open") | None | Some(_) => "open",
    }
}

async fn lock_registration_email(
    transaction: &mut Transaction<'_, Postgres>,
    email: &str,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, i32>(
        r#"
        SELECT id
        FROM ctfzone.registration_email_allowlist
        WHERE lower(email) = lower($1)
        FOR UPDATE
        "#,
    )
    .bind(email)
    .fetch_optional(&mut **transaction)
    .await
    .map(|entry| entry.is_some())
    .map_err(ApiError::database)
}

fn email_domain_allowed(email: &str, whitelist: &str, blacklist: &str) -> bool {
    let domain = email.rsplit_once('@').map_or("", |(_, domain)| domain);
    if !whitelist.trim().is_empty()
        && !whitelist
            .split(',')
            .map(str::trim)
            .any(|rule| domain_rule_matches(rule, domain))
    {
        return false;
    }
    !blacklist
        .split(',')
        .map(str::trim)
        .any(|rule| !rule.is_empty() && domain_rule_matches(rule, domain))
}

fn domain_rule_matches(rule: &str, domain: &str) -> bool {
    let Some(rule) = normalize_domain_rule(rule) else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    if let Some(suffix) = rule.strip_prefix('*') {
        domain.ends_with(suffix)
    } else {
        domain == rule
    }
}

pub(crate) fn normalize_domain_rules(value: &str) -> Result<String, ApiError> {
    let mut normalized = Vec::new();
    for rule in value
        .split(',')
        .map(str::trim)
        .filter(|rule| !rule.is_empty())
    {
        let rule = normalize_domain_rule(rule).ok_or_else(|| {
            ApiError::bad_request(
                "Email domain rules must be exact domains or wildcard subdomains such as *.example.org",
            )
        })?;
        if !normalized.contains(&rule) {
            normalized.push(rule);
        }
    }
    Ok(normalized.join(", "))
}

fn normalize_domain_rule(rule: &str) -> Option<String> {
    let rule = rule.trim().to_ascii_lowercase();
    let domain = rule.strip_prefix("*.").unwrap_or(&rule);
    if rule.contains('*') && !rule.starts_with("*.") || !valid_dns_domain(domain) {
        return None;
    }
    Some(rule)
}

fn valid_dns_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
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
    request_ip: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.user_sessions
            (id,user_id,created,last_seen,initial_ip,last_ip)
        VALUES ($1,$2,timezone('utc',now()),timezone('utc',now()),$3,$3)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
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

pub(crate) fn normalize_ctf_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "CTF name must be between 1 and 128 characters and contain no control characters",
        ));
    }
    Ok(value.to_owned())
}

fn setup_ctf_name(value: Option<&str>) -> Result<String, ApiError> {
    normalize_ctf_name(value.unwrap_or(DEFAULT_CTF_NAME))
}

pub(crate) fn validate_player_frontend(value: &str) -> Result<(), ApiError> {
    let bytes = value.as_bytes();
    let valid_first = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_rest = bytes.iter().skip(1).all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    });
    if bytes.len() > 64 || !valid_first || !valid_rest {
        return Err(ApiError::bad_request(
            "Player frontend must be a lowercase slug of at most 64 characters",
        ));
    }
    Ok(())
}

fn setup_player_frontend(value: Option<&str>) -> Result<String, ApiError> {
    let value = value.unwrap_or(DEFAULT_PLAYER_FRONTEND);
    validate_player_frontend(value)?;
    Ok(value.to_owned())
}

fn safe_local_redirect(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value
            .chars()
            .any(|character| character == '\\' || character.is_control())
        && value.len() <= 2048
}

fn login_error(code: &str) -> Response {
    auth_error(StatusCode::UNAUTHORIZED, code)
}

fn registration_error(code: &str) -> Response {
    auth_error(StatusCode::BAD_REQUEST, code)
}

fn auth_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"success": false, "message": code}))).into_response()
}

fn session_response(session_id: String, redirect: &str) -> Response {
    Json(Success::new(json!({
        "session_id": session_id,
        "redirect": redirect,
    })))
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
        assert!(!safe_local_redirect("/\\evil.example"));
        assert!(!safe_local_redirect("/\\/evil.example"));
        assert!(!safe_local_redirect("/ok\tstill-not-safe"));
        assert!(!safe_local_redirect("/ok\u{7f}"));
        assert!(!safe_local_redirect("/ok\u{85}"));
    }

    #[test]
    fn applies_exact_and_wildcard_domain_rules() {
        assert!(domain_rule_matches("example.org", "example.org"));
        assert!(!domain_rule_matches("example.org", "sub.example.org"));
        assert!(domain_rule_matches("*.example.org", "sub.example.org"));
        assert!(!domain_rule_matches("*.example.org", "example.org"));
        assert!(!domain_rule_matches("*", "example.org"));
        assert!(!domain_rule_matches("example.*", "example.org"));
    }

    #[test]
    fn registration_domain_policy_requires_allow_and_not_deny() {
        assert!(email_domain_allowed("user@example.org", "", ""));
        assert!(email_domain_allowed(
            "user@students.example.org",
            "*.example.org",
            ""
        ));
        assert!(!email_domain_allowed(
            "user@elsewhere.org",
            "*.example.org",
            ""
        ));
        assert!(!email_domain_allowed(
            "user@blocked.example.org",
            "*.example.org",
            "blocked.example.org"
        ));
    }

    #[test]
    fn normalizes_and_validates_domain_rule_lists() {
        assert_eq!(
            normalize_domain_rules(" Example.ORG, *.Students.Example.org, example.org, ").unwrap(),
            "example.org, *.students.example.org"
        );
        for invalid in [
            "*",
            "example.*",
            "https://example.org",
            ".example.org",
            "example.org.",
            "under_score.example.org",
            "-bad.example.org",
            "localhost",
        ] {
            assert!(normalize_domain_rules(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn registration_access_mode_is_explicit_and_validated() {
        for mode in ["open", "domain_rules", "access_code", "email_allowlist"] {
            assert_eq!(effective_registration_access_mode(Some(mode)), mode);
        }
        assert_eq!(effective_registration_access_mode(None), "open");
        assert_eq!(
            effective_registration_access_mode(Some("unsupported")),
            "open"
        );
    }

    #[test]
    fn registration_code_comparison_preserves_ascii_case_insensitivity() {
        assert!(registration_code_matches("Secret-123", "secret-123"));
        assert!(!registration_code_matches("Secret-123", "secret-124"));
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

    #[test]
    fn browser_created_accounts_start_with_unverified_email() {
        assert!(!new_account_email_verified());
    }

    #[test]
    fn setup_site_identity_is_normalized_and_bounded() {
        assert_eq!(setup_ctf_name(None).unwrap(), DEFAULT_CTF_NAME);
        assert_eq!(
            setup_player_frontend(None).unwrap(),
            DEFAULT_PLAYER_FRONTEND
        );
        assert_eq!(
            normalize_ctf_name("  Null Sector CTF  ").unwrap(),
            "Null Sector CTF"
        );
        assert!(normalize_ctf_name("").is_err());
        assert!(normalize_ctf_name(" \t\n ").is_err());
        assert!(normalize_ctf_name("Null\nSector").is_err());
        assert!(normalize_ctf_name(&"x".repeat(129)).is_err());
        assert!(normalize_ctf_name(&"x".repeat(128)).is_ok());
    }

    #[test]
    fn player_frontend_is_an_opaque_safe_slug() {
        for value in ["terminal", "classic-2", "theme_dark"] {
            assert!(validate_player_frontend(value).is_ok(), "{value}");
        }
        for value in [
            "",
            "Terminal",
            "-terminal",
            "_terminal",
            "terminal/theme",
            "terminal.theme",
            "terminal theme",
        ] {
            assert!(validate_player_frontend(value).is_err(), "{value}");
        }
        assert!(validate_player_frontend(&"x".repeat(64)).is_ok());
        assert!(validate_player_frontend(&"x".repeat(65)).is_err());
    }

    #[test]
    fn session_success_is_json_and_never_sets_a_cookie() {
        let response = session_response(
            "00000000-0000-4000-8000-000000000000".to_owned(),
            "/challenges",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response
                .headers()
                .contains_key(axum::http::header::SET_COOKIE)
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
    }
}
