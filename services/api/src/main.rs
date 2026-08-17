mod auth;
mod browser_auth;
mod config;
mod error;
mod object_storage;
mod passwords;
mod rate_limit;
mod routes;
mod setup;

use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use config::Config;
use reqwest::{Client, Url, redirect::Policy};
use serde::Serialize;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, signal};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const PRODUCT_NAME: &str = "CTFZone";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) auth: auth::AuthConfig,
    pub(crate) backend_service_token: String,
    pub(crate) database: PgPool,
    pub(crate) email_verification_ttl_seconds: i64,
    pub(crate) http: Client,
    pub(crate) object_storage: object_storage::ObjectStorage,
    pub(crate) rate_limiter: rate_limit::RateLimiter,
    pub(crate) setup_token: String,
    pub(crate) site_url: Url,
    pub(crate) ssh_gateway_service_token: String,
}

#[derive(Serialize)]
struct ApiEnvelope<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ProductMetadata {
    name: &'static str,
    version: &'static str,
    api_status: &'static str,
    compatibility_backend: bool,
    schema_version: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;
    let database = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(&config.database_url)
        .context("DATABASE_URL is not a valid PostgreSQL connection URL")?;

    let http = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(Policy::none())
        .build()
        .context("failed to create internal HTTP client")?;
    let object_storage = object_storage::ObjectStorage::new(config.object_storage)?;

    let app = router(AppState {
        auth: auth::AuthConfig {
            secret_key: config.api_signing_key,
            session_lifetime_seconds: config.session_lifetime_seconds,
        },
        backend_service_token: config.backend_service_token,
        database,
        email_verification_ttl_seconds: config.email_verification_ttl_seconds,
        http,
        object_storage,
        rate_limiter: rate_limit::RateLimiter::default(),
        setup_token: config.setup_token,
        site_url: config.site_url,
        ssh_gateway_service_token: config.ssh_gateway_service_token,
    });
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("failed to bind API to {}", config.bind_address))?;

    info!(
        product = PRODUCT_NAME,
        version = VERSION,
        address = %config.bind_address,
        "CTFZone API started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("API server failed")?;

    Ok(())
}

fn router(state: AppState) -> Router {
    let request_id_header = axum::http::HeaderName::from_static("x-request-id");
    let application_routes = Router::new()
        .route("/api/v1/ctfzone", get(product_metadata))
        .route("/api/v1/ctfzone/architecture", get(architecture))
        .merge(browser_auth::router())
        .merge(routes::router(state.clone()))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_backend_service,
        ));
    let ssh_gateway_routes = routes::ssh_hosts::private_router().route_layer(
        middleware::from_fn_with_state(state.clone(), auth::require_ssh_gateway_service),
    );

    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .merge(ssh_gateway_routes)
        .merge(application_routes)
        .with_state(state)
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
}

async fn liveness() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "api",
        "name": PRODUCT_NAME,
        "version": VERSION,
    }))
}

async fn readiness(State(state): State<AppState>) -> Response {
    let object_storage_ready = state
        .http
        .head(state.object_storage.internal_bucket_head_url())
        .send()
        .await
        .is_ok_and(|response| response.status().is_success());
    match sqlx::query_as::<
        _,
        (
            Option<String>,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
        ),
    >(
        r#"
        SELECT
            (SELECT value FROM ctfzone.release_metadata WHERE key = 'schema_version'),
            EXISTS(
                SELECT 1 FROM ctfzone.release_metadata
                WHERE key = 'install_complete' AND value = '1.0.0'
            ),
            to_regclass('ctfzone.users') IS NOT NULL,
            to_regclass('ctfzone.challenges') IS NOT NULL
                AND to_regclass('ctfzone.flags') IS NOT NULL
                AND to_regclass('ctfzone.challenge_categories') IS NOT NULL
                AND to_regclass('ctfzone.user_challenge_flags') IS NOT NULL
                AND to_regclass('ctfzone.flag_sharing_events') IS NOT NULL
                AND to_regclass('ctfzone.admin_create_idempotency') IS NOT NULL,
            to_regclass('ctfzone.runtime_settings') IS NOT NULL
                AND to_regclass('ctfzone.challenge_runtime_configs') IS NOT NULL
                AND to_regclass('ctfzone.remote_servers') IS NOT NULL
                AND to_regclass('ctfzone.runtime_instances') IS NOT NULL
                AND to_regclass('ctfzone.runtime_commands') IS NOT NULL
                AND to_regclass('ctfzone.runtime_instance_events') IS NOT NULL,
            to_regclass('ctfzone.user_mode_transitions') IS NOT NULL,
            to_regclass('ctfzone.email_verification_tokens') IS NOT NULL,
            to_regclass('ctfzone.stored_objects') IS NOT NULL,
            to_regclass('ctfzone.object_operations') IS NOT NULL,
            to_regclass('ctfzone.ssh_hosts') IS NOT NULL
                AND to_regclass('ctfzone.ssh_host_events') IS NOT NULL
                AND to_regclass('ctfzone.ssh_host_identity_operations') IS NOT NULL
                AND to_regclass('ctfzone.ssh_host_tickets') IS NOT NULL
                AND to_regclass('ctfzone.ssh_host_key_candidates') IS NOT NULL
                AND to_regclass('ctfzone.ssh_terminal_sessions') IS NOT NULL
                AND (
                    SELECT count(*) = 4
                    FROM information_schema.columns
                    WHERE table_schema='ctfzone'
                      AND table_name='ssh_terminal_sessions'
                      AND column_name IN (
                          'browser_session_id','gateway_instance_id','host_revision',
                          'trusted_host_key_fingerprint'
                      )
                )
        "#,
    )
    .fetch_one(&state.database)
    .await
    {
        Ok((Some(version), true, true, true, true, true, true, true, true, true))
            if version == SCHEMA_VERSION && object_storage_ready =>
        {
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ready",
                    "database": "available",
                    "object_storage": "available",
                    "schema_version": version,
                })),
            )
                .into_response()
        }
        Ok((
            version,
            install_complete,
            users_ready,
            challenges_ready,
            runtime_control_plane_ready,
            user_mode_transitions_ready,
            email_verification_ready,
            objects_ready,
            object_operations_ready,
            ssh_host_control_plane_ready,
        )) => {
            warn!(
                observed_schema_version = ?version,
                expected_schema_version = SCHEMA_VERSION,
                install_complete,
                users_ready,
                challenges_ready,
                runtime_control_plane_ready,
                user_mode_transitions_ready,
                email_verification_ready,
                objects_ready,
                object_operations_ready,
                ssh_host_control_plane_ready,
                object_storage_ready,
                "API readiness check found an incompatible database schema"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "database": "available",
                    "object_storage": if object_storage_ready { "available" } else { "unavailable" },
                    "schema": "incompatible",
                    "expected_schema_version": SCHEMA_VERSION,
                    "observed_schema_version": version,
                    "install_complete": install_complete,
                    "required_tables": {
                        "users": users_ready,
                        "challenges": challenges_ready,
                        "runtime_control_plane": runtime_control_plane_ready,
                        "user_mode_transitions": user_mode_transitions_ready,
                        "email_verification_tokens": email_verification_ready,
                        "stored_objects": objects_ready,
                        "object_operations": object_operations_ready,
                        "ssh_host_control_plane": ssh_host_control_plane_ready,
                    },
                })),
            )
                .into_response()
        }
        Err(error) => {
            warn!(%error, "API readiness check could not verify the database schema");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "database": "unavailable_or_uninitialized",
                    "schema": "unverified",
                    "expected_schema_version": SCHEMA_VERSION,
                })),
            )
                .into_response()
        }
    }
}

async fn product_metadata(State(state): State<AppState>) -> Response {
    let schema_version = sqlx::query_scalar::<_, String>(
        "SELECT value FROM ctfzone.release_metadata WHERE key = 'schema_version'",
    )
    .fetch_optional(&state.database)
    .await;

    match schema_version {
        Ok(value) => Json(ApiEnvelope {
            success: true,
            data: ProductMetadata {
                name: PRODUCT_NAME,
                version: VERSION,
                api_status: "native",
                compatibility_backend: false,
                schema_version: value.unwrap_or_else(|| "unknown".to_owned()),
            },
        })
        .into_response(),
        Err(error) => {
            warn!(%error, "failed to read CTFZone schema metadata");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "success": false,
                    "error": { "code": "database_unavailable" }
                })),
            )
                .into_response()
        }
    }
}

async fn architecture() -> impl IntoResponse {
    Json(ApiEnvelope {
        success: true,
        data: architecture_data(),
    })
}

fn architecture_data() -> serde_json::Value {
    json!({
        "edge": "caddy",
        "frontend": {
            "technologies": ["html", "css", "javascript"],
            "served_by": "backend"
        },
        "backend": {
            "language": "python",
            "mode": "browser-bff",
            "database_access": false
        },
        "api": {
            "language": "rust",
            "status": "native",
            "presentation": "structured-json",
            "renderer_dependency": false
        },
        "controller": { "language": "rust", "status": "event-driven" },
        "database": { "engine": "postgresql", "schema": SCHEMA_VERSION }
    })
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ctfzone_api=info,tower_http=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

async fn shutdown_signal() {
    if let Err(error) = signal::ctrl_c().await {
        warn!(%error, "failed to install shutdown signal handler");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_workspace_version() {
        assert_eq!(VERSION, "1.0.0");
        assert_eq!(SCHEMA_VERSION, VERSION);
    }

    #[test]
    fn architecture_has_no_page_renderer_dependency() {
        let architecture = architecture_data();
        assert_eq!(architecture["frontend"]["served_by"], "backend");
        assert_eq!(architecture["backend"]["mode"], "browser-bff");
        assert_eq!(architecture["backend"]["database_access"], false);
        assert_eq!(architecture["api"]["renderer_dependency"], false);
        assert_eq!(architecture["api"]["presentation"], "structured-json");
    }
}
