mod auth;
mod browser_auth;
mod config;
mod error;
mod passwords;
mod rate_limit;
mod routes;
mod setup;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
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
    pub(crate) database: PgPool,
    pub(crate) http: Client,
    pub(crate) public_base_url: Url,
    pub(crate) rate_limiter: rate_limit::RateLimiter,
    pub(crate) setup_token: String,
    pub(crate) upload_folder: PathBuf,
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
        .redirect(Policy::none())
        .build()
        .context("failed to create internal HTTP client")?;

    let app = router(AppState {
        auth: auth::AuthConfig {
            secret_key: config.secret_key,
            session_cookie_name: config.session_cookie_name,
            session_lifetime_seconds: config.session_lifetime_seconds,
        },
        database,
        http,
        public_base_url: config.public_base_url,
        rate_limiter: rate_limit::RateLimiter::default(),
        setup_token: config.setup_token,
        upload_folder: config.upload_folder,
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
    let native_routes = routes::router(state.clone());
    let browser_auth_routes = browser_auth::router();

    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/api/v1/ctfzone", get(product_metadata))
        .route("/api/v1/ctfzone/architecture", get(architecture))
        .merge(browser_auth_routes)
        .merge(native_routes)
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
    match sqlx::query_as::<_, (Option<String>, bool, bool, bool, bool)>(
        r#"
        SELECT
            (SELECT value FROM ctfzone.release_metadata WHERE key = 'schema_version'),
            EXISTS(
                SELECT 1 FROM ctfzone.release_metadata
                WHERE key = 'install_complete' AND value = '1.0.0'
            ),
            to_regclass('ctfzone.users') IS NOT NULL,
            to_regclass('ctfzone.challenges') IS NOT NULL,
            to_regclass('ctfzone.runtime_instances') IS NOT NULL
        "#,
    )
    .fetch_one(&state.database)
    .await
    {
        Ok((Some(version), true, true, true, true)) if version == SCHEMA_VERSION => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "database": "available",
                "schema_version": version,
            })),
        )
            .into_response(),
        Ok((version, install_complete, users_ready, challenges_ready, runtimes_ready)) => {
            warn!(
                observed_schema_version = ?version,
                expected_schema_version = SCHEMA_VERSION,
                install_complete,
                users_ready,
                challenges_ready,
                runtimes_ready,
                "API readiness check found an incompatible database schema"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "database": "available",
                    "schema": "incompatible",
                    "expected_schema_version": SCHEMA_VERSION,
                    "observed_schema_version": version,
                    "install_complete": install_complete,
                    "required_tables": {
                        "users": users_ready,
                        "challenges": challenges_ready,
                        "runtime_instances": runtimes_ready,
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
