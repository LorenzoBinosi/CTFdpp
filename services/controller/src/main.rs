mod config;
mod journal;
mod remote;
mod state;
mod worker;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use config::Config;
use journal::OperationJournal;
use serde_json::json;
use state::{ControllerMode, SharedStatus};
use tokio::{net::TcpListener, signal};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
struct HttpState {
    status: SharedStatus,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let config = Config::from_env()?;
    let status = SharedStatus::new();
    let journal = Arc::new(OperationJournal::open(config.journal_path.clone()).await?);

    tokio::spawn(worker::run(config.clone(), status.clone(), journal));

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/status", get(controller_status))
        .with_state(HttpState { status });
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("failed to bind controller to {}", config.bind_address))?;
    info!(
        version = VERSION,
        address = %config.bind_address,
        remote_driver = ?config.remote_driver,
        "CTFZone controller started"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("controller HTTP server failed")?;
    Ok(())
}

async fn health(State(state): State<HttpState>) -> Response {
    let status = state.status.snapshot().await;
    Json(json!({
        "status": "ok",
        "service": "controller",
        "version": VERSION,
        "mode": status.mode,
        "database_connected": status.database_connected,
    }))
    .into_response()
}

async fn readiness(State(state): State<HttpState>) -> Response {
    let status = state.status.snapshot().await;
    let ready = status.database_connected
        && status.initial_reconciliation_complete
        && !matches!(
            status.mode,
            ControllerMode::Starting | ControllerMode::Degraded
        );
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "service": "controller",
            "mode": status.mode,
            "database_connected": status.database_connected,
            "initial_reconciliation_complete": status.initial_reconciliation_complete,
        })),
    )
        .into_response()
}

async fn controller_status(State(state): State<HttpState>) -> Response {
    Json(json!({
        "success": true,
        "data": state.status.snapshot().await,
        "version": VERSION,
    }))
    .into_response()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ctfzone_controller=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_workspace_version() {
        assert_eq!(VERSION, "1.0.0");
    }
}
