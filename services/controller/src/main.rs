mod config;
mod journal;
mod remote;
mod state;
mod storage;
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
use tokio::{net::TcpListener, signal, sync::watch};
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
    let storage_config = storage::StorageConfig::from_env(&config)?;
    let status = SharedStatus::new();
    let journal = Arc::new(OperationJournal::open(config.journal_path.clone()).await?);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut worker_task = tokio::spawn(worker::run(
        config.clone(),
        status.clone(),
        journal,
        shutdown_rx.clone(),
    ));
    let mut storage_task = tokio::spawn(storage::run(
        storage_config,
        status.clone(),
        shutdown_rx.clone(),
    ));

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
    let mut server_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
            .await
    });

    tokio::select! {
        () = shutdown_signal() => {
            info!("controller shutdown requested");
            shutdown_tx.send(true).ok();
            server_task.await.context("controller HTTP task panicked")??;
            worker_task.await.context("controller worker task panicked")??;
            storage_task.await.context("object maintenance task panicked")??;
            Ok(())
        }
        worker_result = &mut worker_task => {
            shutdown_tx.send(true).ok();
            server_task.await.context("controller HTTP task panicked")??;
            storage_task.await.context("object maintenance task panicked")??;
            worker_result.context("controller worker task panicked")??;
            anyhow::bail!("controller worker stopped unexpectedly")
        }
        storage_result = &mut storage_task => {
            shutdown_tx.send(true).ok();
            server_task.await.context("controller HTTP task panicked")??;
            worker_task.await.context("controller worker task panicked")??;
            storage_result.context("object maintenance task panicked")??;
            anyhow::bail!("object maintenance worker stopped unexpectedly")
        }
        server_result = &mut server_task => {
            shutdown_tx.send(true).ok();
            worker_task.await.context("controller worker task panicked")??;
            storage_task.await.context("object maintenance task panicked")??;
            server_result.context("controller HTTP task panicked")??;
            anyhow::bail!("controller HTTP server stopped unexpectedly")
        }
    }
}

async fn health(State(state): State<HttpState>) -> Response {
    let status = state.status.snapshot().await;
    Json(json!({
        "status": "ok",
        "service": "controller",
        "version": VERSION,
        "mode": status.mode,
        "database_connected": status.database_connected,
        "object_storage_connected": status.object_storage_connected,
    }))
    .into_response()
}

async fn readiness(State(state): State<HttpState>) -> Response {
    let status = state.status.snapshot().await;
    let ready = status.database_connected
        && status.initial_reconciliation_complete
        && status.object_storage_connected
        && status.storage_initial_reconciliation_complete
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
            "object_storage_connected": status.object_storage_connected,
            "storage_initial_reconciliation_complete": status.storage_initial_reconciliation_complete,
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

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
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
