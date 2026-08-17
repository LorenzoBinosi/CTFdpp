mod api;
mod config;
mod destination;
mod identity;
mod rate_limit;
mod ssh;
mod terminal;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use api::ApiClient;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use config::Config;
use serde_json::json;
use tokio::{
    net::TcpListener,
    signal,
    sync::{Semaphore, watch},
    time::timeout,
};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const MAX_PREAUTH_CONNECTIONS: usize = 128;

#[derive(Clone)]
pub(crate) struct GatewayState {
    config: Arc<Config>,
    api: ApiClient,
    active_sessions: Arc<Semaphore>,
    preauth_connections: Arc<Semaphore>,
    client_ticket_limiter: Arc<rate_limit::ClientTicketLimiter>,
    shutdown: watch::Receiver<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let config = Arc::new(Config::from_env()?);
    identity::prepare_root(&config.identity_directory).await?;
    ensure_command("ssh").await?;
    ensure_command("ssh-keygen").await?;
    ensure_command("ssh-keyscan").await?;

    let gateway_instance_id = Uuid::new_v4();
    let api = ApiClient::new(&config, gateway_instance_id)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = GatewayState {
        config: Arc::clone(&config),
        api: api.clone(),
        active_sessions: Arc::new(Semaphore::new(config.maximum_sessions)),
        preauth_connections: Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS)),
        client_ticket_limiter: Arc::new(rate_limit::ClientTicketLimiter::new()),
        shutdown: shutdown_rx.clone(),
    };
    let identity_config = (*config).clone();
    let identity_shutdown = shutdown_rx.clone();
    let mut identity_task = tokio::spawn(async move {
        tokio::select! {
            result = identity::run(identity_config, api) => result,
            _ = wait_for_shutdown(identity_shutdown) => Ok(()),
        }
    });

    let request_id_header = axum::http::HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/terminal", get(terminal::upgrade))
        .with_state(state)
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(TraceLayer::new_for_http());
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("failed to bind SSH gateway to {}", config.bind_address))?;
    info!(
        version = VERSION,
        address = %config.bind_address,
        %gateway_instance_id,
        "CTFZone SSH gateway started"
    );
    let server_shutdown = shutdown_rx;
    let mut server_task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(server_shutdown))
        .await
    });

    tokio::select! {
        () = shutdown_signal() => {
            info!("SSH gateway shutdown requested");
            shutdown_tx.send(true).ok();
            if timeout(SHUTDOWN_GRACE, &mut server_task).await.is_err() {
                warn!("SSH gateway graceful shutdown timed out");
                server_task.abort();
                let _ = server_task.await;
            }
            if timeout(SHUTDOWN_GRACE, &mut identity_task).await.is_err() {
                identity_task.abort();
                let _ = identity_task.await;
            }
        }
        result = &mut server_task => {
            shutdown_tx.send(true).ok();
            identity_task.await.context("identity worker task panicked")??;
            result.context("SSH gateway HTTP task panicked")??;
        }
        result = &mut identity_task => {
            shutdown_tx.send(true).ok();
            if timeout(SHUTDOWN_GRACE, &mut server_task).await.is_err() {
                warn!("SSH gateway HTTP shutdown timed out after identity worker exit");
                server_task.abort();
                let _ = server_task.await;
            }
            result.context("identity worker task panicked")??;
            anyhow::bail!("SSH identity worker stopped unexpectedly");
        }
    }
    Ok(())
}

async fn health() -> Response {
    Json(json!({
        "status": "ok",
        "service": "ssh-gateway",
        "version": VERSION,
    }))
    .into_response()
}

async fn readiness(State(state): State<GatewayState>) -> Response {
    let ready = state.api.ready().await;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "service": "ssh-gateway",
            "api_connected": ready,
        })),
    )
        .into_response()
}

async fn ensure_command(command: &str) -> Result<()> {
    let status = tokio::process::Command::new(command)
        .arg("-V")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .with_context(|| format!("required command is unavailable: {command}"))?;
    // ssh-keygen/ssh-keyscan use a non-zero status for `-V` on some releases;
    // successfully spawning them is the readiness property we need here.
    if !status.success() {
        info!(%command, %status, "command probe exited non-zero after successful spawn");
    }
    Ok(())
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
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ctfzone_ssh_gateway=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_workspace() {
        assert_eq!(VERSION, "1.0.0");
    }

    #[test]
    fn public_websocket_proxy_strips_browser_and_control_plane_credentials() {
        let caddy = include_str!("../../../Caddyfile");
        let ssh_matcher = caddy
            .split_once("@ssh_terminal {")
            .expect("Caddy exposes a structured SSH terminal matcher")
            .1
            .split_once("\n\t\t}")
            .expect("SSH terminal matcher is bounded")
            .0;
        for requirement in [
            "path /bff/ssh/terminal",
            "method GET",
            "header Connection *Upgrade*",
            "header Upgrade websocket",
            "header Sec-WebSocket-Protocol ctfzone.ssh.v1",
        ] {
            assert!(
                ssh_matcher.contains(requirement),
                "Caddy SSH matcher must require {requirement}"
            );
        }

        let ssh_route = caddy
            .split_once("@ssh_terminal")
            .expect("Caddy exposes the SSH terminal matcher")
            .1
            .split_once("\n\t\thandle {")
            .expect("SSH terminal route precedes the generic backend route")
            .0;
        for header in [
            "Cookie",
            "Authorization",
            "Proxy-Authorization",
            "Csrf-Token",
            "X-Ctfzone-Backend-Token",
            "X-Ctfzone-Ssh-Gateway-Token",
            "X-Ctfzone-Session",
            "X-Ctfzone-Browser-Request-Id",
        ] {
            assert!(
                ssh_route.contains(&format!("header_up -{header}")),
                "Caddy must strip {header} before the SSH gateway"
            );
        }

        let proxy = caddy
            .find("handle @ssh_terminal")
            .expect("Caddy proxies validated SSH WebSockets");
        let plain_http_rejection = caddy
            .find("handle /bff/ssh/terminal")
            .expect("Caddy rejects plain HTTP on the SSH terminal path");
        let generic_backend = caddy
            .find("\n\t\thandle {\n\t\t\treverse_proxy backend:8000")
            .expect("Caddy retains the generic backend route");
        assert!(proxy < plain_http_rejection);
        assert!(plain_http_rejection < generic_backend);
        assert!(
            caddy[plain_http_rejection..generic_backend]
                .contains("respond \"SSH terminal WebSocket upgrade required\" 400")
        );
    }
}
