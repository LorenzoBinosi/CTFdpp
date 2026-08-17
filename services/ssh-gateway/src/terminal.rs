use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr},
    sync::{Arc, mpsc as std_mpsc},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use portable_pty::PtySize;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, watch},
    time::{Instant, MissedTickBehavior, interval, sleep, sleep_until, timeout, timeout_at},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    GatewayState,
    api::{TicketGrant, TicketPurpose},
    destination, identity, ssh,
};

pub(crate) const WEBSOCKET_PROTOCOL: &str = "ctfzone.ssh.v1";
const PREAUTH_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TICKET_BYTES: usize = 128;
const MAX_PTY_FRAME_BYTES: usize = 16 * 1024;
const PTY_QUEUE_DEPTH: usize = 64;
const MIN_COLS: u16 = 20;
const MAX_COLS: u16 = 500;
const MIN_ROWS: u16 = 5;
const MAX_ROWS: u16 = 200;

pub(crate) async fn upgrade(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    if *state.shutdown.borrow() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "SSH gateway is shutting down",
        )
            .into_response();
    }
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| state.config.origin_allowed(origin))
        .map(str::to_owned)
    else {
        return (StatusCode::FORBIDDEN, "WebSocket origin is not allowed").into_response();
    };
    let Some(client_ip) = forwarded_client_ip(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            "A canonical client address is required",
        )
            .into_response();
    };
    if !requested_protocol(&headers) {
        return (
            StatusCode::BAD_REQUEST,
            "The ctfzone.ssh.v1 WebSocket protocol is required",
        )
            .into_response();
    }
    if !state.client_ticket_limiter.allow(client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many SSH terminal connection attempts",
        )
            .into_response();
    }
    let Ok(preauth_permit) = Arc::clone(&state.preauth_connections).try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "SSH authentication capacity is full",
        )
            .into_response();
    };
    websocket
        .protocols([WEBSOCKET_PROTOCOL])
        .max_frame_size(MAX_PTY_FRAME_BYTES)
        .max_message_size(MAX_PTY_FRAME_BYTES)
        .on_upgrade(move |socket| session(socket, state, preauth_permit, peer, client_ip, origin))
}

async fn session(
    mut socket: WebSocket,
    state: GatewayState,
    preauth_permit: OwnedSemaphorePermit,
    peer: SocketAddr,
    client_ip: IpAddr,
    origin: String,
) {
    let local_session_id = Uuid::new_v4();
    let preauth_deadline = Instant::now() + PREAUTH_TIMEOUT;
    let mut auth = match receive_auth(&mut socket).await {
        Ok(auth) => auth,
        Err(code) => {
            send_error(&mut socket, code, "The terminal request was rejected").await;
            return;
        }
    };
    let raw_ticket = std::mem::take(&mut auth.ticket);
    let grant = match timeout_at(
        preauth_deadline,
        state.api.consume_ticket(&raw_ticket, client_ip, &origin),
    )
    .await
    {
        Ok(Ok(grant)) => grant,
        Ok(Err(error)) => {
            warn!(%peer, %local_session_id, error = %redacted_error(&error), "SSH ticket was rejected");
            send_error(
                &mut socket,
                "ticket_rejected",
                "The terminal ticket is invalid or expired",
            )
            .await;
            return;
        }
        Err(_) => {
            send_error(
                &mut socket,
                "auth_timeout",
                "SSH terminal authentication timed out",
            )
            .await;
            return;
        }
    };
    // The raw ticket leaves scope immediately after one atomic consume. It is
    // never placed in a URL, log field, child environment, or SSH argument.
    drop(raw_ticket);
    drop(preauth_permit);

    if *state.shutdown.borrow() {
        close_if_session(&state.api, grant.session_id, "gateway_shutdown").await;
        send_error(
            &mut socket,
            "gateway_shutdown",
            "The SSH gateway is shutting down",
        )
        .await;
        return;
    }
    let Ok(_active_permit) = Arc::clone(&state.active_sessions).try_acquire_owned() else {
        close_if_session(&state.api, grant.session_id, "gateway_capacity").await;
        send_error(
            &mut socket,
            "capacity_full",
            "SSH session capacity is full; request a new ticket and retry",
        )
        .await;
        return;
    };

    if let Err(error) = run_grant(&mut socket, &state, grant, auth, local_session_id).await {
        warn!(%peer, %local_session_id, error = %redacted_error(&error), "SSH WebSocket session failed");
    }
}

async fn run_grant(
    socket: &mut WebSocket,
    state: &GatewayState,
    grant: TicketGrant,
    auth: AuthFrame,
    local_session_id: Uuid,
) -> Result<()> {
    let api_session_id = match grant.purpose {
        TicketPurpose::Probe => None,
        TicketPurpose::Terminal => match grant.session_id {
            Some(session_id) => Some(session_id),
            None => {
                send_error(socket, "invalid_ticket", "The terminal ticket is invalid").await;
                bail!("terminal grant did not include an API session ID");
            }
        },
    };
    let address = match destination::resolve(&state.config, &grant.hostname, grant.ssh_port).await {
        Ok(address) => address,
        Err(error) => {
            close_if_session(&state.api, api_session_id, "destination_denied").await;
            send_error(
                socket,
                "destination_denied",
                "The registered SSH destination is not allowed",
            )
            .await;
            return Err(error);
        }
    };
    let observed_key = match ssh::probe_host_key(&state.config, address).await {
        Ok(key) => key,
        Err(error) => {
            close_if_session(&state.api, api_session_id, "host_key_probe_failed").await;
            send_error(
                socket,
                "host_key_probe_failed",
                "The SSH host key could not be read",
            )
            .await;
            return Err(error);
        }
    };

    if grant.purpose == TicketPurpose::Probe {
        let receipt = state
            .api
            .report_host_key(grant.host_id, grant.ticket_id, &observed_key.public_key)
            .await
            .context("failed to record SSH host-key candidate")?;
        send_control(
            socket,
            &HostKeyFrame {
                kind: "host_key",
                session_id: local_session_id,
                candidate_id: receipt.candidate_id,
                host_revision: receipt.host_revision,
                algorithm: "ssh-ed25519",
                public_key: &observed_key.public_key,
                fingerprint: &observed_key.fingerprint,
            },
        )
        .await?;
        return Ok(());
    }

    let api_session_id = api_session_id.expect("terminal ticket checked above");
    let trusted_key = match ssh::trusted_host_key(&grant) {
        Ok(key) => key,
        Err(error) => {
            close_report(&state.api, api_session_id, "host_key_untrusted", 0, 0, None).await;
            send_error(
                socket,
                "host_key_untrusted",
                "Trust the SSH host key before connecting",
            )
            .await;
            return Err(error);
        }
    };
    if observed_key != trusted_key {
        let _ = state
            .api
            .report_host_key(grant.host_id, grant.ticket_id, &observed_key.public_key)
            .await;
        close_report(&state.api, api_session_id, "host_key_mismatch", 0, 0, None).await;
        send_error(
            socket,
            "host_key_mismatch",
            "The SSH host key changed; connection was blocked",
        )
        .await;
        bail!("observed SSH host key did not match the pinned key");
    }

    let private_key = match identity::validate_identity_binding(
        &state.config.identity_directory,
        grant.host_id,
        &grant.identity_public_key,
        &grant.identity_fingerprint,
    )
    .await
    {
        Ok(path) => path,
        Err(error) => {
            let rotation_result = identity::mark_identity_for_rotation(
                &state.config.identity_directory,
                grant.host_id,
            )
            .await;
            let invalidation_result = state
                .api
                .report_identity_invalid(
                    grant.host_id,
                    error.error_code(),
                    error.observed_fingerprint(),
                )
                .await;
            close_report(
                &state.api,
                api_session_id,
                "identity_unavailable",
                0,
                0,
                None,
            )
            .await;
            send_error(
                socket,
                "identity_unavailable",
                "The SSH identity is unavailable",
            )
            .await;
            rotation_result.context("failed to mark invalid SSH identity for rotation")?;
            invalidation_result.context("failed to invalidate SSH identity metadata")?;
            return Err(anyhow::Error::new(error));
        }
    };
    if let Err(error) = ssh::preflight(
        &state.config,
        &grant,
        address,
        &private_key,
        &trusted_key,
        local_session_id,
    )
    .await
    {
        close_report(
            &state.api,
            api_session_id,
            "authentication_failed",
            0,
            0,
            None,
        )
        .await;
        send_error(
            socket,
            "authentication_failed",
            "SSH public-key authentication failed",
        )
        .await;
        return Err(error);
    }

    let config = (*state.config).clone();
    let terminal_grant = grant.clone();
    let private_key_for_spawn = private_key.clone();
    let trusted_key_for_spawn = trusted_key.clone();
    let rows = auth.rows;
    let cols = auth.cols;
    let mut terminal = match tokio::task::spawn_blocking(move || {
        ssh::spawn_terminal(
            &config,
            &terminal_grant,
            address,
            &private_key_for_spawn,
            &trusted_key_for_spawn,
            local_session_id,
            PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
    })
    .await
    {
        Ok(Ok(terminal)) => terminal,
        Ok(Err(error)) => {
            close_report(&state.api, api_session_id, "ssh_start_failed", 0, 0, None).await;
            send_error(
                socket,
                "ssh_start_failed",
                "The SSH terminal could not be started",
            )
            .await;
            return Err(error);
        }
        Err(error) => {
            close_report(&state.api, api_session_id, "ssh_start_failed", 0, 0, None).await;
            send_error(
                socket,
                "ssh_start_failed",
                "The SSH terminal could not be started",
            )
            .await;
            return Err(error).context("PTY startup task panicked");
        }
    };
    if let Err(error) = state.api.report_connected(api_session_id).await {
        terminal.terminate();
        close_report(
            &state.api,
            api_session_id,
            "control_plane_unavailable",
            0,
            0,
            None,
        )
        .await;
        send_error(
            socket,
            "control_plane_unavailable",
            "The SSH session could not be authorized",
        )
        .await;
        return Err(error).context("failed to report connected SSH session");
    }
    if let Err(error) = send_control(
        socket,
        &ReadyFrame {
            kind: "ready",
            session_id: api_session_id,
            host_key_fingerprint: &trusted_key.fingerprint,
        },
    )
    .await
    {
        terminal.terminate();
        close_report(
            &state.api,
            api_session_id,
            "browser_disconnected",
            0,
            0,
            None,
        )
        .await;
        return Err(error);
    }

    bridge_terminal(
        socket,
        state,
        grant,
        terminal,
        api_session_id,
        local_session_id,
    )
    .await
}

async fn bridge_terminal(
    socket: &mut WebSocket,
    state: &GatewayState,
    grant: TicketGrant,
    mut terminal: ssh::PtySession,
    api_session_id: Uuid,
    local_session_id: Uuid,
) -> Result<()> {
    let ssh::PtyParts {
        master,
        mut reader,
        mut writer,
    } = match terminal.take_parts() {
        Ok(parts) => parts,
        Err(error) => {
            terminal.terminate();
            close_report(&state.api, api_session_id, "ssh_start_failed", 0, 0, None).await;
            return Err(error);
        }
    };
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(PTY_QUEUE_DEPTH);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buffer = vec![0_u8; MAX_PTY_FRAME_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => {
                    if output_tx.blocking_send(buffer[..count].to_vec()).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                // Linux PTYs commonly return EIO after the slave closes.
                Err(_) => return,
            }
        }
    });
    let (input_tx, input_rx) = std_mpsc::sync_channel::<Vec<u8>>(PTY_QUEUE_DEPTH);
    let writer_task = tokio::task::spawn_blocking(move || {
        while let Ok(value) = input_rx.recv() {
            if writer.write_all(&value).is_err() || writer.flush().is_err() {
                return;
            }
        }
    });
    let idle_seconds = grant
        .idle_timeout_seconds
        .max(1)
        .min(state.config.idle_timeout.as_secs());
    let absolute_seconds = grant
        .absolute_timeout_seconds
        .max(1)
        .min(state.config.maximum_session.as_secs());
    let mut idle = Box::pin(sleep_until(
        Instant::now() + Duration::from_secs(idle_seconds),
    ));
    let absolute = sleep_until(Instant::now() + Duration::from_secs(absolute_seconds));
    tokio::pin!(absolute);
    let mut heartbeat = interval(state.config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut child_poll = interval(Duration::from_millis(200));
    child_poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut missed_heartbeats = 0_u8;
    let mut bytes_from_browser = 0_u64;
    let mut bytes_to_browser = 0_u64;
    let mut exit_code = None;
    let reason;
    let mut shutdown = state.shutdown.clone();

    loop {
        tokio::select! {
            biased;
            () = shutdown_requested(&mut shutdown) => {
                reason = "gateway_shutdown";
                break;
            }
            () = &mut absolute => {
                reason = "session_timeout";
                break;
            }
            () = &mut idle => {
                reason = "idle_timeout";
                break;
            }
            _ = heartbeat.tick() => {
                match state.api.heartbeat(api_session_id, bytes_from_browser, bytes_to_browser).await {
                    Ok(true) => missed_heartbeats = 0,
                    Ok(false) => {
                        reason = "session_revoked";
                        break;
                    }
                    Err(_) => {
                        missed_heartbeats = missed_heartbeats.saturating_add(1);
                        if missed_heartbeats >= 2 {
                            reason = "control_plane_unavailable";
                            break;
                        }
                    }
                }
            }
            _ = child_poll.tick() => {
                match terminal.try_wait() {
                    Ok(Some(status)) => {
                        terminal.disarm_after_wait();
                        exit_code = Some(status.exit_code().min(i32::MAX as u32) as i32);
                        reason = "remote_exit";
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        reason = "ssh_wait_failed";
                        break;
                    }
                }
            }
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Binary(value))) => {
                        if value.len() > MAX_PTY_FRAME_BYTES {
                            reason = "input_too_large";
                            break;
                        }
                        bytes_from_browser = bytes_from_browser.saturating_add(value.len() as u64);
                        match input_tx.try_send(value.to_vec()) {
                            Ok(()) => idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds)),
                            Err(std_mpsc::TrySendError::Full(_)) => {
                                reason = "input_backpressure";
                                break;
                            }
                            Err(std_mpsc::TrySendError::Disconnected(_)) => {
                                reason = "ssh_input_closed";
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Text(value))) => {
                        match serde_json::from_str::<ClientControl>(value.as_str()) {
                            Ok(ClientControl::Resize { cols, rows }) if valid_dimensions(cols, rows) => {
                                if master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).is_err() {
                                    reason = "resize_failed";
                                    break;
                                }
                                idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds));
                            }
                            _ => {
                                reason = "invalid_control";
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(_)) | Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        reason = "browser_disconnected";
                        break;
                    }
                }
            }
            output = output_rx.recv() => {
                let Some(output) = output else {
                    match wait_for_terminal_exit(&mut terminal).await {
                        Ok(Some(code)) => {
                            terminal.disarm_after_wait();
                            exit_code = Some(code);
                            reason = "remote_exit";
                        }
                        Ok(None) => reason = "ssh_output_closed",
                        Err(_) => reason = "ssh_wait_failed",
                    }
                    break;
                };
                bytes_to_browser = bytes_to_browser.saturating_add(output.len() as u64);
                match timeout(WRITE_TIMEOUT, socket.send(Message::Binary(output.into()))).await {
                    Ok(Ok(())) => idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds)),
                    _ => {
                        reason = "slow_browser";
                        break;
                    }
                }
            }
        }
    }

    if reason != "remote_exit" {
        terminal.terminate();
    }
    drop(input_tx);
    drop(master);
    if reason == "remote_exit" {
        let _ = send_control(
            socket,
            &ExitFrame {
                kind: "exit",
                code: exit_code.unwrap_or(1),
            },
        )
        .await;
    } else if reason != "browser_disconnected" {
        send_error(socket, reason, close_message(reason)).await;
    }
    close_report(
        &state.api,
        api_session_id,
        reason,
        bytes_from_browser,
        bytes_to_browser,
        exit_code,
    )
    .await;
    reader_task.abort();
    writer_task.abort();
    info!(%api_session_id, %local_session_id, %reason, bytes_from_browser, bytes_to_browser, "SSH terminal session closed");
    Ok(())
}

async fn wait_for_terminal_exit(terminal: &mut ssh::PtySession) -> Result<Option<i32>> {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if let Some(status) = terminal.try_wait()? {
            return Ok(Some(status.exit_code().min(i32::MAX as u32) as i32));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

async fn receive_auth(socket: &mut WebSocket) -> std::result::Result<AuthFrame, &'static str> {
    let message = timeout(PREAUTH_TIMEOUT, socket.recv())
        .await
        .map_err(|_| "authentication_timeout")?
        .ok_or("authentication_missing")?
        .map_err(|_| "authentication_invalid")?;
    let Message::Text(value) = message else {
        return Err("authentication_invalid");
    };
    let auth =
        serde_json::from_str::<AuthFrame>(value.as_str()).map_err(|_| "authentication_invalid")?;
    if auth.kind != "auth"
        || !valid_ticket(&auth.ticket)
        || !valid_dimensions(auth.cols, auth.rows)
        || !matches!(auth.term.as_str(), "xterm" | "xterm-256color")
    {
        return Err("authentication_invalid");
    }
    Ok(auth)
}

fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return None;
    }
    value.split(',').next()?.trim().parse().ok()
}

fn requested_protocol(headers: &HeaderMap) -> bool {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|value| value == WEBSOCKET_PROTOCOL)
        })
}

fn valid_ticket(value: &str) -> bool {
    (43..=MAX_TICKET_BYTES).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn valid_dimensions(cols: u16, rows: u16) -> bool {
    (MIN_COLS..=MAX_COLS).contains(&cols) && (MIN_ROWS..=MAX_ROWS).contains(&rows)
}

async fn close_report(
    api: &crate::api::ApiClient,
    session_id: Uuid,
    reason: &str,
    bytes_from_browser: u64,
    bytes_to_browser: u64,
    exit_code: Option<i32>,
) {
    if let Err(error) = api
        .report_closed(
            session_id,
            reason,
            bytes_from_browser,
            bytes_to_browser,
            exit_code,
        )
        .await
    {
        warn!(%session_id, error = %redacted_error(&error), "failed to report closed SSH session");
    }
}

async fn close_if_session(api: &crate::api::ApiClient, session_id: Option<Uuid>, reason: &str) {
    if let Some(session_id) = session_id {
        close_report(api, session_id, reason, 0, 0, None).await;
    }
}

fn close_message(reason: &str) -> &'static str {
    match reason {
        "idle_timeout" => "The SSH session was closed after being idle",
        "session_timeout" => "The SSH session reached its maximum duration",
        "session_revoked" => "The SSH session was revoked",
        "control_plane_unavailable" => "The SSH session could not be reauthorized",
        "gateway_shutdown" => "The SSH gateway is shutting down",
        "slow_browser" | "input_backpressure" => {
            "The SSH session could not keep up with the connection"
        }
        _ => "The SSH session ended",
    }
}

fn redacted_error(error: &anyhow::Error) -> &'static str {
    if error.chain().count() > 1 {
        "gateway_operation_failed"
    } else {
        "gateway_request_failed"
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthFrame {
    #[serde(rename = "type")]
    kind: String,
    ticket: String,
    cols: u16,
    rows: u16,
    term: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientControl {
    Resize { cols: u16, rows: u16 },
}

#[derive(Serialize)]
struct ControlError<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct HostKeyFrame<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: Uuid,
    candidate_id: Uuid,
    host_revision: i64,
    algorithm: &'a str,
    public_key: &'a str,
    fingerprint: &'a str,
}

#[derive(Serialize)]
struct ReadyFrame<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: Uuid,
    host_key_fingerprint: &'a str,
}

#[derive(Serialize)]
struct ExitFrame<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    code: i32,
}

async fn send_error(socket: &mut WebSocket, code: &str, message: &str) {
    let _ = send_control(
        socket,
        &ControlError {
            kind: "error",
            code,
            message,
        },
    )
    .await;
}

async fn send_control(socket: &mut WebSocket, value: &impl Serialize) -> Result<()> {
    let encoded = serde_json::to_string(value)?;
    timeout(WRITE_TIMEOUT, socket.send(Message::Text(encoded.into())))
        .await
        .context("WebSocket control write timed out")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_protocol_and_auth_are_bounded() {
        assert_eq!(WEBSOCKET_PROTOCOL, "ctfzone.ssh.v1");
        assert!(!WEBSOCKET_PROTOCOL.contains("ticket"));
        assert!(valid_ticket(&"A".repeat(43)));
        assert!(!valid_ticket("short"));
        assert!(!valid_ticket(&format!("{}=", "A".repeat(43))));
        assert!(valid_dimensions(120, 40));
        assert!(!valid_dimensions(501, 40));
    }

    #[test]
    fn forwarded_address_accepts_only_a_canonical_first_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.8, 172.20.0.3".parse().unwrap(),
        );
        assert_eq!(
            forwarded_client_ip(&headers),
            Some("203.0.113.8".parse().unwrap())
        );
        headers.insert("x-forwarded-for", "bad-address".parse().unwrap());
        assert_eq!(forwarded_client_ip(&headers), None);
    }

    #[test]
    fn auth_and_resize_reject_unknown_fields() {
        let auth = r#"{"type":"auth","ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","cols":80,"rows":24,"term":"xterm-256color","private_key":"bad"}"#;
        assert!(serde_json::from_str::<AuthFrame>(auth).is_err());
        assert!(
            serde_json::from_str::<ClientControl>(
                r#"{"type":"resize","cols":80,"rows":24,"command":"id"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn control_plane_and_deadlines_precede_data_in_biased_bridge() {
        let source = include_str!("terminal.rs");
        let data = source.find("message = socket.recv()").unwrap();
        for control in [
            "shutdown_requested(&mut shutdown)",
            "() = &mut absolute",
            "() = &mut idle",
            "_ = heartbeat.tick()",
        ] {
            assert!(
                source.find(control).unwrap() < data,
                "{control} may be starved"
            );
        }
    }

    #[test]
    fn upgrade_admission_and_active_capacity_are_ordered() {
        let source = include_str!("terminal.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let origin = production.find("let Some(origin)").unwrap();
        let client_ip = production.find("let Some(client_ip)").unwrap();
        let protocol = production.find("if !requested_protocol(&headers)").unwrap();
        let rate_limit = production
            .find("state.client_ticket_limiter.allow(client_ip)")
            .unwrap();
        let preauth = source.find("state.preauth_connections").unwrap();
        let consume = source.find(".consume_ticket(").unwrap();
        let active = source.find("state.active_sessions").unwrap();
        assert!(origin < client_ip);
        assert!(client_ip < protocol);
        assert!(protocol < rate_limit);
        assert_eq!(
            production
                .matches("state.client_ticket_limiter.allow(client_ip)")
                .count(),
            1
        );
        assert!(rate_limit < preauth);
        assert!(preauth < consume);
        assert!(consume < active);
        assert!(source.contains("timeout_at(\n        preauth_deadline,"));
        assert_eq!(PREAUTH_TIMEOUT, Duration::from_secs(5));
    }
}
