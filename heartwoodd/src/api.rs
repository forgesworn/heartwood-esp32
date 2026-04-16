// heartwoodd/src/api.rs
//
// HTTP management API for Sapwood. Runs alongside the relay event loop.
// All signing operations are delegated to the SigningBackend abstraction,
// which handles both Hard (ESP32 serial) and Soft (local keyfile) modes.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::backend::{BackendError, SigningBackend, Tier};
use crate::serial::RawSerial;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<dyn SigningBackend>,
    pub daemon_info: Arc<DaemonInfo>,
    pub log_tx: broadcast::Sender<String>,
    /// Optional bearer token. When Some, protected /api/* routes require
    /// `Authorization: Bearer <token>`. When None, the API is open.
    pub api_token: Option<Arc<String>>,
    /// Path to the backup file (e.g. /var/lib/heartwood/backup.json).
    pub backup_path: std::path::PathBuf,
    /// Path to the passphrase file (e.g. /var/lib/heartwood/backup-passphrase.json).
    pub passphrase_path: std::path::PathBuf,
}

pub struct DaemonInfo {
    pub tier: Tier,
    pub relays: Vec<String>,
    pub start_time: Instant,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    masters: serde_json::Value,
    daemon: DaemonInfoResponse,
}

#[derive(Serialize)]
struct DaemonInfoResponse {
    tier: String,
    relays: Vec<String>,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct CreateSlotBody {
    label: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdateSlotBody {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    allowed_kinds: Option<Vec<u64>>,
    #[serde(default)]
    auto_approve: Option<bool>,
}

#[derive(Deserialize)]
struct UnlockBody {
    passphrase: String,
}

#[derive(Deserialize)]
struct CreateMasterBody {
    label: String,
}

#[derive(Deserialize)]
struct ApprovalAction {
    action: String,
}

#[derive(Deserialize)]
struct ChangePassphraseBody {
    old_passphrase: String,
    new_passphrase: String,
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn api_err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorResponse { error: msg.into() })).into_response()
}

fn backend_to_http(err: BackendError) -> Response {
    match err {
        BackendError::NotSupported => {
            api_err(StatusCode::NOT_FOUND, "not supported in this tier")
        }
        BackendError::Locked => {
            api_err(StatusCode::SERVICE_UNAVAILABLE, "daemon is locked -- unlock via Sapwood")
        }
        BackendError::DeviceBusy => {
            api_err(StatusCode::LOCKED, "device busy -- signing in progress")
        }
        BackendError::DeviceTimeout => {
            api_err(StatusCode::GATEWAY_TIMEOUT, "device did not respond")
        }
        BackendError::Denied => {
            api_err(StatusCode::FORBIDDEN, "request denied")
        }
        BackendError::UserCancelled => {
            api_err(StatusCode::CONFLICT, "user did not confirm the operation")
        }
        BackendError::PendingApproval(id) => {
            (StatusCode::ACCEPTED, Json(serde_json::json!({"pending_approval": id}))).into_response()
        }
        BackendError::Internal(msg) => {
            api_err(StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Public: basic daemon info without secrets (tier, locked state, relays, uptime).
async fn get_info(State(state): State<AppState>) -> Response {
    let info = &state.daemon_info;
    Json(serde_json::json!({
        "tier": info.tier.to_string(),
        "locked": state.backend.is_locked(),
        "relays": info.relays,
        "uptime_secs": info.start_time.elapsed().as_secs(),
    })).into_response()
}

/// Protected: list all provisioned masters and daemon summary.
async fn get_status(State(state): State<AppState>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        state.backend.list_masters().map(|masters| {
            let info = &state.daemon_info;
            Json(StatusResponse {
                masters: serde_json::Value::Array(masters),
                daemon: DaemonInfoResponse {
                    tier: info.tier.to_string(),
                    relays: info.relays.clone(),
                    uptime_secs: info.start_time.elapsed().as_secs(),
                },
            }).into_response()
        })
    }).await.unwrap();

    match result {
        Ok(resp) => resp,
        Err(e) => backend_to_http(e),
    }
}

/// Protected: unlock the backend with a passphrase (Soft mode only).
async fn post_unlock(State(state): State<AppState>, Json(body): Json<UnlockBody>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        state.backend.unlock(&body.passphrase)
    }).await.unwrap();

    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: lock the backend, clearing in-memory key material.
async fn post_lock(State(state): State<AppState>) -> Response {
    match state.backend.lock() {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: create a new master (Soft mode only).
async fn create_master(State(state): State<AppState>, Json(body): Json<CreateMasterBody>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        state.backend.create_master(&body.label)
    }).await.unwrap();

    match result {
        Ok(master) => (StatusCode::CREATED, Json(master)).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: list all connection slots for a master.
async fn get_slots(State(state): State<AppState>, Path(master): Path<u8>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        state.backend.list_slots(master)
    }).await.unwrap();

    match result {
        Ok(slots) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&slots).unwrap_or_default()).into_response()
        }
        Err(e) => backend_to_http(e),
    }
}

/// Protected: create a new connection slot for a master.
async fn create_slot(
    State(state): State<AppState>,
    Path(master): Path<u8>,
    Json(body): Json<CreateSlotBody>,
) -> Response {
    let snapshot_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        state.backend.create_slot(master, &body.label)
    }).await.unwrap();

    match result {
        Ok(slot) => {
            trigger_auto_snapshot(snapshot_state);
            (StatusCode::CREATED, [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&slot).unwrap_or_default()).into_response()
        }
        Err(e) => backend_to_http(e),
    }
}

/// Protected: update label and/or policy fields of an existing connection slot.
async fn update_slot(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
    Json(body): Json<UpdateSlotBody>,
) -> Response {
    let snapshot_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let patch = serde_json::to_value(&body).unwrap_or(serde_json::Value::Object(Default::default()));
        state.backend.update_slot(master, index, patch)
    }).await.unwrap();

    match result {
        Ok(slot) => {
            trigger_auto_snapshot(snapshot_state);
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&slot).unwrap_or_default()).into_response()
        }
        Err(e) => backend_to_http(e),
    }
}

/// Protected: revoke (delete) a connection slot.
async fn delete_slot(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
) -> Response {
    let snapshot_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        state.backend.revoke_slot(master, index)
    }).await.unwrap();

    match result {
        Ok(slot) => {
            trigger_auto_snapshot(snapshot_state);
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&slot).unwrap_or_default()).into_response()
        }
        Err(e) => backend_to_http(e),
    }
}

/// Protected: return the full bunker URI for a specific connection slot (including secret).
/// Relay URLs come from the daemon config so the client always has up-to-date relay info.
async fn get_slot_uri(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let relays = state.daemon_info.relays.clone();
        state.backend.get_slot_uri(master, index, &relays)
    }).await.unwrap();

    match result {
        Ok(uri) => Json(serde_json::json!({ "bunker_uri": uri })).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: list pending approval requests (Soft mode; Hard mode always returns empty).
async fn get_approvals(State(state): State<AppState>) -> Response {
    Json(state.backend.list_approvals()).into_response()
}

/// Protected: approve or deny a pending request.
async fn post_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ApprovalAction>,
) -> Response {
    let result = match body.action.as_str() {
        "approve" => state.backend.approve_request(&id),
        "deny" => state.backend.deny_request(&id),
        _ => return api_err(StatusCode::BAD_REQUEST, "action must be 'approve' or 'deny'"),
    };
    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: trigger a factory reset. Requires physical button confirmation on Hard mode.
async fn factory_reset(State(state): State<AppState>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        state.backend.factory_reset()
    }).await.unwrap();

    match result {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: upload new firmware bytes (Hard mode only; Soft mode returns 404).
async fn ota_upload(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let firmware = body.to_vec();
    if firmware.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "empty firmware binary");
    }

    let result = tokio::task::spawn_blocking(move || {
        state.backend.ota_upload(&firmware)
    }).await.unwrap();

    match result {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: restart the daemon process (systemd will restart the service).
async fn daemon_restart() -> Response {
    log::info!("Restart requested via API -- shutting down (systemd will restart)");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    Json(OkResponse { ok: true }).into_response()
}

/// Protected: download the latest auto-snapshot backup file.
async fn get_backup(State(state): State<AppState>) -> Response {
    if !state.backup_path.exists() {
        return api_err(StatusCode::NOT_FOUND, "no backup exists yet");
    }
    match std::fs::read(&state.backup_path) {
        Ok(data) => {
            (StatusCode::OK,
             [(header::CONTENT_TYPE, "application/json"),
              (header::CONTENT_DISPOSITION, "attachment; filename=\"heartwood-backup.json\"")],
             data).into_response()
        }
        Err(e) => api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("read backup: {e}")),
    }
}

/// Protected: trigger a fresh export, encrypt with the stored passphrase, save to disk, and return.
async fn post_backup_export(State(state): State<AppState>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let mut payload = state.backend.backup_export()?;
        payload.created_at = crate::backup::unix_now();

        let token = state.api_token.as_deref().map(|s| s.as_str()).unwrap_or("");
        let passphrase = crate::backup::read_passphrase(&state.passphrase_path, token)
            .map_err(|e| BackendError::Internal(format!("read passphrase: {e}")))?;

        let envelope = crate::backup::encrypt_backup(
            &payload,
            &passphrase,
            crate::backup::DEFAULT_M_COST,
            crate::backup::DEFAULT_T_COST,
            crate::backup::DEFAULT_P_COST,
        ).map_err(|e| BackendError::Internal(format!("encrypt backup: {e}")))?;

        crate::backup::write_backup(&state.backup_path, &envelope)
            .map_err(|e| BackendError::Internal(format!("write backup: {e}")))?;

        let json = serde_json::to_vec(&envelope)
            .map_err(|e| BackendError::Internal(format!("serialise envelope: {e}")))?;
        Ok::<_, BackendError>(json)
    }).await.unwrap();

    match result {
        Ok(data) => {
            (StatusCode::OK,
             [(header::CONTENT_TYPE, "application/json"),
              (header::CONTENT_DISPOSITION, "attachment; filename=\"heartwood-backup.json\"")],
             data).into_response()
        }
        Err(e) => backend_to_http(e),
    }
}

/// Protected: upload an encrypted backup, decrypt it, and import matching masters into the device.
async fn post_backup_import(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let data = body.to_vec();
    let result = tokio::task::spawn_blocking(move || {
        let envelope: crate::backup::BackupEnvelope = serde_json::from_slice(&data)
            .map_err(|e| BackendError::Internal(format!("parse backup: {e}")))?;

        let token = state.api_token.as_deref().map(|s| s.as_str()).unwrap_or("");
        let passphrase = crate::backup::read_passphrase(&state.passphrase_path, token)
            .map_err(|e| BackendError::Internal(format!("read passphrase: {e}")))?;

        let payload = crate::backup::decrypt_backup(&envelope, &passphrase)
            .map_err(|e| BackendError::Internal(e))?;

        // Match backup masters against device masters.
        let device_masters = state.backend.list_masters()?;
        let mut matched_payload = payload.clone();
        let mut match_report = Vec::new();

        matched_payload.masters.retain(|bm| {
            let matched = device_masters.iter().any(|dm| {
                dm.get("pubkey").and_then(|v| v.as_str()) == Some(&bm.pubkey)
            });
            match_report.push(serde_json::json!({
                "slot": bm.slot,
                "label": bm.label,
                "matched": matched,
                "slot_count": bm.connection_slots.len(),
            }));
            matched
        });

        state.backend.backup_import(&matched_payload)?;

        Ok::<_, BackendError>(serde_json::json!({
            "ok": true,
            "masters": match_report,
        }))
    }).await.unwrap();

    match result {
        Ok(report) => Json(report).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Protected: return backup metadata without decrypting the envelope.
async fn get_backup_status(State(state): State<AppState>) -> Response {
    match crate::backup::backup_status(&state.backup_path) {
        Some(status) => Json(serde_json::json!({
            "version": status.version,
            "last_modified": status.last_modified,
        })).into_response(),
        None => api_err(StatusCode::NOT_FOUND, "no backup exists yet"),
    }
}

/// Protected: change the backup passphrase, re-encrypting the existing backup if present.
async fn put_backup_passphrase(
    State(state): State<AppState>,
    Json(body): Json<ChangePassphraseBody>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let token = state.api_token.as_deref().map(|s| s.as_str()).unwrap_or("");

        // Verify old passphrase (constant-time to avoid timing leaks).
        let stored = crate::backup::read_passphrase(&state.passphrase_path, token)
            .map_err(|e| BackendError::Internal(format!("read passphrase: {e}")))?;
        let stored_bytes = stored.as_bytes();
        let provided_bytes = body.old_passphrase.as_bytes();
        let mismatch = if stored_bytes.len() != provided_bytes.len() {
            true
        } else {
            let mut diff = 0u8;
            for (a, b) in stored_bytes.iter().zip(provided_bytes.iter()) {
                diff |= a ^ b;
            }
            diff != 0
        };
        if mismatch {
            return Err(BackendError::Internal("old passphrase does not match".to_string()));
        }

        // Re-encrypt existing backup with new passphrase if one exists.
        if state.backup_path.exists() {
            let envelope = crate::backup::read_backup(&state.backup_path)
                .map_err(|e| BackendError::Internal(e))?;
            let payload = crate::backup::decrypt_backup(&envelope, &stored)
                .map_err(|e| BackendError::Internal(e))?;
            let new_envelope = crate::backup::encrypt_backup(
                &payload,
                &body.new_passphrase,
                crate::backup::DEFAULT_M_COST,
                crate::backup::DEFAULT_T_COST,
                crate::backup::DEFAULT_P_COST,
            ).map_err(|e| BackendError::Internal(e))?;
            crate::backup::write_backup(&state.backup_path, &new_envelope)
                .map_err(|e| BackendError::Internal(e))?;
        }

        // Store new passphrase.
        crate::backup::write_passphrase(&state.passphrase_path, &body.new_passphrase, token)
            .map_err(|e| BackendError::Internal(e))?;

        Ok::<_, BackendError>(())
    }).await.unwrap();

    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => backend_to_http(e),
    }
}

/// Fire-and-forget: export a fresh backup after a slot-modifying operation.
/// Runs in a background tokio task. Errors are logged, not propagated.
fn trigger_auto_snapshot(state: AppState) {
    if state.backend.is_locked() {
        return;
    }
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            let mut payload = state.backend.backup_export()?;
            payload.created_at = crate::backup::unix_now();

            let token = state.api_token.as_deref().map(|s| s.as_str()).unwrap_or("");
            let passphrase = crate::backup::read_passphrase(&state.passphrase_path, token)
                .map_err(|e| BackendError::Internal(format!("read passphrase: {e}")))?;

            let envelope = crate::backup::encrypt_backup(
                &payload,
                &passphrase,
                crate::backup::DEFAULT_M_COST,
                crate::backup::DEFAULT_T_COST,
                crate::backup::DEFAULT_P_COST,
            ).map_err(|e| BackendError::Internal(format!("encrypt: {e}")))?;

            crate::backup::write_backup(&state.backup_path, &envelope)
                .map_err(|e| BackendError::Internal(format!("write: {e}")))?;

            Ok::<_, BackendError>(())
        }).await.unwrap();

        match result {
            Ok(()) => log::info!("Auto-snapshot: backup saved"),
            Err(e) => log::warn!("Auto-snapshot failed: {e}"),
        }
    });
}

// ---------------------------------------------------------------------------
// WebSocket log streaming
// ---------------------------------------------------------------------------

async fn ws_logs(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    let rx = state.log_tx.subscribe();
    ws.on_upgrade(move |socket| handle_ws_logs(socket, rx))
}

async fn handle_ws_logs(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    while let Ok(line) = rx.recv().await {
        if socket.send(Message::Text(line.into())).await.is_err() {
            break; // Client disconnected.
        }
    }
}

/// Background task: poll the serial port for log output when the mutex is free.
/// Reads non-frame bytes (ESP-IDF log lines) and broadcasts them.
///
/// Uses spawn_blocking for the serial read to avoid blocking tokio workers.
/// With VMIN=0/VTIME=1, each read returns within 100ms even if no data arrives.
/// Only spawned in Hard mode; Soft mode has no serial port to poll.
pub async fn log_poller(serial: Arc<Mutex<RawSerial>>, tx: broadcast::Sender<String>) {
    let mut line_buf = String::new();

    loop {
        let serial = Arc::clone(&serial);
        let read_result = tokio::task::spawn_blocking(move || {
            let mut port = match serial.try_lock() {
                Ok(p) => p,
                Err(_) => return None,
            };
            let mut buf = [0u8; 256];
            match port.file.read(&mut buf) {
                Ok(n) if n > 0 => Some(buf[..n].to_vec()),
                _ => None,
            }
        }).await.unwrap_or(None);

        if let Some(bytes) = read_result {
            let text = String::from_utf8_lossy(&bytes);
            line_buf.push_str(&text);

            while let Some(pos) = line_buf.find('\n') {
                let line = line_buf[..pos].trim().to_string();
                line_buf = line_buf[pos + 1..].to_string();
                if !line.is_empty() {
                    let _ = tx.send(line);
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Bearer token auth middleware. Skipped when `state.api_token` is None
/// (dev mode). The only protected routes are those mounted under the
/// protected sub-router below -- public routes do not go through this
/// middleware.
async fn require_bearer(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = state.api_token.as_ref() else {
        // Auth disabled -- pass through.
        return Ok(next.run(req).await);
    };

    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let presented = header.strip_prefix("Bearer ").unwrap_or("");

    // Constant-time comparison to avoid leaking token length / bytes.
    let expected_bytes = expected.as_bytes();
    let presented_bytes = presented.as_bytes();
    if expected_bytes.len() != presented_bytes.len() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut diff = 0u8;
    for (a, b) in expected_bytes.iter().zip(presented_bytes.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

/// Serve Sapwood's index.html with the API token substituted into the
/// `__HEARTWOOD_API_TOKEN__` placeholder. Same-origin Sapwood loads pick
/// this up via a <meta name="heartwood-api-token"> tag and use it on all
/// subsequent /api/* calls -- so the LAN admin never has to type a token.
async fn serve_index(
    State(state): State<AppState>,
    sapwood_dir: String,
) -> impl IntoResponse {
    let path = std::path::Path::new(&sapwood_dir).join("index.html");
    let Ok(html) = std::fs::read_to_string(&path) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "index.html not readable").into_response();
    };
    let token_value = state.api_token.as_deref().map(|s| s.as_str()).unwrap_or("");
    let rendered = html.replace("__HEARTWOOD_API_TOKEN__", token_value);
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        rendered,
    )
        .into_response()
}

pub fn router(state: AppState, sapwood_dir: Option<&str>, enable_cors: bool) -> Router {
    // Protected routes -- require Bearer token when state.api_token is Some.
    let protected: Router<AppState> = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/masters", post(create_master))
        .route("/api/slots/{master}", get(get_slots).post(create_slot))
        .route("/api/slots/{master}/{index}", put(update_slot).delete(delete_slot))
        .route("/api/slots/{master}/{index}/uri", get(get_slot_uri))
        .route("/api/device/factory-reset", post(factory_reset))
        .route("/api/device/ota", post(ota_upload))
        .route("/api/daemon/restart", post(daemon_restart))
        .route("/api/unlock", post(post_unlock))
        .route("/api/lock", post(post_lock))
        .route("/api/approvals", get(get_approvals))
        .route("/api/approvals/{id}", post(post_approval))
        .route("/api/backup", get(get_backup))
        .route("/api/backup/export", post(post_backup_export))
        .route("/api/backup/import", post(post_backup_import))
        .route("/api/backup/status", get(get_backup_status))
        .route("/api/backup/passphrase", put(put_backup_passphrase))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    // Public routes:
    //   /api/info -- basic daemon info, public by definition (no secrets).
    //   /api/logs -- read-only WebSocket stream of ESP-IDF log lines. Browsers
    //     cannot send custom headers on WebSocket upgrades, and the log content
    //     does not contain secrets (same text the Pi journal shows), so this
    //     is intentionally unauthenticated even when api_token is set. Worst
    //     case a LAN observer sees public device activity, already visible on
    //     Nostr relays.
    let public: Router<AppState> = Router::new()
        .route("/api/info", get(get_info))
        .route("/api/logs", get(ws_logs));

    let mut app: Router<AppState> = Router::new().merge(protected).merge(public);

    // Sapwood index.html serve with token templating. Must be added before
    // .with_state() because the handler uses the State<AppState> extractor.
    if let Some(dir) = sapwood_dir {
        let dir_for_root = dir.to_string();
        let dir_for_index = dir.to_string();
        app = app
            .route(
                "/",
                get(move |s: State<AppState>| {
                    let dir = dir_for_root.clone();
                    async move { serve_index(s, dir).await }
                }),
            )
            .route(
                "/index.html",
                get(move |s: State<AppState>| {
                    let dir = dir_for_index.clone();
                    async move { serve_index(s, dir).await }
                }),
            );
    }

    // Finalise state; from here on the router is Router<()> and can take
    // layers and fallback services that do not use AppState.
    let mut app = app.with_state(state);

    if enable_cors {
        use tower_http::cors::{Any, CorsLayer};
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
        app = app.layer(cors);
    }

    if let Some(dir) = sapwood_dir {
        // Everything else under sapwood_dir (assets, favicon, etc) is served as-is.
        let serve = tower_http::services::ServeDir::new(dir);
        app = app.fallback_service(serve);
    }

    app
}
