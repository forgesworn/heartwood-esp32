// heartwoodd/src/api.rs
//
// HTTP management API for Sapwood. Runs alongside the relay event loop.
// All serial operations use try_lock() -- returns 423 if signing is in progress.

use std::io::{Read, Write};
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

use heartwood_common::frame;
use heartwood_common::types::*;

use crate::serial::RawSerial;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub serial: Arc<Mutex<RawSerial>>,
    pub bridge_info: Arc<BridgeInfo>,
    pub log_tx: broadcast::Sender<String>,
    /// Optional bearer token. When Some, protected /api/* routes require
    /// `Authorization: Bearer <token>`. When None, the API is open.
    pub api_token: Option<Arc<String>>,
}

pub struct BridgeInfo {
    pub mode: String,
    pub relays: Vec<String>,
    pub start_time: Instant,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    masters: serde_json::Value,
    bridge: BridgeInfoResponse,
}

#[derive(Serialize)]
struct BridgeInfoResponse {
    mode: String,
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

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn api_err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorResponse { error: msg.into() })).into_response()
}

fn busy() -> Response {
    api_err(StatusCode::LOCKED, "Device busy -- signing in progress")
}

/// Try to acquire the serial port with a few retries.
/// The log poller holds the lock briefly (up to 100ms); retry a few times
/// before giving up and returning 423.
fn acquire_serial(state: &AppState) -> Result<std::sync::MutexGuard<'_, RawSerial>, Response> {
    for _ in 0..10 {
        if let Ok(guard) = state.serial.try_lock() {
            return Ok(guard);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(busy())
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------

/// Send a frame and wait for a response with one of the expected types.
fn send_and_receive(
    port: &mut RawSerial,
    frame_bytes: &[u8],
    expected_types: &[u8],
    timeout_secs: u64,
) -> Result<frame::Frame, Response> {
    port.file.write_all(frame_bytes)
        .map_err(|e| api_err(StatusCode::BAD_GATEWAY, format!("serial write failed: {e}")))?;
    port.file.flush()
        .map_err(|e| api_err(StatusCode::BAD_GATEWAY, format!("serial flush failed: {e}")))?;

    let deadline = Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        if Instant::now() > deadline {
            return Err(api_err(StatusCode::GATEWAY_TIMEOUT, "ESP32 did not respond"));
        }

        let mut byte = [0u8; 1];
        match port.file.read(&mut byte) {
            Ok(1) => {
                if byte[0] != 0x48 { continue; }
                match port.file.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => continue,
                }
                // Got magic -- read header.
                let mut header = [0u8; 3];
                read_exact_timeout(&mut port.file, &mut header, deadline)?;
                let resp_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                if length > MAX_PAYLOAD_SIZE {
                    continue;
                }
                let mut body = vec![0u8; length + 4];
                read_exact_timeout(&mut port.file, &mut body, deadline)?;
                // Reassemble and parse.
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&[0x48, 0x57]);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                match frame::parse_frame(&buf) {
                    Ok(f) => {
                        if expected_types.contains(&f.frame_type) {
                            return Ok(f);
                        }
                        if f.frame_type == FRAME_TYPE_NACK {
                            return Err(api_err(StatusCode::BAD_GATEWAY, "ESP32 sent NACK"));
                        }
                    }
                    Err(_) => continue,
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(api_err(StatusCode::BAD_GATEWAY, format!("serial read error: {e}"))),
        }
    }
}

fn read_exact_timeout(
    file: &mut std::fs::File,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), Response> {
    let mut pos = 0;
    while pos < buf.len() {
        if Instant::now() > deadline {
            return Err(api_err(StatusCode::GATEWAY_TIMEOUT, "timeout reading from serial"));
        }
        match file.read(&mut buf[pos..]) {
            Ok(n) if n > 0 => pos += n,
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(api_err(StatusCode::BAD_GATEWAY, format!("serial read failed: {e}"))),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_status(State(state): State<AppState>) -> Response {
    let result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || -> Result<serde_json::Value, Response> {
            let mut port = acquire_serial(&state)?;
            let frame_bytes = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[])
                .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"))?;
            let resp = send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_PROVISION_LIST_RESPONSE], 10)?;
            let json: serde_json::Value = serde_json::from_slice(&resp.payload)
                .unwrap_or(serde_json::Value::Array(vec![]));
            Ok(json)
        }
    }).await.unwrap();

    match result {
        Ok(masters) => {
            let info = &state.bridge_info;
            Json(StatusResponse {
                masters,
                bridge: BridgeInfoResponse {
                    mode: info.mode.clone(),
                    relays: info.relays.clone(),
                    uptime_secs: info.start_time.elapsed().as_secs(),
                },
            }).into_response()
        }
        Err(e) => e,
    }
}

/// List all connection slots for a master.
async fn get_slots(State(state): State<AppState>, Path(master): Path<u8>) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let frame_bytes = match frame::build_frame(FRAME_TYPE_CONNSLOT_LIST, &[master]) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_CONNSLOT_LIST_RESP], 10) {
            Ok(resp) => {
                // Return raw JSON payload from the device.
                (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")],
                    resp.payload.to_vec()).into_response()
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

/// Create a new connection slot for a master. Returns slot info including the bunker URI.
async fn create_slot(
    State(state): State<AppState>,
    Path(master): Path<u8>,
    Json(body): Json<CreateSlotBody>,
) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        // Payload: master_slot (1) + label (plain UTF-8 string).
        // Relay URLs are not needed here -- they're for CONNSLOT_URI.
        let mut payload = Vec::with_capacity(1 + body.label.len());
        payload.push(master);
        payload.extend_from_slice(body.label.as_bytes());
        let frame_bytes = match frame::build_frame(FRAME_TYPE_CONNSLOT_CREATE, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_CONNSLOT_CREATE_RESP], 10) {
            Ok(resp) => {
                (StatusCode::CREATED, [(axum::http::header::CONTENT_TYPE, "application/json")],
                    resp.payload.to_vec()).into_response()
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

/// Update label and/or policy fields of an existing connection slot.
async fn update_slot(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
    Json(body): Json<UpdateSlotBody>,
) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        // Inject slot_index into the JSON body -- the firmware reads it from there.
        let mut patch = serde_json::to_value(&body).unwrap_or(serde_json::Value::Object(Default::default()));
        patch["slot_index"] = serde_json::Value::Number(index.into());
        let json = match serde_json::to_vec(&patch) {
            Ok(j) => j,
            Err(_) => return api_err(StatusCode::BAD_REQUEST, "invalid JSON"),
        };
        // Payload: master_slot (1) + JSON (includes slot_index)
        let mut payload = Vec::with_capacity(1 + json.len());
        payload.push(master);
        payload.extend_from_slice(&json);
        let frame_bytes = match frame::build_frame(FRAME_TYPE_CONNSLOT_UPDATE, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_CONNSLOT_UPDATE_RESP], 10) {
            Ok(resp) => {
                (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")],
                    resp.payload.to_vec()).into_response()
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

/// Revoke (delete) a connection slot.
async fn delete_slot(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let payload = [master, index];
        let frame_bytes = match frame::build_frame(FRAME_TYPE_CONNSLOT_REVOKE, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_CONNSLOT_REVOKE_RESP], 10) {
            Ok(resp) => {
                (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")],
                    resp.payload.to_vec()).into_response()
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

/// Return the full bunker URI for a specific connection slot (including secret).
/// Relay URLs come from the bridge's config so the client always has up-to-date relay info.
async fn get_slot_uri(
    State(state): State<AppState>,
    Path((master, index)): Path<(u8, u8)>,
) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let relays = state.bridge_info.relays.clone();
        let relay_json = match serde_json::to_vec(&relays) {
            Ok(j) => j,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "relay serialisation failed"),
        };
        // Payload: master_slot (1) + slot_index (1) + relay_urls (JSON)
        let mut payload = Vec::with_capacity(2 + relay_json.len());
        payload.push(master);
        payload.push(index);
        payload.extend_from_slice(&relay_json);
        let frame_bytes = match frame::build_frame(FRAME_TYPE_CONNSLOT_URI, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_CONNSLOT_URI_RESP], 10) {
            Ok(resp) => {
                // Response payload is the raw bunker:// URI as UTF-8.
                match String::from_utf8(resp.payload) {
                    Ok(uri) => Json(serde_json::json!({ "bunker_uri": uri })).into_response(),
                    Err(_) => api_err(StatusCode::BAD_GATEWAY, "invalid UTF-8 in URI response"),
                }
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

async fn factory_reset(State(state): State<AppState>) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let frame_bytes = match frame::build_frame(FRAME_TYPE_FACTORY_RESET, &[]) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        // 60-second timeout -- user needs to press the physical button.
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_ACK, FRAME_TYPE_NACK], 60) {
            Ok(resp) if resp.frame_type == FRAME_TYPE_NACK => {
                api_err(StatusCode::CONFLICT, "factory reset denied by user")
            }
            Ok(_) => Json(OkResponse { ok: true }).into_response(),
            Err(e) => e,
        }
    }).await.unwrap()
}

async fn bridge_info(State(state): State<AppState>) -> Response {
    let info = &state.bridge_info;
    Json(BridgeInfoResponse {
        mode: info.mode.clone(),
        relays: info.relays.clone(),
        uptime_secs: info.start_time.elapsed().as_secs(),
    }).into_response()
}

async fn bridge_restart() -> Response {
    log::info!("Restart requested via API -- shutting down (systemd will restart)");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    Json(OkResponse { ok: true }).into_response()
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

// OTA status codes (matches firmware/common)
const OTA_STATUS_READY: u8 = 0x00;
const OTA_STATUS_CHUNK_OK: u8 = 0x01;
const OTA_STATUS_VERIFIED: u8 = 0x02;

const OTA_CHUNK_SIZE: usize = 4096;

async fn ota_upload(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let firmware = body.to_vec();
    if firmware.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "empty firmware binary");
    }

    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match acquire_serial(&state) {
            Ok(p) => p,
            Err(e) => return e,
        };

        // Compute SHA-256 hash.
        let hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&firmware);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            h
        };

        // OTA_BEGIN: [size_u32_be] [sha256_32]
        let size = firmware.len() as u32;
        let mut begin_payload = Vec::with_capacity(36);
        begin_payload.extend_from_slice(&size.to_be_bytes());
        begin_payload.extend_from_slice(&hash);

        let begin_frame = match frame::build_frame(FRAME_TYPE_OTA_BEGIN, &begin_payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };

        // 60s timeout for button approval.
        match send_and_receive(&mut port, &begin_frame, &[FRAME_TYPE_OTA_STATUS], 60) {
            Ok(resp) if !resp.payload.is_empty() && resp.payload[0] == OTA_STATUS_READY => {}
            Ok(resp) => {
                let code = resp.payload.first().copied().unwrap_or(0xff);
                return api_err(StatusCode::BAD_GATEWAY, format!("OTA begin rejected (status 0x{code:02x})"));
            }
            Err(e) => return e,
        }

        // Stream chunks.
        let mut offset: usize = 0;
        while offset < firmware.len() {
            let end = (offset + OTA_CHUNK_SIZE).min(firmware.len());
            let chunk = &firmware[offset..end];

            let mut chunk_payload = Vec::with_capacity(4 + chunk.len());
            chunk_payload.extend_from_slice(&(offset as u32).to_be_bytes());
            chunk_payload.extend_from_slice(chunk);

            let chunk_frame = match frame::build_frame(FRAME_TYPE_OTA_CHUNK, &chunk_payload) {
                Ok(f) => f,
                Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "chunk frame build failed"),
            };

            match send_and_receive(&mut port, &chunk_frame, &[FRAME_TYPE_OTA_STATUS], 10) {
                Ok(resp) if !resp.payload.is_empty() && resp.payload[0] == OTA_STATUS_CHUNK_OK => {}
                Ok(resp) => {
                    let code = resp.payload.first().copied().unwrap_or(0xff);
                    return api_err(StatusCode::BAD_GATEWAY, format!("chunk at offset {offset} rejected (0x{code:02x})"));
                }
                Err(e) => return e,
            }

            offset = end;
        }

        // OTA_FINISH
        let finish_frame = match frame::build_frame(FRAME_TYPE_OTA_FINISH, &[]) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "finish frame build failed"),
        };

        match send_and_receive(&mut port, &finish_frame, &[FRAME_TYPE_OTA_STATUS], 30) {
            Ok(resp) if !resp.payload.is_empty() && resp.payload[0] == OTA_STATUS_VERIFIED => {
                Json(OkResponse { ok: true }).into_response()
            }
            Ok(resp) => {
                let code = resp.payload.first().copied().unwrap_or(0xff);
                api_err(StatusCode::BAD_GATEWAY, format!("verification failed (0x{code:02x}). Automatic rollback."))
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Bearer token auth middleware. Skipped when `state.api_token` is None
/// (dev mode). The only protected routes are those mounted under
/// `protected_routes()` below -- public routes (bridge info, static files)
/// do not go through this middleware.
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
        .route("/api/slots/{master}", get(get_slots).post(create_slot))
        .route("/api/slots/{master}/{index}", put(update_slot).delete(delete_slot))
        .route("/api/slots/{master}/{index}/uri", get(get_slot_uri))
        .route("/api/device/factory-reset", post(factory_reset))
        .route("/api/device/ota", post(ota_upload))
        .route("/api/bridge/restart", post(bridge_restart))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    // Public routes:
    //   /api/bridge/info -- bunker URI, public by definition (shareable pairing data).
    //   /api/logs -- read-only WebSocket stream of ESP-IDF log lines. Browsers can
    //     not send custom headers on WebSocket upgrades, and the log content does
    //     not contain secrets (it is the same text the Pi journal shows), so this
    //     is intentionally unauthenticated even when api_token is set. Worst case
    //     a LAN observer sees public device activity, which is already visible on
    //     Nostr relays.
    let public: Router<AppState> = Router::new()
        .route("/api/bridge/info", get(bridge_info))
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
