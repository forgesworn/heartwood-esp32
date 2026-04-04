// bridge/src/api.rs
//
// HTTP management API for Sapwood. Runs alongside the relay event loop.
// All serial operations use try_lock() -- returns 423 if signing is in progress.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use heartwood_common::frame;
use heartwood_common::types::*;

use crate::RawSerial;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub serial: Arc<Mutex<RawSerial>>,
    pub bridge_info: Arc<BridgeInfo>,
}

pub struct BridgeInfo {
    pub mode: String,
    pub relays: Vec<String>,
    pub bunker_uri: String,
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
    bunker_uri: String,
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

#[derive(Serialize, Deserialize)]
struct ClientPolicyBody {
    client_pubkey: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_kinds: Vec<u64>,
    #[serde(default)]
    auto_approve: bool,
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
            let mut port = state.serial.try_lock().map_err(|_| busy())?;
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
                    bunker_uri: info.bunker_uri.clone(),
                    uptime_secs: info.start_time.elapsed().as_secs(),
                },
            }).into_response()
        }
        Err(e) => e,
    }
}

async fn get_clients(State(state): State<AppState>, Path(slot): Path<u8>) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match state.serial.try_lock() {
            Ok(p) => p,
            Err(_) => return busy(),
        };
        let frame_bytes = match frame::build_frame(FRAME_TYPE_POLICY_LIST_REQUEST, &[slot]) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_POLICY_LIST_RESPONSE], 10) {
            Ok(resp) => {
                // Return raw JSON payload from the device.
                (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")],
                    resp.payload.to_vec()).into_response()
            }
            Err(e) => e,
        }
    }).await.unwrap()
}

async fn delete_client(
    State(state): State<AppState>,
    Path((slot, pubkey)): Path<(u8, String)>,
) -> Response {
    if pubkey.len() != 64 {
        return api_err(StatusCode::BAD_REQUEST, "pubkey must be 64 hex chars");
    }
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match state.serial.try_lock() {
            Ok(p) => p,
            Err(_) => return busy(),
        };
        let mut payload = Vec::with_capacity(65);
        payload.push(slot);
        payload.extend_from_slice(pubkey.as_bytes());
        let frame_bytes = match frame::build_frame(FRAME_TYPE_POLICY_REVOKE, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_ACK, FRAME_TYPE_NACK], 10) {
            Ok(resp) if resp.frame_type == FRAME_TYPE_NACK => {
                api_err(StatusCode::CONFLICT, "client not found")
            }
            Ok(_) => Json(OkResponse { ok: true }).into_response(),
            Err(e) => e,
        }
    }).await.unwrap()
}

async fn put_client(
    State(state): State<AppState>,
    Path(slot): Path<u8>,
    Json(body): Json<ClientPolicyBody>,
) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match state.serial.try_lock() {
            Ok(p) => p,
            Err(_) => return busy(),
        };
        let json = match serde_json::to_vec(&body) {
            Ok(j) => j,
            Err(_) => return api_err(StatusCode::BAD_REQUEST, "invalid JSON"),
        };
        let mut payload = Vec::with_capacity(1 + json.len());
        payload.push(slot);
        payload.extend_from_slice(&json);
        let frame_bytes = match frame::build_frame(FRAME_TYPE_POLICY_UPDATE, &payload) {
            Ok(f) => f,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "frame build failed"),
        };
        match send_and_receive(&mut port, &frame_bytes, &[FRAME_TYPE_ACK, FRAME_TYPE_NACK], 10) {
            Ok(resp) if resp.frame_type == FRAME_TYPE_NACK => {
                api_err(StatusCode::BAD_GATEWAY, "device rejected update")
            }
            Ok(_) => Json(OkResponse { ok: true }).into_response(),
            Err(e) => e,
        }
    }).await.unwrap()
}

async fn factory_reset(State(state): State<AppState>) -> Response {
    tokio::task::spawn_blocking(move || -> Response {
        let mut port = match state.serial.try_lock() {
            Ok(p) => p,
            Err(_) => return busy(),
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
        bunker_uri: info.bunker_uri.clone(),
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
        let mut port = match state.serial.try_lock() {
            Ok(p) => p,
            Err(_) => return busy(),
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

pub fn router(state: AppState, sapwood_dir: Option<&str>, enable_cors: bool) -> Router {
    let mut app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/clients/{slot}", get(get_clients).put(put_client))
        .route("/api/clients/{slot}/{pubkey}", delete(delete_client))
        .route("/api/device/factory-reset", post(factory_reset))
        .route("/api/device/ota", post(ota_upload))
        .route("/api/bridge/info", get(bridge_info))
        .route("/api/bridge/restart", post(bridge_restart))
        .with_state(state);

    if enable_cors {
        use tower_http::cors::{Any, CorsLayer};
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
        app = app.layer(cors);
    }

    if let Some(dir) = sapwood_dir {
        let serve = tower_http::services::ServeDir::new(dir)
            .fallback(tower_http::services::ServeFile::new(
                std::path::Path::new(dir).join("index.html"),
            ));
        app = app.fallback_service(serve);
    }

    app
}
