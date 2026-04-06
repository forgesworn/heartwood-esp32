// heartwoodd/src/main.rs
//
// Heartwood daemon -- Nostr signing service.
//
// Two operating modes from the same binary:
//
//   Hard mode (ESP32 attached via USB serial):
//     Delegates all signing to the ESP32. Pi is zero-trust plumbing.
//     ESP32 holds keys, makes all signing decisions, button press required.
//
//   Soft mode (Pi alone, no ESP32):
//     Signs locally with keys encrypted at rest (Argon2id + XChaCha20-Poly1305).
//     Unlocked via Sapwood web UI. Policy-based auto-approve with Sapwood
//     approval queue for out-of-policy requests.
//
// Mode is auto-detected at startup (probe for ESP32, fall back to Soft)
// or overridden with --mode <soft|hard|auto>.

mod api;
mod backend;
mod serial;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use nostr::nips::nip44;
use nostr_sdk::prelude::*;

use heartwood_common::frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::types::*;

use serial::RawSerial;

#[derive(Parser)]
#[command(name = "heartwood-bridge")]
#[command(about = "Relay bridge for heartwood-esp32 signing bunker")]
struct Cli {
    /// Serial port for ESP32 (e.g. /dev/ttyUSB0, /dev/cu.usbserial-*)
    #[arg(short, long)]
    port: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    /// Bunker secret key (nsec or hex) -- used for relay auth and, in bridge-decrypts mode, NIP-44 crypto.
    /// Prefer HEARTWOOD_BUNKER_SECRET env var over passing this as a CLI arg: systemd expands env
    /// into ExecStart at service start, so anything in --flags is visible in /proc/<pid>/cmdline to
    /// every local user. The env form is read via clap's `env = ...` and never enters argv.
    #[arg(long, env = "HEARTWOOD_BUNKER_SECRET", hide_env_values = true)]
    bunker_secret: String,

    /// Relay URLs (comma-separated)
    #[arg(short, long, default_value = "wss://relay.damus.io,wss://nos.lol")]
    relays: String,

    /// Data directory for the heartwood-device instance (e.g. /var/lib/heartwood/hsm).
    /// When set, the bridge writes bunker-uri.txt here so the web UI can serve it
    /// to Bark during pairing.
    #[arg(long)]
    data_dir: Option<String>,

    /// Bridge authentication secret (hex, 64 chars). Must match the ESP32's NVS bridge secret.
    /// If provided, uses device-decrypts mode. If omitted, falls back to bridge-decrypts mode.
    /// Prefer HEARTWOOD_BRIDGE_SECRET env var -- see the equivalent note on --bunker-secret.
    #[arg(long, env = "HEARTWOOD_BRIDGE_SECRET", hide_env_values = true)]
    bridge_secret: Option<String>,

    /// Boot PIN (4-8 ASCII digits). When provided, the bridge sends a PIN_UNLOCK (0x26) frame
    /// immediately after opening the serial port, before SESSION_AUTH. If the device has no
    /// PIN set (or is already unlocked) omit this argument entirely.
    #[arg(long)]
    pin: Option<String>,

    /// Port for the management API (default 3100)
    #[arg(long, default_value_t = 3100)]
    api_port: u16,

    /// Directory containing Sapwood dist/ files to serve. If omitted, only the API is available.
    #[arg(long)]
    sapwood_dir: Option<String>,

    /// Enable CORS headers on API responses (auto-enabled when --sapwood-dir is not set)
    #[arg(long)]
    cors: bool,

    /// Bearer token required on management API calls. When set, every /api/* route except
    /// /api/bridge/info (public bunker URI) and the static Sapwood serve requires an
    /// `Authorization: Bearer <token>` header. When unset, the API is open (development mode).
    /// The token is injected into Sapwood's index.html via a __HEARTWOOD_API_TOKEN__ placeholder
    /// so same-origin Sapwood loads work without manual entry.
    /// Prefer HEARTWOOD_API_TOKEN env var -- see the note on --bunker-secret.
    #[arg(long, env = "HEARTWOOD_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------

/// Send a NIP-46 JSON-RPC request to the ESP32 over serial and read the response.
/// Bridge-decrypts mode only — forwards plaintext, expects a NIP46_RESPONSE (0x03) frame back.
fn forward_to_esp32(
    port: &mut RawSerial,
    request_json: &str,
    log_tx: Option<&tokio::sync::broadcast::Sender<String>>,
) -> Result<String, String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    read_any_response(port, log_tx)
}

/// Authenticate the bridge session with the ESP32.
///
/// Sends a SESSION_AUTH (0x21) frame containing the 32-byte bridge secret and
/// waits for a SESSION_ACK (0x22) frame with status byte 0x00.
fn authenticate_bridge(
    port: &mut RawSerial,
    bridge_secret: &[u8; 32],
) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_SESSION_AUTH, bridge_secret)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for session ACK".into());
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if byte[0] != 0x48 { continue; }
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => continue,
                }
                let mut header = [0u8; 3];
                read_exact_deadline(port, &mut header, deadline)?;
                let resp_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                let mut body = vec![0u8; length + 4];
                read_exact_deadline(port, &mut body, deadline)?;
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&MAGIC_BYTES);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                if let Ok(f) = frame::parse_frame(&buf) {
                    if f.frame_type == FRAME_TYPE_SESSION_ACK {
                        if f.payload.first() == Some(&0x00) {
                            log::info!("Bridge session authenticated");
                            return Ok(());
                        } else {
                            return Err(format!(
                                "bridge auth failed: status 0x{:02x}",
                                f.payload.first().unwrap_or(&0xFF)
                            ));
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

/// Send a PIN_UNLOCK (0x26) frame and wait for ACK (0x06) or NACK (0x15).
///
/// The PIN is sent as raw ASCII bytes (e.g. "1234" → [0x31, 0x32, 0x33, 0x34]).
/// On NACK the bridge exits immediately — retrying wastes attempts and risks wiping
/// the device after 5 failures.
fn unlock_pin(
    port: &mut RawSerial,
    pin: &str,
) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_PIN_UNLOCK, pin.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for PIN unlock response".into());
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if byte[0] != 0x48 { continue; }
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => continue,
                }
                let mut header = [0u8; 3];
                read_exact_deadline(port, &mut header, deadline)?;
                let resp_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                let mut body = vec![0u8; length + 4];
                read_exact_deadline(port, &mut body, deadline)?;
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&MAGIC_BYTES);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                if let Ok(f) = frame::parse_frame(&buf) {
                    if f.frame_type == FRAME_TYPE_ACK {
                        log::info!("PIN unlock accepted");
                        return Ok(());
                    } else if f.frame_type == FRAME_TYPE_NACK {
                        return Err("PIN unlock rejected (NACK) — wrong PIN".into());
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

/// Send an encrypted NIP-46 request to the ESP32 via an ENCRYPTED_REQUEST (0x10) frame.
///
/// Frame payload layout: `[master_pubkey_32][client_pubkey_32][ciphertext_bytes...]`
///
/// The ESP32 decrypts, processes, re-encrypts, and returns the response.
/// Query the ESP32 for its loaded masters via PROVISION_LIST (0x05).
/// Returns the parsed list of masters (slot, label, npub, mode).
fn query_master_list(
    port: &mut RawSerial,
    log_tx: Option<&tokio::sync::broadcast::Sender<String>>,
) -> Result<Vec<serde_json::Value>, String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[])
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    let json = read_any_response(port, log_tx)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| format!("provision list JSON parse failed: {e}"))?;
    match parsed {
        serde_json::Value::Array(arr) => Ok(arr),
        _ => Err("provision list response was not a JSON array".into()),
    }
}

/// Ask the ESP32 to build and sign a NIP-46 kind:24133 envelope event
/// wrapping the given ciphertext. Returns the fully serialised signed event
/// ready to publish to relays verbatim.
///
/// Payload layout matches FRAME_TYPE_SIGN_ENVELOPE (0x34):
///   [master_pubkey_32][client_pubkey_32][created_at_u64_be_8][ciphertext_bytes...]
fn forward_sign_envelope(
    port: &mut RawSerial,
    master_pubkey: &[u8; 32],
    client_pubkey: &[u8; 32],
    created_at: u64,
    ciphertext: &str,
    log_tx: Option<&tokio::sync::broadcast::Sender<String>>,
) -> Result<String, String> {
    let mut payload = Vec::with_capacity(72 + ciphertext.len());
    payload.extend_from_slice(master_pubkey);
    payload.extend_from_slice(client_pubkey);
    payload.extend_from_slice(&created_at.to_be_bytes());
    payload.extend_from_slice(ciphertext.as_bytes());

    let frame_bytes = frame::build_frame(FRAME_TYPE_SIGN_ENVELOPE, &payload)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    read_any_response(port, log_tx)
}

fn forward_encrypted(
    port: &mut RawSerial,
    master_pubkey: &[u8; 32],
    client_pubkey: &[u8; 32],
    ciphertext: &str,
    log_tx: Option<&tokio::sync::broadcast::Sender<String>>,
) -> Result<String, String> {
    let mut payload = Vec::with_capacity(64 + ciphertext.len());
    payload.extend_from_slice(master_pubkey);
    payload.extend_from_slice(client_pubkey);
    payload.extend_from_slice(ciphertext.as_bytes());

    let frame_bytes = frame::build_frame(FRAME_TYPE_ENCRYPTED_REQUEST, &payload)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    let t_send = std::time::Instant::now();

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    log::debug!("serial: request sent ({} bytes, flush took {}ms)",
        frame_bytes.len(), t_send.elapsed().as_millis());

    let result = read_any_response(port, log_tx);

    log::info!("serial: total round-trip {}ms", t_send.elapsed().as_millis());

    result
}

/// Read a response frame from the ESP32, accepting both NIP46_RESPONSE (0x03, plaintext)
/// and ENCRYPTED_RESPONSE (0x11, ciphertext) frame types.
///
/// Non-frame bytes (ESP-IDF log output that the device prints between frames)
/// are forwarded line-by-line to `log_tx` if provided, so Sapwood's /api/logs
/// WebSocket can surface device-side log output even during long-running frame
/// exchanges (e.g. a sign_event waiting on a button press). Without this,
/// the log_poller background task never gets a chance to read the serial port
/// while the mutex is held, and all device logs during a sign flow are lost.
///
/// Returns the payload as a UTF-8 string (either raw JSON or NIP-44 ciphertext).
fn read_any_response(
    port: &mut RawSerial,
    log_tx: Option<&tokio::sync::broadcast::Sender<String>>,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let t_start = std::time::Instant::now();
    let mut skipped_bytes: usize = 0;
    // Accumulator for device log lines discovered between frames. Flushed on
    // newline or when we give up and hit a frame boundary.
    let mut log_line_buf: Vec<u8> = Vec::with_capacity(256);

    let flush_log_line = |buf: &mut Vec<u8>, tx: Option<&tokio::sync::broadcast::Sender<String>>| {
        if buf.is_empty() { return; }
        if let Ok(s) = std::str::from_utf8(buf) {
            let trimmed = s.trim_end_matches(|c: char| c == '\r' || c == '\n');
            if !trimmed.is_empty() {
                if let Some(sender) = tx {
                    let _ = sender.send(trimmed.to_string());
                }
            }
        }
        buf.clear();
    };

    loop {
        if std::time::Instant::now() > deadline {
            flush_log_line(&mut log_line_buf, log_tx);
            return Err("timeout waiting for ESP32 response".into());
        }

        // Hunt for magic bytes -- skip ESP-IDF log output that pollutes USB-CDC.
        // Non-magic bytes are forwarded to log_tx line-by-line so Sapwood can
        // surface them in the log panel.
        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if byte[0] != 0x48 {
                    skipped_bytes += 1;
                    // Accumulate for line-based log forwarding.
                    log_line_buf.push(byte[0]);
                    if byte[0] == b'\n' || log_line_buf.len() > 512 {
                        flush_log_line(&mut log_line_buf, log_tx);
                    }
                    continue;
                }
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => {
                        // The 0x48 we saw wasn't followed by 0x57 -- treat as
                        // log noise and roll it into the line buffer.
                        log_line_buf.push(0x48);
                        if let Ok(1) = Ok::<usize, std::io::Error>(1) {
                            log_line_buf.push(byte[0]);
                        }
                        skipped_bytes += 1;
                        continue;
                    }
                }
                // Found a real frame boundary. Flush any partial log line.
                flush_log_line(&mut log_line_buf, log_tx);

                let t_magic = t_start.elapsed().as_millis();
                log::debug!("serial: magic found after {}ms (skipped {} bytes)", t_magic, skipped_bytes);

                // Got magic -- read header (type + length).
                let mut header = [0u8; 3];
                read_exact_deadline(port, &mut header, deadline)?;
                let resp_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                // Read payload + CRC.
                let mut body = vec![0u8; length + 4];
                read_exact_deadline(port, &mut body, deadline)?;

                let t_read = t_start.elapsed().as_millis();
                log::debug!("serial: frame read complete after {}ms (type=0x{:02x}, {} payload bytes)",
                    t_read, resp_type, length);

                // Reassemble and parse.
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&MAGIC_BYTES);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                match frame::parse_frame(&buf) {
                    Ok(f) => {
                        log::debug!("serial: response parsed after {}ms total (type=0x{:02x})",
                            t_start.elapsed().as_millis(), f.frame_type);
                        match f.frame_type {
                            FRAME_TYPE_NIP46_RESPONSE
                            | FRAME_TYPE_PROVISION_LIST_RESPONSE
                            | FRAME_TYPE_SIGN_ENVELOPE_RESPONSE => {
                                // Pure UTF-8 JSON payloads.
                                return String::from_utf8(f.payload)
                                    .map_err(|e| format!("invalid UTF-8 in response: {e}"));
                            }
                            FRAME_TYPE_ENCRYPTED_RESPONSE => {
                                // Payload layout: [client_pubkey_32][ciphertext_b64_ascii...]
                                // Strip the raw pubkey prefix -- the caller only needs
                                // the base64 ciphertext, and the prefix bytes are not
                                // valid UTF-8 on their own.
                                if f.payload.len() < 32 {
                                    return Err("encrypted response too short".into());
                                }
                                return String::from_utf8(f.payload[32..].to_vec())
                                    .map_err(|e| format!("invalid UTF-8 in encrypted response: {e}"));
                            }
                            FRAME_TYPE_NACK => return Err("ESP32 sent NACK".into()),
                            _ => {
                                // Other frame type -- skip and keep hunting.
                                skipped_bytes = 0;
                            }
                        }
                    }
                    Err(_) => { skipped_bytes = 0; continue; }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

/// Read exactly `buf.len()` bytes, respecting a deadline.
fn read_exact_deadline(
    port: &mut RawSerial,
    buf: &mut [u8],
    deadline: std::time::Instant,
) -> Result<(), String> {
    let mut pos = 0;
    while pos < buf.len() {
        if std::time::Instant::now() > deadline {
            return Err("timeout reading from serial".into());
        }
        match port.read(&mut buf[pos..]) {
            Ok(n) if n > 0 => pos += n,
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read failed: {e}")),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hex decoding (no extra crate needed — bridge secret is exactly 32 bytes)
// ---------------------------------------------------------------------------

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!(
            "--bridge-secret must be 64 hex chars (32 bytes), got {} chars",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // Broadcast channel for device log lines (WebSocket streaming to Sapwood).
    // Created early so it can be threaded into every serial helper that reads
    // frame responses -- they opportunistically forward non-frame bytes from
    // the device as log lines, which is the only way Sapwood sees device logs
    // during long-running frame exchanges (the background log_poller task is
    // starved while a sign_event holds the serial mutex waiting on a button).
    let (log_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    // Parse bridge secret early so we fail fast on bad input
    let bridge_secret: Option<[u8; 32]> = match &cli.bridge_secret {
        Some(hex_str) => Some(decode_hex_32(hex_str).expect("invalid --bridge-secret")),
        None => None,
    };

    let passthrough = bridge_secret.is_some();

    // Parse bunker keys
    let bunker_keys = Keys::parse(&cli.bunker_secret)?;
    let bunker_pubkey = bunker_keys.public_key();

    log::info!("Bunker pubkey: {}", bunker_pubkey.to_bech32()?);
    log::info!(
        "Mode: {}",
        if passthrough { "device-decrypts (encrypted)" } else { "bridge-decrypts (plaintext)" }
    );

    // NOTE: bunker-uri.txt for the data_dir path is written AFTER we query the
    // device master list below, so it reflects the real signing master pubkey
    // rather than the Pi-side ephemeral bunker key.

    // Open serial port using raw POSIX I/O — no DTR toggling, no ESP32 reboot.
    // The serialport crate's open() asserts DTR before the caller can disable it,
    // which resets the ESP32-S3 via USB-CDC. Using termios with CLOCAL avoids this.
    let mut port = RawSerial::open(&cli.port, cli.baud)
        .expect("failed to open serial port");

    log::info!("Serial port {} open (no DTR — ESP32 not reset)", cli.port);

    // Drain any stale data in the serial buffer from a previous bridge session.
    // Without this, old response frames pollute the request/response pairing and
    // every response is shifted by one, causing clients to ignore all replies.
    {
        let mut drain_buf = [0u8; 1024];
        let mut total = 0;
        loop {
            match port.read(&mut drain_buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(_) => break,
            }
        }
        if total > 0 {
            log::info!("Drained {} stale bytes from serial buffer", total);
        }
    }

    // If a boot PIN was provided, unlock the device before doing anything else.
    // The ESP32 only accepts PIN_UNLOCK (0x26) and PROVISION_LIST (0x05) while locked.
    if let Some(pin) = &cli.pin {
        if let Err(e) = unlock_pin(&mut port, pin) {
            panic!("PIN unlock failed: {e}");
        }
    }

    // Authenticate with the ESP32 if running in device-decrypts mode
    if let Some(secret) = &bridge_secret {
        if let Err(e) = authenticate_bridge(&mut port, secret) {
            panic!("Session authentication failed: {e}");
        }
    }

    // Query the ESP32 for its loaded masters so we can route NIP-46 traffic
    // to a real on-device identity rather than to a Pi-side bunker key. This
    // is the correctness fix for device-decrypts mode: Bark encrypts to the
    // master pubkey, the device decrypts with the matching master secret,
    // and the device signs the outer envelope event via SIGN_ENVELOPE so no
    // master secret ever touches the Pi.
    //
    // Master selection: slot 0 by default. A future release will accept a
    // --signing-master <slot|npub> flag for multi-master deployments; for
    // now the bridge is scoped to one active signing identity at a time.
    let (signing_master_slot, signing_master_pubkey, signing_master_label) = if passthrough {
        let masters = query_master_list(&mut port, Some(&log_tx))
            .expect("failed to query master list from ESP32 -- is the device provisioned?");
        if masters.is_empty() {
            panic!("ESP32 has no masters provisioned -- run setup-hsm.py first");
        }

        for m in &masters {
            log::info!(
                "Device master: slot={} label={} mode={} npub={}",
                m.get("slot").and_then(|v| v.as_u64()).unwrap_or(0),
                m.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                m.get("mode").and_then(|v| v.as_u64()).unwrap_or(0),
                m.get("npub").and_then(|v| v.as_str()).unwrap_or(""),
            );
        }

        let first = &masters[0];
        let slot = first.get("slot").and_then(|v| v.as_u64())
            .expect("master slot missing") as u8;
        let label = first.get("label").and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let npub = first.get("npub").and_then(|v| v.as_str())
            .expect("master npub missing");
        let pk = PublicKey::parse(npub)
            .expect("failed to decode master npub");
        let pk_bytes: [u8; 32] = pk.to_bytes();
        log::info!("Routing NIP-46 traffic to master slot {} ({}), pubkey {}",
            slot, label, hex_encode(&pk_bytes));
        (slot, pk_bytes, label)
    } else {
        // Legacy bridge-decrypts mode -- no on-device routing, the Pi does all
        // NIP-44 crypto with bunker_keys and forwards plaintext NIP-46 to the
        // device. In this mode the "master" concept does not apply and we keep
        // the historical behaviour (bunker_pubkey is used throughout).
        log::warn!("Running in bridge-decrypts (legacy) mode -- master signing happens on host");
        (0u8, bunker_pubkey.to_bytes(), "legacy".to_string())
    };

    // Now that we know the signing master, write bunker-uri.txt with the
    // real URI for the heartwood-device web UI / Bark pairing.
    if let Some(ref dir) = cli.data_dir {
        let relay_params: String = cli
            .relays
            .split(',')
            .filter(|r| !r.trim().is_empty())
            .map(|r| format!("relay={}", urlencoding::encode(r.trim())))
            .collect::<Vec<_>>()
            .join("&");
        let bunker_uri_file = format!(
            "bunker://{}?{}",
            hex_encode(&signing_master_pubkey),
            relay_params,
        );
        let path = std::path::Path::new(dir).join("bunker-uri.txt");
        match std::fs::write(&path, &bunker_uri_file) {
            Ok(()) => log::info!("Wrote bunker URI to {}", path.display()),
            Err(e) => log::error!("Failed to write bunker-uri.txt: {e}"),
        }
    }

    let port = Arc::new(Mutex::new(port));

    // Build relay URL list for BridgeInfo (used by /api/slots/:master/:index/uri).
    let relay_list: Vec<String> = cli.relays.split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    log::info!("Paired clients will sign as: {} (slot {})",
        signing_master_label, signing_master_slot);

    // log_tx is created at the top of main() so it can be threaded into
    // startup-time serial helpers (query_master_list etc).

    // Spawn the management API server.
    let api_token = cli.api_token.clone().map(Arc::new);
    if api_token.is_some() {
        log::info!("API token auth ENABLED -- /api/* routes (except /api/info) require Bearer token");
    } else {
        log::warn!("API token auth DISABLED -- any LAN client can hit /api/device/factory-reset. Set HEARTWOOD_API_TOKEN to enable.");
    }

    let serial_backend = backend::serial::SerialBackend::new(Arc::clone(&port), log_tx.clone());
    let serial_arc = serial_backend.serial().clone();

    let app_state = api::AppState {
        backend: Arc::new(serial_backend),
        daemon_info: Arc::new(api::DaemonInfo {
            tier: backend::Tier::Hard,
            relays: relay_list.clone(),
            start_time: std::time::Instant::now(),
        }),
        log_tx: log_tx.clone(),
        api_token: api_token.clone(),
    };

    // Spawn the background log poller (reads serial when idle, broadcasts to WebSocket clients).
    tokio::spawn(api::log_poller(serial_arc, log_tx.clone()));

    let enable_cors = cli.cors || cli.sapwood_dir.is_none();
    let api_router = api::router(app_state, cli.sapwood_dir.as_deref(), enable_cors);
    let api_port = cli.api_port;

    log::info!("Spawning management API on port {api_port}...");
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
        log::info!("Binding API to {addr}...");
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                log::info!("Management API listening on http://0.0.0.0:{api_port}");
                if let Err(e) = axum::serve(listener, api_router).await {
                    log::error!("API server error: {e}");
                }
            }
            Err(e) => {
                log::error!("Failed to bind API port {api_port}: {e}");
            }
        }
    });

    // Connect to relays
    let client = Client::new(bunker_keys.clone());
    for relay_url in cli.relays.split(',') {
        let url = relay_url.trim();
        if !url.is_empty() {
            client.add_relay(url).await?;
        }
    }
    client.connect().await;

    // Wait for at least one relay to actually connect before subscribing.
    // client.connect() starts connections in the background — subscribing
    // before any WebSocket is open silently drops the REQ.
    log::info!("Waiting for relay connections...");
    tokio::time::sleep(Duration::from_secs(3)).await;
    log::info!("Connected to relays");

    // Subscribe to NIP-46 requests p-tagged with the signing master pubkey.
    // In device-decrypts mode this is the on-device master we resolved above;
    // in legacy mode it falls back to bunker_pubkey. The Pi-side bunker_keys
    // is used only by the Client for relay-layer signing (NIP-42 auth etc),
    // not for the NIP-46 application layer.
    let signing_master_nostr_pubkey = PublicKey::from_slice(&signing_master_pubkey)
        .expect("signing master pubkey is valid secp256k1 x-only");
    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(signing_master_nostr_pubkey)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!("Subscribed to NIP-46 events — waiting for requests...");

    // Pre-compute the master pubkey bytes once (used in both the ENCRYPTED_REQUEST
    // routing and the SIGN_ENVELOPE envelope-signing round-trip).
    let master_pubkey_bytes: [u8; 32] = signing_master_pubkey;

    // Event loop — process incoming NIP-46 requests
    client
        .handle_notifications(|notification| {
            let bunker_keys = bunker_keys.clone();
            let client_clone = client.clone();
            let port = &port;
            let log_tx = log_tx.clone();

            async move {
                let event = match notification {
                    RelayPoolNotification::Event { event, .. } => event,
                    _ => return Ok(false),
                };

                // Only process NIP-46 events
                if event.kind != Kind::NostrConnect {
                    return Ok(false);
                }

                let client_pubkey = event.pubkey;
                log::info!("NIP-46 request from {}", client_pubkey);

                if passthrough {
                    // -------------------------------------------------------
                    // Device-decrypts mode — forward raw ciphertext to ESP32,
                    // then ask the ESP32 to sign the outer envelope event so
                    // the master secret never leaves the device.
                    // -------------------------------------------------------
                    let client_pubkey_bytes: [u8; 32] = client_pubkey.to_bytes();

                    // Step 1: forward the encrypted request to the device and
                    // receive the encrypted response ciphertext (base64 ASCII).
                    let response_ciphertext = {
                        let mut port = port.lock().unwrap();
                        match forward_encrypted(
                            &mut port,
                            &master_pubkey_bytes,
                            &client_pubkey_bytes,
                            &event.content,
                            Some(&log_tx),
                        ) {
                            Ok(resp) => resp,
                            Err(e) => {
                                log::error!("ESP32 forward (encrypted) failed: {e}");
                                return Ok(false);
                            }
                        }
                    };
                    log::info!(
                        "ESP32 encrypted response ({} bytes)",
                        response_ciphertext.len()
                    );

                    // Step 2: ask the device to build and sign the outer
                    // kind:24133 envelope event with the master secret. The
                    // host never holds a signing-capable key for this path.
                    let created_at: u64 = Timestamp::now().as_secs();
                    let signed_event_json = {
                        let mut port = port.lock().unwrap();
                        match forward_sign_envelope(
                            &mut port,
                            &master_pubkey_bytes,
                            &client_pubkey_bytes,
                            created_at,
                            &response_ciphertext,
                            Some(&log_tx),
                        ) {
                            Ok(json) => json,
                            Err(e) => {
                                log::error!("ESP32 envelope sign failed: {e}");
                                return Ok(false);
                            }
                        }
                    };

                    // Step 3: parse and publish the pre-signed event verbatim.
                    let signed_event = match Event::from_json(&signed_event_json) {
                        Ok(ev) => ev,
                        Err(e) => {
                            log::error!("Failed to parse signed envelope from device: {e}");
                            return Ok(false);
                        }
                    };
                    match client_clone.send_event(&signed_event).await {
                        Ok(output) => log::info!("Response published: {}", output.id()),
                        Err(e) => log::error!("Failed to publish response: {e}"),
                    }
                } else {
                    // -------------------------------------------------------
                    // Bridge-decrypts mode — bridge does NIP-44 decrypt/encrypt
                    // -------------------------------------------------------
                    let plaintext = match nip44::decrypt(
                        bunker_keys.secret_key(),
                        &client_pubkey,
                        &event.content,
                    ) {
                        Ok(pt) => pt,
                        Err(e) => {
                            log::error!("NIP-44 decrypt failed: {e}");
                            return Ok(false);
                        }
                    };

                    // Inject the client pubkey so the ESP32 can identify
                    // the client for TOFU policy in bridge-decrypts mode.
                    let plaintext = if plaintext.starts_with('{') {
                        format!(
                            "{{\"_client_pubkey\":\"{}\",{}",
                            client_pubkey.to_hex(),
                            &plaintext[1..],
                        )
                    } else {
                        plaintext
                    };

                    log::info!(
                        "Decrypted request: {}",
                        &plaintext[..plaintext.len().min(300)]
                    );

                    let response_json = {
                        let mut port = port.lock().unwrap();
                        match forward_to_esp32(&mut port, &plaintext, Some(&log_tx)) {
                            Ok(resp) => resp,
                            Err(e) => {
                                log::error!("ESP32 forward failed: {e}");
                                return Ok(false);
                            }
                        }
                    };

                    log::info!(
                        "ESP32 response: {}",
                        &response_json[..response_json.len().min(100)]
                    );

                    let ciphertext = match nip44::encrypt(
                        bunker_keys.secret_key(),
                        &client_pubkey,
                        &response_json,
                        nip44::Version::default(),
                    ) {
                        Ok(ct) => ct,
                        Err(e) => {
                            log::error!("NIP-44 encrypt failed: {e}");
                            return Ok(false);
                        }
                    };

                    let response_event = EventBuilder::new(Kind::NostrConnect, ciphertext)
                        .tag(Tag::public_key(client_pubkey));

                    match client_clone.send_event_builder(response_event).await {
                        Ok(output) => log::info!("Response published: {}", output.id()),
                        Err(e) => log::error!("Failed to publish response: {e}"),
                    }
                }

                Ok(false) // keep listening
            }
        })
        .await?;

    Ok(())
}
