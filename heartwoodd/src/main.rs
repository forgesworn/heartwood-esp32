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
mod backup;
mod backend;
mod relay;
mod serial;
mod vault;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use nostr_sdk::prelude::*;
use zeroize::Zeroize;

use heartwood_common::frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::types::*;

use serial::RawSerial;

/// Vault encryption deliberately performs a slow key derivation for every
/// provisioned identity. Keep startup unlock on the same generous budget as
/// enable/disable so a multi-identity signer is not queried while still busy.
const VAULT_OPERATION_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "heartwoodd")]
#[command(about = "Heartwood daemon -- Nostr signing service")]
struct Cli {
    /// Operating mode: hard, soft, or auto (default: auto-detect)
    #[arg(long, default_value = "auto")]
    mode: String,

    /// Serial port for ESP32 (default: /dev/ttyACM0)
    #[arg(short, long, default_value = "/dev/ttyACM0")]
    port: String,

    /// Baud rate
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    /// Data directory for keystore and bunker-uri.txt
    #[arg(long, default_value = "/var/lib/heartwood")]
    data_dir: String,

    /// Relay URLs (comma-separated)
    #[arg(short, long, default_value = "wss://relay.damus.io,wss://nos.lol")]
    relays: String,

    /// Master slot whose bunker URI is written to bunker-uri.txt (default: 0).
    /// NIP-46 routing accepts requests for every provisioned master regardless of this flag.
    #[arg(long, default_value_t = 0)]
    slot: u8,

    /// Management API port
    #[arg(long, default_value_t = 3100)]
    api_port: u16,

    /// Sapwood static files directory
    #[arg(long)]
    sapwood_dir: Option<String>,

    /// Enable CORS headers on API responses. Off by default: Sapwood is
    /// served same-origin via --sapwood-dir, and permissive CORS would let
    /// any web page a LAN user visits drive the API from their browser.
    #[arg(long)]
    cors: bool,

    /// Bearer token for API auth (env: HEARTWOOD_API_TOKEN)
    #[arg(long, env = "HEARTWOOD_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,

    // -- Hard mode options ---------------------------------------------------

    /// Bunker secret key (nsec or hex) for relay-layer auth. Required in Hard mode.
    /// In Soft mode, an ephemeral keypair is generated if omitted.
    /// Prefer HEARTWOOD_BUNKER_SECRET env var over passing on the command line:
    /// anything in --flags is visible in /proc/<pid>/cmdline to every local user.
    #[arg(long, env = "HEARTWOOD_BUNKER_SECRET", hide_env_values = true)]
    bunker_secret: Option<String>,

    /// ESP32 bridge session auth secret (hex, 64 chars). Must match the NVS bridge secret.
    /// Prefer HEARTWOOD_BRIDGE_SECRET env var -- see the note on --bunker-secret.
    #[arg(long, env = "HEARTWOOD_BRIDGE_SECRET", hide_env_values = true)]
    bridge_secret: Option<String>,

    /// Boot PIN (4-8 ASCII digits). Sent as a PIN_UNLOCK frame before SESSION_AUTH.
    /// Omit if the device has no PIN set or is already unlocked.
    #[arg(long)]
    pin: Option<String>,

    /// One-shot: enable at-rest vault encryption on the device, then exit.
    /// Generates <data-dir>/vault.key on first use, sends VAULT_SET over
    /// serial (requires --bridge-secret and a physical button press).
    /// For operators without Sapwood.
    #[arg(long, conflicts_with = "vault_disable")]
    vault_enable: bool,

    /// One-shot: disable at-rest vault encryption (plaintext seeds), then exit.
    /// Same serial/auth/button requirements as --vault-enable.
    #[arg(long)]
    vault_disable: bool,
}

// ---------------------------------------------------------------------------
// Mode detection
// ---------------------------------------------------------------------------

enum DetectedMode {
    Hard(RawSerial),
    Soft,
}

/// Detect operating mode. In "auto" mode, open the serial port and send a
/// PROVISION_LIST probe; if the device responds with the magic byte within 3s
/// it is an ESP32 and we use Hard mode, otherwise we fall back to Soft.
fn detect_mode(cli: &Cli) -> DetectedMode {
    match cli.mode.as_str() {
        "hard" => {
            let port = RawSerial::open(&cli.port, cli.baud)
                .expect("--mode=hard but failed to open serial port");
            DetectedMode::Hard(port)
        }
        "soft" => DetectedMode::Soft,
        _ => {
            // "auto" or anything unrecognised -- probe first.
            match RawSerial::open(&cli.port, cli.baud) {
                Ok(mut port) => {
                    let probe = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[]);
                    if let Ok(frame_bytes) = probe {
                        let _ = port.write_frame_paced(&frame_bytes);
                        let _ = port.flush();
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        while std::time::Instant::now() < deadline {
                            let mut buf = [0u8; 1];
                            match port.read(&mut buf) {
                                Ok(1) if buf[0] == 0x48 => {
                                    log::info!("ESP32 detected on {} -- Hard mode", cli.port);
                                    return DetectedMode::Hard(port);
                                }
                                _ => {}
                            }
                        }
                    }
                    log::info!("No ESP32 response on {} -- Soft mode", cli.port);
                    DetectedMode::Soft
                }
                Err(_) => {
                    log::info!("Serial port {} not available -- Soft mode", cli.port);
                    DetectedMode::Soft
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Startup-only serial helpers (operate on RawSerial before port is shared)
// ---------------------------------------------------------------------------

/// Drain any stale bytes from the serial buffer left by a previous session.
/// Without this, old response frames pollute request/response pairing.
fn drain_serial(port: &mut RawSerial) {
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    loop {
        match port.read(&mut buf) {
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

/// Send a PIN_UNLOCK (0x26) frame and wait for ACK (0x06) or NACK (0x15).
///
/// The PIN is sent as raw ASCII bytes (e.g. "1234" -> [0x31, 0x32, 0x33, 0x34]).
/// On NACK the daemon exits immediately -- retrying risks wiping the device
/// after 5 failures.
fn unlock_pin(port: &mut RawSerial, pin: &str) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_PIN_UNLOCK, pin.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_frame_paced(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;

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
                        return Err("PIN unlock rejected (NACK) -- wrong PIN".into());
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

/// Authenticate the bridge session with the ESP32.
///
/// Sends a SESSION_AUTH (0x21) frame containing the 32-byte bridge secret and
/// waits for a SESSION_ACK (0x22) frame with status byte 0x00.
fn authenticate_bridge(port: &mut RawSerial, bridge_secret: &[u8; 32]) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_SESSION_AUTH, bridge_secret)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_frame_paced(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;

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

/// Send a frame over the startup (not yet shared) serial port and wait for an
/// ACK or NACK reply, returning the reply frame. Used for one-shot vault
/// operations and startup vault unlock, where the full SerialBackend does not
/// exist yet.
fn send_frame_wait_ack(
    port: &mut RawSerial,
    frame_type: u8,
    payload: &[u8],
    timeout_secs: u64,
) -> Result<frame::Frame, String> {
    let frame_bytes = frame::build_frame(frame_type, payload)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_frame_paced(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for device reply".into());
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
                if length > MAX_PAYLOAD_SIZE {
                    continue;
                }
                let mut body = vec![0u8; length + 4];
                read_exact_deadline(port, &mut body, deadline)?;
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&MAGIC_BYTES);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                if let Ok(f) = frame::parse_frame(&buf) {
                    if f.frame_type == FRAME_TYPE_ACK || f.frame_type == FRAME_TYPE_NACK {
                        return Ok(f);
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

/// Perform a one-shot vault enable/disable over serial, then return the
/// process exit code. For operators without Sapwood: opens the port, runs
/// PIN unlock (if given) and bridge session auth, sends VAULT_SET, and
/// reports the device reply. The key is zeroized after use.
fn run_vault_oneshot(cli: &Cli, vault_key_path: &std::path::Path) -> i32 {
    let mut port = match RawSerial::open(&cli.port, cli.baud) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to open serial port {}: {e}", cli.port);
            return 1;
        }
    };

    drain_serial(&mut port);

    // PIN unlock must happen before any other frame exchange.
    if let Some(pin) = &cli.pin {
        if let Err(e) = unlock_pin(&mut port, pin) {
            log::error!("PIN unlock failed: {e}");
            return 1;
        }
    }

    // VAULT_SET requires an authenticated bridge session on the device.
    let Some(hex_str) = &cli.bridge_secret else {
        log::error!(
            "--bridge-secret (or HEARTWOOD_BRIDGE_SECRET) is required for vault operations"
        );
        return 1;
    };
    let secret = match decode_hex_32(hex_str) {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return 1;
        }
    };
    if let Err(e) = authenticate_bridge(&mut port, &secret) {
        log::error!("Session authentication failed: {e}");
        return 1;
    }

    // The device holds a 30-second physical-approval window; allow margin.
    let result = if cli.vault_enable {
        match vault::load_or_generate_vault_key(vault_key_path) {
            Ok(mut key) => {
                let r = send_frame_wait_ack(
                    &mut port,
                    FRAME_TYPE_VAULT_SET,
                    &key,
                    VAULT_OPERATION_TIMEOUT_SECS,
                );
                key.zeroize();
                r
            }
            Err(e) => Err(e),
        }
    } else {
        send_frame_wait_ack(
            &mut port,
            FRAME_TYPE_VAULT_SET,
            &[],
            VAULT_OPERATION_TIMEOUT_SECS,
        )
    };

    match result {
        Ok(resp) if resp.frame_type == FRAME_TYPE_ACK => {
            log::info!(
                "Vault {} confirmed on device (button pressed)",
                if cli.vault_enable { "enable" } else { "disable" }
            );
            0
        }
        Ok(resp) => {
            let reason = String::from_utf8_lossy(&resp.payload);
            let reason = reason.trim();
            if reason.is_empty() {
                log::error!("Vault operation rejected on device (button not pressed or refused)");
            } else {
                log::error!("Vault operation rejected on device: {reason}");
            }
            1
        }
        Err(e) => {
            log::error!("Vault operation failed: {e}");
            1
        }
    }
}

/// Read exactly `buf.len()` bytes from the serial port, respecting a deadline.
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

/// Parse a 32-byte value from a 64-character hex string.
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
// Request-logging label maps
// ---------------------------------------------------------------------------

/// Build a map of master x-only pubkey -> human label, for request logging.
/// Returns an empty map if the backend is locked or has no masters.
fn build_master_labels(
    backend: &Arc<dyn backend::SigningBackend>,
) -> std::collections::HashMap<[u8; 32], String> {
    let mut map = std::collections::HashMap::new();
    let masters = match backend.list_masters() {
        Ok(m) => m,
        Err(_) => return map,
    };
    for master in &masters {
        let label = master.get("label").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(npub) = master.get("npub").and_then(|v| v.as_str()) {
            if let Ok(pk) = PublicKey::parse(npub) {
                map.insert(pk.to_bytes(), label.to_string());
            }
        }
    }
    map
}

/// Build a map of bound client x-only pubkey -> connection-slot label.
///
/// Best-effort: reads `current_pubkey` and `authorized_pubkeys` from each
/// slot returned by `list_slots`. Clients bound after startup (new `connect`)
/// will not appear until the daemon restarts; unknown clients simply log as
/// bare hex. Never fails -- errors yield an empty map.
fn build_client_labels(
    backend: &Arc<dyn backend::SigningBackend>,
) -> std::collections::HashMap<[u8; 32], String> {
    let mut map = std::collections::HashMap::new();
    let masters = match backend.list_masters() {
        Ok(m) => m,
        Err(_) => return map,
    };
    for master in &masters {
        let slot = master.get("slot").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let slots = match backend.list_slots(slot) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let arr = match slots.as_array() {
            Some(a) => a,
            None => continue,
        };
        for s in arr {
            let label = s
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut pubkeys: Vec<String> = Vec::new();
            if let Some(cp) = s.get("current_pubkey").and_then(|v| v.as_str()) {
                pubkeys.push(cp.to_string());
            }
            if let Some(authorized) = s.get("authorized_pubkeys").and_then(|v| v.as_array()) {
                for p in authorized {
                    if let Some(ps) = p.as_str() {
                        pubkeys.push(ps.to_string());
                    }
                }
            }
            for p in pubkeys {
                if let Ok(bytes) = decode_hex_32(&p) {
                    map.insert(bytes, label.clone());
                }
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Load the per-install API token from `<data_dir>/api-token`, generating one
/// (32 random bytes, hex-encoded, file mode 0600) on first boot. This keeps
/// API auth mandatory even when no --api-token / HEARTWOOD_API_TOKEN is given.
fn load_or_generate_api_token(data_dir: &str) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let path = std::path::Path::new(data_dir).join("api-token");

    if path.exists() {
        let token = std::fs::read_to_string(&path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let token = token.trim().to_string();
        if token.len() < 32 {
            return Err(format!(
                "{}: token too short ({} chars) -- delete the file to regenerate",
                path.display(),
                token.len()
            ));
        }
        return Ok(token);
    }

    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom api token: {e}"))?;
    let token = hex_encode(&bytes);

    std::fs::create_dir_all(data_dir).map_err(|e| format!("create {data_dir}: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(token.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))?;

    Ok(token)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    // Broadcast channel for device log lines (WebSocket streaming to Sapwood).
    // Created early so startup-time serial helpers can forward non-frame bytes
    // from the device as log lines. The background log_poller cannot reach the
    // serial mutex while a sign_event holds it, so opportunistic forwarding
    // during frame reads is the only way device logs appear during signing.
    let (log_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    let vault_key_path = vault::vault_key_path(&cli.data_dir);

    // One-shot vault operations run over serial and exit without starting
    // the daemon (--vault-enable / --vault-disable).
    if cli.vault_enable || cli.vault_disable {
        std::process::exit(run_vault_oneshot(&cli, &vault_key_path));
    }

    let relay_list: Vec<String> = cli.relays.split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    // Detect mode and construct backend + bunker keys.
    // Channel carrying operator-approved response envelopes from the backend
    // to the relay publisher (spawned per reconnect below). Only Soft mode
    // produces these — Hard-mode approvals complete on the device and answer
    // through the normal request path.
    let (resp_tx, resp_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let resp_rx = std::sync::Arc::new(tokio::sync::Mutex::new(resp_rx));

    let (backend_arc, bunker_keys, signing_master_pubkeys) = match detect_mode(&cli) {

        // ----------------------------------------------------------------
        // Hard mode -- ESP32 attached via USB serial
        // ----------------------------------------------------------------
        DetectedMode::Hard(mut port) => {
            let bunker_keys = Keys::parse(
                cli.bunker_secret.as_deref()
                    .expect("--bunker-secret (or HEARTWOOD_BUNKER_SECRET) is required in Hard mode")
            )?;

            log::info!("Hard mode -- ESP32 on {}", cli.port);
            log::info!("Bunker pubkey: {}", bunker_keys.public_key().to_bech32()?);

            // Drain stale bytes left by a previous session.
            drain_serial(&mut port);

            // PIN unlock must happen before any other frame exchange.
            if let Some(pin) = &cli.pin {
                if let Err(e) = unlock_pin(&mut port, pin) {
                    panic!("PIN unlock failed: {e}");
                }
            }

            // Bridge session authentication (device-decrypts mode).
            let bridge_secret: Option<[u8; 32]> = match &cli.bridge_secret {
                Some(hex_str) => Some(decode_hex_32(hex_str).expect("invalid --bridge-secret")),
                None => None,
            };

            if let Some(ref secret) = bridge_secret {
                if let Err(e) = authenticate_bridge(&mut port, secret) {
                    panic!("Session authentication failed: {e}");
                }
            }

            // At-rest vault unlock: if the host holds a vault key, deliver it
            // now so the device decrypts its seeds at boot without waiting for
            // a Sapwood/PIN unlock. Failures never stop the daemon -- the
            // device can be unlocked later via Sapwood or PIN.
            let mut vault_unlocked_at_startup = false;
            match vault::load_vault_key(&vault_key_path) {
                Ok(Some(mut key)) => {
                    match send_frame_wait_ack(
                        &mut port,
                        FRAME_TYPE_VAULT_UNLOCK,
                        &key,
                        VAULT_OPERATION_TIMEOUT_SECS,
                    ) {
                        Ok(resp) if resp.frame_type == FRAME_TYPE_ACK => {
                            log::info!("Vault unlock accepted -- device seeds decrypted");
                            vault_unlocked_at_startup = true;
                        }
                        Ok(resp) => {
                            let reason = String::from_utf8_lossy(&resp.payload);
                            let reason = reason.trim();
                            if reason == "already unlocked" {
                                log::debug!("Vault unlock skipped -- device already unlocked");
                            } else {
                                log::error!(
                                    "VAULT KEY REJECTED{} -- device stays locked; check vault.key",
                                    if reason.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" ({reason})")
                                    }
                                );
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Vault unlock failed: {e} -- device stays locked; check vault.key"
                            );
                        }
                    }
                    key.zeroize();
                }
                Ok(None) => {}
                Err(e) => {
                    log::error!(
                        "Could not load vault key: {e} -- device stays locked; check vault.key"
                    );
                }
            }

            // The locked boot loop authenticates only the temporary vault
            // delivery session. After a successful unlock, firmware builds a
            // fresh policy engine whose bridge session starts unauthenticated.
            // Authenticate again so the first encrypted signing request is not
            // rejected even though the vault delivery itself succeeded.
            if vault_unlocked_at_startup {
                if let Some(ref secret) = bridge_secret {
                    if let Err(e) = authenticate_bridge(&mut port, secret) {
                        panic!("Post-unlock session authentication failed: {e}");
                    }
                }
            }

            // Wrap in Arc<Mutex> and construct SerialBackend.
            let port = Arc::new(Mutex::new(port));
            let serial_backend = backend::serial::SerialBackend::new(
                Arc::clone(&port), log_tx.clone()
            );
            let serial_arc = serial_backend.serial().clone();
            let backend_arc: Arc<dyn backend::SigningBackend> = Arc::new(serial_backend);

            // Query master list to find the signing identity.
            let masters = backend_arc.list_masters()
                .expect("failed to query master list from ESP32 -- is the device provisioned?");
            if masters.is_empty() {
                panic!("ESP32 has no masters provisioned -- run setup-hsm.py first");
            }

            // Parse every master's pubkey. NIP-46 routing accepts p-tags for
            // any of them; --slot only selects which URI gets written to
            // bunker-uri.txt for backward-compatible single-master tooling.
            let relay_params: String = cli.relays.split(',')
                .filter(|r| !r.trim().is_empty())
                .map(|r| format!("relay={}", urlencoding::encode(r.trim())))
                .collect::<Vec<_>>()
                .join("&");

            let target_slot = cli.slot;
            let mut signing_master_pubkeys: Vec<[u8; 32]> = Vec::with_capacity(masters.len());
            let mut default_bunker_uri: Option<(u8, String, String)> = None;

            for m in &masters {
                let slot = m.get("slot").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let label = m.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mode = m.get("mode").and_then(|v| v.as_u64()).unwrap_or(0);
                let npub = m.get("npub").and_then(|v| v.as_str())
                    .expect("master npub missing");
                let pk = PublicKey::parse(npub)
                    .expect("failed to decode master npub");
                let pubkey_bytes: [u8; 32] = pk.to_bytes();
                let bunker_uri = format!(
                    "bunker://{}?{}",
                    hex_encode(&pubkey_bytes),
                    relay_params,
                );

                log::info!(
                    "Device master: slot={slot} label={label} mode={mode} npub={npub}"
                );
                log::info!("  bunker URI: {bunker_uri}");

                signing_master_pubkeys.push(pubkey_bytes);

                if slot == target_slot {
                    default_bunker_uri = Some((slot, label.clone(), bunker_uri));
                }
            }

            log::info!(
                "Routing NIP-46 traffic for {} master(s) simultaneously",
                signing_master_pubkeys.len()
            );

            // Write bunker-uri.txt for the --slot master so the Sapwood web UI
            // and existing tooling can serve it for pairing.
            let data_dir = std::path::PathBuf::from(&cli.data_dir);
            std::fs::create_dir_all(&data_dir).ok();
            let uri_path = data_dir.join("bunker-uri.txt");
            match &default_bunker_uri {
                Some((slot, label, bunker_uri)) => {
                    match std::fs::write(&uri_path, bunker_uri) {
                        Ok(()) => log::info!(
                            "Wrote default bunker URI (slot {slot}, {label}) to {}",
                            uri_path.display()
                        ),
                        Err(e) => log::error!("Failed to write bunker-uri.txt: {e}"),
                    }
                }
                None => {
                    let available: Vec<String> = masters.iter()
                        .filter_map(|m| m.get("slot").and_then(|v| v.as_u64()).map(|s| s.to_string()))
                        .collect();
                    log::warn!(
                        "No master in --slot {target_slot} -- bunker-uri.txt not written (available slots: {})",
                        available.join(", ")
                    );
                }
            }

            // Spawn background log poller (Hard mode only -- reads serial when idle).
            tokio::spawn(api::log_poller(serial_arc, log_tx.clone()));

            (backend_arc, bunker_keys, signing_master_pubkeys)
        }

        // ----------------------------------------------------------------
        // Soft mode -- Pi alone, keys encrypted at rest
        // ----------------------------------------------------------------
        DetectedMode::Soft => {
            let bunker_keys = match cli.bunker_secret.as_deref() {
                Some(secret) => Keys::parse(secret)?,
                None => Keys::generate(),
            };

            log::info!("Soft mode -- unlock via Sapwood to start signing");
            log::info!("Bunker pubkey: {}", bunker_keys.public_key().to_bech32()?);

            let data_dir = std::path::PathBuf::from(&cli.data_dir);
            std::fs::create_dir_all(&data_dir).ok();
            let soft_backend = backend::soft::SoftBackend::new(data_dir);
            soft_backend.set_response_sender(resp_tx);
            let backend_arc: Arc<dyn backend::SigningBackend> = Arc::new(soft_backend);

            // Use the bunker pubkey as placeholder until unlock reveals the real master.
            let placeholder: [u8; 32] = bunker_keys.public_key().to_bytes();

            (backend_arc, bunker_keys, vec![placeholder])
        }
    };

    // API token: explicit flag/env wins. Otherwise load the per-install token
    // from <data_dir>/api-token, generating one on first boot -- auth is never
    // silently disabled (an open API lets any LAN client factory-reset the
    // signer or export backups).
    let api_token = match cli.api_token.clone() {
        Some(token) => token,
        None => load_or_generate_api_token(&cli.data_dir)?,
    };
    if cli.api_token.is_some() {
        log::info!("API token auth ENABLED -- /api/* routes (except /api/info) require Bearer token");
    } else {
        log::info!(
            "API token auth ENABLED -- generated/stored at {}/api-token (mode 0600); enter it in Sapwood when prompted",
            cli.data_dir
        );
    }

    // Build AppState and spawn the management API.
    let app_state = api::AppState {
        backend: Arc::clone(&backend_arc),
        daemon_info: Arc::new(api::DaemonInfo {
            tier: backend_arc.tier(),
            relays: relay_list.clone(),
            start_time: std::time::Instant::now(),
        }),
        log_tx: log_tx.clone(),
        api_token: Some(Arc::new(api_token)),
        backup_path: std::path::PathBuf::from(&cli.data_dir).join("backup.json"),
        passphrase_path: std::path::PathBuf::from(&cli.data_dir).join("backup-passphrase.json"),
        vault_key_path: vault_key_path.clone(),
    };

    // CORS is opt-in only: the API serves bearer-authenticated requests, and
    // allowing any origin would let any web page a LAN user visits drive the
    // API from their browser. Sapwood is served same-origin via --sapwood-dir,
    // so it needs no CORS.
    let enable_cors = cli.cors;
    let api_router = api::router(app_state, cli.sapwood_dir.as_deref(), enable_cors);
    let api_port = cli.api_port;

    log::info!("Spawning management API on port {api_port}...");
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
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

    // Best-effort label maps for relay-side request logging. Built once from
    // the backend's master + connection-slot metadata so each NIP-46 request
    // logs as `"bark" (<hex>)` instead of an opaque pubkey. Empty when the
    // backend is locked (Soft mode before unlock) or when the device omits
    // bound pubkeys -- in which case logging falls back to bare hex.
    let master_labels = build_master_labels(&backend_arc);
    let client_labels = build_client_labels(&backend_arc);
    log::info!(
        "Request logging: {} master label(s), {} client label(s)",
        master_labels.len(),
        client_labels.len(),
    );

    // Relay event loop with automatic reconnection. If the relay drops the
    // connection (e.g. idle timeout during a demo pause), we reconnect with
    // backoff rather than exiting the daemon.
    let mut backoff_secs = 5u64;
    loop {
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(bunker_keys.clone()))
            .build();
        for url in &relay_list {
            client.add_relay(url.as_str()).await?;
        }
        client.connect().await;

        log::info!("Waiting for relay connections...");
        tokio::time::sleep(Duration::from_secs(3)).await;
        log::info!("Connected to relays");

        // Publish operator-approved responses (Soft mode approval queue).
        // Respawned each reconnect so it always uses the live client.
        let publisher = {
            let client = client.clone();
            let resp_rx = std::sync::Arc::clone(&resp_rx);
            tokio::spawn(async move {
                loop {
                    let json = {
                        let mut rx = resp_rx.lock().await;
                        match rx.recv().await {
                            Some(json) => json,
                            None => break, // sender dropped — daemon is exiting
                        }
                    };
                    match Event::from_json(&json) {
                        Ok(ev) => match client.send_event(&ev).await {
                            Ok(output) => {
                                log::info!("Approved response published: {}", output.id())
                            }
                            Err(e) => log::error!("Approved response publish failed: {e}"),
                        },
                        Err(e) => log::error!("Approved response is not a valid event: {e}"),
                    }
                }
            })
        };

        match relay::run_event_loop(
            &client,
            &backend_arc,
            &signing_master_pubkeys,
            &master_labels,
            &client_labels,
        )
        .await
        {
            Ok(()) => {
                log::warn!("Relay event loop ended -- reconnecting in {backoff_secs}s");
            }
            Err(e) => {
                log::error!("Relay event loop error: {e} -- reconnecting in {backoff_secs}s");
            }
        }

        publisher.abort();

        // Disconnect cleanly before reconnecting.
        client.disconnect().await;

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
}
