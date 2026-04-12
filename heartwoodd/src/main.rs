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

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use nostr_sdk::prelude::*;

use heartwood_common::frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::types::*;

use serial::RawSerial;

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

    /// Master slot index to use (default: 0)
    #[arg(long, default_value_t = 0)]
    slot: u8,

    /// Management API port
    #[arg(long, default_value_t = 3100)]
    api_port: u16,

    /// Sapwood static files directory
    #[arg(long)]
    sapwood_dir: Option<String>,

    /// Enable CORS headers on API responses (auto-enabled when --sapwood-dir is not set)
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
                        let _ = port.write_all(&frame_bytes);
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
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // Broadcast channel for device log lines (WebSocket streaming to Sapwood).
    // Created early so startup-time serial helpers can forward non-frame bytes
    // from the device as log lines. The background log_poller cannot reach the
    // serial mutex while a sign_event holds it, so opportunistic forwarding
    // during frame reads is the only way device logs appear during signing.
    let (log_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    let relay_list: Vec<String> = cli.relays.split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    // Detect mode and construct backend + bunker keys.
    let (backend_arc, bunker_keys, signing_master_pubkey) = match detect_mode(&cli) {

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

            for m in &masters {
                log::info!(
                    "Device master: slot={} label={} mode={} npub={}",
                    m.get("slot").and_then(|v| v.as_u64()).unwrap_or(0),
                    m.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                    m.get("mode").and_then(|v| v.as_u64()).unwrap_or(0),
                    m.get("npub").and_then(|v| v.as_str()).unwrap_or(""),
                );
            }

            let target_slot = cli.slot;
            let selected = masters.iter()
                .find(|m| m.get("slot").and_then(|v| v.as_u64()) == Some(target_slot as u64))
                .unwrap_or_else(|| panic!(
                    "No master in slot {} -- available slots: {}",
                    target_slot,
                    masters.iter()
                        .filter_map(|m| m.get("slot").and_then(|v| v.as_u64()).map(|s| s.to_string()))
                        .collect::<Vec<_>>().join(", ")
                ));
            let slot = target_slot;
            let label = selected.get("label").and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let npub = selected.get("npub").and_then(|v| v.as_str())
                .expect("master npub missing");
            let pk = PublicKey::parse(npub)
                .expect("failed to decode master npub");
            let signing_master_pubkey: [u8; 32] = pk.to_bytes();
            log::info!("Routing NIP-46 traffic to master slot {} ({}), pubkey {}",
                slot, label, hex_encode(&signing_master_pubkey));

            // Write bunker-uri.txt so the Sapwood web UI can serve it for pairing.
            let relay_params: String = cli.relays.split(',')
                .filter(|r| !r.trim().is_empty())
                .map(|r| format!("relay={}", urlencoding::encode(r.trim())))
                .collect::<Vec<_>>()
                .join("&");
            let bunker_uri = format!(
                "bunker://{}?{}",
                hex_encode(&signing_master_pubkey),
                relay_params,
            );
            let data_dir = std::path::PathBuf::from(&cli.data_dir);
            std::fs::create_dir_all(&data_dir).ok();
            let uri_path = data_dir.join("bunker-uri.txt");
            match std::fs::write(&uri_path, &bunker_uri) {
                Ok(()) => log::info!("Wrote bunker URI to {}", uri_path.display()),
                Err(e) => log::error!("Failed to write bunker-uri.txt: {e}"),
            }

            // Spawn background log poller (Hard mode only -- reads serial when idle).
            tokio::spawn(api::log_poller(serial_arc, log_tx.clone()));

            (backend_arc, bunker_keys, signing_master_pubkey)
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
            let backend_arc: Arc<dyn backend::SigningBackend> = Arc::new(soft_backend);

            // Use the bunker pubkey as placeholder until unlock reveals the real master.
            let placeholder: [u8; 32] = bunker_keys.public_key().to_bytes();

            (backend_arc, bunker_keys, placeholder)
        }
    };

    // API token logging.
    if cli.api_token.is_some() {
        log::info!("API token auth ENABLED -- /api/* routes (except /api/info) require Bearer token");
    } else {
        log::warn!("API token auth DISABLED -- any LAN client can hit /api/device/factory-reset. Set HEARTWOOD_API_TOKEN to enable.");
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
        api_token: cli.api_token.clone().map(Arc::new),
    };

    let enable_cors = cli.cors || cli.sapwood_dir.is_none();
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

    // Relay event loop with automatic reconnection. If the relay drops the
    // connection (e.g. idle timeout during a demo pause), we reconnect with
    // backoff rather than exiting the daemon.
    let mut backoff_secs = 5u64;
    loop {
        let client = Client::new(bunker_keys.clone());
        for url in &relay_list {
            client.add_relay(url.as_str()).await?;
        }
        client.connect().await;

        log::info!("Waiting for relay connections...");
        tokio::time::sleep(Duration::from_secs(3)).await;
        log::info!("Connected to relays");

        match relay::run_event_loop(&client, &backend_arc, &signing_master_pubkey).await {
            Ok(()) => {
                log::warn!("Relay event loop ended -- reconnecting in {backoff_secs}s");
            }
            Err(e) => {
                log::error!("Relay event loop error: {e} -- reconnecting in {backoff_secs}s");
            }
        }

        // Disconnect cleanly before reconnecting.
        client.disconnect().await;

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
}
