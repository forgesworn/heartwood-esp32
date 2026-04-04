// bridge/src/main.rs
//
// Pi-side relay bridge for the Heartwood ESP32 signing bunker.
//
// Connects to Nostr relays, subscribes to NIP-46 request events addressed to
// the bunker pubkey, and forwards them to the ESP32 over serial.
//
// Two operating modes:
//
//   Device-decrypts mode (--bridge-secret provided):
//     Authenticates with the ESP32 at startup via a SESSION_AUTH (0x21) frame.
//     Forwards raw NIP-44 ciphertext to the ESP32 via ENCRYPTED_REQUEST (0x10)
//     frames. The ESP32 decrypts, signs, re-encrypts and returns ENCRYPTED_RESPONSE
//     (0x11). The bridge publishes the ciphertext verbatim — no crypto happens here.
//
//   Bridge-decrypts mode (no --bridge-secret):
//     Bridge NIP-44 decrypts the request, forwards the plaintext NIP-46 JSON-RPC
//     to the ESP32 via NIP46_REQUEST (0x02) frames, receives the plaintext response,
//     NIP-44 encrypts it and publishes to the relay.
//
// The ESP32 is the brain — it holds the keys and makes all signing decisions.
// This bridge is a dumb pipe that provides network access.

mod api;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use nix::sys::termios;
use nostr::nips::nip44;
use nostr_sdk::prelude::*;

use heartwood_common::frame;
use heartwood_common::types::*;

// ---------------------------------------------------------------------------
// Raw POSIX serial wrapper
// ---------------------------------------------------------------------------

/// Thin wrapper around a raw file descriptor for serial I/O.
/// Uses POSIX termios instead of the `serialport` crate to avoid
/// DTR toggling on open (which reboots the ESP32-S3 via USB-CDC).
pub struct RawSerial {
    pub file: File,
}

impl RawSerial {
    /// Open a serial port with raw POSIX I/O.
    ///
    /// Sets CLOCAL (ignore modem control lines) so DTR is never asserted,
    /// configures raw mode at the given baud rate, and explicitly clears
    /// DTR/RTS via ioctl.
    fn open(path: &str, baud: u32) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let raw_fd = file.as_raw_fd();
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        let mut cfg = termios::tcgetattr(fd)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        termios::cfmakeraw(&mut cfg);

        // Map baud rate
        let baud_rate = match baud {
            9600 => termios::BaudRate::B9600,
            19200 => termios::BaudRate::B19200,
            38400 => termios::BaudRate::B38400,
            57600 => termios::BaudRate::B57600,
            115200 => termios::BaudRate::B115200,
            230400 => termios::BaudRate::B230400,
            _ => termios::BaudRate::B115200,
        };
        termios::cfsetspeed(&mut cfg, baud_rate)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Disable hardware flow control
        cfg.control_flags.remove(termios::ControlFlags::CRTSCTS);
        // Enable receiver, local mode (ignore modem control = no DTR)
        cfg.control_flags.insert(termios::ControlFlags::CREAD);
        cfg.control_flags.insert(termios::ControlFlags::CLOCAL);
        // Disable HUPCL (don't drop DTR on close)
        cfg.control_flags.remove(termios::ControlFlags::HUPCL);

        // VMIN=1, VTIME=0 -- block until at least 1 byte arrives.
        // Previous setting (VMIN=0, VTIME=1) added 100ms latency per read
        // because VTIME=1 means "wait up to 100ms even if data is available."
        // With VMIN=1/VTIME=0 the read returns as soon as any byte arrives,
        // cutting serial round-trip from ~6s to <200ms for typical responses.
        cfg.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 1;
        cfg.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 0;

        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &cfg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Clear DTR and RTS explicitly via ioctl
        unsafe {
            let mut bits: libc::c_int = libc::TIOCM_DTR | libc::TIOCM_RTS;
            libc::ioctl(raw_fd, libc::TIOCMBIC as _, &mut bits);
        }

        Ok(Self { file })
    }
}

impl Read for RawSerial {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for RawSerial {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

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

    /// Bunker secret key (nsec or hex) — used for relay auth and, in bridge-decrypts mode, NIP-44 crypto
    #[arg(long)]
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
    #[arg(long)]
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
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------

/// Send a NIP-46 JSON-RPC request to the ESP32 over serial and read the response.
/// Bridge-decrypts mode only — forwards plaintext, expects a NIP46_RESPONSE (0x03) frame back.
fn forward_to_esp32(
    port: &mut RawSerial,
    request_json: &str,
) -> Result<String, String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    port.write_all(&frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush failed: {e}"))?;

    read_any_response(port)
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
fn forward_encrypted(
    port: &mut RawSerial,
    master_pubkey: &[u8; 32],
    client_pubkey: &[u8; 32],
    ciphertext: &str,
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

    let result = read_any_response(port);

    log::info!("serial: total round-trip {}ms", t_send.elapsed().as_millis());

    result
}

/// Read a response frame from the ESP32, accepting both NIP46_RESPONSE (0x03, plaintext)
/// and ENCRYPTED_RESPONSE (0x11, ciphertext) frame types.
///
/// Returns the payload as a UTF-8 string (either raw JSON or NIP-44 ciphertext).
fn read_any_response(port: &mut RawSerial) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let t_start = std::time::Instant::now();
    let mut skipped_bytes: usize = 0;

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for ESP32 response".into());
        }

        // Hunt for magic bytes -- skip ESP-IDF log output that pollutes USB-CDC.
        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if byte[0] != 0x48 {
                    skipped_bytes += 1;
                    continue;
                }
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => { skipped_bytes += 1; continue; }
                }

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
                        if f.frame_type == FRAME_TYPE_NIP46_RESPONSE
                            || f.frame_type == FRAME_TYPE_ENCRYPTED_RESPONSE
                            || f.frame_type == FRAME_TYPE_PROVISION_LIST_RESPONSE
                        {
                            log::debug!("serial: response parsed after {}ms total", t_start.elapsed().as_millis());
                            return String::from_utf8(f.payload)
                                .map_err(|e| format!("invalid UTF-8 in response: {e}"));
                        } else if f.frame_type == FRAME_TYPE_NACK {
                            return Err("ESP32 sent NACK".into());
                        }
                        // Other frame type -- skip and keep hunting.
                        skipped_bytes = 0;
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

    // Write bunker-uri.txt so the heartwood-device web UI can serve it to Bark.
    if let Some(ref dir) = cli.data_dir {
        let relay_params: String = cli
            .relays
            .split(',')
            .filter(|r| !r.trim().is_empty())
            .map(|r| format!("relay={}", urlencoding::encode(r.trim())))
            .collect::<Vec<_>>()
            .join("&");
        let bunker_uri = format!(
            "bunker://{}?{}",
            bunker_pubkey.to_hex(),
            relay_params,
        );
        let path = std::path::Path::new(dir).join("bunker-uri.txt");
        match std::fs::write(&path, &bunker_uri) {
            Ok(()) => log::info!("Wrote bunker URI to {}", path.display()),
            Err(e) => log::error!("Failed to write bunker-uri.txt: {e}"),
        }
    }

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

    let port = Arc::new(Mutex::new(port));

    // Build the bunker URI for the API info endpoint.
    let relay_list: Vec<String> = cli.relays.split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    let relay_params: String = relay_list.iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect::<Vec<_>>()
        .join("&");
    let bunker_uri = format!("bunker://{}?{}", bunker_pubkey.to_hex(), relay_params);

    // Spawn the management API server.
    let app_state = api::AppState {
        serial: Arc::clone(&port),
        bridge_info: Arc::new(api::BridgeInfo {
            mode: if passthrough { "device-decrypts".into() } else { "bridge-decrypts".into() },
            relays: relay_list.clone(),
            bunker_uri: bunker_uri.clone(),
            start_time: std::time::Instant::now(),
        }),
    };

    let enable_cors = cli.cors || cli.sapwood_dir.is_none();
    let api_router = api::router(app_state, cli.sapwood_dir.as_deref(), enable_cors);
    let api_port = cli.api_port;

    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
        let listener = tokio::net::TcpListener::bind(addr).await
            .expect("failed to bind API port");
        log::info!("Management API listening on http://0.0.0.0:{api_port}");
        if let Err(e) = axum::serve(listener, api_router).await {
            log::error!("API server error: {e}");
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

    // Subscribe to NIP-46 requests addressed to our bunker pubkey
    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(bunker_pubkey)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!("Subscribed to NIP-46 events — waiting for requests...");

    // Pre-compute the bunker pubkey bytes once (used in device-decrypts mode)
    let master_pubkey_bytes: [u8; 32] = bunker_pubkey.to_bytes();

    // Event loop — process incoming NIP-46 requests
    client
        .handle_notifications(|notification| {
            let bunker_keys = bunker_keys.clone();
            let client_clone = client.clone();
            let port = &port;

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
                    // Device-decrypts mode — forward raw ciphertext to ESP32
                    // -------------------------------------------------------
                    let client_pubkey_bytes: [u8; 32] = client_pubkey.to_bytes();

                    let response_content = {
                        let mut port = port.lock().unwrap();
                        match forward_encrypted(
                            &mut port,
                            &master_pubkey_bytes,
                            &client_pubkey_bytes,
                            &event.content,
                        ) {
                            Ok(resp) => resp,
                            Err(e) => {
                                log::error!("ESP32 forward (encrypted) failed: {e}");
                                return Ok(false);
                            }
                        }
                    };

                    log::info!(
                        "ESP32 response ({} bytes)",
                        response_content.len()
                    );

                    // Publish the response verbatim — the ESP32 has already encrypted it
                    let response_event = EventBuilder::new(Kind::NostrConnect, response_content)
                        .tag(Tag::public_key(client_pubkey));

                    match client_clone.send_event_builder(response_event).await {
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
                        match forward_to_esp32(&mut port, &plaintext) {
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
