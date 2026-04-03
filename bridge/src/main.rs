// bridge/src/main.rs
//
// Pi-side relay bridge for the Heartwood ESP32 signing bunker.
//
// Connects to Nostr relays, subscribes to NIP-46 request events addressed to
// the bunker pubkey, and forwards them to the ESP32 over serial.
//
// Two operating modes:
//
//   Passthrough mode (--bridge-secret provided):
//     Authenticates with the ESP32 at startup via a SESSION_AUTH (0x21) frame.
//     Forwards raw NIP-44 ciphertext to the ESP32 via ENCRYPTED_REQUEST (0x10)
//     frames. The ESP32 decrypts, signs, re-encrypts and returns ENCRYPTED_RESPONSE
//     (0x11). The bridge publishes the ciphertext verbatim — no crypto happens here.
//
//   Legacy mode (no --bridge-secret):
//     Bridge NIP-44 decrypts the request, forwards the plaintext NIP-46 JSON-RPC
//     to the ESP32 via NIP46_REQUEST (0x02) frames, receives the plaintext response,
//     NIP-44 encrypts it and publishes to the relay.
//
// The ESP32 is the brain — it holds the keys and makes all signing decisions.
// This bridge is a dumb pipe that provides network access.

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use nostr::nips::nip44;
use nostr_sdk::prelude::*;

use heartwood_common::frame;
use heartwood_common::types::*;

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

    /// Bunker secret key (nsec or hex) — used for relay auth and, in legacy mode, NIP-44 crypto
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
    /// If provided, uses encrypted passthrough mode. If omitted, falls back to legacy mode.
    #[arg(long)]
    bridge_secret: Option<String>,

    /// Boot PIN (4–8 ASCII digits). When provided, the bridge sends a PIN_UNLOCK (0x26) frame
    /// immediately after opening the serial port, before SESSION_AUTH. If the device has no
    /// PIN set (or is already unlocked) omit this argument entirely.
    #[arg(long)]
    pin: Option<String>,
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------

/// Send a NIP-46 JSON-RPC request to the ESP32 over serial and read the response.
/// Legacy mode only — forwards plaintext, expects a NIP46_RESPONSE (0x03) frame back.
/// Read exactly `buf.len()` bytes from the serial port, respecting a deadline.
fn read_exact_timeout(
    port: &mut Box<dyn serialport::SerialPort>,
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
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read failed: {e}")),
        }
    }
    Ok(())
}

fn forward_to_esp32(
    port: &mut Box<dyn serialport::SerialPort>,
    request_json: &str,
) -> Result<String, String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    std::io::Write::write_all(port.as_mut(), &frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    std::io::Write::flush(port.as_mut())
        .map_err(|e| format!("serial flush failed: {e}"))?;

    read_any_response(port)
}

/// Authenticate the bridge session with the ESP32.
///
/// Sends a SESSION_AUTH (0x21) frame containing the 32-byte bridge secret and
/// waits for a SESSION_ACK (0x22) frame with status byte 0x00.
fn authenticate_bridge(
    port: &mut Box<dyn serialport::SerialPort>,
    bridge_secret: &[u8; 32],
) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_SESSION_AUTH, bridge_secret)
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    std::io::Write::write_all(port.as_mut(), &frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    std::io::Write::flush(port.as_mut())
        .map_err(|e| format!("serial flush failed: {e}"))?;

    // Read response — hunt for magic bytes [0x48, 0x57] since ESP-IDF log
    // output pollutes the USB-CDC stream alongside frame data.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for session ACK".into());
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                // Hunt for first magic byte.
                if byte[0] != 0x48 {
                    continue;
                }
                // Confirm second magic byte.
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => continue,
                }
                // Read header: type + length (3 bytes).
                let mut header = [0u8; 3];
                read_exact_timeout(port, &mut header, deadline)?;
                let frame_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                // Read payload + CRC.
                let mut body = vec![0u8; length + 4];
                read_exact_timeout(port, &mut body, deadline)?;
                // Reassemble and parse.
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&[0x48, 0x57]);
                buf.push(frame_type);
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
    port: &mut Box<dyn serialport::SerialPort>,
    pin: &str,
) -> Result<(), String> {
    let frame_bytes = frame::build_frame(FRAME_TYPE_PIN_UNLOCK, pin.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    std::io::Write::write_all(port.as_mut(), &frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    std::io::Write::flush(port.as_mut())
        .map_err(|e| format!("serial flush failed: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut buf = vec![0u8; MAX_PAYLOAD_SIZE + FRAME_OVERHEAD];
    let mut pos = 0;

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for PIN unlock response".into());
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if pos < buf.len() {
                    buf[pos] = byte[0];
                    pos += 1;
                }

                if pos >= FRAME_OVERHEAD {
                    match frame::parse_frame(&buf[..pos]) {
                        Ok(f) if f.frame_type == FRAME_TYPE_ACK => {
                            log::info!("PIN unlock accepted");
                            return Ok(());
                        }
                        Ok(f) if f.frame_type == FRAME_TYPE_NACK => {
                            return Err("PIN unlock rejected (NACK) — wrong PIN".into());
                        }
                        Err(frame::FrameError::TooShort) => continue,
                        _ => continue,
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
    port: &mut Box<dyn serialport::SerialPort>,
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

    std::io::Write::write_all(port.as_mut(), &frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    std::io::Write::flush(port.as_mut())
        .map_err(|e| format!("serial flush failed: {e}"))?;

    read_any_response(port)
}

/// Read a response frame from the ESP32, accepting both NIP46_RESPONSE (0x03, plaintext)
/// and ENCRYPTED_RESPONSE (0x11, ciphertext) frame types.
///
/// Hunts for magic bytes `[0x48, 0x57]` in the stream to skip ESP-IDF log
/// output that pollutes the USB-CDC channel.
///
/// Returns the payload as a UTF-8 string (either raw JSON or NIP-44 ciphertext).
fn read_any_response(port: &mut Box<dyn serialport::SerialPort>) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for ESP32 response".into());
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                // Hunt for first magic byte.
                if byte[0] != 0x48 {
                    continue;
                }
                // Confirm second magic byte.
                match port.read(&mut byte) {
                    Ok(1) if byte[0] == 0x57 => {}
                    _ => continue,
                }
                // Read header: type + length (3 bytes).
                let mut header = [0u8; 3];
                read_exact_timeout(port, &mut header, deadline)?;
                let resp_type = header[0];
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                // Read payload + CRC.
                let mut body = vec![0u8; length + 4];
                read_exact_timeout(port, &mut body, deadline)?;
                // Reassemble and parse.
                let mut buf = Vec::with_capacity(5 + length + 4);
                buf.extend_from_slice(&MAGIC_BYTES);
                buf.push(resp_type);
                buf.extend_from_slice(&header[1..3]);
                buf.extend_from_slice(&body);
                match frame::parse_frame(&buf) {
                    Ok(response_frame) => {
                        if response_frame.frame_type == FRAME_TYPE_NIP46_RESPONSE
                            || response_frame.frame_type == FRAME_TYPE_ENCRYPTED_RESPONSE
                        {
                            return String::from_utf8(response_frame.payload)
                                .map_err(|e| format!("invalid UTF-8 in response: {e}"));
                        } else if response_frame.frame_type == FRAME_TYPE_NACK {
                            return Err("ESP32 sent NACK".into());
                        }
                        // Other frame type — skip and keep hunting.
                    }
                    Err(_) => continue, // Bad CRC — skip and keep hunting.
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
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
        if passthrough { "passthrough (encrypted)" } else { "legacy (bridge decrypts)" }
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

    // Open serial port (wrapped in Mutex for shared access from async closure)
    let port: Box<dyn serialport::SerialPort> = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_secs(60))
        .open()
        .expect("failed to open serial port");

    // Disable DTR/RTS — toggling these resets the ESP32
    let mut port = port;
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    // Drain any stale bytes in the serial buffer before starting.
    port.set_timeout(Duration::from_millis(100)).ok();
    let mut drain = [0u8; 1024];
    while port.read(&mut drain).unwrap_or(0) > 0 {}
    port.set_timeout(Duration::from_secs(10)).ok();

    log::info!("Serial port {} open", cli.port);

    // If a boot PIN was provided, unlock the device before doing anything else.
    // The ESP32 only accepts PIN_UNLOCK (0x26) and PROVISION_LIST (0x05) while locked.
    if let Some(pin) = &cli.pin {
        if let Err(e) = unlock_pin(&mut port, pin) {
            panic!("PIN unlock failed: {e}");
        }
    }

    // Authenticate with the ESP32 if running in passthrough mode
    if let Some(secret) = &bridge_secret {
        if let Err(e) = authenticate_bridge(&mut port, secret) {
            panic!("Session authentication failed: {e}");
        }
    }

    let port = Mutex::new(port);

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

    // Pre-compute the bunker pubkey bytes once (used in passthrough mode)
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
                    // Passthrough mode — forward raw ciphertext to ESP32
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
                    // Legacy mode — bridge does NIP-44 decrypt/encrypt
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

                    // Inject the client pubkey into the request so the ESP32
                    // can identify the client for TOFU policy in legacy mode.
                    let plaintext = match serde_json::from_str::<serde_json::Value>(&plaintext) {
                        Ok(mut v) => {
                            v["_client_pubkey"] = serde_json::json!(client_pubkey.to_hex());
                            v.to_string()
                        }
                        Err(_) => plaintext,
                    };

                    log::info!(
                        "Decrypted request: {}",
                        &plaintext[..plaintext.len().min(100)]
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
