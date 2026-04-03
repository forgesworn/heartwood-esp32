// bridge/src/main.rs
//
// Pi-side relay bridge for the Heartwood ESP32 signing bunker.
//
// Connects to Nostr relays, subscribes to NIP-46 request events addressed to
// the bunker pubkey, NIP-44 decrypts them, forwards the plaintext NIP-46
// JSON-RPC over serial to the ESP32, reads the response, NIP-44 encrypts it,
// and publishes back to the relay.
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

    /// Bunker secret key (nsec or hex) — used for NIP-44 encryption and relay auth
    #[arg(long)]
    bunker_secret: String,

    /// Relay URLs (comma-separated)
    #[arg(short, long, default_value = "wss://relay.damus.io,wss://nos.lol")]
    relays: String,
}

/// Send a NIP-46 JSON-RPC request to the ESP32 over serial and read the response.
fn forward_to_esp32(
    port: &mut Box<dyn serialport::SerialPort>,
    request_json: &str,
) -> Result<String, String> {
    // Build and send the request frame
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .map_err(|e| format!("frame build failed: {:?}", e))?;

    std::io::Write::write_all(port.as_mut(), &frame_bytes)
        .map_err(|e| format!("serial write failed: {e}"))?;
    std::io::Write::flush(port.as_mut())
        .map_err(|e| format!("serial flush failed: {e}"))?;

    // Read response — hunt for a valid frame (ESP-IDF log noise may be mixed in)
    let mut buf = vec![0u8; MAX_PAYLOAD_SIZE + FRAME_OVERHEAD];
    let mut pos = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);

    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for ESP32 response".into());
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
                        Ok(response_frame) => {
                            if response_frame.frame_type == FRAME_TYPE_NIP46_RESPONSE {
                                return String::from_utf8(response_frame.payload)
                                    .map_err(|e| format!("invalid UTF-8 in response: {e}"));
                            } else if response_frame.frame_type == FRAME_TYPE_NACK {
                                return Err("ESP32 sent NACK".into());
                            } else {
                                return Err(format!(
                                    "unexpected frame type: 0x{:02x}",
                                    response_frame.frame_type
                                ));
                            }
                        }
                        Err(frame::FrameError::TooShort) => continue,
                        Err(_) => {
                            // Bad frame — try to find next magic bytes
                            if let Some(magic_pos) = buf[1..pos]
                                .windows(2)
                                .position(|w| w == &MAGIC_BYTES)
                            {
                                let new_start = magic_pos + 1;
                                buf.copy_within(new_start..pos, 0);
                                pos -= new_start;
                            } else {
                                pos = 0;
                            }
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    // Parse bunker keys
    let bunker_keys = Keys::parse(&cli.bunker_secret)?;
    let bunker_pubkey = bunker_keys.public_key();

    log::info!("Bunker pubkey: {}", bunker_pubkey.to_bech32()?);

    // Open serial port (wrapped in Mutex for shared access from async closure)
    let port: Box<dyn serialport::SerialPort> = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_secs(60))
        .open()
        .expect("failed to open serial port");

    // Disable DTR/RTS — toggling these resets the ESP32
    let mut port = port;
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    let port = Mutex::new(port);

    log::info!("Serial port {} open", cli.port);

    // Connect to relays
    let client = Client::new(bunker_keys.clone());
    for relay_url in cli.relays.split(',') {
        let url = relay_url.trim();
        if !url.is_empty() {
            client.add_relay(url).await?;
        }
    }
    client.connect().await;
    log::info!("Connected to relays");

    // Subscribe to NIP-46 requests addressed to our bunker pubkey
    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(bunker_pubkey)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!("Subscribed to NIP-46 events — waiting for requests...");

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

                // NIP-44 decrypt the content
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

                log::info!(
                    "Decrypted request: {}",
                    &plaintext[..plaintext.len().min(100)]
                );

                // Forward to ESP32 over serial (blocking — fine for single-request flow)
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

                // NIP-44 encrypt the response
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

                // Build and publish the response event (kind 24133)
                let response_event = EventBuilder::new(Kind::NostrConnect, ciphertext)
                    .tag(Tag::public_key(client_pubkey));

                match client_clone.send_event_builder(response_event).await {
                    Ok(output) => log::info!("Response published: {}", output.id()),
                    Err(e) => log::error!("Failed to publish response: {e}"),
                }

                Ok(false) // keep listening
            }
        })
        .await?;

    Ok(())
}
