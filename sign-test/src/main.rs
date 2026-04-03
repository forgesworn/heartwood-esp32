// sign-test/src/main.rs
//
// Test harness CLI for the heartwood-esp32 signing oracle.
//
// Sends NIP-46 sign_event or get_public_key requests over serial and prints
// the response from the device. Useful for validating the full signing flow
// without needing a Nostr client.

use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use heartwood_common::frame::{self, FrameError};
use heartwood_common::types::{FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, MAGIC_BYTES};

#[derive(Parser)]
#[command(name = "heartwood-sign-test")]
#[command(about = "Test harness for heartwood-esp32 — sends NIP-46 requests over serial")]
struct Cli {
    /// Serial port path (e.g. /dev/cu.usbserial-* or /dev/ttyUSB0)
    #[arg(short, long)]
    port: String,

    /// Baud rate
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    /// NIP-46 method to invoke (sign_event or get_public_key)
    #[arg(short, long, default_value = "sign_event")]
    method: String,

    /// Heartwood derivation purpose (e.g. "persona/social"). Omit for master key.
    #[arg(long)]
    purpose: Option<String>,

    /// Derivation index within the purpose branch
    #[arg(long, default_value_t = 0)]
    index: u32,

    /// Nostr event kind (used with sign_event)
    #[arg(short, long, default_value_t = 1)]
    kind: u64,

    /// Event content (used with sign_event)
    #[arg(short, long, default_value = "Hello from sign-test")]
    content: String,
}

fn main() {
    let cli = Cli::parse();

    // Build the NIP-46 JSON-RPC request.
    let request_id = "sign-test-1";
    let request_json = build_request(&cli, request_id);

    println!("Request JSON:");
    // Pretty-print the request before sending.
    match serde_json::from_str::<serde_json::Value>(&request_json) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(_) => println!("{request_json}"),
    }
    println!();

    // Frame the request.
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .unwrap_or_else(|_| {
            eprintln!("Request JSON too large to fit in a serial frame (max 4096 bytes).");
            std::process::exit(1);
        });

    // Open the serial port.
    println!("Opening {}...", cli.port);
    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_millis(100))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    // Disable DTR/RTS — toggling these resets the ESP32-S3 USB-Serial-JTAG.
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    // Allow the device time to settle after port open.
    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(2));

    // Send the framed request.
    println!("Sending {} request...", cli.method);
    port.write_all(&frame_bytes).unwrap_or_else(|e| {
        eprintln!("Failed to write to serial port: {e}");
        std::process::exit(1);
    });
    port.flush().unwrap_or_else(|e| {
        eprintln!("Failed to flush serial port: {e}");
        std::process::exit(1);
    });

    // Read response — hunt for a valid NIP-46 response frame in the stream.
    // The serial channel is shared with ESP-IDF log output, so we may receive
    // arbitrary bytes before the frame magic bytes appear.
    println!("Waiting for response (60 s timeout)...\n");
    let response_json = read_response_frame(&mut *port, FRAME_TYPE_NIP46_RESPONSE);

    println!("Response JSON:");
    match serde_json::from_str::<serde_json::Value>(&response_json) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());

            // If this is a get_public_key response, show the npub too.
            if cli.method == "get_public_key" {
                if let Some(hex_pubkey) = v.get("result").and_then(|r| r.as_str()) {
                    if hex_pubkey.len() == 64 {
                        let npub = heartwood_common::encoding::encode_npub(
                            &hex_decode_32(hex_pubkey).unwrap_or([0u8; 32]),
                        );
                        println!("\nnpub: {npub}");
                    }
                }
            }
        }
        Err(_) => println!("{response_json}"),
    }
}

/// Build the NIP-46 JSON-RPC request body for the given CLI arguments.
fn build_request(cli: &Cli, request_id: &str) -> String {
    // Optional Heartwood context for child-key derivation.
    let heartwood_ctx = cli.purpose.as_deref().map(|purpose| {
        serde_json::json!({
            "purpose": purpose,
            "index": cli.index,
        })
    });

    let request = match cli.method.as_str() {
        "get_public_key" => {
            serde_json::json!({
                "id": request_id,
                "method": "get_public_key",
                "params": [],
                "heartwood": heartwood_ctx,
            })
        }
        "sign_event" | _ => {
            // Current Unix timestamp for the event.
            let created_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();

            // Unsigned event with a placeholder zero pubkey — the device will
            // substitute the real pubkey before signing.
            let unsigned_event = serde_json::json!({
                "pubkey": "0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": created_at,
                "kind": cli.kind,
                "tags": [],
                "content": cli.content,
            });

            // NIP-46 sign_event passes the event as a JSON string in params[0].
            let event_str = serde_json::to_string(&unsigned_event)
                .expect("failed to serialise unsigned event");

            serde_json::json!({
                "id": request_id,
                "method": "sign_event",
                "params": [event_str],
                "heartwood": heartwood_ctx,
            })
        }
    };

    serde_json::to_string(&request).expect("failed to serialise NIP-46 request")
}

/// Read bytes from the port until a valid frame of `expected_type` is found,
/// or the 60-second deadline is reached.
///
/// Handles the ESP-IDF log noise on the shared USB-Serial-JTAG channel by
/// scanning the accumulation buffer for the frame magic bytes when a parse
/// attempt fails.
fn read_response_frame(port: &mut dyn serialport::SerialPort, expected_type: u8) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut buf: Vec<u8> = Vec::new();
    let mut read_chunk = [0u8; 256];

    loop {
        if Instant::now() > deadline {
            eprintln!("Timeout waiting for response from device.");
            std::process::exit(1);
        }

        // Read whatever is available.
        match port.read(&mut read_chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&read_chunk[..n]),
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("Serial read error: {e}");
                std::process::exit(1);
            }
        }

        // Attempt to parse a frame from the current buffer.
        match frame::parse_frame(&buf) {
            Ok(f) if f.frame_type == expected_type => {
                // Successfully received the response frame.
                return String::from_utf8_lossy(&f.payload).into_owned();
            }
            Ok(f) => {
                // Valid frame but wrong type — log and discard, keep reading.
                eprintln!(
                    "Unexpected frame type 0x{:02X} (expected 0x{:02X}), skipping.",
                    f.frame_type, expected_type
                );
                buf.clear();
            }
            Err(FrameError::TooShort) => {
                // Incomplete frame — keep reading until more bytes arrive.
            }
            Err(_) => {
                // Bad magic, bad CRC, or oversized payload — the buffer may
                // contain log noise followed by a valid frame. Shift the buffer
                // forward to the next magic byte sequence.
                buf = advance_to_magic(buf);
            }
        }
    }
}

/// Advance the buffer to the first occurrence of the frame magic bytes after
/// position 0, discarding everything before it.
///
/// If no magic bytes are found, returns an empty buffer so we start fresh.
fn advance_to_magic(buf: Vec<u8>) -> Vec<u8> {
    // Start searching from position 1 to skip the current (failed) position.
    for i in 1..buf.len().saturating_sub(1) {
        if buf[i] == MAGIC_BYTES[0] && buf[i + 1] == MAGIC_BYTES[1] {
            return buf[i..].to_vec();
        }
    }
    Vec::new()
}

/// Decode a 64-char hex string to 32 bytes.
fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use heartwood_common::frame::build_frame;

    #[test]
    fn advance_to_magic_finds_second_occurrence() {
        // First two bytes look like magic but are not a valid frame start;
        // the second occurrence is the real one.
        let mut data = vec![0x48, 0x57, 0xFF, 0xFF]; // first candidate (invalid)
        data.extend_from_slice(b"noise");
        data.push(0x48);
        data.push(0x57); // second candidate
        data.extend_from_slice(b"rest");

        let advanced = advance_to_magic(data);
        assert_eq!(&advanced[..2], &[0x48, 0x57]);
        assert_eq!(&advanced[2..], b"rest");
    }

    #[test]
    fn advance_to_magic_returns_empty_when_absent() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let advanced = advance_to_magic(data);
        assert!(advanced.is_empty());
    }

    #[test]
    fn build_request_sign_event_contains_expected_fields() {
        let cli = Cli {
            port: "/dev/null".to_string(),
            baud: 115200,
            method: "sign_event".to_string(),
            purpose: None,
            index: 0,
            kind: 1,
            content: "Test content".to_string(),
        };
        let json = build_request(&cli, "test-id");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["id"], "test-id");
        assert_eq!(v["method"], "sign_event");
        assert!(v["heartwood"].is_null());

        // params[0] should be a JSON string containing the unsigned event.
        let event_str = v["params"][0].as_str().expect("params[0] should be a string");
        let event: serde_json::Value = serde_json::from_str(event_str).unwrap();
        assert_eq!(event["kind"], 1u64);
        assert_eq!(event["content"], "Test content");
    }

    #[test]
    fn build_request_get_public_key_no_params() {
        let cli = Cli {
            port: "/dev/null".to_string(),
            baud: 115200,
            method: "get_public_key".to_string(),
            purpose: Some("persona/social".to_string()),
            index: 2,
            kind: 1,
            content: String::new(),
        };
        let json = build_request(&cli, "pk-req");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["method"], "get_public_key");
        assert_eq!(v["params"].as_array().unwrap().len(), 0);
        assert_eq!(v["heartwood"]["purpose"], "persona/social");
        assert_eq!(v["heartwood"]["index"], 2u32);
    }

    #[test]
    fn response_frame_roundtrip() {
        // Verify that a properly framed response can be round-tripped through
        // the frame module (simulating what the device sends back).
        let payload = r#"{"id":"sign-test-1","result":"deadbeef"}"#;
        let framed = build_frame(FRAME_TYPE_NIP46_RESPONSE, payload.as_bytes()).unwrap();
        let parsed = frame::parse_frame(&framed).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_NIP46_RESPONSE);
        assert_eq!(parsed.payload, payload.as_bytes());
    }
}
