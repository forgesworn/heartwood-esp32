// ota/src/main.rs
//
// Pi-side OTA firmware update tool for heartwood-esp32.
//
// Sends a firmware binary to the ESP32 over serial using the heartwood frame
// protocol. The ESP32 verifies the SHA-256 hash after all chunks arrive and
// reboots into the new firmware on success.
//
// Usage:
//   heartwood-ota --port /dev/ttyUSB0 --firmware heartwood-esp32.bin
//   heartwood-ota --port /dev/ttyUSB0 --firmware heartwood-esp32.bin --baud 115200

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use heartwood_common::frame::{self, FrameError};
use heartwood_common::types::*;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "heartwood-ota")]
#[command(about = "Push OTA firmware updates to the heartwood-esp32 over serial")]
struct Cli {
    /// Serial port path (e.g. /dev/ttyUSB0, /dev/cu.usbserial-*)
    #[arg(short, long)]
    port: String,

    /// Firmware binary file to flash
    #[arg(short, long)]
    firmware: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum bytes of firmware data per OTA_CHUNK payload.
/// Payload = [offset_u32_be (4 bytes)] + [data], total must not exceed MAX_PAYLOAD_SIZE.
const CHUNK_DATA_SIZE: usize = 4088;

/// Timeout waiting for OTA_STATUS_READY after OTA_BEGIN.
const READY_TIMEOUT: Duration = Duration::from_secs(40);

/// Timeout waiting for OTA_STATUS_CHUNK_OK after each OTA_CHUNK.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout waiting for OTA_STATUS_VERIFIED after OTA_FINISH.
/// The device runs SHA-256 over the whole image before responding.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Frame I/O helpers
// ---------------------------------------------------------------------------

/// Write a complete frame to the serial port and flush.
fn send_frame(
    port: &mut Box<dyn serialport::SerialPort>,
    frame_type: u8,
    payload: &[u8],
) -> Result<(), String> {
    let bytes = frame::build_frame(frame_type, payload)
        .map_err(|e| format!("frame build error: {:?}", e))?;
    port.write_all(&bytes)
        .map_err(|e| format!("serial write error: {e}"))?;
    port.flush()
        .map_err(|e| format!("serial flush error: {e}"))?;
    Ok(())
}

/// Read an OTA_STATUS frame from the serial port, hunting for magic bytes and
/// discarding anything that is not a well-formed frame. Returns the status byte
/// (payload[0]) on success, or an error string on timeout or device error.
fn read_ota_status(
    port: &mut Box<dyn serialport::SerialPort>,
    timeout: Duration,
) -> Result<u8, String> {
    // Buffer large enough for one full frame.
    let mut buf = vec![0u8; MAX_PAYLOAD_SIZE + FRAME_OVERHEAD];
    let mut pos = 0usize;
    let deadline = Instant::now() + timeout;

    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "timeout ({:.0}s) waiting for OTA_STATUS frame",
                timeout.as_secs_f32()
            ));
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                // Append incoming byte, but never overflow the buffer.
                if pos < buf.len() {
                    buf[pos] = byte[0];
                    pos += 1;
                } else {
                    // Buffer full without a valid frame — slide forward one byte
                    // so we do not stall forever on garbage.
                    buf.copy_within(1..pos, 0);
                    buf[pos - 1] = byte[0];
                }

                // Need at least FRAME_OVERHEAD bytes before attempting a parse.
                if pos < FRAME_OVERHEAD {
                    continue;
                }

                match frame::parse_frame(&buf[..pos]) {
                    Ok(f) => {
                        if f.frame_type == FRAME_TYPE_OTA_STATUS {
                            if f.payload.is_empty() {
                                return Err("OTA_STATUS frame has empty payload".into());
                            }
                            let status = f.payload[0];
                            // Map device error codes to human-readable messages.
                            match status {
                                OTA_STATUS_READY
                                | OTA_STATUS_CHUNK_OK
                                | OTA_STATUS_VERIFIED => return Ok(status),
                                OTA_STATUS_ERR_HASH => {
                                    return Err("device rejected firmware: SHA-256 mismatch (0x10)".into())
                                }
                                OTA_STATUS_ERR_SIZE => {
                                    return Err("device rejected firmware: size mismatch (0x11)".into())
                                }
                                OTA_STATUS_ERR_WRITE => {
                                    return Err("device reported flash write error (0x12)".into())
                                }
                                OTA_STATUS_ERR_NOT_STARTED => {
                                    return Err(
                                        "device received chunk before OTA session started (0x13)".into(),
                                    )
                                }
                                other => {
                                    return Err(format!(
                                        "unknown OTA status code: 0x{other:02x}"
                                    ))
                                }
                            }
                        } else {
                            // Unexpected frame type — ignore and keep accumulating.
                            eprintln!(
                                "warning: unexpected frame type 0x{:02x} during OTA — ignoring",
                                f.frame_type
                            );
                            pos = 0;
                        }
                    }
                    Err(FrameError::TooShort) => {
                        // Not enough data yet — keep reading.
                        continue;
                    }
                    Err(_) => {
                        // Malformed frame — hunt forward for the next magic sequence.
                        if let Some(magic_offset) =
                            buf[1..pos].windows(2).position(|w| w == &MAGIC_BYTES)
                        {
                            let new_start = magic_offset + 1;
                            buf.copy_within(new_start..pos, 0);
                            pos -= new_start;
                        } else {
                            pos = 0;
                        }
                    }
                }
            }
            Ok(_) => {
                // Zero-byte read — nothing available yet, spin.
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Serial timeout — keep looping until our own deadline fires.
            }
            Err(e) => return Err(format!("serial read error: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // ------------------------------------------------------------------
    // Step 1: read firmware and compute SHA-256
    // ------------------------------------------------------------------
    let firmware = std::fs::read(&cli.firmware).unwrap_or_else(|e| {
        eprintln!("error: cannot read firmware file '{}': {e}", cli.firmware);
        std::process::exit(1);
    });

    if firmware.is_empty() {
        eprintln!("error: firmware file is empty");
        std::process::exit(1);
    }

    let mut hasher = Sha256::new();
    hasher.update(&firmware);
    let digest: [u8; 32] = hasher.finalize().into();

    let total_size = firmware.len() as u32;

    println!(
        "Firmware: {} ({} bytes, SHA-256: {})",
        cli.firmware,
        total_size,
        hex_encode(&digest)
    );

    // ------------------------------------------------------------------
    // Step 2: open serial port
    // ------------------------------------------------------------------
    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_millis(100))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("error: cannot open serial port '{}': {e}", cli.port);
            std::process::exit(1);
        });

    // Disable DTR/RTS — toggling these resets the ESP32.
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    println!("Serial port {} open at {} baud", cli.port, cli.baud);

    // ------------------------------------------------------------------
    // Step 3: send OTA_BEGIN — payload = [total_size_u32_be][sha256_32]
    // ------------------------------------------------------------------
    let mut begin_payload = Vec::with_capacity(36);
    begin_payload.extend_from_slice(&total_size.to_be_bytes());
    begin_payload.extend_from_slice(&digest);

    println!("Sending OTA_BEGIN ({} byte image)...", total_size);

    send_frame(&mut port, FRAME_TYPE_OTA_BEGIN, &begin_payload).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // ------------------------------------------------------------------
    // Step 4: wait for OTA_STATUS_READY
    // ------------------------------------------------------------------
    println!("Waiting for device ready...");
    match read_ota_status(&mut port, READY_TIMEOUT) {
        Ok(OTA_STATUS_READY) => {
            println!("Device ready — beginning transfer");
            // Drain any buffered log output from the device before starting
            // the chunk loop. ESP-IDF log lines share the serial port and can
            // contain bytes that the frame parser misidentifies as a status
            // response.
            std::thread::sleep(Duration::from_millis(200));
            let mut drain = [0u8; 4096];
            while let Ok(n) = port.read(&mut drain) {
                if n == 0 { break; }
            }
        }
        Ok(other) => {
            eprintln!("error: expected OTA_STATUS_READY (0x00), got 0x{other:02x}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }

    // ------------------------------------------------------------------
    // Step 5 & 6: stream firmware in chunks, waiting for CHUNK_OK after each
    // ------------------------------------------------------------------
    let chunk_count = firmware.chunks(CHUNK_DATA_SIZE).count();

    let bar = ProgressBar::new(total_size as u64);
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    for (i, chunk_data) in firmware.chunks(CHUNK_DATA_SIZE).enumerate() {
        let offset = (i * CHUNK_DATA_SIZE) as u32;

        // Payload = [offset_u32_be][chunk_data...]
        let mut chunk_payload = Vec::with_capacity(4 + chunk_data.len());
        chunk_payload.extend_from_slice(&offset.to_be_bytes());
        chunk_payload.extend_from_slice(chunk_data);

        send_frame(&mut port, FRAME_TYPE_OTA_CHUNK, &chunk_payload).unwrap_or_else(|e| {
            let msg = format!("write error at chunk {i}: {e}");
            bar.abandon_with_message(msg.clone());
            eprintln!("error: {msg}");
            std::process::exit(1);
        });

        match read_ota_status(&mut port, CHUNK_TIMEOUT) {
            Ok(OTA_STATUS_CHUNK_OK) => {}
            Ok(other) => {
                let msg = format!(
                    "unexpected status 0x{other:02x} after chunk {}/{chunk_count}",
                    i + 1
                );
                bar.abandon_with_message(msg.clone());
                eprintln!("error: {msg}");
                std::process::exit(1);
            }
            Err(e) => {
                let msg = format!("chunk {}/{chunk_count}: {e}", i + 1);
                bar.abandon_with_message(msg.clone());
                eprintln!("error: {msg}");
                std::process::exit(1);
            }
        }

        bar.inc(chunk_data.len() as u64);
    }

    bar.finish_with_message("Transfer complete");

    // ------------------------------------------------------------------
    // Step 8: send OTA_FINISH
    // ------------------------------------------------------------------
    println!("Sending OTA_FINISH...");
    send_frame(&mut port, FRAME_TYPE_OTA_FINISH, &[]).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // ------------------------------------------------------------------
    // Step 9: wait for OTA_STATUS_VERIFIED — device will reboot
    // ------------------------------------------------------------------
    println!("Waiting for device verification (SHA-256 check)...");
    match read_ota_status(&mut port, VERIFY_TIMEOUT) {
        Ok(OTA_STATUS_VERIFIED) => {
            println!("Firmware verified. Device is rebooting into the new image.");
        }
        Ok(other) => {
            eprintln!("error: expected OTA_STATUS_VERIFIED (0x02), got 0x{other:02x}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
