// firmware/src/protocol.rs
//
// Serial frame reader/writer. Reads bytes from the board's host transport
// (USB-Serial-JTAG on V4, UART0 via CP2102 on V3, abstracted behind
// `SerialPort`), assembles frames, and validates them using common::frame.
//
// Frame format (defined in heartwood-common):
//   [0x48 0x57] [type_u8] [length_u16_be] [payload...] [crc32_4]

use esp_idf_hal::delay;
use crate::serial::SerialPort;

use heartwood_common::frame::{self, Frame};
use heartwood_common::types::{
    FRAME_HEADER_SIZE, FRAME_OVERHEAD, MAGIC_BYTES, MAX_PAYLOAD_SIZE,
};
use serde::Serialize;

const MAX_WRITE_CHUNK: usize = 512;
const WRITE_CHUNK_TIMEOUT: u32 = 100;
const WRITE_STALL_BUDGET: u32 = 2_000;

/// Read a single byte from the USB serial driver, blocking until available.
fn read_byte(usb: &mut SerialPort<'_>) -> u8 {
    let mut buf = [0u8; 1];
    loop {
        match usb.read(&mut buf, delay::BLOCK) {
            Ok(n) if n > 0 => return buf[0],
            _ => {}
        }
    }
}

/// Attempt to read a single byte within `timeout_ms` milliseconds.
///
/// Returns `Some(byte)` if a byte arrived in time, `None` if the read timed
/// out without receiving data.
fn try_read_byte(usb: &mut SerialPort<'_>, timeout_ms: u32) -> Option<u8> {
    let mut buf = [0u8; 1];
    match usb.read(&mut buf, timeout_ms) {
        Ok(n) if n > 0 => Some(buf[0]),
        _ => None,
    }
}

/// Read exactly `buf.len()` bytes from the USB serial driver, blocking until
/// all bytes have been received.
///
/// Reads are chunked to the same limit as writes to avoid crashing the
/// USB-Serial-JTAG driver with large buffer operations.
fn read_exact(usb: &mut SerialPort<'_>, buf: &mut [u8]) {
    /// Maximum bytes per `usb.read()` call — mirrors the write chunk limit.
    const MAX_CHUNK: usize = 512;

    let mut pos = 0;
    while pos < buf.len() {
        let end = (pos + MAX_CHUNK).min(buf.len());
        match usb.read(&mut buf[pos..end], delay::BLOCK) {
            Ok(n) if n > 0 => pos += n,
            _ => {}
        }
    }
}

/// Like [`read_exact`], but gives up if the stream stalls: any read window
/// that makes no progress within `stall_timeout` aborts with `false`, and the
/// caller discards the partial frame and resyncs on the next magic hunt.
///
/// This exists for the wifi relay loop's non-blocking USB poll. A frame whose
/// tail was lost to a UART ring overflow used to park the whole loop inside a
/// `delay::BLOCK` read — the signer stopped serving its relay AND ate every
/// later USB byte as phantom payload until enough arrived. Senders pace real
/// frames continuously, so a stalled stream only ever means truncation.
fn read_exact_bounded(usb: &mut SerialPort<'_>, buf: &mut [u8], stall_timeout: u32) -> bool {
    const MAX_CHUNK: usize = 512;

    let mut pos = 0;
    while pos < buf.len() {
        let end = (pos + MAX_CHUNK).min(buf.len());
        match usb.read(&mut buf[pos..end], stall_timeout) {
            Ok(n) if n > 0 => pos += n,
            _ => return false,
        }
    }
    true
}

/// Read and return the next valid frame from the serial link.
///
/// Hunts for the two-byte magic sequence `[0x48, 0x57]`, reads the header
/// (type + 16-bit big-endian length), reads the payload and CRC, then
/// validates via [`frame::parse_frame`]. On any error the function logs a
/// warning and resumes hunting from the current byte stream position.
pub fn read_frame(usb: &mut SerialPort<'_>) -> Frame {
    loop {
        // Step 1 — hunt for the first magic byte.
        let b = read_byte(usb);
        if b != MAGIC_BYTES[0] {
            continue;
        }

        // Step 2 — confirm second magic byte.
        let b = read_byte(usb);
        if b != MAGIC_BYTES[1] {
            // The byte we just read might itself be the start of a new frame;
            // check it before discarding.
            if b == MAGIC_BYTES[0] {
                // Peek at the next byte.
                let next = read_byte(usb);
                if next == MAGIC_BYTES[1] {
                    // Found valid magic — fall through with header read below.
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }

        // Step 3 — read frame type and 16-bit length (3 bytes total).
        let mut header = [0u8; 3];
        read_exact(usb, &mut header);
        let frame_type = header[0];
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;

        // Step 4 — reject oversized payloads early to avoid buffer blow-up.
        if length > MAX_PAYLOAD_SIZE {
            log::warn!(
                "Incoming frame payload length {} exceeds MAX_PAYLOAD_SIZE {} — discarding",
                length,
                MAX_PAYLOAD_SIZE
            );
            continue;
        }

        // Read directly into the payload that the returned Frame will own.
        // The old path read payload+CRC, rebuilt a complete frame Vec, then
        // parse_frame cloned the payload a third time. Large sign_event bodies
        // could therefore OOM before the handler set its crash breadcrumb.
        let mut payload = vec![0u8; length];
        read_exact(usb, &mut payload);
        let mut crc_bytes = [0u8; 4];
        read_exact(usb, &mut crc_bytes);
        if frame_crc_valid(frame_type, &header[1..], &payload, crc_bytes) {
            return Frame {
                frame_type,
                payload,
            };
        }
        log::warn!("Frame validation failed (BadCrc) — resuming hunt");
    }
}

/// Attempt to read a complete frame within `idle_timeout_ms` milliseconds.
///
/// The timeout applies to the wait for the *first byte* of the magic header.
/// Subsequent bytes (second magic byte, header, payload) use a short timeout
/// rather than blocking forever -- this prevents a stray byte matching
/// MAGIC[0] from locking up the idle loop and starving the display timeout.
///
/// Returns `Some(Frame)` on success, `None` if no data arrived within the
/// timeout window or if a partial/invalid frame was received.
pub fn try_read_frame(usb: &mut SerialPort<'_>, idle_timeout_ms: u32) -> Option<Frame> {
    /// Once the first magic byte matches, allow this long for each subsequent
    /// byte before giving up. The bridge sends frames atomically so inter-byte
    /// gaps are negligible; 200 ms is generous enough to absorb scheduling jitter
    /// while still returning promptly on noise.
    const CONTINUATION_TIMEOUT_MS: u32 = 200;

    // Hunt for the first magic byte within the caller's timeout window.
    let b = try_read_byte(usb, idle_timeout_ms)?;
    if b != MAGIC_BYTES[0] {
        return None;
    }

    // Confirm second magic byte with a bounded timeout.
    let b = match try_read_byte(usb, CONTINUATION_TIMEOUT_MS) {
        Some(b) => b,
        None => return None,
    };
    if b != MAGIC_BYTES[1] {
        if b == MAGIC_BYTES[0] {
            let next = match try_read_byte(usb, CONTINUATION_TIMEOUT_MS) {
                Some(b) => b,
                None => return None,
            };
            if next != MAGIC_BYTES[1] {
                return None;
            }
        } else {
            return None;
        }
    }

    // Read header (type + 16-bit length). Bounded: a frame truncated by a
    // ring overflow must never wedge the caller (the wifi relay loop).
    const BODY_STALL_TIMEOUT_MS: u32 = 500;
    let mut header = [0u8; 3];
    if !read_exact_bounded(usb, &mut header, BODY_STALL_TIMEOUT_MS) {
        log::warn!("try_read_frame: header stalled — discarding partial frame");
        return None;
    }
    let frame_type = header[0];
    let length = u16::from_be_bytes([header[1], header[2]]) as usize;

    if length > MAX_PAYLOAD_SIZE {
        log::warn!(
            "try_read_frame: payload length {} exceeds MAX_PAYLOAD_SIZE {} — discarding",
            length,
            MAX_PAYLOAD_SIZE,
        );
        return None;
    }

    // Read directly into the one payload allocation retained by the Frame.
    let mut payload = vec![0u8; length];
    if !read_exact_bounded(usb, &mut payload, BODY_STALL_TIMEOUT_MS) {
        log::warn!(
            "try_read_frame: body stalled at type 0x{frame_type:02x} len {length} — discarding partial frame"
        );
        return None;
    }
    let mut crc_bytes = [0u8; 4];
    if !read_exact_bounded(usb, &mut crc_bytes, BODY_STALL_TIMEOUT_MS) {
        log::warn!(
            "try_read_frame: CRC stalled at type 0x{frame_type:02x} len {length} — discarding partial frame"
        );
        return None;
    }
    if frame_crc_valid(frame_type, &header[1..], &payload, crc_bytes) {
        Some(Frame {
            frame_type,
            payload,
        })
    } else {
        log::warn!("try_read_frame: validation failed (BadCrc) — discarding");
        None
    }
}

fn frame_crc_valid(
    frame_type: u8,
    length_bytes: &[u8],
    payload: &[u8],
    received: [u8; 4],
) -> bool {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[frame_type]);
    hasher.update(length_bytes);
    hasher.update(payload);
    hasher.finalize() == u32::from_be_bytes(received)
}

/// Build a frame from `frame_type` and `payload` and write it to the serial
/// link. Logs a warning if the payload exceeds `MAX_PAYLOAD_SIZE` or the
/// underlying write fails.
///
/// Writes are chunked to avoid crashing the underlying driver with large
/// slices. On the V4 the USB-Serial-JTAG ring buffer is small; passing an
/// 11KB+ slice in a single `write()` call has been observed to hard-fault on
/// ESP32-S3. On the V3 the CP2102 UART path is more forgiving but we keep
/// the same chunk size for consistency.
pub fn write_frame(usb: &mut SerialPort<'_>, frame_type: u8, payload: &[u8]) {
    match frame::build_frame(frame_type, payload) {
        Ok(bytes) => write_encoded_frame(usb, &bytes),
        Err(e) => {
            log::warn!("Failed to build frame (type=0x{:02X}): {:?}", frame_type, e);
        }
    }
}

/// Serialise a JSON payload directly into its protocol frame allocation.
/// Large signed envelopes otherwise exist as a JSON String and are then copied
/// wholesale by `build_frame`, which is unnecessary pressure on the signer.
pub fn write_json_frame<T: Serialize>(
    usb: &mut SerialPort<'_>,
    frame_type: u8,
    value: &T,
    capacity_hint: usize,
) -> Result<usize, String> {
    let mut bytes = Vec::with_capacity(
        FRAME_OVERHEAD
            .saturating_add(capacity_hint)
            .min(FRAME_OVERHEAD + MAX_PAYLOAD_SIZE),
    );
    bytes.extend_from_slice(&MAGIC_BYTES);
    bytes.push(frame_type);
    bytes.extend_from_slice(&[0, 0]);
    serde_json::to_writer(&mut bytes, value).map_err(|e| format!("serialise: {e}"))?;

    let payload_len = bytes.len() - FRAME_HEADER_SIZE;
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(format!("payload too large: {payload_len} bytes"));
    }
    let length = (payload_len as u16).to_be_bytes();
    bytes[3..5].copy_from_slice(&length);

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[2..]);
    bytes.extend_from_slice(&hasher.finalize().to_be_bytes());
    write_encoded_frame(usb, &bytes);
    Ok(payload_len)
}

/// Frame an owned text payload by reusing its allocation. This is primarily
/// for large NIP-46 responses, where copying the complete JSON into a second
/// `build_frame` Vec can exhaust contiguous heap after signing succeeds.
pub fn write_owned_frame(usb: &mut SerialPort<'_>, frame_type: u8, payload: String) {
    let payload_len = payload.len();
    if payload_len > MAX_PAYLOAD_SIZE {
        log::warn!(
            "Failed to build frame (type=0x{frame_type:02X}): payload too large ({payload_len})"
        );
        return;
    }

    let mut bytes = payload.into_bytes();
    bytes.reserve(FRAME_OVERHEAD);
    bytes.resize(payload_len + FRAME_OVERHEAD, 0);
    bytes.copy_within(0..payload_len, FRAME_HEADER_SIZE);
    bytes[..2].copy_from_slice(&MAGIC_BYTES);
    bytes[2] = frame_type;
    bytes[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());

    let crc_offset = FRAME_HEADER_SIZE + payload_len;
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[2..crc_offset]);
    bytes[crc_offset..].copy_from_slice(&hasher.finalize().to_be_bytes());
    write_encoded_frame(usb, &bytes);
}

/// Write one already-framed message without allocating again. The native USB
/// TX buffer only drains while a host reads, so bounded writes also prevent a
/// suspended host from freezing the relay loop indefinitely.
fn write_encoded_frame(usb: &mut SerialPort<'_>, bytes: &[u8]) {
    let mut pos = 0;
    let mut stalled: u32 = 0;
    while pos < bytes.len() {
        let end = (pos + MAX_WRITE_CHUNK).min(bytes.len());
        match usb.write_bounded(&bytes[pos..end], WRITE_CHUNK_TIMEOUT) {
            Ok(n) if n > 0 => {
                pos += n;
                stalled = 0;
            }
            Ok(_) => {
                stalled += WRITE_CHUNK_TIMEOUT;
                if stalled >= WRITE_STALL_BUDGET {
                    log::warn!(
                        "Serial write stalled at byte {}/{} — host not draining; dropping frame",
                        pos,
                        bytes.len()
                    );
                    return;
                }
            }
            Err(e) => {
                log::warn!("Serial write error at byte {}/{}: {:?}", pos, bytes.len(), e);
                return;
            }
        }
    }
}
