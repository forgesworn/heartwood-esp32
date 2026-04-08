// firmware/src/protocol.rs
//
// Serial frame reader/writer. Reads bytes from USB-Serial-JTAG,
// assembles frames, and validates them using common::frame.
//
// Frame format (defined in heartwood-common):
//   [0x48 0x57] [type_u8] [length_u16_be] [payload...] [crc32_4]

use esp_idf_hal::delay;
use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::frame::{self, Frame};
use heartwood_common::types::{MAGIC_BYTES, MAX_PAYLOAD_SIZE, FRAME_HEADER_SIZE};

/// Read a single byte from the USB serial driver, blocking until available.
fn read_byte(usb: &mut UsbSerialDriver<'_>) -> u8 {
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
fn try_read_byte(usb: &mut UsbSerialDriver<'_>, timeout_ms: u32) -> Option<u8> {
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
fn read_exact(usb: &mut UsbSerialDriver<'_>, buf: &mut [u8]) {
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

/// Read and return the next valid frame from the serial link.
///
/// Hunts for the two-byte magic sequence `[0x48, 0x57]`, reads the header
/// (type + 16-bit big-endian length), reads the payload and CRC, then
/// validates via [`frame::parse_frame`]. On any error the function logs a
/// warning and resumes hunting from the current byte stream position.
pub fn read_frame(usb: &mut UsbSerialDriver<'_>) -> Frame {
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

        // Step 5 — read payload + 4-byte CRC.
        let mut body = vec![0u8; length + 4];
        read_exact(usb, &mut body);

        // Step 6 — reassemble the complete frame buffer for parse_frame.
        // Layout: [magic(2)] [type(1)] [length(2)] [payload(length)] [crc(4)]
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + length + 4);
        buf.extend_from_slice(&MAGIC_BYTES);
        buf.push(frame_type);
        buf.extend_from_slice(&(length as u16).to_be_bytes());
        buf.extend_from_slice(&body);

        // Step 7 — validate and return, or log and resume hunting.
        match frame::parse_frame(&buf) {
            Ok(f) => return f,
            Err(e) => {
                log::warn!("Frame validation failed ({:?}) — resuming hunt", e);
            }
        }
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
pub fn try_read_frame(usb: &mut UsbSerialDriver<'_>, idle_timeout_ms: u32) -> Option<Frame> {
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

    // Read header (type + 16-bit length).  Still use blocking reads here --
    // once we have confirmed magic bytes a real frame is in flight.
    let mut header = [0u8; 3];
    read_exact(usb, &mut header);
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

    // Read payload + 4-byte CRC.
    let mut body = vec![0u8; length + 4];
    read_exact(usb, &mut body);

    // Reassemble and validate.
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + length + 4);
    buf.extend_from_slice(&MAGIC_BYTES);
    buf.push(frame_type);
    buf.extend_from_slice(&(length as u16).to_be_bytes());
    buf.extend_from_slice(&body);

    match frame::parse_frame(&buf) {
        Ok(f) => Some(f),
        Err(e) => {
            log::warn!("try_read_frame: validation failed ({:?}) — discarding", e);
            None
        }
    }
}

/// Build a frame from `frame_type` and `payload` and write it to the serial
/// link. Logs a warning if the payload exceeds `MAX_PAYLOAD_SIZE` or the
/// underlying write fails.
///
/// Writes are chunked to avoid crashing the USB-Serial-JTAG driver with
/// large slices. The ESP-IDF driver's internal ring buffer is small; passing
/// an 11KB+ slice in a single `write()` call causes a hard fault on ESP32-S3.
pub fn write_frame(usb: &mut UsbSerialDriver<'_>, frame_type: u8, payload: &[u8]) {
    /// Maximum bytes per `usb.write()` call. The USB-Serial-JTAG TX FIFO is
    /// 64 bytes and the ESP-IDF ring buffer is typically 256 bytes, but we
    /// use a larger chunk to keep throughput reasonable while staying safe.
    const MAX_CHUNK: usize = 512;

    match frame::build_frame(frame_type, payload) {
        Ok(bytes) => {
            let mut pos = 0;
            while pos < bytes.len() {
                let end = (pos + MAX_CHUNK).min(bytes.len());
                match usb.write(&bytes[pos..end], delay::BLOCK) {
                    Ok(n) if n > 0 => pos += n,
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("Serial write error at byte {}/{}: {:?}", pos, bytes.len(), e);
                        return;
                    }
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to build frame (type=0x{:02X}): {:?}", frame_type, e);
        }
    }
}
