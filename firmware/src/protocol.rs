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

/// Read exactly `buf.len()` bytes from the USB serial driver, blocking until
/// all bytes have been received.
fn read_exact(usb: &mut UsbSerialDriver<'_>, buf: &mut [u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        match usb.read(&mut buf[pos..], delay::BLOCK) {
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

/// Build a frame from `frame_type` and `payload` and write it to the serial
/// link. Logs a warning if the payload exceeds `MAX_PAYLOAD_SIZE` or the
/// underlying write fails.
pub fn write_frame(usb: &mut UsbSerialDriver<'_>, frame_type: u8, payload: &[u8]) {
    match frame::build_frame(frame_type, payload) {
        Ok(bytes) => {
            let mut pos = 0;
            while pos < bytes.len() {
                match usb.write(&bytes[pos..], delay::BLOCK) {
                    Ok(n) if n > 0 => pos += n,
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("Serial write error at byte {}: {:?}", pos, e);
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
