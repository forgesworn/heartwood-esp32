// firmware/src/provision.rs
//
// Serial provisioning protocol (ESP32 side).
// Uses the USB-Serial-JTAG driver directly for reliable blocking reads.

use esp_idf_hal::delay;
use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::types::{ACK, MAGIC_BYTES, NACK};

/// Read exactly `n` bytes from the USB serial driver, blocking until available.
fn read_exact(usb: &mut UsbSerialDriver<'_>, buf: &mut [u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        match usb.read(&mut buf[pos..], delay::BLOCK) {
            Ok(n) if n > 0 => pos += n,
            _ => {}
        }
    }
}

/// Listen on USB-Serial-JTAG for a provisioning frame.
/// Blocks until a valid frame is received. Returns the 32-byte root secret.
pub fn wait_for_secret(usb: &mut UsbSerialDriver<'_>) -> [u8; 32] {
    log::info!("Waiting for provisioning frame...");

    loop {
        // Wait for first magic byte
        let mut byte = [0u8; 1];
        read_exact(usb, &mut byte);
        if byte[0] == MAGIC_BYTES[0] {
            // Check second magic byte
            read_exact(usb, &mut byte);
            if byte[0] == MAGIC_BYTES[1] {
                log::info!("Magic bytes received");
                // Read remaining 36 bytes (32 secret + 4 CRC)
                let mut payload = [0u8; 36];
                read_exact(usb, &mut payload);

                let secret = &payload[0..32];
                let frame_crc = u32::from_be_bytes([
                    payload[32], payload[33], payload[34], payload[35],
                ]);
                let computed_crc = crc32fast::hash(secret);

                if frame_crc == computed_crc {
                    // Send ACK
                    let _ = usb.write(&[ACK], delay::BLOCK);
                    log::info!("Provisioning frame received — CRC OK");
                    let mut result = [0u8; 32];
                    result.copy_from_slice(secret);
                    return result;
                } else {
                    log::warn!("Provisioning frame CRC mismatch");
                    let _ = usb.write(&[NACK], delay::BLOCK);
                }
            }
        }
    }
}
