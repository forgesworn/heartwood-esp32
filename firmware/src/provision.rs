// firmware/src/provision.rs
//
// Serial provisioning protocol (ESP32 side).
// Reads from stdin (USB-Serial-JTAG on Heltec V4) for a 38-byte frame.

use heartwood_common::types::{ACK, MAGIC_BYTES, NACK};

/// Listen on stdin for a provisioning frame. Blocks until a valid frame is received.
/// Returns the 32-byte root secret.
///
/// Uses stdin/stdout because the Heltec V4's USB-C connects to the ESP32-S3's
/// USB-Serial-JTAG peripheral, not UART0. ESP-IDF maps stdin/stdout to this
/// peripheral automatically — no GPIO pin configuration needed.
pub fn wait_for_secret() -> [u8; 32] {
    use std::io::{Read, Write};

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    loop {
        // Wait for first magic byte
        let mut byte = [0u8; 1];
        if stdin.read_exact(&mut byte).is_ok() && byte[0] == MAGIC_BYTES[0] {
            // Check second magic byte
            if stdin.read_exact(&mut byte).is_ok() && byte[0] == MAGIC_BYTES[1] {
                // Read remaining 36 bytes (32 secret + 4 CRC)
                let mut payload = [0u8; 36];
                if stdin.read_exact(&mut payload).is_ok() {
                    let secret = &payload[0..32];
                    let frame_crc = u32::from_be_bytes([
                        payload[32], payload[33], payload[34], payload[35],
                    ]);
                    let computed_crc = crc32fast::hash(secret);

                    if frame_crc == computed_crc {
                        // Send ACK before logging — log output shares stdout
                        // and would push the ACK byte further from where the
                        // CLI expects it.
                        let _ = stdout.write_all(&[ACK]);
                        let _ = stdout.flush();
                        log::info!("Provisioning frame received — CRC OK");
                        let mut result = [0u8; 32];
                        result.copy_from_slice(secret);
                        return result;
                    } else {
                        log::warn!("Provisioning frame CRC mismatch");
                        let _ = stdout.write_all(&[NACK]);
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }
}
