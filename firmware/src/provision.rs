// firmware/src/provision.rs
//
// Provisioning handler. Receives a 32-byte root secret from a provision frame
// and stores it in NVS.

use esp_idf_hal::usb_serial::UsbSerialDriver;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::frame::Frame;
use heartwood_common::types::{FRAME_TYPE_ACK, FRAME_TYPE_NACK};

use crate::nvs;
use crate::oled::{self, Display};
use crate::protocol;

/// Handle an incoming provision frame.
///
/// Validates that the payload is exactly 32 bytes, writes the secret to NVS,
/// and sends an ACK. Returns the secret on success, or `None` on any error
/// (a NACK is sent before returning `None`).
pub fn handle_provision(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut Display<'_>,
) -> Option<[u8; 32]> {
    if frame.payload.len() != 32 {
        log::warn!(
            "Provision payload is {} bytes, expected 32",
            frame.payload.len()
        );
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return None;
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&frame.payload);

    match nvs::write_root_secret(nvs, &secret) {
        Ok(()) => {
            log::info!("Provisioned — identity stored in NVS");
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            Some(secret)
        }
        Err(e) => {
            log::error!("NVS write failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            oled::show_error(display, "NVS write failed");
            None
        }
    }
}
