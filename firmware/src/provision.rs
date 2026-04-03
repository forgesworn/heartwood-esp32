// firmware/src/provision.rs
//
// Multi-master provisioning handler.
//
// Frame 0x01 (PROVISION_ADD): [mode_u8][label_len_u8][label...][secret_32]
//   - Legacy compat: if payload is exactly 32 bytes, treat as tree-mnemonic with label "default".
// Frame 0x04 (PROVISION_REMOVE): [slot_u8]
// Frame 0x05 (PROVISION_LIST): (empty) → responds with 0x07 (PROVISION_LIST_RESPONSE)

use esp_idf_hal::usb_serial::UsbSerialDriver;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use secp256k1::Secp256k1;
use std::sync::Arc;

use heartwood_common::encoding::encode_npub;
use heartwood_common::frame::Frame;
use heartwood_common::types::{
    MasterMode, FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION_LIST_RESPONSE,
};

use crate::masters::{self, LoadedMaster};
use crate::oled::{self, Display};
use crate::protocol;

/// Handle a PROVISION_ADD frame (0x01). Returns the new `LoadedMaster` on success.
pub fn handle_add(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    secp: &Arc<Secp256k1<secp256k1::SignOnly>>,
    display: &mut Display<'_>,
) -> Option<LoadedMaster> {
    // Legacy format: exactly 32 bytes = tree-mnemonic with label "default".
    let (mode, label, secret) = if frame.payload.len() == 32 {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&frame.payload);
        (MasterMode::TreeMnemonic, "default".to_string(), secret)
    } else if frame.payload.len() >= 2 + 32 {
        let mode_byte = frame.payload[0];
        let mode = match MasterMode::from_u8(mode_byte) {
            Some(m) => m,
            None => {
                log::warn!("Unknown provision mode byte: 0x{:02x}", mode_byte);
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                return None;
            }
        };

        let label_len = frame.payload[1] as usize;
        if frame.payload.len() < 2 + label_len + 32 {
            log::warn!("Provision payload too short for label ({} bytes) + secret", label_len);
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }

        let label = String::from_utf8_lossy(&frame.payload[2..2 + label_len]).to_string();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&frame.payload[2 + label_len..2 + label_len + 32]);

        (mode, label, secret)
    } else {
        log::warn!(
            "Provision payload is {} bytes, expected exactly 32 or >= 34",
            frame.payload.len()
        );
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return None;
    };

    // Derive the x-only public key from the secret.
    let keypair = match secp256k1::Keypair::from_seckey_slice(secp, &secret) {
        Ok(kp) => kp,
        Err(_) => {
            log::error!("Invalid secret key in provision payload");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }
    };
    let (xonly, _) = keypair.x_only_public_key();
    let pubkey = xonly.serialize();

    // Generate a random connect secret using the ESP32 hardware RNG.
    let mut connect_secret = [0u8; 32];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            connect_secret.as_mut_ptr() as *mut core::ffi::c_void,
            32,
        );
    }

    // Persist to NVS.
    match masters::add_master(nvs, &secret, &label, mode, &pubkey, &connect_secret) {
        Ok(slot) => {
            let npub = encode_npub(&pubkey);
            log::info!("Provisioned slot {slot}: {label} ({npub})");
            oled::show_npub(display, &npub);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);

            Some(LoadedMaster {
                slot,
                secret,
                label,
                mode,
                pubkey,
                connect_secret,
            })
        }
        Err(e) => {
            log::error!("Provision add failed: {e}");
            oled::show_error(display, "Provision failed");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            None
        }
    }
}

/// Handle a PROVISION_REMOVE frame (0x04). Removes the named slot and
/// re-numbers the in-memory list to stay consistent with NVS.
pub fn handle_remove(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    loaded: &mut Vec<LoadedMaster>,
    display: &mut Display<'_>,
) {
    if frame.payload.len() != 1 {
        log::warn!(
            "PROVISION_REMOVE payload is {} bytes, expected 1",
            frame.payload.len()
        );
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let slot = frame.payload[0];
    match masters::remove_master(nvs, slot) {
        Ok(()) => {
            // Remove from the in-memory list and re-number to match NVS order.
            loaded.retain(|m| m.slot != slot);
            for (i, m) in loaded.iter_mut().enumerate() {
                m.slot = i as u8;
            }
            let msg = format!("Removed slot {slot}");
            oled::show_error(display, &msg);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        }
        Err(e) => {
            log::error!("Remove master slot {slot} failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}

/// Handle a PROVISION_LIST frame (0x05). Responds with frame 0x07 containing
/// a JSON array of `{slot, label, mode, npub}` objects.
pub fn handle_list(usb: &mut UsbSerialDriver<'_>, loaded: &[LoadedMaster]) {
    let infos: Vec<serde_json::Value> = loaded
        .iter()
        .map(|m| {
            serde_json::json!({
                "slot": m.slot,
                "label": m.label,
                "mode": m.mode as u8,
                "npub": encode_npub(&m.pubkey),
            })
        })
        .collect();

    let json = serde_json::to_string(&infos).unwrap_or_else(|_| "[]".to_string());
    protocol::write_frame(usb, FRAME_TYPE_PROVISION_LIST_RESPONSE, json.as_bytes());
}
