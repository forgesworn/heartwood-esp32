// firmware/src/backup.rs
//
// Backup export and import handlers for the ESP32.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::backup::{BackupMaster, BackupPayload};
use heartwood_common::hex::hex_encode;
use heartwood_common::types::{
    FRAME_TYPE_BACKUP_EXPORT_RESPONSE, FRAME_TYPE_BACKUP_IMPORT_RESPONSE,
    FRAME_TYPE_NACK,
};

use crate::masters::LoadedMaster;
use crate::policy::PolicyEngine;
use crate::protocol;
use crate::serial::SerialPort;
use crate::session;

/// Handle BACKUP_EXPORT_REQUEST (0x50).
///
/// Collects all master metadata, connection slots (with secrets), and
/// the bridge secret into a BackupPayload JSON and sends it back.
pub fn handle_export(
    usb: &mut SerialPort<'_>,
    loaded_masters: &[LoadedMaster],
    policy_engine: &PolicyEngine,
    nvs: &EspNvs<NvsDefault>,
) {
    // Collect master metadata + unredacted slots.
    let mut masters = Vec::new();
    for m in loaded_masters {
        let pubkey_hex = hex_encode(&m.pubkey);
        let slots = policy_engine.list_slots(m.slot).to_vec();

        masters.push(BackupMaster {
            slot: m.slot,
            label: m.label.clone(),
            mode: m.mode as u8,
            pubkey: pubkey_hex,
            connection_slots: slots,
        });
    }

    // Read bridge secret for the device_id fingerprint and backup payload.
    let bridge_secret = session::read_bridge_secret(nvs);
    let bridge_hex = bridge_secret
        .map(|s| hex_encode(&s))
        .unwrap_or_default();

    // device_id = SHA-256(bridge_secret) -- non-secret fingerprint.
    let device_id = if let Some(ref secret) = bridge_secret {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(secret);
        hex_encode(&hash)
    } else {
        String::new()
    };

    // created_at = 0; heartwoodd sets the real timestamp on the Pi side.
    let payload = BackupPayload {
        created_at: 0,
        device_id,
        masters,
        bridge_secret: bridge_hex,
    };

    match serde_json::to_vec(&payload) {
        Ok(json) => {
            log::info!("Backup export: {} masters, {} bytes", payload.masters.len(), json.len());
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_EXPORT_RESPONSE, &json);
        }
        Err(e) => {
            log::error!("Backup export serialisation failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
