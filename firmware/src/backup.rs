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

/// Handle BACKUP_IMPORT_REQUEST (0x52).
///
/// Receives a BackupPayload JSON with pre-matched masters (heartwoodd
/// already filtered to only include masters whose pubkeys match the
/// device's current provisioned masters). Shows a summary on the OLED,
/// waits for physical button confirmation, then writes to NVS.
pub fn handle_import(
    usb: &mut SerialPort<'_>,
    payload_bytes: &[u8],
    loaded_masters: &[LoadedMaster],
    policy_engine: &mut PolicyEngine,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    // Parse the backup payload.
    let backup: BackupPayload = match serde_json::from_slice(payload_bytes) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Backup import: invalid JSON: {e}");
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
            return;
        }
    };

    // Count total slots to restore.
    let total_slots: usize = backup.masters.iter()
        .map(|m| m.connection_slots.len())
        .sum();

    if total_slots == 0 && backup.bridge_secret.is_empty() {
        log::warn!("Backup import: nothing to restore");
        protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
        return;
    }

    // Check if any existing slots will be overwritten.
    let has_existing: bool = backup.masters.iter().any(|bm| {
        !policy_engine.list_slots(bm.slot).is_empty()
    });

    // Show summary on OLED and wait for button confirmation.
    let prompt = if has_existing {
        format!("Restore {} slots?\n(overwrites)", total_slots)
    } else {
        format!("Restore {} slots?", total_slots)
    };

    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            let msg = format!("{}\n{}s", prompt, remaining);
            crate::oled::show_error(d, &msg);
        },
    );

    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("Backup import denied by user");
        protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
        return;
    }

    // Write connection slots to the policy engine and persist to NVS.
    for backup_master in &backup.masters {
        // Verify this master is actually provisioned on the device.
        let device_master = loaded_masters.iter().find(|m| {
            let device_pubkey_hex = hex_encode(&m.pubkey);
            device_pubkey_hex == backup_master.pubkey
        });

        if device_master.is_none() {
            log::warn!(
                "Backup import: skipping master slot {} -- not provisioned on device",
                backup_master.slot
            );
            continue;
        }

        let device_slot = device_master.unwrap().slot;

        // Replace all slots for this master with the backup data.
        let slots = policy_engine.slots_mut(device_slot);
        slots.clear();
        slots.extend(backup_master.connection_slots.clone());
        policy_engine.slots_dirty = true;
        policy_engine.persist_slots(nvs, device_slot);

        log::info!(
            "Backup import: restored {} slots for master slot {}",
            backup_master.connection_slots.len(),
            device_slot
        );
    }

    // Restore bridge secret if present.
    if backup.bridge_secret.len() == 64 {
        if let Ok(secret_bytes) = heartwood_common::hex::hex_decode(&backup.bridge_secret) {
            if secret_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&secret_bytes);
                match session::write_bridge_secret(nvs, &arr) {
                    Ok(()) => log::info!("Backup import: bridge secret restored"),
                    Err(e) => log::error!("Backup import: failed to write bridge secret: {e}"),
                }
            }
        }
    }

    log::info!("Backup import complete");
    crate::oled::show_error(display, "Restore\ncomplete!");
    esp_idf_hal::delay::FreeRtos::delay_ms(1500);
    protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x01]);
}
