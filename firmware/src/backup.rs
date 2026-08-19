// firmware/src/backup.rs
//
// Backup export and import handlers for the ESP32.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use zeroize::Zeroize;

use heartwood_common::backup::{BackupMaster, BackupPayload};
use heartwood_common::hex::hex_encode;
use heartwood_common::policy::validate_exact_slot_policy;
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
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    let total_slots: usize = loaded_masters
        .iter()
        .map(|m| policy_engine.list_slots(m.slot).len())
        .sum();

    let result = crate::approval::run_approval_loop(
        display,
        buttons,
        30,
        |d, remaining| {
            let msg = format!(
                "Export backup?\n{} masters/{} slots",
                loaded_masters.len(),
                total_slots,
            );
            crate::oled::show_change_approval(d, &msg, remaining, 30);
        },
    );

    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("Backup export denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

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

    // device_id = SHA-256(bridge_secret) -- non-secret fingerprint.
    let device_id = match &bridge_secret {
        Some(secret) => {
            use sha2::{Digest, Sha256};
            hex_encode(&Sha256::digest(secret))
        }
        None => String::new(),
    };

    let bridge_hex = bridge_secret
        .map(|s| hex_encode(&s))
        .unwrap_or_default();

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
            // Repaint, or the OLED is left on the approval card forever: the
            // operator sees "approved" and nothing else, reads the device as
            // hung, and reaches for the power. handle_import has always closed
            // with "Restore complete"; export was the odd one out.
            let done = format!("{} masters/{} slots", loaded_masters.len(), total_slots);
            crate::oled::show_change_done(display, "Backup exported", &done);
            esp_idf_hal::delay::FreeRtos::delay_ms(1200);
        }
        Err(e) => {
            log::error!("Backup export serialisation failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            crate::oled::show_error(display, "Backup export failed");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
        }
    }
}

/// Handle BACKUP_IMPORT_REQUEST (0x52).
///
/// Receives a BackupPayload JSON with pre-matched masters (heartwoodd
/// already filtered to only include masters whose pubkeys match the
/// device's current provisioned masters). Shows a summary on the OLED,
/// waits for physical button confirmation, then writes to NVS.
///
/// Authority is never imported as-is (FW-H2):
/// - every slot is re-validated through `validate_exact_slot_policy`, the
///   same validator the management API uses — a backup carrying methods or
///   kind ceilings no signed-in path could have installed is refused whole;
/// - `signing_approved` is forced false and `sign_event`/kind ceilings are
///   stripped, so a backup restores PAIRINGS, never silent signing — each
///   slot re-earns signing from the physical button (legacy slots) or the
///   authenticated operator (strict slots);
/// - a carried bridge secret is installed only under its own distinct
///   approval prompt, never by the slot-restore hold.
///
/// The wire format is unchanged: older hosts and backups round-trip, the
/// signing grant simply does not survive the restore.
pub fn handle_import(
    usb: &mut SerialPort<'_>,
    payload_bytes: &[u8],
    loaded_masters: &[LoadedMaster],
    policy_engine: &mut PolicyEngine,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
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

    // Re-validate and sanitise every slot BEFORE any approval or write.
    let mut masters = backup.masters;
    let mut signing_stripped = 0usize;
    for bm in &mut masters {
        if bm.connection_slots.len() > 16 {
            log::warn!(
                "Backup import refused: {} slots for one master exceeds the 16-slot capacity",
                bm.connection_slots.len()
            );
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
            return;
        }
        for slot in &mut bm.connection_slots {
            let had_signing = slot.signing_approved
                || slot.allowed_methods.iter().any(|m| m == "sign_event");
            if had_signing {
                signing_stripped += 1;
            }
            slot.signing_approved = false;
            slot.allowed_methods.retain(|m| m != "sign_event");
            // Kind ceilings are meaningless without sign_event (and the
            // validator rejects the combination) — clear them with it.
            slot.allowed_kinds.clear();
            match validate_exact_slot_policy(
                slot.allowed_methods.clone(),
                Vec::new(),
                slot.auto_approve,
            ) {
                Ok(policy) => {
                    slot.allowed_methods = policy.allowed_methods;
                    slot.allowed_kinds = policy.allowed_kinds;
                    slot.auto_approve = policy.auto_approve;
                }
                Err(e) => {
                    log::warn!(
                        "Backup import refused: slot {} on master slot {} fails policy validation: {e}",
                        slot.slot_index,
                        bm.slot
                    );
                    protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
                    return;
                }
            }
        }
    }

    // Match backup masters to device masters by pubkey. The device slot, not
    // the backup's slot number, is where the restore lands.
    let matched: Vec<(u8, &BackupMaster)> = masters
        .iter()
        .filter_map(|bm| {
            loaded_masters
                .iter()
                .find(|m| hex_encode(&m.pubkey) == bm.pubkey)
                .map(|dm| (dm.slot, bm))
        })
        .collect();
    if matched.is_empty() && total_slots > 0 {
        log::warn!("Backup import: no backup master matches a provisioned identity");
        protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
        return;
    }

    // Content summary on the OLED before the hold (FW-H2): labels and the
    // signing grants being stripped, not a bare count. `restore_slots` counts
    // only slots that will actually be written (matched masters). The approval
    // card renders at most two ~25-glyph lines, so the summary is built to
    // fit: labels preview, then the stripped-signing count (or the overwrite
    // note) as a suffix.
    let restore_slots: usize = matched
        .iter()
        .map(|(_, bm)| bm.connection_slots.len())
        .sum();
    let has_existing: bool = matched
        .iter()
        .any(|(device_slot, _)| !policy_engine.list_slots(*device_slot).is_empty());
    if restore_slots > 0 || has_existing {
        let mut labels: Vec<&str> = Vec::new();
        for (_, bm) in &matched {
            for slot in &bm.connection_slots {
                labels.push(slot.label.as_str());
            }
        }
        let preview = if labels.len() <= 2 {
            labels.join(", ")
        } else {
            format!("{}, +{}", labels[..2].join(", "), labels.len() - 2)
        };
        let prompt = if restore_slots > 0 {
            let suffix = if signing_stripped > 0 {
                format!(" -{signing_stripped} sign")
            } else if has_existing {
                " (overwrites)".to_string()
            } else {
                String::new()
            };
            let budget = 25usize.saturating_sub(suffix.len()).max(8);
            let preview: String = preview.chars().take(budget).collect();
            format!("Restore {restore_slots} slots?\n{preview}{suffix}")
        } else {
            // A matched master with no slots in the backup has its pairings
            // wiped by the replace below — the prompt must exist for that.
            "Replace pairings?\nbackup holds no slots".to_string()
        };

        let result = crate::approval::run_approval_loop(
            display,
            buttons,
            30,
            |d, remaining| {
                crate::oled::show_change_approval(d, &prompt, remaining, 30);
            },
        );

        if !matches!(result, crate::approval::ApprovalResult::Approved) {
            log::info!("Backup import denied by user");
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
            return;
        }
    }

    // Write connection slots to the policy engine and persist to NVS.
    for (device_slot, backup_master) in &matched {
        // Replace all slots for this master with the sanitised backup data.
        let slots = policy_engine.slots_mut(*device_slot);
        slots.clear();
        slots.extend(backup_master.connection_slots.iter().cloned());
        policy_engine.slots_dirty = true;
        policy_engine.persist_slots(nvs, *device_slot);

        log::info!(
            "Backup import: restored {} slots for master slot {}",
            backup_master.connection_slots.len(),
            device_slot
        );
    }

    // Restore the bridge secret only under its OWN distinct approval — it
    // decides who can open an authenticated USB session at all, so it must
    // never ride the slot-restore hold (FW-H2). Denial skips the secret but
    // keeps the restored slots.
    let mut bridge_secret = backup.bridge_secret;
    if bridge_secret.len() == 64 {
        let decoded: Option<[u8; 32]> = heartwood_common::hex::hex_decode(&bridge_secret)
            .ok()
            .and_then(|v| v.try_into().ok());
        match decoded {
            Some(secret_bytes) => {
                let action = if session::read_bridge_secret(nvs).is_some() {
                    "Replace bridge\nsecret?"
                } else {
                    "Set bridge\nsecret?"
                };
                let result = crate::approval::run_approval_loop(
                    display,
                    buttons,
                    30,
                    |d, remaining| {
                        crate::oled::show_change_approval(d, action, remaining, 30);
                    },
                );
                if matches!(result, crate::approval::ApprovalResult::Approved) {
                    match session::write_bridge_secret(nvs, &secret_bytes) {
                        Ok(()) => log::info!("Backup import: bridge secret restored"),
                        Err(e) => {
                            log::error!("Backup import: failed to write bridge secret: {e}")
                        }
                    }
                } else {
                    log::info!("Backup import: bridge secret skipped (denied by user)");
                }
            }
            None => {
                log::warn!("Backup import: bridge secret is not valid 32-byte hex — skipped");
            }
        }
    }
    bridge_secret.zeroize();

    log::info!("Backup import complete");
    crate::oled::show_change_done(display, "Restore complete", "App pairings imported");
    esp_idf_hal::delay::FreeRtos::delay_ms(1500);
    protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x01]);
}
