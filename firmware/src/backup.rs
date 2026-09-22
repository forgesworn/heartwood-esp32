// firmware/src/backup.rs
//
// Backup export and import handlers for the ESP32.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use zeroize::Zeroize;

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
///
/// Bearer notes ride along as a non-spendable INVENTORY only (#86): the
/// public commitment each mint already files a note under, plus amount,
/// mint, state and timestamps. No `k1`, no note key, nothing from which
/// either can be derived. Restoring this file cannot move a satoshi, it can
/// only tell you what a dead board took with it.
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

    // Read the inventory BEFORE the card, so the operator is told what is
    // actually about to leave, including that some notes could not be read.
    let (note_inventory, unreadable_notes) = crate::notes::backup_inventory();
    if unreadable_notes > 0 {
        log::warn!(
            "[backup] {unreadable_notes} note record(s) unreadable this boot \
             (sealed or unindexed); the exported inventory is incomplete"
        );
    }

    // The card is two lines and the narrowest panel fits 25 glyphs on the
    // second, so the clauses are built in priority order and the softest one
    // is dropped rather than truncated (the same budgeting handle_import
    // does for its label preview).
    //
    // Priority: the counts, then "N unreadable" because a file that is
    // silently incomplete is the failure this feature exists to prevent,
    // then "+amt/mint" because the inventory carries amounts and mint hosts
    // as well as commitments and an operator approving an export should know
    // that. docs/SECURITY-MODEL.md spells the full contents out.
    const CARD_LINE: usize = 25;
    let summary = if note_inventory.is_empty() && unreadable_notes == 0 {
        format!("{} masters/{} slots", loaded_masters.len(), total_slots)
    } else {
        let counts = format!(
            "{}m {}sl {}nt",
            loaded_masters.len(),
            total_slots,
            note_inventory.len(),
        );
        let locked = if unreadable_notes > 0 {
            format!(" {unreadable_notes} UNREAD")
        } else {
            String::new()
        };
        let detail = format!("{counts}{locked}+amt/mint");
        if detail.len() <= CARD_LINE {
            detail
        } else {
            format!("{counts}{locked}")
        }
    };

    let result = crate::approval::run_approval_loop(
        display,
        buttons,
        30,
        |d, remaining| {
            let msg = format!("Export backup?\n{summary}");
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
            derivation_version: m.derivation_version,
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
        note_inventory: Some(heartwood_common::backup::NoteInventory::Entries(
            note_inventory,
        )),
        // Carried in the FILE, not only in the log above: an export taken on
        // a locked board would otherwise be byte-identical to one taken on an
        // empty locker, and "I could not see N of them" is a different
        // statement from "there were none".
        note_inventory_unreadable: unreadable_notes as u32,
    };

    match serde_json::to_vec(&payload) {
        Ok(json) => {
            log::info!("Backup export: {} masters, {} bytes", payload.masters.len(), json.len());
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_EXPORT_RESPONSE, &json);
            // Repaint, or the OLED is left on the approval card forever: the
            // operator sees "approved" and nothing else, reads the device as
            // hung, and reaches for the power. handle_import has always closed
            // with "Restore complete"; export was the odd one out.
            crate::oled::show_change_done(display, "Backup exported", &summary);
            esp_idf_hal::delay::FreeRtos::delay_ms(1200);
        }
        Err(e) => {
            log::error!("Backup export serialisation failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            crate::oled::show_error(display, "Backup export\nfailed");
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
/// - every slot is re-validated through `sanitise_imported_slot`, the
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
///
/// A carried note inventory (#86) is looked at and dropped. It is a record of
/// what a board held, not a means of getting it back: restoring a bearer
/// secret onto a second board is a double spend, so the locker is never read,
/// written or consulted here, and no code path from this function reaches it.
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

    // Note inventory: shape-checked for the log, then dropped. Nothing below
    // this point touches it, and nothing anywhere touches the note locker.
    let inventory = heartwood_common::backup::inspect_imported_inventory(&backup);
    if inventory.entries > 0 {
        log::info!(
            "Backup import: ignoring a {}-entry note inventory ({} malformed{}); \
             notes are never restored",
            inventory.entries,
            inventory.malformed,
            if inventory.over_cap { ", over cap" } else { "" },
        );
    }
    if inventory.unreadable_field {
        log::info!(
            "Backup import: the note inventory is in no shape this firmware reads; \
             ignoring it. Identities and app slots are unaffected."
        );
    }
    if inventory.unreadable_notes > 0 {
        log::info!(
            "Backup import: the exporting board could not read {} of its own notes; \
             its inventory is incomplete by that many",
            inventory.unreadable_notes
        );
    }

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
            // Signing and kind ceilings are stripped and the method ceiling
            // re-validated (host-tested in common::policy).
            match heartwood_common::policy::sanitise_imported_slot(slot) {
                Ok(had_signing) => signing_stripped += usize::from(had_signing),
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

    log::info!("Backup restore requires renewed persona consent; {signing_stripped} signing grants stripped");
    for master in &mut masters {
        heartwood_common::policy::remove_ambiguous_pubkeys(&mut master.connection_slots);
        if heartwood_common::policy::migrate_client_grants(&mut master.connection_slots).is_err() {
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
            return;
        }
    }
    if masters.iter().enumerate().any(|(i, m)| masters[..i].iter().any(|previous| previous.pubkey == m.pubkey)) {
        protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
        return;
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
        let prompt = if restore_slots > 0 {
            format!("Restore {restore_slots} slots?\nRenew app consent")
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

    // Retain rollback points for every attempted master. NVS is atomic per
    // key, not across masters: never report a partially persisted restore as
    // complete. A failed read-back may have committed, so compensate durably.
    let mut restored_snapshots = Vec::new();
    for (device_slot, backup_master) in &matched {
        // A corrupt/quarantined table needs an explicit empty recovery baseline,
        // verified before serving any authority. This is after the physical hold.
        let recovered = policy_engine.recover_pairings_for_backup_restore(nvs, *device_slot);
        if recovered {
            restored_snapshots.push(policy_engine.snapshot_slot_state(*device_slot));
            let slots = policy_engine.slots_mut(*device_slot);
            slots.clear();
            slots.extend(backup_master.connection_slots.iter().cloned());
            policy_engine.slots_dirty = true;
        }
        if !recovered || !policy_engine.persist_slots(nvs, *device_slot) {
            let mut rollback_ok = true;
            for snapshot in restored_snapshots.into_iter().rev() {
                rollback_ok &= policy_engine.restore_slot_state_durably(nvs, snapshot);
            }
            log::error!("Backup import failed: slot persistence; rollback verified={rollback_ok}");
            crate::oled::show_error(display, if rollback_ok {
                "Restore failed\nStorage error"
            } else {
                "Storage fault\nUse USB recovery"
            });
            protocol::write_frame(usb, FRAME_TYPE_BACKUP_IMPORT_RESPONSE, &[0x00]);
            return;
        }

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
