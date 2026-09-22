// firmware/src/connslot.rs
//
// Connection-slot (client) management over the frame protocol. Shared by the
// USB dispatch loop (main.rs) AND the WiFi-standalone relay loop's USB poll
// (relay.rs), so a wifi signer can be managed over the cable as well as over
// its relay. These are thin wrappers over `PolicyEngine`; the relay's
// kind-24134 path performs the same operations via JSON-RPC.
//
// Frame map: 0x40 create, 0x42 list, 0x44 update, 0x46 revoke, 0x48 uri.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::frame::Frame;
use heartwood_common::types::{
    FRAME_TYPE_CONNSLOT_CREATE_RESP, FRAME_TYPE_CONNSLOT_LIST_RESP,
    FRAME_TYPE_CONNSLOT_REVOKE_RESP, FRAME_TYPE_CONNSLOT_UPDATE_RESP, FRAME_TYPE_CONNSLOT_URI_RESP,
    FRAME_TYPE_NACK,
};

use crate::masters::LoadedMaster;
use crate::oled::Display;
use crate::policy::PolicyEngine;
use crate::protocol;
use crate::serial::SerialPort;

/// Sent as the NACK payload when connection-slot management is attempted on a
/// channel that has not completed SESSION_AUTH.
///
/// Every one of these operations mints or moves a signing credential, so the
/// gate itself is right. What was wrong was saying nothing: a plain USB caller
/// got an empty NACK and reported "the signer refused", which reads as a fault
/// rather than a missing session.
const BRIDGE_AUTH_REQUIRED: &[u8] =
    b"connection-slot management requires an authenticated bridge session";

/// 0x40 — create a connection slot (requires bridge auth). Returns the slot's
/// secret + bunker npub once; the secret is never shown again.
pub fn handle_create(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    policy_engine: &mut PolicyEngine,
    masters: &[LoadedMaster],
    nvs: &mut EspNvs<NvsDefault>,
) {
    if !policy_engine.bridge_authenticated {
        // Say WHY. An empty NACK left callers guessing: the sapwood CLI
        // reported "the signer refused" for what is simply an unauthenticated
        // channel, with no hint that connection-slot management needs a bridge
        // session at all.
        protocol::write_frame(usb, FRAME_TYPE_NACK, BRIDGE_AUTH_REQUIRED);
    } else if !crate::entropy::rng_ok() {
        // Fresh secrets need fresh entropy — fail closed if the boot-time
        // RNG self-test didn't pass. The reason distinguishes a real fault
        // from the power-cycle a post-wipe boot owes us.
        let why = crate::entropy::rng_refusal();
        log::error!("CONNSLOT_CREATE refused: {why}");
        protocol::write_frame(usb, FRAME_TYPE_NACK, why.as_bytes());
    } else if frame.payload.is_empty() {
        log::warn!("CONNSLOT_CREATE missing master_slot");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        let label = if frame.payload.len() > 1 {
            String::from_utf8_lossy(&frame.payload[1..]).to_string()
        } else {
            "unnamed".to_string()
        };

        // Generate secret via hardware RNG, with a guaranteed entropy source
        // (the radio may be off in USB mode).
        let mut secret_bytes = [0u8; 32];
        crate::fill_random_strong(&mut secret_bytes);
        let secret_hex = heartwood_common::hex::hex_encode(&secret_bytes);
        secret_bytes.iter_mut().for_each(|b| *b = 0); // zeroize raw bytes

        let snapshot = policy_engine.snapshot_slot_state(ms);
        match policy_engine.create_slot(ms, label.clone(), secret_hex.clone()) {
            Some(index) => {
                if !policy_engine.persist_slots(nvs, ms) {
                    policy_engine.restore_slot_state_durably(nvs, snapshot);
                    protocol::write_frame(usb, FRAME_TYPE_NACK, b"storage_unavailable: pairing was not saved");
                    return;
                }

                // Build response with slot info and master pubkey.
                let npub_hex = masters
                    .iter()
                    .find(|m| m.slot == ms)
                    .map(|m| heartwood_common::hex::hex_encode(&m.pubkey))
                    .unwrap_or_default();

                let resp = serde_json::json!({
                    "slot_index": index,
                    "secret": secret_hex,
                    "label": label,
                    "npub": npub_hex,
                });
                protocol::write_frame(
                    usb,
                    FRAME_TYPE_CONNSLOT_CREATE_RESP,
                    resp.to_string().as_bytes(),
                );
                log::info!("Created connection slot {} ({}) for master {}", index, label, ms);
            }
            None => {
                log::warn!("No free connection slots for master {ms}");
                protocol::write_frame(usb, FRAME_TYPE_NACK, b"slots full");
            }
        }
    }
}

/// 0x42 — list connection slots (secrets redacted). No bridge auth required.
pub fn handle_list(usb: &mut SerialPort<'_>, frame: &Frame, policy_engine: &mut PolicyEngine) {
    if frame.payload.is_empty() {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        let slots = policy_engine.list_slots(ms);
        let redacted: Vec<_> = slots.iter().map(|slot| {
            let mut view = heartwood_common::mgmt::client_summary(slot);
            view["secret"] = serde_json::Value::String(String::new());
            view["ids"] = serde_json::Value::String(slot.approved_identities.clone());
            view["wb"] = serde_json::Value::Bool(slot.was_bound);
            view
        }).collect();
        match serde_json::to_vec(&redacted) {
            Ok(json) => protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_LIST_RESP, &json),
            Err(e) => {
                log::error!("Failed to serialise slot list: {e}");
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}

/// 0x44 — update a connection slot (requires bridge auth + a button hold).
pub fn handle_update(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    policy_engine: &mut PolicyEngine,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    if !policy_engine.bridge_authenticated {
        // Say WHY. An empty NACK left callers guessing: the sapwood CLI
        // reported "the signer refused" for what is simply an unauthenticated
        // channel, with no hint that connection-slot management needs a bridge
        // session at all.
        protocol::write_frame(usb, FRAME_TYPE_NACK, BRIDGE_AUTH_REQUIRED);
    } else if frame.payload.len() < 2 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        match serde_json::from_slice::<serde_json::Value>(&frame.payload[1..]) {
            Ok(v) => {
                let idx = v["slot_index"].as_u64().unwrap_or(255) as u8;

                // Versioned narrowing-only operation. Its own response binds to
                // the observed credential, so a reused numeric slot cannot be
                // changed from a stale management screen. No physical hold is
                // needed to withdraw authority on an authenticated cable.
                if let Some(withdrawal) = v.get("withdraw_consent_v1") {
                    let result = (|| -> Result<(), &'static str> {
                        if !withdrawal.is_object() { return Err("invalid consent withdrawal"); }
                        let target = policy_engine.list_slots(ms).iter()
                            .find(|slot| slot.slot_index == idx).ok_or("pairing not found")?;
                        if target.client_grants.is_none() { return Err("per-device consent unavailable"); }
                        let fingerprint = heartwood_common::mgmt::credential_fingerprint(&target.secret);
                        if v.get("expected_secret_fingerprint").and_then(|value| value.as_str()) != Some(fingerprint.as_str()) {
                            return Err("pairing_changed: refresh the signer");
                        }
                        let client = withdrawal.get("client_pubkey").map(|value| {
                            value.as_str().filter(|key| heartwood_common::policy::decode_client_key(key).is_some()
                                && heartwood_common::policy::slot_authorizes(target, key)).ok_or("unknown client credential")
                        }).transpose()?;
                        let identity = withdrawal.get("identity").map(|value| value.as_str().ok_or("invalid identity")).transpose()?;
                        let snapshot = policy_engine.snapshot_slot_state(ms);
                        match identity {
                            Some(identity) => { policy_engine.revoke_identity(ms, idx, identity, client).ok_or("pairing not found")??; }
                            None => { policy_engine.clear_identities(ms, idx, client).ok_or("pairing not found")?; }
                        }
                        if !policy_engine.persist_slots(nvs, ms) {
                            policy_engine.restore_slot_state_durably(nvs, snapshot);
                            return Err("storage_unavailable: consent withdrawal was not saved");
                        }
                        Ok(())
                    })();
                    match result {
                        Ok(()) => protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_UPDATE_RESP, b"consent_withdrawn_v1"),
                        Err(reason) => protocol::write_frame(usb, FRAME_TYPE_NACK, reason.as_bytes()),
                    }
                    return;
                }

                // Resolve the slot label for the OLED prompt.
                let slot_label = policy_engine
                    .list_slots(ms)
                    .iter()
                    .find(|s| s.slot_index == idx)
                    .map(|s| s.label.clone())
                    .unwrap_or_else(|| format!("slot {idx}"));

                // Build a short description of what's changing.
                let mut changes = String::new();
                if v.get("allowed_kinds").is_some() {
                    changes.push_str("kinds");
                }
                if v.get("auto_approve").is_some() {
                    if !changes.is_empty() { changes.push_str(", "); }
                    changes.push_str("auto");
                }
                if v.get("label").is_some() {
                    if !changes.is_empty() { changes.push_str(", "); }
                    changes.push_str("label");
                }
                // Family-bunker C3 flags travel over the cable too, so the
                // guardian's own hands can flag a slot without an operator.
                if v.get("escalate").is_some()
                    || v.get("petition_on_deny").is_some()
                    || v.get("audit_child_wrap").is_some()
                    || v.get("guardian_notice_wrap").is_some()
                    || v.get("bound_identity").is_some()
                {
                    if !changes.is_empty() { changes.push_str(", "); }
                    changes.push_str("family");
                }
                if changes.is_empty() { changes.push_str("policy"); }

                // Truncate label for OLED (max ~12 chars per line)
                let short_label: String = slot_label.chars().take(12).collect();

                let result = crate::approval::run_approval_loop(
                    display,
                    buttons,
                    30,
                    |d, remaining| {
                        let msg = format!("Update {}?\n{}", short_label, changes);
                        crate::oled::show_change_approval(d, &msg, remaining, 30);
                    },
                );

                if !matches!(result, crate::approval::ApprovalResult::Approved) {
                    log::info!("CONNSLOT_UPDATE denied by user for {}", slot_label);
                    protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                } else {
                    let label = v["label"].as_str().map(|s| s.to_string());
                    let methods = v["allowed_methods"].as_array().map(|arr| {
                        arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                    });
                    let kinds = v["allowed_kinds"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect());
                    let auto = v["auto_approve"].as_bool();

                    let snapshot = policy_engine.snapshot_slot_state(ms);
                    if policy_engine.update_slot(ms, idx, label, methods, kinds, auto) {
                        // Family-bunker C3 flags: absent keys keep the slot's
                        // existing values (same merge rule as the fields
                        // above). Applied under the same button approval.
                        if v.get("escalate").is_some()
                            || v.get("petition_on_deny").is_some()
                            || v.get("audit_child_wrap").is_some()
                            || v.get("guardian_notice_wrap").is_some()
                            || v.get("bound_identity").is_some()
                        {
                            let existing = policy_engine
                                .list_slots(ms)
                                .iter()
                                .find(|s| s.slot_index == idx)
                                .map(|s| {
                                    (
                                        s.escalate,
                                        s.petition_on_deny,
                                        s.audit_child_wrap,
                                        s.guardian_notice_wrap,
                                        s.bound_identity.clone(),
                                    )
                                })
                                .unwrap_or((false, false, false, false, None));
                            policy_engine.set_slot_family_flags(
                                ms,
                                idx,
                                v["escalate"].as_bool().unwrap_or(existing.0),
                                v["petition_on_deny"].as_bool().unwrap_or(existing.1),
                                v["audit_child_wrap"].as_bool().unwrap_or(existing.2),
                                v["guardian_notice_wrap"].as_bool().unwrap_or(existing.3),
                                v["bound_identity"]
                                    .as_str()
                                    .filter(|s| {
                                        s.len() == 64
                                            && s.bytes().all(|b| b.is_ascii_hexdigit())
                                    })
                                    .map(|s| s.to_ascii_lowercase())
                                    .or(existing.4),
                            );
                        }
                        if !policy_engine.persist_slots(nvs, ms) {
                            policy_engine.restore_slot_state_durably(nvs, snapshot);
                            protocol::write_frame(usb, FRAME_TYPE_NACK, b"storage_unavailable: permissions were not saved");
                            return;
                        }
                        log::info!("Updated slot {} ({}) — approved by button", idx, slot_label);
                        protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_UPDATE_RESP, b"ok");
                    } else {
                        protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_UPDATE_RESP, b"not found");
                    }
                }
            }
            Err(e) => {
                log::error!("CONNSLOT_UPDATE bad JSON: {e}");
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}

/// 0x46 — revoke a connection slot (requires bridge auth).
pub fn handle_revoke(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    policy_engine: &mut PolicyEngine,
    nvs: &mut EspNvs<NvsDefault>,
) {
    if !policy_engine.bridge_authenticated {
        // Say WHY. An empty NACK left callers guessing: the sapwood CLI
        // reported "the signer refused" for what is simply an unauthenticated
        // channel, with no hint that connection-slot management needs a bridge
        // session at all.
        protocol::write_frame(usb, FRAME_TYPE_NACK, BRIDGE_AUTH_REQUIRED);
    } else if frame.payload.len() < 2 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        let idx = frame.payload[1];
        let snapshot = policy_engine.snapshot_slot_state(ms);
        if policy_engine.revoke_slot(ms, idx) {
            if !policy_engine.persist_slots(nvs, ms) {
                policy_engine.restore_slot_state_durably(nvs, snapshot);
                protocol::write_frame(usb, FRAME_TYPE_NACK, b"storage_unavailable: pairing was not revoked");
                return;
            }
            protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_REVOKE_RESP, b"ok");
            log::info!("Revoked connection slot {} for master {}", idx, ms);
        } else {
            protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_REVOKE_RESP, b"not found");
        }
    }
}

/// 0x48 — build the bunker URI for a connection slot (requires bridge auth).
pub fn handle_uri(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    policy_engine: &mut PolicyEngine,
    masters: &[LoadedMaster],
) {
    if !policy_engine.bridge_authenticated {
        // Say WHY. An empty NACK left callers guessing: the sapwood CLI
        // reported "the signer refused" for what is simply an unauthenticated
        // channel, with no hint that connection-slot management needs a bridge
        // session at all.
        protocol::write_frame(usb, FRAME_TYPE_NACK, BRIDGE_AUTH_REQUIRED);
    } else if frame.payload.len() < 2 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        let idx = frame.payload[1];
        let relay_json = if frame.payload.len() > 2 {
            String::from_utf8_lossy(&frame.payload[2..]).to_string()
        } else {
            "[]".to_string()
        };

        let slot = policy_engine.list_slots(ms).iter().find(|s| s.slot_index == idx);
        let master = masters.iter().find(|m| m.slot == ms);

        match (slot, master) {
            (Some(slot), Some(master)) => {
                let npub_hex = heartwood_common::hex::hex_encode(&master.pubkey);
                let relays: Vec<String> = serde_json::from_str(&relay_json).unwrap_or_default();
                let relay_params = relays
                    .iter()
                    .map(|r| format!("relay={}", r))
                    .collect::<Vec<_>>()
                    .join("&");
                let uri = if relay_params.is_empty() {
                    format!("bunker://{}?secret={}", npub_hex, slot.secret)
                } else {
                    format!("bunker://{}?{}&secret={}", npub_hex, relay_params, slot.secret)
                };
                protocol::write_frame(usb, FRAME_TYPE_CONNSLOT_URI_RESP, uri.as_bytes());
            }
            _ => {
                protocol::write_frame(usb, FRAME_TYPE_NACK, b"not found");
            }
        }
    }
}
