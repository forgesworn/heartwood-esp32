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
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
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

        match policy_engine.create_slot(ms, label.clone(), secret_hex.clone()) {
            Some(index) => {
                policy_engine.persist_slots(nvs, ms);

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
        let redacted: Vec<_> = slots.iter().map(heartwood_common::policy::redact_slot).collect();
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
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    if !policy_engine.bridge_authenticated {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else if frame.payload.len() < 2 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        match serde_json::from_slice::<serde_json::Value>(&frame.payload[1..]) {
            Ok(v) => {
                let idx = v["slot_index"].as_u64().unwrap_or(255) as u8;

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
                if changes.is_empty() { changes.push_str("policy"); }

                // Truncate label for OLED (max ~12 chars per line)
                let short_label: String = slot_label.chars().take(12).collect();

                let result = crate::approval::run_approval_loop(
                    display,
                    button_pin,
                    30,
                    |d, remaining| {
                        let msg = format!("Update {}?\n{}\n{}s", short_label, changes, remaining);
                        crate::oled::show_error(d, &msg);
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

                    if policy_engine.update_slot(ms, idx, label, methods, kinds, auto) {
                        policy_engine.persist_slots(nvs, ms);
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
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else if frame.payload.len() < 2 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    } else {
        let ms = frame.payload[0];
        let idx = frame.payload[1];
        if policy_engine.revoke_slot(ms, idx) {
            policy_engine.persist_slots(nvs, ms);
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
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
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
