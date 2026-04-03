// firmware/src/session.rs
//
// Bridge session management. The bridge authenticates with a shared secret
// (stored in NVS at provision time), then pushes client policies.

use esp_idf_hal::usb_serial::UsbSerialDriver;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::policy::ClientPolicy;
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_SESSION_ACK,
};

use crate::masters::LoadedMaster;
use crate::policy::PolicyEngine;
use crate::protocol;

const NVS_BRIDGE_SECRET_KEY: &str = "bridge_secret";

/// Read the bridge authentication secret from NVS.
pub fn read_bridge_secret(nvs: &EspNvs<NvsDefault>) -> Option<[u8; 32]> {
    let mut buf = [0u8; 32];
    match nvs.get_blob(NVS_BRIDGE_SECRET_KEY, &mut buf) {
        Ok(Some(b)) if b.len() == 32 => Some(buf),
        _ => None,
    }
}

/// Write the bridge authentication secret to NVS.
pub fn write_bridge_secret(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
) -> Result<(), &'static str> {
    nvs.set_blob(NVS_BRIDGE_SECRET_KEY, secret)
        .map_err(|_| "failed to write bridge secret")
}

/// Handle a SESSION_AUTH frame (0x21).
///
/// The bridge sends its 32-byte shared secret; we compare it in constant time
/// against the value stored in NVS. On success we mark the policy engine as
/// authenticated and reply with a SESSION_ACK (0x00 = success).
pub fn handle_auth(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    nvs: &EspNvs<NvsDefault>,
    policy_engine: &mut PolicyEngine,
) {
    if payload.len() != 32 {
        log::warn!("SESSION_AUTH payload is {} bytes, expected 32", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x01]); // 0x01 = failed
        return;
    }

    let bridge_secret = match read_bridge_secret(nvs) {
        Some(s) => s,
        None => {
            log::warn!("No bridge secret in NVS — cannot authenticate");
            protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x02]); // 0x02 = no secret configured
            return;
        }
    };

    // Constant-time comparison to avoid timing side-channels.
    let mut diff = 0u8;
    for (a, b) in payload.iter().zip(bridge_secret.iter()) {
        diff |= a ^ b;
    }

    if diff != 0 {
        log::warn!("Bridge authentication failed — wrong secret");
        policy_engine.bridge_authenticated = false;
        protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x01]); // 0x01 = failed
        return;
    }

    log::info!("Bridge authenticated successfully");
    policy_engine.bridge_authenticated = true;
    protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x00]); // 0x00 = success
}

/// Handle a POLICY_PUSH frame (0x20).
///
/// Payload layout: 32 bytes master pubkey | JSON-encoded `Vec<ClientPolicy>`.
/// The bridge must be authenticated before policies are accepted.
pub fn handle_policy_push(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    masters: &[LoadedMaster],
    policy_engine: &mut PolicyEngine,
) {
    if !policy_engine.bridge_authenticated {
        log::warn!("Policy push rejected — bridge not authenticated");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    if payload.len() < 32 {
        log::warn!("Policy push payload too short");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let master_pubkey: [u8; 32] = payload[..32].try_into().unwrap();
    let policy_json = &payload[32..];

    // Locate the provisioned master that corresponds to this pubkey.
    let master_idx = match crate::masters::find_by_pubkey(masters, &master_pubkey) {
        Some(idx) => idx,
        None => {
            log::warn!("Policy push for unknown master pubkey");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    // Parse the JSON-encoded policy list.
    let policies: Vec<ClientPolicy> = match serde_json::from_slice(policy_json) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse policies: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    let slot = masters[master_idx].slot;
    let count = policies.len();
    policy_engine.set_policies(slot, policies);
    log::info!("Loaded {count} client policies for master slot {slot}");
    protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
}
