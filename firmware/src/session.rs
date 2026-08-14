// firmware/src/session.rs
//
// Bridge session management. The bridge authenticates with a shared secret
// (stored in NVS at provision time), then pushes client policies.

use crate::serial::SerialPort;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_SESSION_ACK,
};

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

/// Verify a presented 32-byte bridge secret against NVS in constant time,
/// without touching a PolicyEngine — for the locked boot loop, which runs
/// before the policy engine exists. Returns `Some(true)` on match,
/// `Some(false)` on mismatch or malformed payload, `None` when no bridge
/// secret is configured.
pub fn verify_bridge_secret(payload: &[u8], nvs: &EspNvs<NvsDefault>) -> Option<bool> {
    if payload.len() != 32 {
        return Some(false);
    }
    let bridge_secret = read_bridge_secret(nvs)?;
    let mut diff = 0u8;
    for (a, b) in payload.iter().zip(bridge_secret.iter()) {
        diff |= a ^ b;
    }
    Some(diff == 0)
}

/// Handle a SESSION_AUTH frame (0x21).
///
/// The bridge sends its 32-byte shared secret; we compare it in constant time
/// against the value stored in NVS. On success we mark the policy engine as
/// authenticated and reply with a SESSION_ACK (0x00 = success).
pub fn handle_auth(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &EspNvs<NvsDefault>,
    policy_engine: &mut PolicyEngine,
) {
    match verify_bridge_secret(payload, nvs) {
        Some(true) => {
            log::info!("Bridge authenticated successfully");
            policy_engine.bridge_authenticated = true;
            protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x00]); // 0x00 = success
        }
        Some(false) => {
            log::warn!("Bridge authentication failed — wrong secret");
            policy_engine.bridge_authenticated = false;
            protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x01]); // 0x01 = failed
        }
        None => {
            log::warn!("No bridge secret in NVS — cannot authenticate");
            protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x02]); // 0x02 = no secret configured
        }
    }
}

/// Handle a SET_BRIDGE_SECRET frame (0x23).
///
/// Allows the host to provision the bridge authentication secret via USB.
/// Rejected if the bridge is currently authenticated (to prevent secret
/// replacement by an already-connected bridge without physical consent).
/// Requires a 2-second button hold to confirm — shown as a 30-second
/// countdown on the OLED.
pub fn handle_set_bridge_secret(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    policy_engine: &PolicyEngine,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    if policy_engine.bridge_authenticated {
        log::warn!("SET_BRIDGE_SECRET rejected — bridge is currently authenticated");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    if payload.len() != 32 {
        log::warn!("SET_BRIDGE_SECRET payload is {} bytes, expected 32", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let result = crate::approval::run_approval_loop(
        display,
        buttons,
        30,
        |d, remaining| {
            crate::oled::show_change_approval(d, "Set bridge secret?", remaining, 30);
        },
    );

    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("SET_BRIDGE_SECRET denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let secret: [u8; 32] = payload.try_into().unwrap();
    match write_bridge_secret(nvs, &secret) {
        Ok(()) => {
            log::info!("Bridge secret written to NVS");
            crate::oled::show_error(display, "Bridge secret\nset!");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        }
        Err(e) => {
            log::error!("Failed to write bridge secret: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
