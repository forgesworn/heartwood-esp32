// firmware/src/transport.rs
//
// On-device NIP-44 transport encryption/decryption.
//
// Decrypts inbound 0x10 frames, routes to the NIP-46 handler.
// Currently sends plaintext 0x03 response — full encrypted 0x11
// response requires refactoring the handler to return JSON
// instead of writing directly to USB.

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;
use secp256k1::{Secp256k1, SignOnly};
use std::sync::Arc;

use heartwood_common::frame::Frame;
use heartwood_common::nip44;
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_NIP46_REQUEST};

use crate::masters::LoadedMaster;
use crate::oled::Display;
use crate::policy::PolicyEngine;
use crate::protocol;

/// Handle an encrypted NIP-46 request frame (0x10).
///
/// Payload layout: [master_pubkey_32][client_pubkey_32][ciphertext_b64...]
///
/// Decrypts the NIP-44 ciphertext using the target master's secret,
/// then dispatches to the NIP-46 handler. The response currently goes
/// out as plaintext (0x03) — the bridge handles both formats during
/// the transition period.
pub fn handle_encrypted_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    masters: &[LoadedMaster],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    policy_engine: &mut PolicyEngine,
) {
    if frame.payload.len() < 65 {
        log::warn!("Encrypted request too short ({} bytes)", frame.payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let master_pubkey: [u8; 32] = frame.payload[..32].try_into().unwrap();
    let client_pubkey: [u8; 32] = frame.payload[32..64].try_into().unwrap();
    let ciphertext_bytes = &frame.payload[64..];

    // Find the master.
    let master_idx = match crate::masters::find_by_pubkey(masters, &master_pubkey) {
        Some(idx) => idx,
        None => {
            log::warn!("Encrypted request for unknown master pubkey");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };
    let master = &masters[master_idx];

    // Derive conversation key.
    let conversation_key = match nip44::get_conversation_key(&master.secret, &client_pubkey) {
        Ok(ck) => ck,
        Err(e) => {
            log::error!("Conversation key derivation failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    // Ciphertext is base64-encoded NIP-44.
    let ciphertext_b64 = match std::str::from_utf8(ciphertext_bytes) {
        Ok(s) => s,
        Err(_) => {
            log::error!("Ciphertext is not valid UTF-8");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    let plaintext_json = match nip44::decrypt(&conversation_key, ciphertext_b64) {
        Ok(pt) => pt,
        Err(e) => {
            log::error!("NIP-44 decrypt failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    log::info!("Decrypted NIP-46 request ({} bytes)", plaintext_json.len());

    // Build a plaintext frame for the NIP-46 handler.
    let inner_frame = Frame {
        frame_type: FRAME_TYPE_NIP46_REQUEST,
        payload: plaintext_json.as_bytes().to_vec(),
    };

    // Dispatch to the handler — it writes the response as plaintext 0x03.
    // The bridge must handle both 0x03 and 0x11 during the transition.
    crate::nip46_handler::handle_request(
        usb,
        &inner_frame,
        &master.secret,
        &master.label,
        master.mode,
        master.slot,
        secp,
        display,
        button_pin,
        policy_engine,
    );
}
