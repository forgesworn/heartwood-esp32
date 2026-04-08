// firmware/src/transport.rs
//
// On-device NIP-44 transport encryption/decryption.
//
// Decrypts inbound 0x10 frames, routes to the NIP-46 handler, then
// re-encrypts the response as a 0x11 frame. Every method — including
// sign_event — now returns a JSON string, so the response is always
// encrypted before leaving the device.

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use secp256k1::{Secp256k1, SignOnly};
use std::sync::Arc;

use heartwood_common::frame::Frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip44;
use heartwood_common::nip46::{self, SignedEvent, UnsignedEvent};
use heartwood_common::types::{
    FRAME_TYPE_ENCRYPTED_RESPONSE, FRAME_TYPE_NACK, FRAME_TYPE_NIP46_REQUEST,
    FRAME_TYPE_SIGN_ENVELOPE_RESPONSE,
};

use crate::masters::LoadedMaster;
use crate::oled::Display;
use crate::policy::PolicyEngine;
use crate::protocol;

/// Handle an encrypted NIP-46 request frame (0x10).
///
/// Payload layout: [master_pubkey_32][client_pubkey_32][ciphertext_b64...]
///
/// Decrypts the NIP-44 ciphertext using the target master's secret,
/// dispatches to the NIP-46 handler, then re-encrypts the response
/// (including sign_event outcomes) and sends it as a 0x11 frame.
/// The Pi never sees plaintext — all responses are encrypted.
pub fn handle_encrypted_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    masters: &[LoadedMaster],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    nvs: &mut EspNvs<NvsDefault>,
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

    // Dispatch to the handler — always returns a JSON response string.
    let response_json = crate::nip46_handler::handle_request(
        &inner_frame,
        &master.secret,
        &master.label,
        master.mode,
        master.slot,
        secp,
        display,
        button_pin,
        policy_engine,
        identity_caches,
        Some(&client_pubkey),
    );

    // Persist slots if a connect or sign_event may have modified one.
    policy_engine.persist_slots(nvs, master.slot);

    let free_heap = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
    log::info!(
        "NIP-46 response ready: {} bytes, free heap: {} bytes",
        response_json.len(),
        free_heap,
    );

    // Drop the decrypted request data before encrypting the response to
    // free heap — the plaintext_json and inner_frame are no longer needed.
    drop(inner_frame);
    drop(plaintext_json);

    let free_after_drop = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
    log::info!("After dropping request buffers: free heap {} bytes", free_after_drop);

    // Re-encrypt the response and send as a 0x11 frame.
    let nonce = random_nonce_32();
    log::info!("Encrypting {} byte response...", response_json.len());
    match nip44::encrypt(&conversation_key, &response_json, &nonce) {
        Ok(ciphertext_b64) => {
            log::info!("Encrypted: {} bytes base64", ciphertext_b64.len());
            // Drop the plaintext response now that we have the ciphertext.
            drop(response_json);
            // Response payload: [client_pubkey_32][ciphertext_b64...]
            let mut response_payload =
                Vec::with_capacity(32 + ciphertext_b64.len());
            response_payload.extend_from_slice(&client_pubkey);
            response_payload.extend_from_slice(ciphertext_b64.as_bytes());
            log::info!("Writing {} byte encrypted response frame", response_payload.len());
            protocol::write_frame(usb, FRAME_TYPE_ENCRYPTED_RESPONSE, &response_payload);
            log::info!("Encrypted response frame sent");
        }
        Err(e) => {
            log::error!("NIP-44 encrypt response failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}

/// Fill a 32-byte buffer with cryptographically random bytes from the ESP-IDF
/// hardware RNG. Used as the NIP-44 per-message nonce.
fn random_nonce_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            nonce.as_mut_ptr() as *mut core::ffi::c_void,
            32,
        );
    }
    nonce
}

/// Kind number for NIP-46 envelope events. Hardcoded here (not read from
/// the frame) so the host cannot coerce the device into signing a kind other
/// than an NIP-46 envelope via this frame type. Arbitrary event signing
/// still goes through the NIP-46 sign_event path with button approval.
const NIP46_ENVELOPE_KIND: u64 = 24133;

/// Handle a SIGN_ENVELOPE frame (0x34).
///
/// Builds a NIP-46 kind:24133 envelope event on-device, signs it with the
/// matching master's secret, and returns the fully serialised signed event.
/// The host provides the target master pubkey as a lookup hint, the client
/// pubkey to p-tag, the `created_at` timestamp, and the NIP-44 ciphertext
/// that should go in the event content.
///
/// Security notes:
/// - The host provides ONLY the lookup key, the p-tag target, the timestamp,
///   and the content ciphertext. The device builds the rest of the event
///   structure itself: kind is hardcoded to 24133, the author pubkey is
///   recomputed from the master's actual secret (not taken from the frame),
///   and tags contain exactly one `p` tag with the client pubkey. A malicious
///   bridge cannot ask the device to sign an arbitrary event via this path.
/// - No button approval is required. NIP-46 envelope events are signed many
///   times per user operation (once per response) and button-gating each
///   would make the user experience unusable. Security for user-visible
///   event signing remains with the NIP-46 sign_event method, which IS
///   button-gated and operates on the inner NIP-46 `sign_event` request.
/// - The frame is accepted only when `bridge_authenticated` is true (the
///   caller in main.rs enforces this, same as ENCRYPTED_REQUEST).
///
/// Payload layout:
///   [master_pubkey_32][client_pubkey_32][created_at_u64_be_8][ciphertext_bytes...]
///
/// The ciphertext is copied into the event content as a UTF-8 string (it is
/// base64-encoded NIP-44 v2 payload emitted by `handle_encrypted_request`'s
/// re-encryption step or an equivalent bridge-side encryption, so it is
/// already ASCII).
pub fn handle_sign_envelope(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    masters: &[LoadedMaster],
    secp: &Arc<Secp256k1<SignOnly>>,
) {
    // 32 (master pub) + 32 (client pub) + 8 (created_at) = 72 minimum header
    if frame.payload.len() < 72 {
        log::warn!("SIGN_ENVELOPE payload too short ({} bytes, need >= 72)", frame.payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let master_pubkey: [u8; 32] = frame.payload[..32].try_into().unwrap();
    let client_pubkey: [u8; 32] = frame.payload[32..64].try_into().unwrap();
    let created_at = u64::from_be_bytes(frame.payload[64..72].try_into().unwrap());
    let ciphertext_bytes = &frame.payload[72..];

    let master_idx = match crate::masters::find_by_pubkey(masters, &master_pubkey) {
        Some(idx) => idx,
        None => {
            log::warn!("SIGN_ENVELOPE for unknown master pubkey");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };
    let master = &masters[master_idx];

    let ciphertext_str = match std::str::from_utf8(ciphertext_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            log::error!("SIGN_ENVELOPE ciphertext is not valid UTF-8");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    // Recompute the author pubkey from the master secret directly. We do NOT
    // trust the `master_pubkey` bytes from the frame for this; they were only
    // used as a lookup hint above. This prevents a malicious host from
    // passing a lookup-matching pubkey and then having the device emit an
    // event whose `pubkey` field differs.
    let keypair = match secp256k1::Keypair::from_seckey_slice(secp, &master.secret) {
        Ok(kp) => kp,
        Err(_) => {
            log::error!("SIGN_ENVELOPE: invalid master secret in slot");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };
    let (xonly, _) = keypair.x_only_public_key();
    let author_pubkey_hex = hex_encode(&xonly.serialize());

    let client_pubkey_hex = hex_encode(&client_pubkey);

    let unsigned = UnsignedEvent {
        pubkey: author_pubkey_hex,
        created_at,
        kind: NIP46_ENVELOPE_KIND,
        tags: vec![vec!["p".to_string(), client_pubkey_hex]],
        content: ciphertext_str,
    };

    let event_id_bytes = nip46::compute_event_id(&unsigned);
    let sig_bytes = match crate::sign::sign_hash(secp, &master.secret, &event_id_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("SIGN_ENVELOPE: sign_hash failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    let signed = SignedEvent {
        id: hex_encode(&event_id_bytes),
        pubkey: unsigned.pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
        sig: hex_encode(&sig_bytes),
    };

    let event_json = match serde_json::to_string(&signed) {
        Ok(s) => s,
        Err(e) => {
            log::error!("SIGN_ENVELOPE: JSON serialise failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    log::info!("SIGN_ENVELOPE: built and signed {} byte event", event_json.len());
    protocol::write_frame(usb, FRAME_TYPE_SIGN_ENVELOPE_RESPONSE, event_json.as_bytes());
}
