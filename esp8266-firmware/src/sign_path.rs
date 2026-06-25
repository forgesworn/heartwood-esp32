//! The inline `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35) path.
//!
//! Mirrors the ESP32 firmware's `transport.rs`: NIP-44 decrypt → NIP-46 dispatch
//! → re-encrypt → build & sign the kind:24133 envelope, all on-device, reusing
//! `heartwood-common` for the NIP-44 + NIP-46 crypto. The daemon never sees
//! plaintext or key material.

use alloc::string::{String, ToString};
use alloc::vec;

use heartwood_common::nip44;
use heartwood_common::nip46::{self, SignedEvent, UnsignedEvent};

use crate::crypto;

const NIP46_KIND: u64 = 24133;

/// Handle a `0x10` payload
/// `[master_pk 32][client_pk 32][created_at u64-be 8][nip44_ciphertext_b64]`.
/// Returns the fully-signed kind:24133 event JSON (the `0x35` body), or `None`
/// to NACK (decrypt failure, bad request, sign failure).
///
/// `#[inline(never)]`: keep this large body out of the frame dispatcher — the
/// lx106 LLVM backend fails register allocation ("Cannot scavenge register") on
/// over-large merged functions when everything is inlined under LTO.
#[inline(never)]
pub fn handle(seed: &[u8; 32], payload: &[u8]) -> Option<String> {
    if payload.len() < 72 {
        return None;
    }
    let client_pk: [u8; 32] = payload[32..64].try_into().ok()?;
    let created_at = u64::from_be_bytes(payload[64..72].try_into().ok()?);
    let ciphertext_b64 = core::str::from_utf8(&payload[72..]).ok()?;

    // 1. Conversation key (ECDH + HKDF) and decrypt the NIP-46 request.
    let ck = nip44::get_conversation_key(seed, &client_pk).ok()?;
    let request_json = nip44::decrypt(&ck, ciphertext_b64).ok()?;

    // 2. Dispatch the NIP-46 method → response JSON.
    let our_pubkey = crypto::pubkey(seed)?;
    let our_pubkey_hex = hex_lower(&our_pubkey);
    let response_json = dispatch(&request_json, seed, &our_pubkey_hex)?;

    // 3. Re-encrypt the response under the same conversation key.
    let nonce = random_nonce();
    let response_ct = nip44::encrypt(&ck, &response_json, &nonce).ok()?;

    // 4. Build & sign the kind:24133 envelope (author = us, p-tag = the client).
    let unsigned = UnsignedEvent {
        pubkey: our_pubkey_hex.clone(),
        created_at,
        kind: NIP46_KIND,
        tags: vec![vec!["p".to_string(), hex_lower(&client_pk)]],
        content: response_ct,
    };
    let id = nip46::compute_event_id(&unsigned);
    let sig = crypto::sign(seed, &id)?;
    let signed = SignedEvent {
        id: hex_lower(&id),
        pubkey: unsigned.pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
        sig: hex_lower(&sig),
    };
    serde_json::to_string(&signed).ok()
}

/// Minimal NIP-46 dispatch: `get_public_key`, `sign_event`, `connect`, `ping`.
/// No policy engine or button approvals yet (auto-approve) — those arrive with
/// the OLED/button tier.
fn dispatch(request_json: &str, seed: &[u8; 32], our_pubkey_hex: &str) -> Option<String> {
    let req = nip46::parse_request(request_json.as_bytes()).ok()?;
    let resp = match req.method.as_str() {
        "get_public_key" => nip46::build_pubkey_response(&req.id, our_pubkey_hex),
        "connect" => nip46::build_connect_response(&req.id),
        "ping" => nip46::build_ping_response(&req.id),
        "sign_event" => match nip46::parse_unsigned_event(&req.params) {
            Ok(mut ev) => {
                ev.pubkey = our_pubkey_hex.to_string();
                let id = nip46::compute_event_id(&ev);
                match crypto::sign(seed, &id) {
                    Some(sig) => {
                        let signed = SignedEvent {
                            id: hex_lower(&id),
                            pubkey: ev.pubkey,
                            created_at: ev.created_at,
                            kind: ev.kind,
                            tags: ev.tags,
                            content: ev.content,
                            sig: hex_lower(&sig),
                        };
                        nip46::build_sign_response(&req.id, &signed)
                    }
                    None => nip46::build_error_response(&req.id, -32603, "sign failed"),
                }
            }
            Err(e) => nip46::build_error_response(&req.id, -32602, &e),
        },
        _ => nip46::build_error_response(&req.id, -32601, "method not supported"),
    };
    resp.ok()
}

/// Lowercase hex.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// 32 random bytes for the NIP-44 per-message nonce, from the ESP8266 hardware
/// RNG register (`WDEV_RAND`, 0x3FF20E44).
///
/// KNOWN GAP: like the ESP32, this RNG is only well-seeded when the RF/Wi-Fi
/// hardware is active. A USB-tethered (radio-off) signer needs an entropy
/// review before production — nonce reuse would be catastrophic for NIP-44.
fn random_nonce() -> [u8; 32] {
    const RNG_REG: *const u32 = 0x3FF2_0E44 as *const u32;
    let mut nonce = [0u8; 32];
    for chunk in nonce.chunks_mut(4) {
        let r = unsafe { core::ptr::read_volatile(RNG_REG) };
        chunk.copy_from_slice(&r.to_le_bytes());
    }
    nonce
}
