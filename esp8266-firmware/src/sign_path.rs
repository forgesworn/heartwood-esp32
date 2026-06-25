//! The inline `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35) path.
//!
//! Mirrors the ESP32 firmware's `transport.rs`: NIP-44 decrypt → NIP-46 dispatch
//! → re-encrypt → build & sign the kind:24133 envelope, all on-device, reusing
//! `heartwood-common` for the NIP-44 + NIP-46 crypto. The daemon never sees
//! plaintext or key material.

use alloc::string::{String, ToString};
use alloc::vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
pub fn handle(seed: &[u8; 32], payload: &[u8], oled: &mut crate::oled::Oled) -> Option<String> {
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
    let response_json = dispatch(&request_json, seed, &our_pubkey_hex, oled)?;

    // 3. Re-encrypt the response under the same conversation key, with a
    //    synthetic (deterministic) nonce — no reliance on the hardware RNG.
    let nonce = synthetic_nonce(seed, &client_pk, &response_json);
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
/// `sign_event` shows the request on the OLED and requires a physical button hold
/// (`button::await_approval`) before signing; a richer policy engine is still to come.
fn dispatch(
    request_json: &str,
    seed: &[u8; 32],
    our_pubkey_hex: &str,
    oled: &mut crate::oled::Oled,
) -> Option<String> {
    let req = nip46::parse_request(request_json.as_bytes()).ok()?;
    let resp = match req.method.as_str() {
        "get_public_key" => nip46::build_pubkey_response(&req.id, our_pubkey_hex),
        "connect" => nip46::build_connect_response(&req.id),
        "ping" => nip46::build_ping_response(&req.id),
        "sign_event" => match nip46::parse_unsigned_event(&req.params) {
            Ok(mut ev) => {
                // Physical-approval gate: the daemon can deliver a sign request
                // but cannot approve it — show what's being signed and require an
                // on-device button hold.
                oled.show_sign_prompt(ev.kind, &ev.content);
                if !crate::button::await_approval() {
                    oled.show_status("denied");
                    nip46::build_error_response(&req.id, -32000, "denied at device")
                } else {
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
                            oled.show_status("signed");
                            nip46::build_sign_response(&req.id, &signed)
                        }
                        None => nip46::build_error_response(&req.id, -32603, "sign failed"),
                    }
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

/// A deterministic 32-byte NIP-44 nonce, derived from the master secret instead
/// of the hardware RNG.
///
/// The ESP8266's `WDEV_RAND` register (0x3FF20E44) is only well-seeded when the
/// RF/Wi-Fi hardware is active; a USB-tethered (radio-off) signer cannot rely on
/// it, and a repeated NIP-44 nonce is catastrophic. So we synthesise the nonce as
/// `HMAC-SHA256(seed; tag || client_pk || plaintext)`:
/// - keyed by the secret seed → unpredictable to anyone without the key;
/// - bound to the conversation (`client_pk`) and the message (`plaintext`) → a
///   fresh nonce whenever either differs. An identical (peer, plaintext) re-encrypts
///   to the same ciphertext, which leaks nothing new (it is the same plaintext).
///
/// Signing needs no RNG either — see `crypto::sign` (`aux_rand = 0`). So no part
/// of the security-critical path depends on the unreliable hardware RNG.
fn synthetic_nonce(seed: &[u8; 32], client_pk: &[u8; 32], plaintext: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(b"heartwood-nip44-nonce-v1");
    mac.update(client_pk);
    mac.update(plaintext.as_bytes());
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&mac.finalize().into_bytes());
    nonce
}
