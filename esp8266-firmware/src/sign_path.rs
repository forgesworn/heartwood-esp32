//! The inline `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35) path.
//!
//! Mirrors the ESP32 firmware's `transport.rs` / `nip46_handler.rs`: NIP-44
//! decrypt → NIP-46 dispatch → re-encrypt → build & sign the kind:24133 envelope,
//! all on-device, reusing `heartwood-common`. The daemon never sees plaintext or
//! key material.
//!
//! Multi-identity (nsec-tree): the kind:24133 **envelope** is ALWAYS authored by
//! the master — it is the device's relay/bunker identity, what the bridge
//! subscribes `#p=` to. Only the **inner** `sign_event` (its author + signature)
//! and `get_public_key` resolve to the *active identity*: an explicit per-request
//! `heartwood` context wins, else the client's switched-to persona (session
//! state), else the master account. Personas derive via the canonical
//! `nostr:persona:<name>` namespace in `heartwood_common::derive`, byte-for-byte
//! identical to signet, the CLI, and the WiFi firmware.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

use heartwood_common::nip44;
use heartwood_common::nip46::{self, Nip46Request, SignedEvent, UnsignedEvent};
use heartwood_common::validate::validate_persona_name;

use crate::crypto;
use crate::identity::{self, IdentityCache, Sessions};

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
pub fn handle(
    seed: &[u8; 32],
    mode: u8,
    payload: &[u8],
    cache: &mut IdentityCache,
    sessions: &mut Sessions,
    oled: &mut crate::oled::Oled,
) -> Option<String> {
    if payload.len() < 72 {
        return None;
    }
    let client_pk: [u8; 32] = payload[32..64].try_into().ok()?;
    let created_at = u64::from_be_bytes(payload[64..72].try_into().ok()?);
    let ciphertext_b64 = core::str::from_utf8(&payload[72..]).ok()?;

    // 1. Conversation key (ECDH + HKDF) and decrypt the NIP-46 request. The
    //    transport — both the NIP-44 conversation and the kind:24133 envelope
    //    below — is ALWAYS the master identity (the device's relay/bunker key).
    let ck = nip44::get_conversation_key(seed, &client_pk).ok()?;
    let request_json = nip44::decrypt(&ck, ciphertext_b64).ok()?;

    let master_pubkey = crypto::pubkey(seed)?;
    let master_pubkey_hex = hex_lower(&master_pubkey);

    // 2. Dispatch the NIP-46 method → response JSON (may resolve a persona).
    let response_json = dispatch(
        &request_json,
        seed,
        mode,
        &master_pubkey,
        &master_pubkey_hex,
        &client_pk,
        cache,
        sessions,
        oled,
    )?;

    // 3. Re-encrypt the response under the same conversation key, with a
    //    synthetic (deterministic) nonce — no reliance on the hardware RNG.
    let nonce = nip44::synthetic_nonce(seed, &client_pk, &response_json);
    let response_ct = nip44::encrypt(&ck, &response_json, &nonce).ok()?;

    // 4. Build & sign the kind:24133 envelope (author = master, p-tag = client).
    let unsigned = UnsignedEvent {
        pubkey: master_pubkey_hex,
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

/// Resolve the active identity for the request, then route the NIP-46 method.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn dispatch(
    request_json: &str,
    seed: &[u8; 32],
    mode: u8,
    master_pk: &[u8; 32],
    master_pubkey_hex: &str,
    client_pk: &[u8; 32],
    cache: &mut IdentityCache,
    sessions: &mut Sessions,
    oled: &mut crate::oled::Oled,
) -> Option<String> {
    let req = nip46::parse_request(request_json.as_bytes()).ok()?;

    // Active identity: an explicit per-request heartwood context wins; else the
    // client's switched-to identity (session); else None (= the master account).
    let ctx: Option<(String, u32)> = if let Some(h) = &req.heartwood {
        Some((h.purpose.clone(), h.index))
    } else if let Some(idx) = sessions.active(client_pk) {
        cache.get(idx).map(|c| (c.purpose.clone(), c.index))
    } else {
        None
    };

    match req.method.as_str() {
        "get_public_key" => get_public_key(&req, seed, mode, master_pubkey_hex, &ctx),
        "connect" => nip46::build_connect_response(&req.id).ok(),
        "ping" => nip46::build_ping_response(&req.id).ok(),
        "sign_event" => sign_event(&req, seed, mode, master_pubkey_hex, &ctx, oled),
        "nip44_encrypt" => nip44_encrypt(&req, seed, mode, &ctx),
        "nip44_decrypt" => nip44_decrypt(&req, seed, mode, &ctx),
        "heartwood_derive_persona" => derive_persona(&req, seed, mode, cache),
        "heartwood_derive" => derive_purpose(&req, seed, mode, cache),
        "heartwood_switch" => switch(&req, master_pk, cache, sessions, client_pk),
        "heartwood_list_identities" => {
            nip46::build_result_response(&req.id, &cache.list_json()).ok()
        }
        _ => nip46::build_error_response(&req.id, -32601, "method not supported").ok(),
    }
}

/// `get_public_key` → the resolved identity's x-only pubkey (master or persona).
#[inline(never)]
fn get_public_key(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    master_pubkey_hex: &str,
    ctx: &Option<(String, u32)>,
) -> Option<String> {
    let pk_hex = match ctx {
        None => master_pubkey_hex.to_string(),
        Some((purpose, index)) => {
            let (pk, _, _) = identity::derive_pubkey_meta(seed, mode, purpose, *index)?;
            hex_lower(&pk)
        }
    };
    nip46::build_pubkey_response(&req.id, &pk_hex).ok()
}

/// `sign_event` — shows the request on the OLED, requires a physical button hold,
/// then signs the INNER event as the resolved identity (master or persona).
#[inline(never)]
fn sign_event(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    master_pubkey_hex: &str,
    ctx: &Option<(String, u32)>,
    oled: &mut crate::oled::Oled,
) -> Option<String> {
    let mut ev = match nip46::parse_unsigned_event(&req.params) {
        Ok(ev) => ev,
        Err(e) => return nip46::build_error_response(&req.id, -32602, &e).ok(),
    };

    // Physical-approval gate: the daemon can deliver a sign request but cannot
    // approve it — show what is being signed and require an on-device button hold.
    oled.show_sign_prompt(ev.kind, &ev.content);
    if !crate::button::await_approval() {
        oled.show_status("denied");
        return nip46::build_error_response(&req.id, -32000, "denied at device").ok();
    }

    // Materialise the signing secret only after approval.
    let (secret, pubkey_hex) = match ctx {
        None => (*seed, master_pubkey_hex.to_string()),
        Some((purpose, index)) => {
            let (sk, pk) = identity::derive_signing(seed, mode, purpose, *index)?;
            (sk, hex_lower(&pk))
        }
    };

    ev.pubkey = pubkey_hex;
    let id = nip46::compute_event_id(&ev);
    let sig = crypto::sign(&secret, &id)?;
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
    nip46::build_sign_response(&req.id, &signed).ok()
}

/// Resolve `(signing secret, peer x-only pubkey)` for a NIP-44 encrypt/decrypt.
/// The secret is the *active* identity's (master, or the switched-to / explicit
/// persona) — exactly like `sign_event` — so a DM uses whichever identity the
/// client is acting as. `params[0]` is the 64-hex peer pubkey.
fn resolve_secret_and_peer(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    ctx: &Option<(String, u32)>,
) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let peer_hex = req
        .params
        .first()
        .and_then(|v| v.as_str())
        .ok_or("requires [peer_pubkey, payload]")?;
    let peer_bytes =
        heartwood_common::hex::hex_decode(peer_hex).map_err(|_| "peer pubkey must be hex")?;
    if peer_bytes.len() != 32 {
        return Err("peer pubkey must be 32 bytes");
    }
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&peer_bytes);

    let secret = match ctx {
        None => *seed,
        Some((purpose, index)) => {
            identity::derive_signing(seed, mode, purpose, *index).ok_or("derivation failed")?.0
        }
    };
    Ok((secret, peer))
}

/// `nip44_encrypt` — `[peer_pubkey, plaintext]` → NIP-44 ciphertext to the peer,
/// under the active identity. The per-message nonce is the deterministic
/// `synthetic_nonce` (no hardware RNG), so encrypting the same plaintext to the
/// same peer is repeatable — the documented trade-off for a radio-off signer.
#[inline(never)]
fn nip44_encrypt(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    ctx: &Option<(String, u32)>,
) -> Option<String> {
    let (secret, peer) = match resolve_secret_and_peer(req, seed, mode, ctx) {
        Ok(v) => v,
        Err(e) => return nip46::build_error_response(&req.id, -3, e).ok(),
    };
    let plaintext = match req.params.get(1).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return nip46::build_error_response(&req.id, -3, "requires [peer_pubkey, plaintext]").ok(),
    };
    let ck = match nip44::get_conversation_key(&secret, &peer) {
        Ok(k) => k,
        Err(_) => return nip46::build_error_response(&req.id, -4, "conversation key failed").ok(),
    };
    let nonce = nip44::synthetic_nonce(&secret, &peer, plaintext);
    match nip44::encrypt(&ck, plaintext, &nonce) {
        Ok(ct) => nip46::build_result_response(&req.id, &ct).ok(),
        Err(_) => nip46::build_error_response(&req.id, -4, "encryption failed").ok(),
    }
}

/// `nip44_decrypt` — `[peer_pubkey, ciphertext]` → plaintext, under the active
/// identity. No nonce needed (it travels in the NIP-44 payload).
#[inline(never)]
fn nip44_decrypt(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    ctx: &Option<(String, u32)>,
) -> Option<String> {
    let (secret, peer) = match resolve_secret_and_peer(req, seed, mode, ctx) {
        Ok(v) => v,
        Err(e) => return nip46::build_error_response(&req.id, -3, e).ok(),
    };
    let ciphertext = match req.params.get(1).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return nip46::build_error_response(&req.id, -3, "requires [peer_pubkey, ciphertext]").ok(),
    };
    let ck = match nip44::get_conversation_key(&secret, &peer) {
        Ok(k) => k,
        Err(_) => return nip46::build_error_response(&req.id, -4, "conversation key failed").ok(),
    };
    match nip44::decrypt(&ck, ciphertext) {
        Ok(pt) => nip46::build_result_response(&req.id, &pt).ok(),
        Err(_) => nip46::build_error_response(&req.id, -4, "decryption failed").ok(),
    }
}

/// `heartwood_derive_persona` — derive (and cache) the child at the reserved
/// `nostr:persona:<name>` purpose. Returns `{npub, purpose, index, personaName}`.
#[inline(never)]
fn derive_persona(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    cache: &mut IdentityCache,
) -> Option<String> {
    let name = match req.params.first().and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return nip46::build_error_response(&req.id, -3, "requires [name, index?]").ok(),
    };
    if let Err(e) = validate_persona_name(name) {
        return nip46::build_error_response(&req.id, -3, e).ok();
    }
    let index = req.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let purpose = format!("nostr:persona:{name}");
    let idx = match cache.derive_and_cache(seed, mode, &purpose, index, Some(name.to_string())) {
        Ok(i) => i,
        Err(e) => return nip46::build_error_response(&req.id, -4, e).ok(),
    };
    let c = cache.get(idx)?;
    let result = serde_json::json!({
        "npub": c.npub,
        "purpose": c.purpose,
        "index": c.index,
        "personaName": name,
    });
    nip46::build_result_response(&req.id, &result.to_string()).ok()
}

/// `heartwood_derive` — derive (and cache) the child at an arbitrary purpose.
/// Returns `{npub, purpose, index}`.
#[inline(never)]
fn derive_purpose(
    req: &Nip46Request,
    seed: &[u8; 32],
    mode: u8,
    cache: &mut IdentityCache,
) -> Option<String> {
    let purpose = match req.params.first().and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return nip46::build_error_response(&req.id, -3, "requires [purpose, index?]").ok(),
    };
    let index = req.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let idx = match cache.derive_and_cache(seed, mode, purpose, index, None) {
        Ok(i) => i,
        Err(e) => return nip46::build_error_response(&req.id, -4, e).ok(),
    };
    let c = cache.get(idx)?;
    let result = serde_json::json!({
        "npub": c.npub,
        "purpose": c.purpose,
        "index": c.index,
    });
    nip46::build_result_response(&req.id, &result.to_string()).ok()
}

/// `heartwood_switch` — set the client's active identity (it must already be in
/// the cache). `"master"` clears it back to the account key.
#[inline(never)]
fn switch(
    req: &Nip46Request,
    master_pk: &[u8; 32],
    cache: &IdentityCache,
    sessions: &mut Sessions,
    client_pk: &[u8; 32],
) -> Option<String> {
    let target = match req.params.first().and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            return nip46::build_error_response(&req.id, -3, "requires [target, index_hint?]").ok()
        }
    };

    if target == "master" {
        sessions.set(client_pk, None);
        let npub = heartwood_common::encoding::encode_npub(master_pk);
        let result = serde_json::json!({ "npub": npub, "purpose": "master", "index": 0 });
        return nip46::build_result_response(&req.id, &result.to_string()).ok();
    }

    let index_hint = req.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let found = cache
        .find_by_npub(target)
        .or_else(|| cache.find_by_persona(target))
        .or_else(|| cache.find(target, index_hint));
    match found {
        Some(idx) => {
            sessions.set(client_pk, Some(idx));
            let c = cache.get(idx)?;
            let mut result = serde_json::json!({
                "npub": c.npub,
                "purpose": c.purpose,
                "index": c.index,
            });
            if let Some(name) = &c.persona_name {
                result["personaName"] = serde_json::json!(name);
            }
            nip46::build_result_response(&req.id, &result.to_string()).ok()
        }
        None => nip46::build_error_response(&req.id, -4, "identity not found in cache").ok(),
    }
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
