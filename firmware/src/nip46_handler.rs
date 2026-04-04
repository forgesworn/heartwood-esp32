// firmware/src/nip46_handler.rs
//
// NIP-46 request dispatcher for the Heartwood HSM.
//
// Handles the following methods:
//   sign_event      — shows event on OLED, waits for button approval, signs
//   get_public_key  — returns the hex public key immediately (no approval needed)
//   connect         — returns ACK to complete the handshake
//   ping            — returns pong
//   nip44_encrypt / nip44_decrypt / nip04_encrypt / nip04_decrypt — delegated to NIP-44/NIP-04 helpers
//   heartwood_derive / heartwood_derive_persona / heartwood_switch — tree-mode key derivation
//   heartwood_list_identities / heartwood_recover               — identity cache management
//   heartwood_create_proof / heartwood_verify_proof              — stubs (not yet implemented)
//
// Return convention:
//   Every method returns a JSON response string. The caller is responsible for
//   framing and sending it — plaintext 0x03 or encrypted 0x11 as appropriate.
//   sign_event now runs the interactive approval loop and returns a JSON string
//   for all outcomes (approved, denied, timed out) rather than writing directly.

use std::sync::Arc;

use esp_idf_hal::gpio::{Input, PinDriver};

use heartwood_common::derive;
use heartwood_common::frame::Frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip04;
use heartwood_common::nip44;
use heartwood_common::nip46::{
    self, HeartwoodContext, SignedEvent, UnsignedEvent,
};
use heartwood_common::types::MasterMode;
use secp256k1::{Secp256k1, SignOnly};
use zeroize::Zeroize;

use crate::approval::ApprovalResult;
use crate::oled::Display;
use crate::policy::PolicyEngine;

/// Timeout in seconds shown on the OLED countdown bar.
const APPROVAL_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Dispatch a NIP-46 request frame.
///
/// Returns a JSON response string for all methods. The caller is responsible
/// for framing and sending it — as a plaintext 0x03 frame or encrypted 0x11
/// frame depending on the transport. sign_event runs the interactive approval
/// loop and returns a JSON string for all outcomes (approved, denied, timed out).
pub fn handle_request(
    frame: &Frame,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    connect_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
) -> String {
    let request = match nip46::parse_request(&frame.payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse NIP-46 request: {e}");
            return nip46::build_error_response("unknown", -3, "invalid JSON-RPC request")
                .unwrap_or_default();
        }
    };

    log::info!(
        "NIP-46 request: method={} id={} master_slot={}",
        request.method,
        request.id,
        master_slot,
    );

    let method = nip46::Nip46Method::from_str(&request.method);
    let event_kind = if matches!(method, nip46::Nip46Method::SignEvent) {
        nip46::parse_unsigned_event(&request.params).ok().map(|e| e.kind)
    } else {
        None
    };

    // Determine the client pubkey for policy lookups.
    // In encrypted mode (passthrough), it comes from the frame header.
    // In legacy mode, the bridge injects `_client_pubkey` into the JSON.
    let client_hex = if let Some(pk) = client_pubkey {
        heartwood_common::hex::hex_encode(pk)
    } else {
        // Legacy mode — bridge injects the relay event author as _client_pubkey.
        serde_json::from_slice::<serde_json::Value>(&frame.payload)
            .ok()
            .and_then(|v| v["_client_pubkey"].as_str().map(|s| s.to_string()))
            .unwrap_or_default()
    };
    let has_client = !client_hex.is_empty() && client_hex.len() == 64;
    let tier = if has_client {
        policy_engine.check(master_slot, &client_hex, &method, event_kind)
    } else {
        heartwood_common::policy::ApprovalTier::ButtonRequired
    };

    match request.method.as_str() {
        "sign_event" => {
            match tier {
                heartwood_common::policy::ApprovalTier::AutoApprove => {
                    log::info!("sign_event: auto-approved by policy");
                    match handle_auto_sign(master_secret, secp, &request) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::OledNotify => {
                    crate::oled::show_auto_approved(display, master_label, "sign_event");
                    esp_idf_hal::delay::FreeRtos::delay_ms(1000);
                    match handle_auto_sign(master_secret, secp, &request) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::ButtonRequired => {
                    let result = handle_sign_event(master_secret, secp, display, button_pin, &request);
                    // TOFU: if approved and we have a client pubkey, remember this client.
                    // Use has_client (populated from _client_pubkey JSON in legacy mode)
                    // rather than client_pubkey.is_some() (only set in passthrough mode).
                    if has_client && !result.contains("\"error\"") {
                        tofu_approve(policy_engine, master_slot, &client_hex);
                    }
                    result
                }
            }
        }

        "get_public_key" => handle_get_public_key(master_secret, secp, &request),

        "connect" => {
            // params[0] is the client pubkey; params[1] is the optional secret.
            // Register the client in a session so TOFU works for subsequent requests.
            if has_client {
                if let Ok(pk_bytes) = hex_decode_32_safe(&client_hex) {
                    policy_engine.get_or_create_session(pk_bytes, master_slot);
                }
            }

            let client_secret = request.params.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let stored_secret_hex = hex_encode(connect_secret);
            if client_secret.is_empty() {
                // No secret provided — accept but don't TOFU-approve.
                nip46::build_connect_response(&request.id).unwrap_or_default()
            } else if constant_time_eq(client_secret.as_bytes(), stored_secret_hex.as_bytes()) {
                // Secret matches — client proved it has the bunker URI.
                // TOFU: auto-approve this client for all safe methods so
                // sign_event works immediately without button approval.
                // Policy persistence happens in the main loop after we return.
                if has_client {
                    tofu_approve(policy_engine, master_slot, &client_hex);
                    log::info!("TOFU: approved client on connect (secret verified)");
                }
                nip46::build_connect_response_with_secret(&request.id, &stored_secret_hex).unwrap_or_default()
            } else {
                log::warn!("connect rejected — incorrect secret (master_slot={})", master_slot);
                build_error_json(&request.id, -1, "unauthorised")
            }
        }

        "ping" => nip46::build_ping_response(&request.id).unwrap_or_default(),

        "nip44_encrypt" => handle_nip44_encrypt(master_secret, &request),

        "nip44_decrypt" => handle_nip44_decrypt(master_secret, &request),

        "nip04_encrypt" => handle_nip04_encrypt(master_secret, &request),

        "nip04_decrypt" => handle_nip04_decrypt(master_secret, &request),

        "heartwood_derive" => {
            if !master_mode.is_tree() {
                return build_error_json(&request.id, -5, "not available in bunker mode");
            }
            let purpose = match request.params.first().and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return build_error_json(&request.id, -3, "requires [purpose, index?]"),
            };
            let index = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            let cache = match identity_caches.iter_mut().find(|c| c.master_slot == master_slot) {
                Some(c) => c,
                None => return build_error_json(&request.id, -4, "no identity cache for this master"),
            };

            match cache.derive_and_cache(master_secret, purpose, index, None) {
                Ok(idx) => {
                    let id = &cache.identities[idx];
                    let result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                    });
                    nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default()
                }
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_derive_persona" => {
            if !master_mode.is_tree() {
                return build_error_json(&request.id, -5, "not available in bunker mode");
            }
            let name = match request.params.first().and_then(|v| v.as_str()) {
                Some(n) => n,
                None => return build_error_json(&request.id, -3, "requires [name, index?]"),
            };
            let index = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let purpose = format!("persona/{name}");

            let cache = match identity_caches.iter_mut().find(|c| c.master_slot == master_slot) {
                Some(c) => c,
                None => return build_error_json(&request.id, -4, "no identity cache for this master"),
            };

            match cache.derive_and_cache(master_secret, &purpose, index, Some(name.to_string())) {
                Ok(idx) => {
                    let id = &cache.identities[idx];
                    let result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                        "personaName": name,
                    });
                    nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default()
                }
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_switch" => {
            if !master_mode.is_tree() {
                return build_error_json(&request.id, -5, "not available in bunker mode");
            }
            let target = match request.params.first().and_then(|v| v.as_str()) {
                Some(t) => t,
                None => return build_error_json(&request.id, -3, "requires [target, index_hint?]"),
            };

            // "master" resets to the master identity — return its npub.
            if target == "master" {
                use heartwood_common::encoding::encode_npub;
                let pubkey_result = secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                    .map(|kp| {
                        let (xonly, _) = kp.x_only_public_key();
                        encode_npub(&xonly.serialize())
                    })
                    .map_err(|_| "invalid master secret".to_string());
                return match pubkey_result {
                    Ok(npub) => {
                        let result = serde_json::json!({ "npub": npub, "purpose": "master", "index": 0 });
                        nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default()
                    }
                    Err(e) => build_error_json(&request.id, -4, &e),
                };
            }

            let cache = match identity_caches.iter_mut().find(|c| c.master_slot == master_slot) {
                Some(c) => c,
                None => return build_error_json(&request.id, -4, "no identity cache for this master"),
            };

            // Search by npub, then persona name, then purpose+index.
            let index_hint = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let found = cache
                .find_by_npub(target)
                .or_else(|| cache.find_by_persona(target))
                .or_else(|| cache.find(target, index_hint));

            match found {
                Some(idx) => {
                    let id = &cache.identities[idx];
                    let mut result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                    });
                    if let Some(name) = &id.persona_name {
                        result["personaName"] = serde_json::json!(name);
                    }
                    nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default()
                }
                None => build_error_json(&request.id, -4, "identity not found in cache"),
            }
        }

        "heartwood_list_identities" => {
            if !master_mode.is_tree() {
                // Bunker mode — no derived identities, return empty array.
                return nip46::build_result_response(&request.id, "[]").unwrap_or_default();
            }

            let cache = match identity_caches.iter().find(|c| c.master_slot == master_slot) {
                Some(c) => c,
                None => return build_error_json(&request.id, -4, "no identity cache for this master"),
            };

            nip46::build_result_response(&request.id, &cache.list_json()).unwrap_or_default()
        }

        "heartwood_recover" => {
            if !master_mode.is_tree() {
                return build_error_json(&request.id, -5, "not available in bunker mode");
            }
            let lookahead = request.params.first().and_then(|v| v.as_u64()).unwrap_or(20) as u32;

            let cache = match identity_caches.iter_mut().find(|c| c.master_slot == master_slot) {
                Some(c) => c,
                None => return build_error_json(&request.id, -4, "no identity cache for this master"),
            };

            match cache.recover(master_secret, lookahead) {
                Ok(count) => {
                    let identities_json = cache.list_json();
                    let result = format!(r#"{{"recovered":{count},"identities":{identities_json}}}"#);
                    nip46::build_result_response(&request.id, &result).unwrap_or_default()
                }
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_create_proof" => {
            // Proof generation not yet implemented.
            build_error_json(&request.id, -6, "not yet implemented")
        }

        "heartwood_verify_proof" => {
            // Proof verification not yet implemented.
            build_error_json(&request.id, -6, "not yet implemented")
        }

        other => {
            log::warn!("Unknown NIP-46 method: {other}");
            build_error_json(&request.id, -2, "unknown method")
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-sign (policy-approved, no button required)
// ---------------------------------------------------------------------------

fn handle_auto_sign(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) -> Result<String, String> {
    let event = nip46::parse_unsigned_event(&request.params)
        .map_err(|e| format!("bad event format: {e}"))?;
    let signed = do_sign(&event, master_secret, secp, request.heartwood.as_ref())?;
    nip46::build_sign_response(&request.id, &signed)
}

// ---------------------------------------------------------------------------
// TOFU approval
// ---------------------------------------------------------------------------

fn tofu_approve(policy_engine: &mut PolicyEngine, master_slot: u8, client_hex: &str) {
    use heartwood_common::policy::{ClientPolicy, TOFU_SAFE_METHODS};

    let existing = policy_engine.master_policies
        .iter()
        .any(|mp| mp.master_slot == master_slot
            && mp.policies.iter().any(|p| p.client_pubkey == client_hex));

    if existing {
        return;
    }

    let policy = ClientPolicy {
        client_pubkey: client_hex.to_string(),
        label: String::new(),
        allowed_methods: TOFU_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
        allowed_kinds: vec![],
        auto_approve: true,
    };

    policy_engine.add_tofu_policy(master_slot, policy);
    log::info!("TOFU: auto-approved client {}", &client_hex[..16.min(client_hex.len())]);
}

// ---------------------------------------------------------------------------
// sign_event (interactive, button-required)
// ---------------------------------------------------------------------------

fn handle_sign_event(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    request: &nip46::Nip46Request,
) -> String {
    let event = match nip46::parse_unsigned_event(&request.params) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("sign_event: bad event format: {e}");
            return build_error_json(&request.id, -3, "bad event format");
        }
    };

    let (kind, content_preview) = nip46::event_display_summary(&event, 50);

    let purpose = request
        .heartwood
        .as_ref()
        .map(|h| h.purpose.as_str())
        .unwrap_or("master");

    // Show the signing request on the OLED and wait for button approval.
    // The countdown bar updates every second; the approval module handles
    // "Hold 2s..." feedback while the button is held down.
    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        APPROVAL_TIMEOUT_SECS,
        |d, remaining| {
            crate::oled::show_sign_request(d, purpose, kind, &content_preview, remaining);
        },
    );

    match result {
        ApprovalResult::Approved => {
            log::info!("sign_event: approved");
            crate::oled::show_error(display, "Signing...");
            match do_sign(&event, master_secret, secp, request.heartwood.as_ref()) {
                Ok(signed) => {
                    match nip46::build_sign_response(&request.id, &signed) {
                        Ok(json) => {
                            crate::oled::show_result(display, "Signed!");
                            json
                        }
                        Err(e) => {
                            log::error!("Failed to build sign response: {e}");
                            crate::oled::show_result(display, "Sign error");
                            build_error_json(&request.id, -4, "signing failed")
                        }
                    }
                }
                Err(ref e) => {
                    log::error!("Signing failed: {e}");
                    crate::oled::show_error(display, &format!("ERR:{}", &e[..e.len().min(18)]));
                    esp_idf_hal::delay::FreeRtos::delay_ms(3000);
                    crate::oled::show_result(display, "Sign error");
                    build_error_json(&request.id, -4, "signing/derivation failure")
                }
            }
        }
        ApprovalResult::Denied => {
            log::info!("sign_event: denied by user");
            crate::oled::show_result(display, "Denied");
            build_error_json(&request.id, -1, "user denied")
        }
        ApprovalResult::TimedOut => {
            log::info!("sign_event: timed out");
            crate::oled::show_result(display, "Timed out");
            build_error_json(&request.id, -1, "timeout")
        }
    }
}

// ---------------------------------------------------------------------------
// do_sign — runs inline on the main thread
// ---------------------------------------------------------------------------

fn do_sign(
    event: &UnsignedEvent,
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    heartwood: Option<&HeartwoodContext>,
) -> Result<SignedEvent, String> {
    let event_id_bytes = nip46::compute_event_id(event);

    let (mut signing_secret, hex_pubkey) = match heartwood {
        Some(ctx) => {
            let root = derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))?;
            let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                .map_err(|e| format!("derive: {e}"))?;
            let pubkey_hex = hex_encode(&identity.public_key);
            let private_bytes = *identity.private_key;
            (private_bytes, pubkey_hex)
        }
        None => {
            let keypair = secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                .map_err(|_| "invalid master secret".to_string())?;
            let (xonly, _) = keypair.x_only_public_key();
            let pubkey_hex = hex_encode(&xonly.serialize());
            (*master_secret, pubkey_hex)
        }
    };

    let sig_bytes = crate::sign::sign_hash(secp, &signing_secret, &event_id_bytes)
        .map_err(|e| e.to_string())?;

    signing_secret.zeroize();

    let event_id_hex = hex_encode(&event_id_bytes);
    let sig_hex = hex_encode(&sig_bytes);

    Ok(SignedEvent {
        id: event_id_hex,
        pubkey: hex_pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
        sig: sig_hex,
    })
}

// ---------------------------------------------------------------------------
// get_public_key
// ---------------------------------------------------------------------------

/// Returns a NIP-46 JSON response string (or an error JSON on failure).
fn handle_get_public_key(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) -> String {
    let pubkey_result = match &request.heartwood {
        Some(ctx) => {
            derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))
                .and_then(|root| {
                    derive::derive(&root, &ctx.purpose, ctx.index)
                        .map_err(|e| format!("derive: {e}"))
                })
                .map(|identity| hex_encode(&identity.public_key))
        }
        None => {
            secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                .map(|keypair| {
                    let (xonly, _) = keypair.x_only_public_key();
                    hex_encode(&xonly.serialize())
                })
                .map_err(|_| "invalid master secret".to_string())
        }
    };

    match pubkey_result {
        Ok(hex_pubkey) => match nip46::build_pubkey_response(&request.id, &hex_pubkey) {
            Ok(json) => {
                log::info!("get_public_key: built pubkey response for {hex_pubkey}");
                json
            }
            Err(e) => {
                log::error!("Failed to build pubkey response: {e}");
                build_error_json(&request.id, -4, "failed to build response")
            }
        },
        Err(e) => {
            log::error!("get_public_key failed: {e}");
            build_error_json(&request.id, -4, "signing/derivation failure")
        }
    }
}

// ---------------------------------------------------------------------------
// nip44_encrypt
// ---------------------------------------------------------------------------

fn handle_nip44_encrypt(
    master_secret: &[u8; 32],
    request: &nip46::Nip46Request,
) -> String {
    if request.params.len() < 2 {
        return build_error_json(&request.id, -3, "nip44_encrypt requires 2 params");
    }
    let peer_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "peer pubkey param must be a string"),
    };
    let plaintext = match request.params[1].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "plaintext param must be a string"),
    };

    let signing_secret = match resolve_signing_secret(master_secret, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip44_encrypt: key derivation failed: {e}");
            return build_error_json(&request.id, -4, "key derivation failure");
        }
    };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex"),
    };

    let conv_key = match nip44::get_conversation_key(&signing_secret, &peer_bytes) {
        Ok(k) => k,
        Err(e) => {
            log::error!("nip44_encrypt: conversation key failed: {e}");
            return build_error_json(&request.id, -4, "conversation key derivation failed");
        }
    };

    let nonce = random_nonce_24();
    match nip44::encrypt(&conv_key, plaintext, &nonce) {
        Ok(ciphertext) => {
            nip46::build_result_response(&request.id, &ciphertext).unwrap_or_default()
        }
        Err(e) => {
            log::error!("nip44_encrypt: encrypt failed: {e}");
            build_error_json(&request.id, -4, "encryption failed")
        }
    }
}

// ---------------------------------------------------------------------------
// nip44_decrypt
// ---------------------------------------------------------------------------

fn handle_nip44_decrypt(
    master_secret: &[u8; 32],
    request: &nip46::Nip46Request,
) -> String {
    if request.params.len() < 2 {
        return build_error_json(&request.id, -3, "nip44_decrypt requires 2 params");
    }
    let peer_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "peer pubkey param must be a string"),
    };
    let ciphertext_b64 = match request.params[1].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "ciphertext param must be a string"),
    };

    let signing_secret = match resolve_signing_secret(master_secret, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip44_decrypt: key derivation failed: {e}");
            return build_error_json(&request.id, -4, "key derivation failure");
        }
    };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex"),
    };

    let conv_key = match nip44::get_conversation_key(&signing_secret, &peer_bytes) {
        Ok(k) => k,
        Err(e) => {
            log::error!("nip44_decrypt: conversation key failed: {e}");
            return build_error_json(&request.id, -4, "conversation key derivation failed");
        }
    };

    match nip44::decrypt(&conv_key, ciphertext_b64) {
        Ok(plaintext) => {
            nip46::build_result_response(&request.id, &plaintext).unwrap_or_default()
        }
        Err(e) => {
            log::error!("nip44_decrypt: decrypt failed: {e}");
            build_error_json(&request.id, -4, "decryption failed")
        }
    }
}

// ---------------------------------------------------------------------------
// nip04_encrypt
// ---------------------------------------------------------------------------

fn handle_nip04_encrypt(
    master_secret: &[u8; 32],
    request: &nip46::Nip46Request,
) -> String {
    if request.params.len() < 2 {
        return build_error_json(&request.id, -3, "nip04_encrypt requires 2 params");
    }
    let peer_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "peer pubkey param must be a string"),
    };
    let plaintext = match request.params[1].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "plaintext param must be a string"),
    };

    let signing_secret = match resolve_signing_secret(master_secret, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip04_encrypt: key derivation failed: {e}");
            return build_error_json(&request.id, -4, "key derivation failure");
        }
    };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex"),
    };

    let shared_secret = match nip04::get_shared_secret(&signing_secret, &peer_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip04_encrypt: shared secret failed: {e}");
            return build_error_json(&request.id, -4, "shared secret derivation failed");
        }
    };

    let iv = random_iv_16();
    match nip04::encrypt(&shared_secret, plaintext, &iv) {
        Ok(ciphertext) => {
            nip46::build_result_response(&request.id, &ciphertext).unwrap_or_default()
        }
        Err(e) => {
            log::error!("nip04_encrypt: encrypt failed: {e}");
            build_error_json(&request.id, -4, "encryption failed")
        }
    }
}

// ---------------------------------------------------------------------------
// nip04_decrypt
// ---------------------------------------------------------------------------

fn handle_nip04_decrypt(
    master_secret: &[u8; 32],
    request: &nip46::Nip46Request,
) -> String {
    if request.params.len() < 2 {
        return build_error_json(&request.id, -3, "nip04_decrypt requires 2 params");
    }
    let peer_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "peer pubkey param must be a string"),
    };
    let ciphertext = match request.params[1].as_str() {
        Some(s) => s,
        None => return build_error_json(&request.id, -3, "ciphertext param must be a string"),
    };

    let signing_secret = match resolve_signing_secret(master_secret, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip04_decrypt: key derivation failed: {e}");
            return build_error_json(&request.id, -4, "key derivation failure");
        }
    };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex"),
    };

    let shared_secret = match nip04::get_shared_secret(&signing_secret, &peer_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("nip04_decrypt: shared secret failed: {e}");
            return build_error_json(&request.id, -4, "shared secret derivation failed");
        }
    };

    match nip04::decrypt(&shared_secret, ciphertext) {
        Ok(plaintext) => {
            nip46::build_result_response(&request.id, &plaintext).unwrap_or_default()
        }
        Err(e) => {
            log::error!("nip04_decrypt: decrypt failed: {e}");
            build_error_json(&request.id, -4, "decryption failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Resolve the signing secret — master key or a derived child based on the
/// heartwood context.
fn resolve_signing_secret(
    master_secret: &[u8; 32],
    heartwood: Option<&HeartwoodContext>,
) -> Result<[u8; 32], String> {
    match heartwood {
        Some(ctx) => {
            let root = derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))?;
            let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                .map_err(|e| format!("derive: {e}"))?;
            Ok(*identity.private_key)
        }
        None => Ok(*master_secret),
    }
}

/// Decode a 64-character hex string into 32 bytes (Result version).
fn hex_decode_32_safe(hex: &str) -> Result<[u8; 32], ()> {
    hex_decode_32(hex).ok_or(())
}

/// Decode a 64-character hex string into 32 bytes.
/// Returns `None` if the string is not exactly 64 hex characters.
fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// Generate a random 24-byte nonce using the ESP32 hardware RNG.
/// Used as the per-message nonce for NIP-44 encryption.
fn random_nonce_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            nonce.as_mut_ptr() as *mut core::ffi::c_void,
            24,
        );
    }
    nonce
}

/// Generate a random 16-byte IV using the ESP32 hardware RNG.
/// Used as the per-message IV for NIP-04 encryption.
fn random_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            iv.as_mut_ptr() as *mut core::ffi::c_void,
            16,
        );
    }
    iv
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a NIP-46 error response JSON string.
/// Falls back to an empty string on serialisation failure (should never occur).
fn build_error_json(request_id: &str, code: i32, message: &str) -> String {
    nip46::build_error_response(request_id, code, message).unwrap_or_default()
}

/// Compare two byte slices in constant time to prevent timing-based attacks
/// when validating connect secrets.
///
/// Returns `true` only when both slices are identical in both length and content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

