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
use heartwood_common::nip46::{self, HeartwoodContext, SignedEvent, UnsignedEvent};
use heartwood_common::types::MasterMode;
use heartwood_common::validate::validate_persona_name;
use secp256k1::{Secp256k1, SignOnly};
use serde_json::Value;
use zeroize::Zeroize;

use crate::approval::ApprovalResult;
use crate::oled::Display;
use crate::policy::PolicyEngine;

/// Timeout in seconds shown on the OLED countdown bar.
const APPROVAL_TIMEOUT_SECS: u64 = 30;

/// A strict slot's `Denied` decision is a dispatch-wide ceiling, not a hint for
/// individual method arms. Keep the remote-client condition explicit so the
/// direct USB path retains its physical-possession semantics.
fn denied_before_dispatch(
    has_client: bool,
    tier: heartwood_common::policy::ApprovalTier,
) -> bool {
    has_client && tier == heartwood_common::policy::ApprovalTier::Denied
}

/// A public relay is not an approval queue. Only a client already bound to a
/// slot may make the device wait for a physical decision; otherwise strangers
/// can serialize fresh keys/ids into an endless series of 30-second prompts.
fn unbound_remote_request_denied(
    has_client: bool,
    client_is_bound: bool,
    method: &nip46::Nip46Method,
) -> bool {
    has_client
        && !client_is_bound
        && (matches!(method, nip46::Nip46Method::SignEvent)
            || method.always_requires_button())
}

/// Exact v2 authority is installed for the relay-addressed identity. An
/// explicit Heartwood context can redirect the same approved method to an
/// arbitrary derived child, which that policy did not name, so strict slots
/// reject it independent of method. Legacy slots retain their historical
/// context behavior; an internally-resolved active identity is not explicit.
fn strict_slot_denies_explicit_context(
    has_client: bool,
    strict_slot: bool,
    explicit_heartwood_context: bool,
) -> bool {
    has_client && strict_slot && explicit_heartwood_context
}

/// Remote Heartwood extensions that mutate identity state must cross one
/// physical-approval boundary before their match arm can run. `sign_event` owns
/// its richer event-specific prompt, while direct USB (`has_client == false`)
/// retains physical-possession semantics. Standard crypto methods are not
/// included here: an unbound remote crypto request remains refused below.
fn remote_extension_requires_approval(
    has_client: bool,
    method: &nip46::Nip46Method,
    tier: heartwood_common::policy::ApprovalTier,
) -> bool {
    has_client
        && !matches!(method, nip46::Nip46Method::SignEvent)
        && method.always_requires_button()
        && tier == heartwood_common::policy::ApprovalTier::ButtonRequired
}

/// `None` is the only outcome that permits dispatch. Denial and timeout become
/// normal NIP-46 errors before any extension state can be touched.
fn extension_approval_failure(request_id: &str, result: ApprovalResult) -> Option<String> {
    match result {
        ApprovalResult::Approved => None,
        ApprovalResult::Denied => Some(build_error_json(request_id, -1, "user denied")),
        ApprovalResult::TimedOut => Some(build_error_json(request_id, -1, "timeout")),
    }
}

/// Keep the approval preview ASCII and bounded because the OLED renderer uses
/// byte-oriented truncation. Include both requester and first parameter (the
/// derive purpose, persona target, or recovery lookahead) when available.
fn extension_approval_preview(requester: &str, params: &[Value]) -> String {
    let sanitise = |raw: &str| {
        raw.chars()
            .map(|ch| if ch.is_ascii_graphic() || ch == ' ' { ch } else { '?' })
            .take(18)
            .collect::<String>()
    };
    let requester = sanitise(requester);
    let target = params.first().map(|value| match value {
        Value::String(value) => sanitise(value),
        other => sanitise(&other.to_string()),
    });
    match target.filter(|value| !value.is_empty()) {
        Some(target) => format!("{requester}: {target}"),
        None => requester,
    }
}

/// Whether a remote request can change durable slot authority when approved.
/// Callers use this before dispatch to take a rollback snapshot without cloning
/// the slot table for every routine auto-sign request.
pub(crate) fn request_may_mutate_slot_state(
    request: &nip46::Nip46Request,
    tier: heartwood_common::policy::ApprovalTier,
) -> bool {
    match nip46::Nip46Method::from_str(&request.method) {
        nip46::Nip46Method::Connect => request
            .params
            .get(1)
            .and_then(|value| value.as_str())
            .map(|secret| !secret.is_empty())
            .unwrap_or(false),
        nip46::Nip46Method::SignEvent => {
            tier == heartwood_common::policy::ApprovalTier::ButtonRequired
        }
        _ => false,
    }
}

fn connect_success_response(request_id: &str, client_secret: &str) -> String {
    if client_secret.is_empty() {
        nip46::build_connect_response(request_id).unwrap_or_default()
    } else {
        nip46::build_connect_response_with_secret(request_id, client_secret).unwrap_or_default()
    }
}

fn metadata_name(value: &Value) -> Option<String> {
    let metadata = match value {
        Value::String(s) => serde_json::from_str::<Value>(s).ok()?,
        Value::Object(_) => value.clone(),
        _ => return None,
    };

    metadata
        .get("name")
        .and_then(|name| name.as_str())
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string())
}

fn connect_app_label(params: &[Value]) -> String {
    // Standard NIP-46 connect params are:
    // [remote_pubkey, secret, permissions, metadata].
    // Older Heartwood clients placed metadata at params[2], so keep a fallback.
    params
        .get(3)
        .and_then(metadata_name)
        .or_else(|| params.get(2).and_then(metadata_name))
        .unwrap_or_default()
}

/// Return the 32-byte secret to use for nsec-tree derivation.
///
/// In tree modes (TreeMnemonic, TreeNsec) the stored master secret is already
/// the tree root — use it directly. In Bunker mode the stored secret is a raw
/// nsec, so apply the intermediate HMAC to produce the tree root on demand.
/// The returned bytes are wrapped in `Zeroizing` for automatic cleanup.
fn derivation_secret(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    if master_mode.is_tree() {
        Ok(zeroize::Zeroizing::new(*master_secret))
    } else {
        derive::nsec_to_tree_root(master_secret)
    }
}

/// Derive a child identity's signing key and x-only pubkey from its owning
/// master. Mirrors the derivation chain in `do_sign` / `handle_get_public_key`
/// (mode → tree root → derive(purpose, index)). Used by the transport layer to
/// resolve a persona that a request was addressed to by its own pubkey.
pub(crate) fn derive_identity(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    purpose: &str,
    index: u32,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), String> {
    let derive_secret = derivation_secret(master_secret, master_mode)
        .map_err(|e| format!("derivation_secret: {e}"))?;
    let root =
        derive::create_tree_root(&derive_secret).map_err(|e| format!("create_tree_root: {e}"))?;
    let identity = derive::derive(&root, purpose, index).map_err(|e| format!("derive: {e}"))?;
    Ok((identity.private_key, identity.public_key))
}

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
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
) -> String {
    let mut request = match nip46::parse_request(&frame.payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse NIP-46 request: {e}");
            return nip46::build_error_response("unknown", -3, "invalid JSON-RPC request")
                .unwrap_or_default();
        }
    };
    // Capture caller intent before a legacy session's active identity may be
    // resolved into this field below. Only a caller-supplied context is a
    // strict-policy redirection attempt.
    let explicit_heartwood_context = request.heartwood.is_some();

    log::info!(
        "NIP-46 request: method={} id={} master_slot={}",
        request.method,
        request.id,
        master_slot,
    );

    // If no heartwood context in the request, resolve from the session's
    // active identity (set by a prior heartwood_switch call).
    if request.heartwood.is_none() {
        if let Some(cpk) = client_pubkey {
            if let Some(session) = policy_engine
                .sessions
                .iter()
                .find(|s| s.client_pubkey == *cpk && s.master_slot == master_slot)
            {
                if let Some(identity_idx) = session.active_identity {
                    if let Some(cache) = identity_caches
                        .iter()
                        .find(|c| c.master_slot == master_slot)
                    {
                        if let Some(identity) = cache.identities.get(identity_idx) {
                            log::info!(
                                "Resolving active identity: purpose={} index={}",
                                identity.purpose,
                                identity.index,
                            );
                            request.heartwood = Some(HeartwoodContext {
                                purpose: identity.purpose.clone(),
                                index: identity.index,
                            });
                        }
                    }
                }
            }
        }
    }

    let method = nip46::Nip46Method::from_str(&request.method);
    let event_kind = if matches!(method, nip46::Nip46Method::SignEvent) {
        nip46::parse_unsigned_event(&request.params)
            .ok()
            .map(|e| e.kind)
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
    let (client_is_bound, strict_slot) = if has_client {
        policy_engine
            .find_slot_by_pubkey(master_slot, &client_hex)
            .map(|slot| (true, slot.strict_permissions))
            .unwrap_or((false, false))
    } else {
        (false, false)
    };
    let requester_label = if has_client {
        signing_requester_label(policy_engine, master_slot, &client_hex)
    } else {
        "direct app".to_string()
    };
    let tier = if has_client {
        policy_engine.check(master_slot, &client_hex, &method, event_kind)
    } else {
        heartwood_common::policy::ApprovalTier::ButtonRequired
    };

    // Requests that can enter the physical approval loop are served remotely
    // only to a slot-bound client. Besides blocking unapproved identity-state
    // mutation, this protects the single-threaded shelf signer from strangers
    // keeping it permanently inside repeated 30-second sign prompts. Direct
    // USB retains its physical-possession semantics.
    if unbound_remote_request_denied(has_client, client_is_bound, &method) {
        log::warn!("{}: refused — unbound client", request.method);
        return build_error_json(&request.id, -1, "unauthorised");
    }

    // A strict slot names methods and event kinds for the identity selected by
    // relay routing. It grants no authority to redirect those same operations
    // to a caller-chosen derived child via top-level `heartwood` context.
    if strict_slot_denies_explicit_context(
        has_client,
        strict_slot,
        explicit_heartwood_context,
    ) {
        log::warn!(
            "{}: refused — explicit Heartwood identity context is outside exact slot policy",
            request.method
        );
        return build_error_json(&request.id, -1, "unauthorised");
    }

    // SECURITY BOUNDARY: exact v2 slots deny every method outside their
    // operator-installed ceiling. Enforce that once before dispatch so a new or
    // Heartwood-specific method cannot accidentally bypass the policy merely
    // because its individual match arm does not inspect `tier`.
    if denied_before_dispatch(has_client, tier) {
        log::warn!("{}: refused — outside exact slot policy", request.method);
        return build_error_json(&request.id, -1, "unauthorised");
    }

    // A ButtonRequired tier is meaningful only if the handler actually stops
    // for the button. Keep this single gate before dispatch so a new extension
    // cannot accidentally mutate state merely by omitting approval code from
    // its individual match arm. Strict v2 denials returned above never prompt.
    if remote_extension_requires_approval(has_client, &method, tier) {
        let preview = extension_approval_preview(&requester_label, &request.params);
        let approval = crate::approval::run_approval_loop(
            display,
            button_pin,
            APPROVAL_TIMEOUT_SECS,
            |d, remaining| {
                crate::oled::show_master_sign_request(
                    d,
                    master_label,
                    &request.method,
                    None,
                    &preview,
                    remaining,
                );
            },
        );
        if let Some(response) = extension_approval_failure(&request.id, approval) {
            log::info!("{}: physical approval denied or timed out", request.method);
            crate::oled::show_result(display, "Not approved");
            return response;
        }
        log::info!("{}: physically approved", request.method);
    }

    match request.method.as_str() {
        "sign_event" => {
            match tier {
                heartwood_common::policy::ApprovalTier::AutoApprove => {
                    log::info!("sign_event: auto-approved by policy");
                    if let Ok(event) = nip46::parse_unsigned_event(&request.params) {
                        crate::oled::show_auto_signed(display, &requester_label, event.kind);
                    } else {
                        crate::oled::show_auto_approved(display, &requester_label, "sign_event");
                    }
                    match handle_auto_sign(master_secret, master_mode, secp, &request) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::OledNotify => {
                    if let Ok(event) = nip46::parse_unsigned_event(&request.params) {
                        crate::oled::show_auto_signed(display, &requester_label, event.kind);
                    } else {
                        crate::oled::show_auto_approved(display, &requester_label, "sign_event");
                    }
                    match handle_auto_sign(master_secret, master_mode, secp, &request) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::ButtonRequired => {
                    let result = handle_sign_event(
                        master_secret,
                        master_mode,
                        secp,
                        display,
                        button_pin,
                        &request,
                        &requester_label,
                    );
                    let is_success = serde_json::from_str::<serde_json::Value>(&result)
                        .map(|v| v.get("error").is_none())
                        .unwrap_or(false);
                    if has_client && is_success {
                        // Upgrade the slot to full signing if not already.
                        if let Some(slot) =
                            policy_engine.find_slot_by_pubkey(master_slot, &client_hex)
                        {
                            let idx = slot.slot_index;
                            policy_engine.upgrade_to_signing(master_slot, idx);
                        }
                    }
                    result
                }
                heartwood_common::policy::ApprovalTier::Denied => {
                    log::warn!("sign_event: refused — outside exact slot policy");
                    build_error_json(&request.id, -1, "unauthorised")
                }
            }
        }

        "get_public_key" => handle_get_public_key(master_secret, master_mode, secp, &request),

        "connect" => {
            // params[0] is the client pubkey; params[1] is the optional secret;
            // params[2] is permissions; params[3] is optional JSON metadata.
            if has_client {
                if let Ok(pk_bytes) = hex_decode_32_safe(&client_hex) {
                    policy_engine.get_or_create_session(pk_bytes, master_slot);
                }
            }

            let app_label = connect_app_label(&request.params);

            let client_secret = request.params.get(1).and_then(|v| v.as_str()).unwrap_or("");
            if client_secret.is_empty() {
                // No secret -- accept but no slot assigned. Stranger path.
                connect_success_response(&request.id, client_secret)
            } else if !has_client {
                build_error_json(&request.id, -1, "missing client pubkey")
            } else {
                // Look up slot by secret.
                match policy_engine.find_slot_by_secret(master_slot, client_secret) {
                    None => {
                        log::warn!(
                            "connect: secret mismatch from {}",
                            &client_hex[..16.min(client_hex.len())]
                        );
                        build_error_json(&request.id, -1, "unauthorised")
                    }
                    Some(slot) => {
                        let slot_index = slot.slot_index;
                        let slot_label = slot.label.clone();
                        let was_signing = slot.signing_approved;
                        let old_pubkey = slot.current_pubkey.clone();

                        match &old_pubkey {
                            None => {
                                // First use -- assign pubkey.
                                policy_engine.assign_pubkey_to_slot(
                                    master_slot,
                                    slot_index,
                                    client_hex.clone(),
                                );
                                // Update label from app metadata if slot is still "default".
                                if !app_label.is_empty() {
                                    let slots = policy_engine.slots_mut(master_slot);
                                    if let Some(s) =
                                        slots.iter_mut().find(|s| s.slot_index == slot_index)
                                    {
                                        if s.label == "default" {
                                            s.label = app_label.clone();
                                        }
                                    }
                                }
                                log::info!(
                                    "Slot {} ({}) assigned to {}",
                                    slot_index,
                                    slot_label,
                                    &client_hex[..16.min(client_hex.len())]
                                );
                            }
                            Some(existing) if existing == &client_hex => {
                                // Same pubkey reconnecting -- no-op.
                                log::info!(
                                    "Slot {} ({}) reconnected (same pubkey)",
                                    slot_index,
                                    slot_label
                                );
                            }
                            Some(_old) => {
                                // New ephemeral key for existing slot.
                                if was_signing {
                                    // OLED flash for signing-approved slots.
                                    crate::oled::show_auto_approved(
                                        display,
                                        &slot_label,
                                        "reconnected",
                                    );
                                }
                                policy_engine.assign_pubkey_to_slot(
                                    master_slot,
                                    slot_index,
                                    client_hex.clone(),
                                );
                                log::info!("Slot {} ({}) pubkey swapped", slot_index, slot_label);
                            }
                        }

                        connect_success_response(&request.id, client_secret)
                    }
                }
            }
        }

        "ping" => nip46::build_ping_response(&request.id).unwrap_or_default(),

        // Encrypt/decrypt as the master's identity are safe ONLY for a client
        // bound to a connect slot (which lifts `tier` to AutoApprove/OledNotify)
        // or for the physically-present direct-USB path (no remote client at
        // all — `has_client` is false there). A *remote* client that is not
        // slot-bound lands on ButtonRequired; we refuse rather than act as an
        // encryption/decryption oracle for keys addressed to the master.
        //
        // This is the fix for the relay-path oracle: `handle_nip46_event`
        // dispatches for ANY event author, so without this gate an unbound
        // relay peer could send `nip44_decrypt([alice, C])` and get back the
        // plaintext of any NIP-44 message Alice sent to the master (the ECDH
        // key is master_secret × alice, so the MAC verifies regardless of who
        // asks). `has_client` keeps the local USB user (client = None)
        // unaffected — physical possession is its own authorisation.
        "nip44_encrypt" | "nip44_decrypt" | "nip04_encrypt" | "nip04_decrypt"
            if has_client
                && matches!(
                    tier,
                    heartwood_common::policy::ApprovalTier::ButtonRequired
                        | heartwood_common::policy::ApprovalTier::Denied
                ) =>
        {
            log::warn!("{}: refused — unbound client", request.method);
            build_error_json(&request.id, -1, "unauthorised")
        }

        "nip44_encrypt" => handle_nip44_encrypt(master_secret, master_mode, &request),

        "nip44_decrypt" => handle_nip44_decrypt(master_secret, master_mode, &request),

        "nip04_encrypt" => handle_nip04_encrypt(master_secret, master_mode, &request),

        "nip04_decrypt" => handle_nip04_decrypt(master_secret, master_mode, &request),

        "heartwood_derive" => {
            let derive_secret = match derivation_secret(master_secret, master_mode) {
                Ok(s) => s,
                Err(e) => return build_error_json(&request.id, -4, e),
            };
            let purpose = match request.params.first().and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return build_error_json(&request.id, -3, "requires [purpose, index?]"),
            };
            let index = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            let cache = match identity_caches
                .iter_mut()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            match cache.derive_and_cache(&derive_secret, purpose, index, None) {
                Ok(idx) => {
                    let id = &cache.identities[idx];
                    let result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                    });
                    nip46::build_result_response(&request.id, &result.to_string())
                        .unwrap_or_default()
                }
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_derive_persona" => {
            let derive_secret = match derivation_secret(master_secret, master_mode) {
                Ok(s) => s,
                Err(e) => return build_error_json(&request.id, -4, e),
            };
            let name = match request.params.first().and_then(|v| v.as_str()) {
                Some(n) => n,
                None => return build_error_json(&request.id, -3, "requires [name, index?]"),
            };
            if let Err(e) = validate_persona_name(name) {
                return build_error_json(&request.id, -3, e);
            }
            let index = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            // Reserved persona namespace (PROTOCOL v1.1 §3.1) — the same purpose
            // signet, the library, and the CLI's `derive persona` use, so a
            // persona reproduces byte-for-byte across all of them.
            let purpose = format!("nostr:persona:{name}");

            let cache = match identity_caches
                .iter_mut()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            match cache.derive_and_cache(&derive_secret, &purpose, index, Some(name.to_string())) {
                Ok(idx) => {
                    let id = &cache.identities[idx];
                    let result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                        "personaName": name,
                    });
                    nip46::build_result_response(&request.id, &result.to_string())
                        .unwrap_or_default()
                }
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_switch" => {
            let target = match request.params.first().and_then(|v| v.as_str()) {
                Some(t) => t,
                None => return build_error_json(&request.id, -3, "requires [target, index_hint?]"),
            };

            // "master" resets to the master identity — return its npub.
            if target == "master" {
                // Clear active identity on the session.
                if let Some(cpk) = client_pubkey {
                    if let Some(session) = policy_engine.get_or_create_session(*cpk, master_slot) {
                        session.active_identity = None;
                    }
                }
                use heartwood_common::encoding::encode_npub;
                let pubkey_result = secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                    .map(|kp| {
                        let (xonly, _) = kp.x_only_public_key();
                        encode_npub(&xonly.serialize())
                    })
                    .map_err(|_| "invalid master secret".to_string());
                return match pubkey_result {
                    Ok(npub) => {
                        crate::oled::show_identity_switch(display, master_label, "master", &npub);
                        let result =
                            serde_json::json!({ "npub": npub, "purpose": "master", "index": 0 });
                        nip46::build_result_response(&request.id, &result.to_string())
                            .unwrap_or_default()
                    }
                    Err(e) => build_error_json(&request.id, -4, &e),
                };
            }

            let cache = match identity_caches
                .iter_mut()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            // Search by npub, then persona name, then purpose+index.
            let index_hint = request.params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let found = cache
                .find_by_npub(target)
                .or_else(|| cache.find_by_persona(target))
                .or_else(|| cache.find(target, index_hint));

            match found {
                Some(idx) => {
                    // Set active identity on the client session.
                    if let Some(cpk) = client_pubkey {
                        if let Some(session) =
                            policy_engine.get_or_create_session(*cpk, master_slot)
                        {
                            session.active_identity = Some(idx);
                            log::info!("Set active identity to index {idx}");
                        }
                    }
                    let id = &cache.identities[idx];
                    // Show the completed switch after the pre-dispatch button
                    // approval, so the owner sees both the request and result.
                    crate::oled::show_identity_switch(display, master_label, &id.purpose, &id.npub);
                    let mut result = serde_json::json!({
                        "npub": id.npub,
                        "purpose": id.purpose,
                        "index": id.index,
                    });
                    if let Some(name) = &id.persona_name {
                        result["personaName"] = serde_json::json!(name);
                    }
                    nip46::build_result_response(&request.id, &result.to_string())
                        .unwrap_or_default()
                }
                None => build_error_json(&request.id, -4, "identity not found in cache"),
            }
        }

        "heartwood_list_identities" => {
            let cache = match identity_caches
                .iter()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            nip46::build_result_response(&request.id, &cache.list_json()).unwrap_or_default()
        }

        "heartwood_recover" => {
            let derive_secret = match derivation_secret(master_secret, master_mode) {
                Ok(s) => s,
                Err(e) => return build_error_json(&request.id, -4, e),
            };
            let lookahead = request
                .params
                .first()
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as u32;

            let cache = match identity_caches
                .iter_mut()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            match cache.recover(&derive_secret, lookahead) {
                Ok(count) => {
                    let identities_json = cache.list_json();
                    let result =
                        format!(r#"{{"recovered":{count},"identities":{identities_json}}}"#);
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

        "switch_relays" => {
            // Non-standard method sent by some clients (e.g. Coracle).
            // Return success to avoid blocking the handshake.
            nip46::build_result_response(&request.id, "{}").unwrap_or_default()
        }

        other => {
            log::warn!("Unknown NIP-46 method: {other}");
            build_error_json(&request.id, -2, "unknown method")
        }
    }
}

fn signing_requester_label(
    policy_engine: &PolicyEngine,
    master_slot: u8,
    client_hex: &str,
) -> String {
    policy_engine
        .find_slot_by_pubkey(master_slot, client_hex)
        .map(|slot| slot.label.trim())
        .filter(|label| !label.is_empty())
        .map(|label| label.to_string())
        .unwrap_or_else(|| anonymous_client_label(client_hex))
}

/// Label for a client with no slot label: truncated npub, or the legacy hex
/// prefix if the pubkey string is malformed. Identification UX only —
/// approval policy does not depend on the label.
fn anonymous_client_label(client_hex: &str) -> String {
    hex_decode_32(client_hex)
        .map(|pk| heartwood_common::encoding::client_fallback_label(&pk))
        .unwrap_or_else(|| format!("client {}", &client_hex[..client_hex.len().min(8)]))
}

// ---------------------------------------------------------------------------
// Auto-sign (policy-approved, no button required)
// ---------------------------------------------------------------------------

fn handle_auto_sign(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) -> Result<String, String> {
    let mut event = nip46::parse_unsigned_event(&request.params)
        .map_err(|e| format!("bad event format: {e}"))?;
    let signed = do_sign(
        &mut event,
        master_secret,
        master_mode,
        secp,
        request.heartwood.as_ref(),
    )?;
    nip46::build_sign_response(&request.id, &signed)
}

// ---------------------------------------------------------------------------
// sign_event (interactive, button-required)
// ---------------------------------------------------------------------------

fn handle_sign_event(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    request: &nip46::Nip46Request,
    requester_label: &str,
) -> String {
    let mut event = match nip46::parse_unsigned_event(&request.params) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("sign_event: bad event format: {e}");
            return build_error_json(&request.id, -3, "bad event format");
        }
    };

    let (kind, content_preview) = nip46::event_display_summary(&event, 50);

    // Show the signing request on the OLED and wait for button approval.
    // The countdown bar updates every second; the approval module handles
    // "Hold 2s..." feedback while the button is held down.
    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        APPROVAL_TIMEOUT_SECS,
        |d, remaining| {
            crate::oled::show_sign_request(d, requester_label, kind, &content_preview, remaining);
        },
    );

    match result {
        ApprovalResult::Approved => {
            log::info!("sign_event: approved");
            crate::oled::show_signing(display);
            match do_sign(
                &mut event,
                master_secret,
                master_mode,
                secp,
                request.heartwood.as_ref(),
            ) {
                Ok(signed) => match nip46::build_sign_response(&request.id, &signed) {
                    Ok(json) => {
                        crate::oled::show_signed(display);
                        json
                    }
                    Err(e) => {
                        log::error!("Failed to build sign response: {e}");
                        crate::oled::show_result(display, "Sign error");
                        build_error_json(&request.id, -4, "signing failed")
                    }
                },
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
            // Not a failure to shout about: the prompt just expired unanswered.
            crate::oled::show_result(display, "Not signed");
            build_error_json(&request.id, -1, "timeout")
        }
    }
}

// ---------------------------------------------------------------------------
// do_sign — runs inline on the main thread
// ---------------------------------------------------------------------------

fn do_sign(
    event: &mut UnsignedEvent,
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    heartwood: Option<&HeartwoodContext>,
) -> Result<SignedEvent, String> {
    // Derive the signing identity first -- we may need the pubkey to fill the template.
    let (mut signing_secret, hex_pubkey) = match heartwood {
        Some(ctx) => {
            let derive_secret = derivation_secret(master_secret, master_mode)
                .map_err(|e| format!("derivation_secret: {e}"))?;
            let root = derive::create_tree_root(&derive_secret)
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

    // NIP-46 spec: the signer owns the identity, so ALWAYS stamp the resolved
    // signer's pubkey onto the template before hashing — never trust a
    // client-supplied value. A pubkey that disagreed with the signer (reachable
    // now that personas exist: the client sends the master while we resolve a
    // persona) would otherwise be hashed into the event id while the returned
    // event reports `hex_pubkey`, yielding an id that fails NIP-01 verification.
    // Overwriting guarantees id, pubkey and sig all agree. Matches the esp8266
    // signer, which already overwrites unconditionally (sign_path.rs).
    event.pubkey = hex_pubkey.clone();

    let event_id_bytes = nip46::compute_event_id(event);

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
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) -> String {
    let pubkey_result = match &request.heartwood {
        Some(ctx) => derivation_secret(master_secret, master_mode)
            .map_err(|e| format!("derivation_secret: {e}"))
            .and_then(|ds| {
                derive::create_tree_root(&ds).map_err(|e| format!("create_tree_root: {e}"))
            })
            .and_then(|root| {
                derive::derive(&root, &ctx.purpose, ctx.index).map_err(|e| format!("derive: {e}"))
            })
            .map(|identity| hex_encode(&identity.public_key)),
        None => secp256k1::Keypair::from_seckey_slice(secp, master_secret)
            .map(|keypair| {
                let (xonly, _) = keypair.x_only_public_key();
                hex_encode(&xonly.serialize())
            })
            .map_err(|_| "invalid master secret".to_string()),
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
    master_mode: MasterMode,
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

    let mut signing_secret =
        match resolve_signing_secret(master_secret, master_mode, request.heartwood.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("nip44_encrypt: key derivation failed: {e}");
                return build_error_json(&request.id, -4, "key derivation failure");
            }
        };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => {
            signing_secret.zeroize();
            return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex");
        }
    };

    let conv_key = match nip44::get_conversation_key(&signing_secret, &peer_bytes) {
        Ok(k) => k,
        Err(e) => {
            signing_secret.zeroize();
            log::error!("nip44_encrypt: conversation key failed: {e}");
            return build_error_json(&request.id, -4, "conversation key derivation failed");
        }
    };
    signing_secret.zeroize();

    let nonce = random_nonce_32();
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
    master_mode: MasterMode,
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

    let mut signing_secret =
        match resolve_signing_secret(master_secret, master_mode, request.heartwood.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("nip44_decrypt: key derivation failed: {e}");
                return build_error_json(&request.id, -4, "key derivation failure");
            }
        };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => {
            signing_secret.zeroize();
            return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex");
        }
    };

    let conv_key = match nip44::get_conversation_key(&signing_secret, &peer_bytes) {
        Ok(k) => k,
        Err(e) => {
            signing_secret.zeroize();
            log::error!("nip44_decrypt: conversation key failed: {e}");
            return build_error_json(&request.id, -4, "conversation key derivation failed");
        }
    };
    signing_secret.zeroize();

    match nip44::decrypt(&conv_key, ciphertext_b64) {
        Ok(plaintext) => nip46::build_result_response(&request.id, &plaintext).unwrap_or_default(),
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
    master_mode: MasterMode,
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

    let mut signing_secret =
        match resolve_signing_secret(master_secret, master_mode, request.heartwood.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("nip04_encrypt: key derivation failed: {e}");
                return build_error_json(&request.id, -4, "key derivation failure");
            }
        };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => {
            signing_secret.zeroize();
            return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex");
        }
    };

    let shared_secret = match nip04::get_shared_secret(&signing_secret, &peer_bytes) {
        Ok(s) => s,
        Err(e) => {
            signing_secret.zeroize();
            log::error!("nip04_encrypt: shared secret failed: {e}");
            return build_error_json(&request.id, -4, "shared secret derivation failed");
        }
    };
    signing_secret.zeroize();

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
    master_mode: MasterMode,
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

    let mut signing_secret =
        match resolve_signing_secret(master_secret, master_mode, request.heartwood.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("nip04_decrypt: key derivation failed: {e}");
                return build_error_json(&request.id, -4, "key derivation failure");
            }
        };

    let peer_bytes = match hex_decode_32(peer_hex) {
        Some(b) => b,
        None => {
            signing_secret.zeroize();
            return build_error_json(&request.id, -3, "peer pubkey must be 64-char hex");
        }
    };

    let shared_secret = match nip04::get_shared_secret(&signing_secret, &peer_bytes) {
        Ok(s) => s,
        Err(e) => {
            signing_secret.zeroize();
            log::error!("nip04_decrypt: shared secret failed: {e}");
            return build_error_json(&request.id, -4, "shared secret derivation failed");
        }
    };
    signing_secret.zeroize();

    match nip04::decrypt(&shared_secret, ciphertext) {
        Ok(plaintext) => nip46::build_result_response(&request.id, &plaintext).unwrap_or_default(),
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
    master_mode: MasterMode,
    heartwood: Option<&HeartwoodContext>,
) -> Result<[u8; 32], String> {
    match heartwood {
        Some(ctx) => {
            let derive_secret = derivation_secret(master_secret, master_mode)
                .map_err(|e| format!("derivation_secret: {e}"))?;
            let root = derive::create_tree_root(&derive_secret)
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

/// Generate a random 32-byte nonce using the ESP32 hardware RNG.
/// Used as the NIP-44 per-message nonce.
fn random_nonce_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(nonce.as_mut_ptr() as *mut core::ffi::c_void, 32);
    }
    nonce
}

/// Generate a random 16-byte IV using the ESP32 hardware RNG.
/// Used as the per-message IV for NIP-04 encryption.
fn random_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(iv.as_mut_ptr() as *mut core::ffi::c_void, 16);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use heartwood_common::nip46;
    use heartwood_common::policy::{ApprovalTier, ConnectSlot};

    use super::{
        connect_success_response, denied_before_dispatch, extension_approval_failure,
        remote_extension_requires_approval, request_may_mutate_slot_state,
        strict_slot_denies_explicit_context, unbound_remote_request_denied,
    };
    use crate::approval::ApprovalResult;
    use crate::policy::PolicyEngine;

    const CLIENT_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111"; // pragma: allow-secret — fixed test vector

    fn engine_with_slot(strict: bool, allowed_methods: &[&str]) -> PolicyEngine {
        let mut engine = PolicyEngine::new();
        engine.slots_mut(0).push(ConnectSlot {
            slot_index: 0,
            label: "handler regression".into(),
            secret: "22".repeat(32),
            current_pubkey: Some(CLIENT_HEX.into()),
            allowed_methods: allowed_methods.iter().map(|method| (*method).into()).collect(),
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: allowed_methods.contains(&"sign_event"),
            strict_permissions: strict,
            authorized_pubkeys: vec![],
        });
        engine
    }

    #[test]
    fn strict_denial_blocks_every_extension_before_handler_dispatch() {
        let engine = engine_with_slot(true, &["get_public_key", "sign_event"]);

        for method_name in [
            "heartwood_derive",
            "heartwood_derive_persona",
            "heartwood_switch",
            "heartwood_list_identities",
            "heartwood_recover",
            "heartwood_create_proof",
            "heartwood_verify_proof",
            "future_unknown_method",
        ] {
            let method = nip46::Nip46Method::from_str(method_name);
            let tier = engine.check(0, CLIENT_HEX, &method, None);
            assert_eq!(
                tier,
                ApprovalTier::Denied,
                "{method_name} must be outside the strict slot ceiling",
            );
            assert!(
                denied_before_dispatch(true, tier),
                "{method_name} escaped the handler's pre-dispatch denial",
            );
        }
    }

    #[test]
    fn pre_dispatch_gate_preserves_allowed_and_legacy_control_paths() {
        let strict = engine_with_slot(true, &["nip44_encrypt"]);
        let allowed = nip46::Nip46Method::from_str("nip44_encrypt");
        let allowed_tier = strict.check(0, CLIENT_HEX, &allowed, None);
        assert_eq!(allowed_tier, ApprovalTier::AutoApprove);
        assert!(!denied_before_dispatch(true, allowed_tier));

        // Protocol plumbing remains global even when omitted from a strict
        // slot's explicit automatic-authority list.
        for method_name in ["connect", "ping", "get_public_key", "switch_relays"] {
            let method = nip46::Nip46Method::from_str(method_name);
            let tier = strict.check(0, CLIENT_HEX, &method, None);
            assert_eq!(
                tier,
                ApprovalTier::AutoApprove,
                "{method_name} must remain global protocol plumbing",
            );
            assert!(!denied_before_dispatch(true, tier));
        }

        // Legacy slots retain their historical physical-button fallback rather
        // than being converted into hard denials by the handler gate.
        let legacy = engine_with_slot(false, &[]);
        for method_name in ["heartwood_derive", "heartwood_switch"] {
            let method = nip46::Nip46Method::from_str(method_name);
            let tier = legacy.check(0, CLIENT_HEX, &method, None);
            assert_eq!(tier, ApprovalTier::ButtonRequired);
            assert!(!denied_before_dispatch(true, tier));
            assert!(remote_extension_requires_approval(true, &method, tier));
        }

        // No remote client means the direct USB path remains outside this gate.
        assert!(!denied_before_dispatch(false, ApprovalTier::Denied));
    }

    #[test]
    fn unbound_remote_clients_cannot_enter_physical_approval_loops() {
        for method_name in ["sign_event", "heartwood_derive", "heartwood_switch"] {
            let method = nip46::Nip46Method::from_str(method_name);
            assert!(
                unbound_remote_request_denied(true, false, &method),
                "{method_name} would let a stranger occupy the relay loop",
            );
            assert!(
                !unbound_remote_request_denied(true, true, &method),
                "a slot-bound client must retain physical approval fallback",
            );
            assert!(
                !unbound_remote_request_denied(false, false, &method),
                "direct USB retains physical-possession approval",
            );
        }

        for method_name in ["connect", "ping", "get_public_key"] {
            let method = nip46::Nip46Method::from_str(method_name);
            assert!(!unbound_remote_request_denied(true, false, &method));
        }
    }

    #[test]
    fn exact_slots_reject_caller_selected_derived_identity_context() {
        // The gate is deliberately method-independent: get_public_key,
        // sign_event and every standard crypto method could otherwise resolve
        // the same caller-selected child secret.
        for method_name in [
            "get_public_key",
            "sign_event",
            "nip44_encrypt",
            "nip44_decrypt",
            "nip04_encrypt",
            "nip04_decrypt",
        ] {
            let _method = nip46::Nip46Method::from_str(method_name);
            assert!(
                strict_slot_denies_explicit_context(true, true, true),
                "{method_name} escaped strict identity scoping",
            );
        }

        assert!(!strict_slot_denies_explicit_context(true, false, true));
        assert!(!strict_slot_denies_explicit_context(true, true, false));
        assert!(!strict_slot_denies_explicit_context(false, true, true));
    }

    #[test]
    fn remote_mutating_extensions_dispatch_only_after_approval() {
        for method_name in [
            "heartwood_derive",
            "heartwood_derive_persona",
            "heartwood_recover",
            "heartwood_switch",
        ] {
            let method = nip46::Nip46Method::from_str(method_name);
            assert!(
                remote_extension_requires_approval(
                    true,
                    &method,
                    ApprovalTier::ButtonRequired,
                ),
                "{method_name} escaped the central remote approval gate",
            );
        }

        assert!(extension_approval_failure("approved", ApprovalResult::Approved).is_none());

        let denied = extension_approval_failure("denied", ApprovalResult::Denied)
            .expect("denial must stop dispatch");
        let denied: serde_json::Value = serde_json::from_str(&denied).unwrap();
        assert_eq!(denied["id"], "denied");
        assert_eq!(denied["error"], "user denied");

        let timed_out = extension_approval_failure("timed-out", ApprovalResult::TimedOut)
            .expect("timeout must stop dispatch");
        let timed_out: serde_json::Value = serde_json::from_str(&timed_out).unwrap();
        assert_eq!(timed_out["id"], "timed-out");
        assert_eq!(timed_out["error"], "timeout");
    }

    #[test]
    fn central_extension_gate_excludes_usb_sign_event_and_remote_crypto() {
        let derive = nip46::Nip46Method::HeartwoodDerive;
        assert!(!remote_extension_requires_approval(
            false,
            &derive,
            ApprovalTier::ButtonRequired,
        ));
        assert!(!remote_extension_requires_approval(
            true,
            &nip46::Nip46Method::SignEvent,
            ApprovalTier::ButtonRequired,
        ));
        assert!(!remote_extension_requires_approval(
            true,
            &nip46::Nip46Method::Nip44Decrypt,
            ApprovalTier::ButtonRequired,
        ));
    }

    #[test]
    fn slot_mutation_snapshot_is_needed_only_for_connect_binding_or_first_sign() {
        let connect: nip46::Nip46Request = serde_json::from_value(serde_json::json!({
            "id": "connect",
            "method": "connect",
            "params": [CLIENT_HEX, "22".repeat(32)]
        }))
        .unwrap();
        assert!(request_may_mutate_slot_state(
            &connect,
            ApprovalTier::AutoApprove,
        ));

        let reconnect_without_secret: nip46::Nip46Request =
            serde_json::from_value(serde_json::json!({
                "id": "connect",
                "method": "connect",
                "params": [CLIENT_HEX]
            }))
            .unwrap();
        assert!(!request_may_mutate_slot_state(
            &reconnect_without_secret,
            ApprovalTier::AutoApprove,
        ));

        let sign: nip46::Nip46Request = serde_json::from_value(serde_json::json!({
            "id": "sign",
            "method": "sign_event",
            "params": [{}]
        }))
        .unwrap();
        assert!(request_may_mutate_slot_state(
            &sign,
            ApprovalTier::ButtonRequired,
        ));
        assert!(!request_may_mutate_slot_state(
            &sign,
            ApprovalTier::AutoApprove,
        ));
    }

    #[test]
    fn connect_response_echoes_a_supplied_secret_but_keeps_stranger_ack() {
        let stranger: serde_json::Value = serde_json::from_str(&connect_success_response(
            "connect-without-secret",
            "",
        ))
        .expect("secretless connect response should be valid JSON");
        assert_eq!(stranger["id"], "connect-without-secret");
        assert_eq!(stranger["result"], "ack");

        let secret = "aabbccdd".repeat(8);
        let paired: serde_json::Value = serde_json::from_str(&connect_success_response(
            "connect-with-secret",
            &secret,
        ))
        .expect("secret-bearing connect response should be valid JSON");
        assert_eq!(paired["id"], "connect-with-secret");
        assert_eq!(paired["result"], secret);
    }

    /// switch_relays is a non-standard method sent by Coracle during its
    /// NIP-46 handshake. The handler must return a success response (not an
    /// error) so the handshake can complete normally.
    #[test]
    fn switch_relays_returns_success() {
        let request_id = "test-switch-relays-1";

        // Simulate what the handler does for the switch_relays arm.
        let response_json = nip46::build_result_response(request_id, "{}").unwrap();

        let parsed: serde_json::Value =
            serde_json::from_str(&response_json).expect("response should be valid JSON");

        // The id must be echoed back.
        assert_eq!(
            parsed["id"], request_id,
            "response id must match request id"
        );

        // result must be present and must not be an error.
        assert!(
            parsed.get("error").is_none(),
            "switch_relays must not return an error field"
        );
        assert_eq!(
            parsed["result"], "{}",
            "switch_relays result should be an empty JSON object string"
        );
    }
}
