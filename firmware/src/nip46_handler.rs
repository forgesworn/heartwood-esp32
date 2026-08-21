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
/// `heartwood_list_identities` joins the denial set not for the button but
/// because it enumerates the per-boot identity cache (persona purposes/names,
/// child npubs) — metadata an unbound relay peer has no business reading
/// (FW-L5).
fn unbound_remote_request_denied(
    has_client: bool,
    client_is_bound: bool,
    method: &nip46::Nip46Method,
) -> bool {
    has_client
        && !client_is_bound
        && (matches!(method, nip46::Nip46Method::SignEvent)
            || matches!(method, nip46::Nip46Method::HeartwoodListIdentities)
            || method.always_requires_button()
            || is_note_method(method))
}

/// The bearer-note locker's relay methods. All of them require a bound
/// slot (see `unbound_remote_request_denied`), and the disclosure and
/// destructive ones are additionally pinned ButtonRequired whatever the
/// slot's tier says (see the pin in dispatch_inner).
fn is_note_method(method: &nip46::Nip46Method) -> bool {
    matches!(
        method,
        nip46::Nip46Method::HeartwoodNoteList
            | nip46::Nip46Method::HeartwoodNoteNew
            | nip46::Nip46Method::HeartwoodNoteNewPair
            | nip46::Nip46Method::HeartwoodNoteConfirm
            | nip46::Nip46Method::HeartwoodNoteDiscard
            | nip46::Nip46Method::HeartwoodNoteExport
            | nip46::Nip46Method::HeartwoodNoteImport
            | nip46::Nip46Method::HeartwoodNoteSpent
            | nip46::Nip46Method::HeartwoodNoteSend
            | nip46::Nip46Method::HeartwoodNoteTrust
            | nip46::Nip46Method::HeartwoodNoteTrusted
    )
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

/// Local alias for the compact method name, which lives with the protocol.
pub(crate) use heartwood_common::nip46::SIGN_EVENT_COMPACT_METHOD as SIGN_EVENT_COMPACT;

/// Build the reply for a completed signature, compact when the client asked.
///
/// The full form echoes the whole signed event back, which costs one contiguous
/// allocation of about twice the content and is what aborts the chip once the
/// parse cost is removed. The compact form returns a couple of hundred bytes
/// whatever the size.
fn build_sign_reply(
    request: &nip46::Nip46Request,
    signed: &SignedEvent,
) -> Result<String, String> {
    if request.method == SIGN_EVENT_COMPACT {
        nip46::build_sign_response_compact(&request.id, signed)
    } else {
        nip46::build_sign_response(&request.id, signed)
    }
}

/// Persist a connect-slot bind, undoing it if the write does not land.
///
/// #75: `connect` used to answer success as soon as the pubkey was assigned in
/// RAM, so a full NVS produced a client that believed it was paired against a
/// slot the board held no key for — every later request then failed as an
/// unknown client, and the obvious reading was "the signer is broken" rather
/// than "the bind never persisted". Mirrors the relay path's
/// `persist_slot_mutation_or_rollback` (the #67 pattern): a reply that says
/// success must mean the authority survives a reboot.
fn persist_bind_or_rollback(
    policy_engine: &mut PolicyEngine,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    master_slot: u8,
    snapshot: crate::policy::SlotStateSnapshot,
) -> Result<(), String> {
    if policy_engine.persist_slots(nvs, master_slot) {
        return Ok(());
    }
    if policy_engine.restore_slot_state_durably(nvs, snapshot) {
        log::error!("connect: bind was not durable; prior slot authority restored durably");
        Err("could not persist client bind; request was not applied".into())
    } else {
        log::error!(
            "connect: FATAL: bind failed and prior slot authority could not be restored durably"
        );
        Err("fatal storage error: could not restore prior client policy after bind; \
             take the device offline for USB recovery"
            .into())
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
    frame: Frame,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    personas: &mut Vec<crate::personas::LoadedPersona>,
) -> String {
    // Bound the request BEFORE serde_json sees it, as the relay and the
    // encrypted path both do. MAX_PAYLOAD_SIZE admits a 32 KB frame, and
    // unescaping the event NIP-46 carries as a string would then ask for ~64 KB
    // in one contiguous block: the allocator aborts and the chip reboots rather
    // than refusing. The guard below runs after parsing and cannot help.
    //
    // This is the plaintext frame, so the payload IS the request. It is not
    // valid UTF-8 by construction, hence the lossy check: a non-UTF-8 payload
    // will fail to parse anyway, and taking the standard ceiling for it is the
    // conservative answer.
    if let Ok(json) = core::str::from_utf8(&frame.payload) {
        let budget = nip46::request_ceiling(
            json,
            crate::board::MAX_SIGN_BYTES,
            crate::board::MAX_SIGN_BYTES_OBJECT,
        ) + heartwood_common::types::SIGN_RESPONSE_OVERHEAD;
        if json.len() > budget {
            log::warn!(
                "NIP-46 request of {} bytes exceeds the {budget} byte parse budget; refusing",
                json.len()
            );
            return nip46::build_error_response(
                nip46::scan_rpc_id(json).unwrap_or("unknown"),
                -3,
                "request is too large for this signer",
            )
            .unwrap_or_default();
        }
    }

    let request = match nip46::parse_request(&frame.payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse NIP-46 request: {e}");
            return nip46::build_error_response("unknown", -3, "invalid JSON-RPC request")
                .unwrap_or_default();
        }
    };
    drop(frame);

    handle_parsed_request(
        request,
        master_secret,
        master_label,
        master_mode,
        master_slot,
        secp,
        display,
        buttons,
        policy_engine,
        identity_caches,
        client_pubkey,
        nvs,
        personas,
    )
}

/// How the physical approval for a request is being obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Put the card up and block here until the operator answers. The USB
    /// paths use this: the host is synchronously waiting on the reply frame,
    /// so deferring would buy nothing.
    Interactive,
    /// Never block. Return [`Dispatch::NeedsApproval`] at the point the card
    /// would have gone up, so a caller with a loop to keep alive can hold the
    /// ask on screen itself and re-enter once the button is done (#64).
    Deferred,
    /// The operator has already completed the hold for this exact request.
    /// Skip the card and dispatch as approved.
    ButtonApproved,
}

/// What the operator is being asked to approve, enough to draw the card.
pub enum AskCard {
    Sign { requester: String, kind: u64 },
    Extension {
        master_label: String,
        method: String,
        preview: String,
    },
    /// A bearer note that arrived by gift wrap (relay.rs). No client is
    /// owed an answer; the rumor rides `DeferredAsk::event`.
    Receive { title: String },
}

/// An ask handed back to a deferring caller, and handed in again once the
/// hold completes. It carries the request itself so nothing is re-parsed,
/// including `sign_event`'s already-extracted event (its `params` were taken
/// on the way in, so the request alone would no longer be dispatchable).
pub struct DeferredAsk {
    pub card: AskCard,
    pub request: nip46::Nip46Request,
    pub event: Option<UnsignedEvent>,
}

/// Outcome of a dispatch attempt.
pub enum Dispatch {
    /// A response to send, whatever it says.
    Answered(String),
    /// Nothing was done: this request needs a physical approval the caller
    /// asked to obtain for itself. Re-enter [`dispatch`] with the same ask
    /// and [`ApprovalDecision::ButtonApproved`] once the hold completes.
    NeedsApproval(Box<DeferredAsk>),
}

/// Dispatch an already-parsed request, blocking for any approval it needs.
///
/// Encrypted transports use this entry point so the decrypted JSON buffer can
/// be released before signing. The old frame entry point remains for plaintext
/// USB compatibility and forwards here after one parse.
#[allow(clippy::too_many_arguments)]
pub fn handle_parsed_request(
    request: nip46::Nip46Request,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    personas: &mut Vec<crate::personas::LoadedPersona>,
) -> String {
    match dispatch(
        request,
        None,
        master_secret,
        master_label,
        master_mode,
        master_slot,
        secp,
        display,
        buttons,
        policy_engine,
        identity_caches,
        client_pubkey,
        nvs,
        personas,
        ApprovalDecision::Interactive,
    ) {
        Dispatch::Answered(json) => json,
        // Unreachable: only a Deferred caller is ever handed an ask back.
        Dispatch::NeedsApproval(ask) => {
            log::error!("interactive dispatch deferred an approval; refusing");
            build_error_json(&ask.request.id, -4, "internal approval error")
        }
    }
}

/// Dispatch an already-parsed request under an explicit approval decision.
///
/// `prepared_event` re-supplies `sign_event`'s event when resuming a deferred
/// ask; pass `None` for a fresh request.
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    request: nip46::Nip46Request,
    prepared_event: Option<UnsignedEvent>,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    personas: &mut Vec<crate::personas::LoadedPersona>,
    approval: ApprovalDecision,
) -> Dispatch {
    let mut deferred: Option<Box<DeferredAsk>> = None;
    let json = dispatch_inner(
        request,
        prepared_event,
        master_secret,
        master_label,
        master_mode,
        master_slot,
        secp,
        display,
        buttons,
        policy_engine,
        identity_caches,
        client_pubkey,
        nvs,
        personas,
        approval,
        &mut deferred,
    );
    match deferred {
        Some(ask) => Dispatch::NeedsApproval(ask),
        None => Dispatch::Answered(json),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_inner(
    mut request: nip46::Nip46Request,
    prepared_event: Option<UnsignedEvent>,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<crate::identity_cache::IdentityCache>,
    client_pubkey: Option<&[u8; 32]>,
    // Registry access for the storage-full refusal on derivation and for the
    // remove/rename extensions, which mutate the persisted registry directly.
    // Every path here is behind the pre-dispatch policy gates above the match.
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    personas: &mut Vec<crate::personas::LoadedPersona>,
    approval: ApprovalDecision,
    // Set instead of answering when `approval` is `Deferred` and the request
    // reaches a point that would have put a card up. The returned String is
    // ignored in that case.
    deferred: &mut Option<Box<DeferredAsk>>,
) -> String {
    // Enforce the ceiling we advertise in FIRMWARE_INFO, before anything
    // allocates at signing size.
    //
    // Sited here, at the one point every transport funnels through, rather
    // than on the individual entry paths. USB plaintext, USB encrypted and
    // relay all reach dispatch by different routes, and only some of them had
    // any size guard: response_transportable covers the encrypted and relay
    // RESPONSE, but nothing bounded the request on the way in, on any path.
    //
    // Both failures this prevents were measured on a V4 on 2026-08-06. Over
    // USB it signed 28672 bytes of content and then PANICKED on 32000, which
    // MAX_PAYLOAD_SIZE (32768) admits without complaint. Over the relay it
    // signed 16384 and then panicked on 20480, leaving the breadcrumb
    // "relay inbound event (heap 130k)" — with 130 KB still free, so this is
    // not a plain out-of-memory, and a size ceiling is the reliable defence
    // rather than a heap threshold.
    //
    // The allowance over MAX_SIGN_BYTES covers the event's own JSON
    // scaffolding — pubkey, created_at, kind, tags — which wraps the content.
    //
    // params[0] arrives in one of two encodings and BOTH must be measured. The
    // object form used to return None from as_str() and take `unwrap_or(0)`,
    // which skipped this guard entirely: the only thing standing in front of it
    // was the pre-parse budget in relay.rs, and nothing at all on the USB path.
    // Its ceiling is higher because it costs no unescape pass, not because it is
    // unbounded.
    if request.method == "sign_event" || request.method == SIGN_EVENT_COMPACT {
        let (event_bytes, limit) = match request.params.first() {
            Some(Value::String(s)) => (
                s.len(),
                crate::board::MAX_SIGN_BYTES + heartwood_common::types::SIGN_RESPONSE_OVERHEAD,
            ),
            Some(Value::Object(object)) => {
                // Measure the parts that carry size, rather than re-serialising
                // the event just to length it: that copy is the cost this whole
                // guard exists to avoid.
                let content = object
                    .get("content")
                    .and_then(Value::as_str)
                    .map(str::len)
                    .unwrap_or(0);
                let tags = object
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|tags| {
                        tags.iter()
                            .flat_map(|tag| tag.as_array().into_iter().flatten())
                            .filter_map(Value::as_str)
                            .map(str::len)
                            .sum::<usize>()
                    })
                    .unwrap_or(0);
                // Same rule as the pre-parse budget in relay.rs, and it must stay
                // the same: an object that still wants the full event echoed back
                // pays the reply allocation, so it gets the standard ceiling.
                let ceiling = if request.method == SIGN_EVENT_COMPACT {
                    crate::board::MAX_SIGN_BYTES_OBJECT
                } else {
                    crate::board::MAX_SIGN_BYTES
                };
                (
                    content.saturating_add(tags),
                    ceiling + heartwood_common::types::SIGN_RESPONSE_OVERHEAD,
                )
            }
            _ => (0, crate::board::MAX_SIGN_BYTES),
        };
        if event_bytes > limit {
            log::warn!(
                "sign_event event is {event_bytes} B; this board signs at most {limit} B"
            );
            return nip46::build_error_response(
                &request.id,
                -4,
                "event is too large for this signer",
            )
            .unwrap_or_default();
        }
    }

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
    let sign_event = if let Some(event) = prepared_event {
        // Resuming a deferred ask: `params` was emptied when the event was
        // parsed on the first pass, so the event comes back in with the ask
        // rather than being parsed a second time.
        Some(Ok(event))
    } else if matches!(method, nip46::Nip46Method::SignEvent) {
        // Parse once, by value, then release the stringified event before any
        // approval UI, signing or response construction begins.
        Some(nip46::parse_unsigned_event_owned(std::mem::take(
            &mut request.params,
        )))
    } else {
        None
    };
    let event_kind = sign_event
        .as_ref()
        .and_then(|event| event.as_ref().ok())
        .map(|event| event.kind);

    // Determine the client pubkey for policy lookups.
    // In encrypted mode (passthrough), it comes from the frame header.
    // In legacy mode, the bridge injects `_client_pubkey` into the JSON.
    let client_hex = if let Some(pk) = client_pubkey {
        heartwood_common::hex::hex_encode(pk)
    } else {
        // Legacy mode — bridge injects the relay event author as _client_pubkey.
        request.legacy_client_pubkey.take().unwrap_or_default()
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
    // Bearer-note disclosure and destruction are pinned always-ask: naming
    // them in a slot policy must never silence the button (the note-locker
    // goal doc's recorded decision — cheap to relax later, impossible to
    // un-leak). The pin runs the SAME pre-dispatch gate below, so Deferred
    // callers hold the card exactly like any other extension ask.
    let tier = if method.always_requires_button() && is_note_method(&method) {
        heartwood_common::policy::ApprovalTier::ButtonRequired
    } else {
        tier
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

    // Zero-trust USB (FW-M2): with a bridge secret provisioned, an
    // unauthenticated plaintext-USB peer (`has_client == false`) must not use
    // the master as a NIP-44/04 decrypt oracle nor mutate the persisted
    // persona registry — those need SESSION_AUTH first. A device with NO
    // bridge secret deliberately keeps this open direct-USB tier: a locally
    // cabled app is then the whole trust anchor (physical-possession
    // semantics), which the tethered setup flows rely on.
    if !has_client
        && !policy_engine.bridge_authenticated
        && matches!(
            method,
            nip46::Nip46Method::Nip44Decrypt
                | nip46::Nip46Method::Nip04Decrypt
                | nip46::Nip46Method::HeartwoodDerive
                | nip46::Nip46Method::HeartwoodDerivePersona
                | nip46::Nip46Method::HeartwoodRemovePersona
                | nip46::Nip46Method::HeartwoodRenamePersona
                | nip46::Nip46Method::HeartwoodRecover
        )
        && crate::session::read_bridge_secret(nvs).is_some()
    {
        log::warn!(
            "{}: refused — bridge secret provisioned; USB channel needs SESSION_AUTH first",
            request.method
        );
        return build_error_json(&request.id, -1, "unauthorised");
    }

    // A ButtonRequired tier is meaningful only if the handler actually stops
    // for the button. Keep this single gate before dispatch so a new extension
    // cannot accidentally mutate state merely by omitting approval code from
    // its individual match arm. Strict v2 denials returned above never prompt.
    if remote_extension_requires_approval(has_client, &method, tier) {
        // A note card shows the money, not the method name: amount, mint
        // and (for send) the recipient, as the cable path already does.
        let note_card = if matches!(method, nip46::Nip46Method::HeartwoodPairWallet) {
            let label = pair_wallet_label(&request.params);
            Some(("PAIR NEW WALLET", format!("for '{label}'\nit will see your notes")))
        } else if is_note_method(&method) {
            let cmd = heartwood_common::note_cmd::note_cmd_for_method(&request.method, &request.params).ok();
            if let Some(refusal) = cmd.as_ref().and_then(crate::notes::relay_precheck) {
                if !matches!(approval, ApprovalDecision::ButtonApproved) {
                    return build_error_json(&request.id, -1, refusal);
                }
            }
            cmd.and_then(|cmd| crate::notes::relay_card(&cmd))
        } else {
            None
        };
        let preview = match note_card {
            Some((_, title)) => title,
            None => extension_approval_preview(&requester_label, &request.params),
        };
        match approval {
            ApprovalDecision::Deferred => {
                *deferred = Some(Box::new(DeferredAsk {
                    card: AskCard::Extension {
                        master_label: master_label.to_string(),
                        method: request.method.clone(),
                        preview,
                    },
                    request,
                    event: None,
                }));
                return String::new();
            }
            ApprovalDecision::ButtonApproved => {
                log::info!("{}: dispatching on a hold already completed", request.method);
            }
            ApprovalDecision::Interactive => {
                let result = crate::approval::run_approval_loop(
                    display,
                    buttons,
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
                if let Some(response) = extension_approval_failure(&request.id, result) {
                    log::info!("{}: physical approval denied or timed out", request.method);
                    crate::oled::show_result(display, "Not approved");
                    return response;
                }
                log::info!("{}: physically approved", request.method);
            }
        }
    }

    match request.method.as_str() {
        "sign_event" | SIGN_EVENT_COMPACT => {
            let event = match sign_event.expect("sign_event request must prepare an event") {
                Ok(event) => event,
                Err(e) => {
                    log::warn!("sign_event: bad event format: {e}");
                    return build_error_json(&request.id, -3, "bad event format");
                }
            };
            match tier {
                heartwood_common::policy::ApprovalTier::AutoApprove => {
                    log::info!("sign_event: auto-approved by policy");
                    crate::confirm::present(
                        display,
                        crate::confirm::Card {
                            requester: requester_label.clone(),
                            kind: event.kind,
                            auto: true,
                        },
                    );
                    match handle_auto_sign(master_secret, master_mode, secp, &request, event) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::OledNotify => {
                    crate::confirm::present(
                        display,
                        crate::confirm::Card {
                            requester: requester_label.clone(),
                            kind: event.kind,
                            auto: true,
                        },
                    );
                    match handle_auto_sign(master_secret, master_mode, secp, &request, event) {
                        Ok(json) => json,
                        Err(e) => build_error_json(&request.id, -4, &e),
                    }
                }
                heartwood_common::policy::ApprovalTier::ButtonRequired => {
                    if matches!(approval, ApprovalDecision::Deferred) {
                        *deferred = Some(Box::new(DeferredAsk {
                            card: AskCard::Sign {
                                requester: requester_label.clone(),
                                kind: event.kind,
                            },
                            request,
                            event: Some(event),
                        }));
                        return String::new();
                    }
                    let result = if matches!(approval, ApprovalDecision::ButtonApproved) {
                        sign_approved_event(
                            master_secret,
                            master_mode,
                            secp,
                            display,
                            &request,
                            &requester_label,
                            event,
                        )
                    } else {
                        handle_sign_event(
                            master_secret,
                            master_mode,
                            secp,
                            display,
                            buttons,
                            &request,
                            &requester_label,
                            event,
                        )
                    };
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
                        // The authority that matters for a rebind (DS-H2): can
                        // this slot sign RIGHT NOW. A stored signing grant whose
                        // method ceiling no longer lists sign_event is not
                        // currently exercisable and keeps the flash-only path.
                        let slot_can_sign =
                            slot.allowed_methods.iter().any(|m| m == "sign_event");
                        let old_pubkey = slot.current_pubkey.clone();
                        // #75: the bind must be durable before it is
                        // acknowledged. Snapshot the prior authority so a
                        // failed write can be undone rather than leaving the
                        // client holding a pairing the board has no key for.
                        let bind_snapshot = policy_engine.snapshot_slot_state(master_slot);
                        let mut bind_mutated = false;

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
                                bind_mutated = true;
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
                                //
                                // DS-H2: a slot whose policy currently includes
                                // sign_event must never SILENTLY re-bind to a
                                // new client key — the slot secret is a bearer
                                // credential, so a captured bunker URI would
                                // otherwise inherit the slot's whole approved
                                // signing authority with only a transient OLED
                                // flash. The swap now needs the same physical
                                // hold as any other authority grant. (Spec
                                // deviation, deliberate: connect-slots-design
                                // §"Connect Flow" specified the flash; the audit
                                // showed the flash is not an approval.)
                                if slot_can_sign {
                                    let preview = format!("rebind '{slot_label}'");
                                    match approval {
                                        ApprovalDecision::Deferred => {
                                            *deferred = Some(Box::new(DeferredAsk {
                                                card: AskCard::Extension {
                                                    master_label: master_label.to_string(),
                                                    method: request.method.clone(),
                                                    preview,
                                                },
                                                request,
                                                event: None,
                                            }));
                                            return String::new();
                                        }
                                        ApprovalDecision::ButtonApproved => {
                                            log::info!(
                                                "connect: slot {slot_index} rebind dispatching on a hold already completed"
                                            );
                                        }
                                        ApprovalDecision::Interactive => {
                                            let result = crate::approval::run_approval_loop(
                                                display,
                                                buttons,
                                                APPROVAL_TIMEOUT_SECS,
                                                |d, remaining| {
                                                    crate::oled::show_master_sign_request(
                                                        d,
                                                        master_label,
                                                        "connect",
                                                        None,
                                                        &preview,
                                                        remaining,
                                                    );
                                                },
                                            );
                                            if let Some(response) =
                                                extension_approval_failure(&request.id, result)
                                            {
                                                log::info!(
                                                    "connect: slot {slot_index} rebind denied or timed out"
                                                );
                                                crate::oled::show_result(display, "Not approved");
                                                return response;
                                            }
                                            log::info!(
                                                "connect: slot {slot_index} rebind physically approved"
                                            );
                                        }
                                    }
                                } else if was_signing {
                                    // Signing grant stored but not currently in
                                    // the method ceiling: keep the historic OLED
                                    // flash for the swap.
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
                                bind_mutated = true;
                            }
                        }

                        // Answer only once the bind is on flash. Before #75 a
                        // full NVS let `connect` report success while the slot
                        // kept no key, so the client believed it was paired and
                        // every later request failed as an unknown client.
                        if bind_mutated {
                            if let Err(reason) = persist_bind_or_rollback(
                                policy_engine,
                                nvs,
                                master_slot,
                                bind_snapshot,
                            ) {
                                return build_error_json(&request.id, -4, &reason);
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
            let nip46::DeriveParams { purpose, index } =
                match nip46::DeriveParams::from_params(&request.params) {
                    Ok(p) => p,
                    Err(e) => return build_error_json(&request.id, -3, e),
                };

            let cache = match identity_caches
                .iter_mut()
                .find(|c| c.master_slot == master_slot)
            {
                Some(c) => c,
                None => {
                    return build_error_json(&request.id, -4, "no identity cache for this master")
                }
            };

            let len_before = cache.identities.len();
            match cache.derive_and_cache(&derive_secret, purpose, index, None) {
                Ok(idx) => {
                    // Persist a NEW registry entry before answering, and fail
                    // the request when the write fails: the capacity pre-check
                    // counts entries, but a chunk write can still fail under
                    // blob-page pressure, and a success answer for an
                    // unpersisted identity evaporates at reboot (#67). The
                    // post-request sweep remains as a retry for strays only.
                    let pubkey = cache.identities[idx].public_key;
                    if !crate::personas::contains_pubkey(personas, &pubkey) {
                        if let Err(full) = crate::personas::capacity_check(nvs) {
                            if cache.identities.len() > len_before {
                                cache.identities.truncate(len_before);
                            }
                            log::warn!("heartwood_derive: refused — {full}");
                            return build_error_json(&request.id, -4, full);
                        }
                        let (purpose, index, name) = {
                            let id = &cache.identities[idx];
                            (id.purpose.clone(), id.index, id.persona_name.clone())
                        };
                        if let Err(e) = crate::personas::add(
                            nvs,
                            master_slot,
                            &purpose,
                            index,
                            name.as_deref(),
                            &pubkey,
                        ) {
                            if cache.identities.len() > len_before {
                                cache.identities.truncate(len_before);
                            }
                            log::warn!("heartwood_derive: registry write failed — {e}");
                            return build_error_json(&request.id, -4, e);
                        }
                        personas.push(crate::personas::LoadedPersona {
                            master_slot,
                            purpose,
                            index,
                            name,
                            pubkey,
                        });
                    }
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
            let nip46::PersonaParams { name, index } =
                match nip46::PersonaParams::from_params(&request.params) {
                    Ok(p) => p,
                    Err(e) => return build_error_json(&request.id, -3, e),
                };
            if let Err(e) = validate_persona_name(name) {
                return build_error_json(&request.id, -3, e);
            }
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

            let len_before = cache.identities.len();
            match cache.derive_and_cache(&derive_secret, &purpose, index, Some(name.to_string())) {
                Ok(idx) => {
                    // Same clean storage-full refusal as heartwood_derive:
                    // re-deriving an already-registered persona still succeeds
                    // (it is a lookup), only a NEW registry entry is refused.
                    // A new entry is persisted before answering and the
                    // request fails when the write fails (#67) — a success
                    // answer must mean the persona survives reboot.
                    let pubkey = cache.identities[idx].public_key;
                    if !crate::personas::contains_pubkey(personas, &pubkey) {
                        if let Err(full) = crate::personas::capacity_check(nvs) {
                            if cache.identities.len() > len_before {
                                cache.identities.truncate(len_before);
                            }
                            log::warn!("heartwood_derive_persona: refused — {full}");
                            return build_error_json(&request.id, -4, full);
                        }
                        let (reg_purpose, reg_index, reg_name) = {
                            let id = &cache.identities[idx];
                            (id.purpose.clone(), id.index, id.persona_name.clone())
                        };
                        if let Err(e) = crate::personas::add(
                            nvs,
                            master_slot,
                            &reg_purpose,
                            reg_index,
                            reg_name.as_deref(),
                            &pubkey,
                        ) {
                            if cache.identities.len() > len_before {
                                cache.identities.truncate(len_before);
                            }
                            log::warn!("heartwood_derive_persona: registry write failed — {e}");
                            return build_error_json(&request.id, -4, e);
                        }
                        personas.push(crate::personas::LoadedPersona {
                            master_slot,
                            purpose: reg_purpose,
                            index: reg_index,
                            name: reg_name,
                            pubkey,
                        });
                    }
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

        "heartwood_remove_persona" => {
            // Params: [persona pubkey hex]. Registry-only: the derivation tree
            // is untouched, so re-deriving the same purpose later reproduces
            // the identity. Gated like every mutating extension (unbound
            // remote clients never reach here; ButtonRequired tiers stop for
            // the physical button above).
            let pubkey_hex = match request.params.first().and_then(|v| v.as_str()) {
                Some(hex) if hex.len() == 64 => hex,
                _ => return build_error_json(&request.id, -3, "params[0] must be a persona pubkey (64-char hex)"),
            };
            let pubkey: [u8; 32] = match heartwood_common::hex::hex_decode(pubkey_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
            {
                Some(pk) => pk,
                None => return build_error_json(&request.id, -3, "params[0] must be a persona pubkey (64-char hex)"),
            };
            match crate::personas::remove_by_pubkey(nvs, &pubkey) {
                Ok(true) => {
                    if let Some(idx) = crate::personas::find_by_pubkey(personas, &pubkey) {
                        personas.remove(idx);
                    }
                    // Purge the cache too, or the post-request persistence
                    // loop re-adds the persona immediately. Sessions hold
                    // active-identity indices into this cache, so fix them up
                    // as the removal shifts entries.
                    if let Some(cache) = identity_caches
                        .iter_mut()
                        .find(|c| c.master_slot == master_slot)
                    {
                        if let Some(cidx) =
                            cache.identities.iter().position(|i| i.public_key == pubkey)
                        {
                            cache.identities.remove(cidx);
                            for session in policy_engine
                                .sessions
                                .iter_mut()
                                .filter(|s| s.master_slot == master_slot)
                            {
                                match session.active_identity {
                                    Some(ai) if ai == cidx => session.active_identity = None,
                                    Some(ai) if ai > cidx => {
                                        session.active_identity = Some(ai - 1)
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    nip46::build_result_response(&request.id, "{\"removed\":true}")
                        .unwrap_or_default()
                }
                Ok(false) => build_error_json(&request.id, -3, "no such persona"),
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_rename_persona" => {
            // Params: [persona pubkey hex, new name or empty to clear]. Label
            // only — purpose, index and pubkey are untouched.
            let pubkey_hex = match request.params.first().and_then(|v| v.as_str()) {
                Some(hex) if hex.len() == 64 => hex,
                _ => return build_error_json(&request.id, -3, "params[0] must be a persona pubkey (64-char hex)"),
            };
            let pubkey: [u8; 32] = match heartwood_common::hex::hex_decode(pubkey_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
            {
                Some(pk) => pk,
                None => return build_error_json(&request.id, -3, "params[0] must be a persona pubkey (64-char hex)"),
            };
            let raw_name = request
                .params
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if raw_name.len() > 64 {
                return build_error_json(&request.id, -3, "persona name too long (64 bytes max)");
            }
            let name = if raw_name.is_empty() { None } else { Some(raw_name) };
            match crate::personas::rename_by_pubkey(nvs, &pubkey, name) {
                Ok(true) => {
                    if let Some(idx) = crate::personas::find_by_pubkey(personas, &pubkey) {
                        personas[idx].name = name.map(|n| n.to_string());
                    }
                    if let Some(cache) = identity_caches
                        .iter_mut()
                        .find(|c| c.master_slot == master_slot)
                    {
                        if let Some(id) =
                            cache.identities.iter_mut().find(|i| i.public_key == pubkey)
                        {
                            id.persona_name = name.map(|n| n.to_string());
                        }
                    }
                    nip46::build_result_response(&request.id, "{\"renamed\":true}")
                        .unwrap_or_default()
                }
                Ok(false) => build_error_json(&request.id, -3, "no such persona"),
                Err(e) => build_error_json(&request.id, -4, e),
            }
        }

        "heartwood_switch" => {
            let nip46::SwitchParams { target, index_hint } =
                match nip46::SwitchParams::from_params(&request.params) {
                    Ok(p) => p,
                    Err(e) => return build_error_json(&request.id, -3, e),
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
            let nip46::RecoverParams { lookahead } =
                nip46::RecoverParams::from_params(&request.params);

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

        "heartwood_capabilities" => {
            // Extension discovery — handshake-level plumbing, answerable
            // before any slot binding (auto-approved, like ping). The stubbed
            // proof methods are deliberately absent: an advertised method is
            // a promise that it works.
            const METHODS: &[&str] = &[
                "connect",
                "ping",
                "get_public_key",
                "sign_event",
                "sign_event_compact",
                "nip44_encrypt",
                "nip44_decrypt",
                "nip04_encrypt",
                "nip04_decrypt",
                "switch_relays",
                "heartwood_capabilities",
                "heartwood_derive",
                "heartwood_derive_persona",
                "heartwood_remove_persona",
                "heartwood_rename_persona",
                "heartwood_switch",
                "heartwood_list_identities",
                "heartwood_recover",
                "heartwood_note_list",
                "heartwood_note_new",
                "heartwood_note_new_pair",
                "heartwood_note_confirm",
                "heartwood_note_discard",
                "heartwood_note_export",
                "heartwood_note_import",
                "heartwood_note_spent",
                "heartwood_note_send",
                "heartwood_note_trust",
                "heartwood_note_trusted",
                "heartwood_pair_wallet",
            ];
            nip46::build_capabilities_response(&request.id, METHODS).unwrap_or_default()
        }

        "heartwood_pair_wallet" => {
            // A wallet that is already bound mints a slot for another one.
            // The only unauthenticated way onto this device stays "none":
            // the caller proved a binding, and the owner held the button for
            // this specific card. The URI's secret is shown exactly once.
            if !has_client {
                return build_error_json(&request.id, -1, "unauthorised");
            }
            let label = pair_wallet_label(&request.params);
            let mut secret_bytes = [0u8; 32];
            crate::fill_random_strong(&mut secret_bytes);
            let secret_hex = hex_encode(&secret_bytes);
            secret_bytes.iter_mut().for_each(|b| *b = 0);
            let Some(slot_index) = policy_engine.create_slot(master_slot, label.clone(), secret_hex.clone()) else {
                return build_error_json(&request.id, -1, "no free slot");
            };
            if !policy_engine.persist_slots(nvs, master_slot) {
                // A slot that would not survive a reboot is one the other
                // wallet binds to and then loses: refuse rather than mislead.
                policy_engine.revoke_slot(master_slot, slot_index);
                return build_error_json(&request.id, -1, "storage_full");
            }
            let master_hex = match secp256k1::Keypair::from_seckey_slice(secp, master_secret) {
                Ok(kp) => hex_encode(&kp.x_only_public_key().0.serialize()),
                Err(_) => return build_error_json(&request.id, -1, "invalid master secret"),
            };
            let relays = crate::net_config_store::read_net_config(nvs)
                .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok())
                .map(|cfg| cfg.relays)
                .unwrap_or_default();
            let relay_query = relays
                .iter()
                .map(|r| format!("&relay={r}"))
                .collect::<String>();
            let uri = format!("bunker://{master_hex}?secret={secret_hex}{relay_query}");
            log::info!("{m}: slot {slot_index} '{label}' minted for another wallet", m = "heartwood_pair_wallet");
            let body = serde_json::json!({"ok": true, "slot_index": slot_index, "label": label, "uri": uri});
            nip46::build_result_response(&request.id, &body.to_string()).unwrap_or_default()
        }

        m if m.starts_with("heartwood_note_") => {
            // Direct USB NIP-46 (no client) has its own surface for the
            // locker — the NOTE_CMD frame, where the blocking approval
            // belongs. The relay methods exist for bound clients only.
            if !has_client {
                log::warn!("{m}: refused — note methods serve bound clients (USB uses NOTE_CMD frames)");
                return build_error_json(&request.id, -1, "unauthorised");
            }
            match heartwood_common::note_cmd::note_cmd_for_method(m, &request.params) {
                Err(e) => build_error_json(&request.id, -3, e),
                Ok(cmd) => {
                    // Approval for the gated methods happened in the
                    // pre-dispatch gate above (pinned ButtonRequired);
                    // lifecycle rules still apply inside. Send seals the
                    // note as the served identity, so the client relays an
                    // opaque wrap and never sees k1.
                    let mut wrap = |secret: &[u8; 32],
                                    meta: &heartwood_common::note_store::NoteMeta,
                                    to: &[u8; 32]| {
                        crate::relay::seal_note_wrap(secp, master_secret, secret, meta, to)
                    };
                    let response =
                        crate::notes::run_note_cmd_approved(&cmd.to_string(), Some(&mut wrap));
                    if response.get("ok") == Some(&serde_json::Value::Bool(true)) {
                        nip46::build_result_response(&request.id, &response.to_string())
                            .unwrap_or_default()
                    } else {
                        let code = response
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("bad_request");
                        build_error_json(&request.id, -1, code)
                    }
                }
            }
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
    event: UnsignedEvent,
) -> Result<String, String> {
    let signed = do_sign(
        event,
        master_secret,
        master_mode,
        secp,
        request.heartwood.as_ref(),
    )?;
    build_sign_reply(request, &signed)
}

// ---------------------------------------------------------------------------
// sign_event (interactive, button-required)
// ---------------------------------------------------------------------------

fn handle_sign_event(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    request: &nip46::Nip46Request,
    requester_label: &str,
    event: UnsignedEvent,
) -> String {
    let (kind, content_preview) = nip46::event_display_summary(&event, 50);

    // Show the signing request on the OLED and wait for button approval.
    // The countdown bar updates every second; the approval module handles
    // "Hold 2s..." feedback while the button is held down.
    let result = crate::approval::run_approval_loop(
        display,
        buttons,
        APPROVAL_TIMEOUT_SECS,
        |d, remaining| {
            crate::oled::show_sign_request(d, requester_label, kind, &content_preview, remaining);
        },
    );

    match result {
        ApprovalResult::Approved => sign_approved_event(
            master_secret,
            master_mode,
            secp,
            display,
            request,
            requester_label,
            event,
        ),
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

/// Sign an event whose physical approval is already in hand.
///
/// This is the tail the blocking loop runs once the operator completes the
/// hold, and the same tail the non-blocking card runs when its own hold
/// completes (#64) — one signing path, so the two approval styles cannot
/// drift apart in what they do after the button.
fn sign_approved_event(
    master_secret: &[u8; 32],
    master_mode: MasterMode,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    request: &nip46::Nip46Request,
    requester_label: &str,
    event: UnsignedEvent,
) -> String {
    let (kind, _) = nip46::event_display_summary(&event, 50);
    log::info!("sign_event: approved");
    crate::oled::show_signing(display);
    match do_sign(
        event,
        master_secret,
        master_mode,
        secp,
        request.heartwood.as_ref(),
    ) {
        Ok(signed) => match build_sign_reply(request, &signed) {
            Ok(json) => {
                crate::confirm::present(
                    display,
                    crate::confirm::Card {
                        requester: requester_label.to_string(),
                        kind,
                        auto: false,
                    },
                );
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

// ---------------------------------------------------------------------------
// do_sign — runs inline on the main thread
// ---------------------------------------------------------------------------

fn do_sign(
    mut event: UnsignedEvent,
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
    event.pubkey = hex_pubkey;

    let event_id_bytes = nip46::compute_event_id(&event);

    let sig_bytes = crate::sign::sign_hash(secp, &signing_secret, &event_id_bytes)
        .map_err(|e| e.to_string())?;

    signing_secret.zeroize();

    let event_id_hex = hex_encode(&event_id_bytes);
    let sig_hex = hex_encode(&sig_bytes);

    Ok(SignedEvent {
        id: event_id_hex,
        pubkey: event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
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
    let nip46::CryptoParams { peer_pubkey: peer_hex, payload: plaintext } =
        match nip46::CryptoParams::from_params(&request.params) {
            Ok(p) => p,
            Err(e) => return build_error_json(&request.id, -3, e),
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
    let nip46::CryptoParams { peer_pubkey: peer_hex, payload: ciphertext_b64 } =
        match nip46::CryptoParams::from_params(&request.params) {
            Ok(p) => p,
            Err(e) => return build_error_json(&request.id, -3, e),
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
    let nip46::CryptoParams { peer_pubkey: peer_hex, payload: plaintext } =
        match nip46::CryptoParams::from_params(&request.params) {
            Ok(p) => p,
            Err(e) => return build_error_json(&request.id, -3, e),
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
    let nip46::CryptoParams { peer_pubkey: peer_hex, payload: ciphertext } =
        match nip46::CryptoParams::from_params(&request.params) {
            Ok(p) => p,
            Err(e) => return build_error_json(&request.id, -3, e),
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

/// Generate a random 32-byte nonce. Used as the NIP-44 per-message nonce —
/// routed through `fill_random` so the radio-off USB tier still gets a true
/// entropy source.
fn random_nonce_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    crate::fill_random(&mut nonce);
    nonce
}

/// Generate a random 16-byte IV for per-message NIP-04 encryption. Same
/// entropy-source guarantee as `random_nonce_32`.
fn random_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    crate::fill_random(&mut iv);
    iv
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a NIP-46 error response JSON string.
/// Falls back to an empty string on serialisation failure (should never occur).
/// The label a new slot is minted under, from `params[0].label`, bounded
/// and ASCII so the card and the slot list stay legible.
fn pair_wallet_label(params: &[Value]) -> String {
    let raw = params
        .first()
        .and_then(|p| p.get("label"))
        .and_then(|v| v.as_str())
        .unwrap_or("another wallet");
    let clean: String = raw.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(24).collect();
    if clean.trim().is_empty() { "another wallet".to_string() } else { clean.trim().to_string() }
}

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
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            bound_identity: None,
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
        for method_name in [
            "connect",
            "ping",
            "get_public_key",
            "switch_relays",
            "heartwood_capabilities",
        ] {
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

        for method_name in ["connect", "ping", "get_public_key", "heartwood_capabilities"] {
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
