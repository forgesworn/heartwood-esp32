// firmware/src/nip46_gates.rs
//
// The handler's pure pre-dispatch decisions: which requests an unbound relay
// peer may not make, which remote extensions must cross the physical-approval
// boundary before their match arm runs, and which requests may change slot
// state (so the caller takes a rollback snapshot first).
//
// No esp-idf dependencies on purpose: common's host tests compile this file
// verbatim (`#[path]`, beside firmware/src/policy.rs), so its tests run in CI.
// The handler's own test module only builds for the device target, and the
// firmware test target as a whole does not build there (the host-only
// allocation and wipe shims are missing), so tests kept in nip46_handler.rs
// never run.

use heartwood_common::nip46;

/// A public relay is not an approval queue. Only a client already bound to a
/// slot may make the device wait for a physical decision; otherwise strangers
/// can serialize fresh keys/ids into an endless series of 30-second prompts.
/// `heartwood_list_identities` joins the denial set not for the button but
/// because it enumerates the per-boot identity cache (persona purposes/names,
/// child npubs) — metadata an unbound relay peer has no business reading
/// (FW-L5). The bearer-note locker's relay methods all require a bound slot
/// too (the disclosure and destructive ones are additionally pinned
/// ButtonRequired, see the pin in dispatch_inner).
pub(crate) fn unbound_remote_request_denied(
    has_client: bool,
    client_is_bound: bool,
    method: &nip46::Nip46Method,
) -> bool {
    has_client
        && !client_is_bound
        && (matches!(method, nip46::Nip46Method::SignEvent)
            || matches!(method, nip46::Nip46Method::HeartwoodListIdentities)
            || method.always_requires_button()
            || method.is_note_method())
}

/// Remote Heartwood extensions that mutate identity state must cross one
/// physical-approval boundary before their match arm can run. `sign_event` owns
/// its richer event-specific prompt, while direct USB (`has_client == false`)
/// retains physical-possession semantics. Standard crypto methods are not
/// included here: an unbound remote crypto request remains refused below.
pub(crate) fn remote_extension_requires_approval(
    has_client: bool,
    method: &nip46::Nip46Method,
    tier: heartwood_common::policy::ApprovalTier,
) -> bool {
    has_client
        && !matches!(method, nip46::Nip46Method::SignEvent)
        && method.always_requires_button()
        && tier == heartwood_common::policy::ApprovalTier::ButtonRequired
}

/// Whether a remote request can change durable slot authority when approved.
///
/// Callers use this before dispatch to take a rollback snapshot without cloning
/// the slot table for every routine auto-sign request. `owner_pairing` is
/// whether the requesting client's slot is an owner pairing
/// (`owner_pairing::is_owner_pairing`): there a persona derive may record the
/// new identity for the client (spec 6, Rule D).
pub(crate) fn request_may_mutate_slot_state(
    request: &nip46::Nip46Request,
    tier: heartwood_common::policy::ApprovalTier,
    owner_pairing: bool,
) -> bool {
    match nip46::Nip46Method::from_str(&request.method) {
        // One-hold pairing (spec 4.5): the setup hold grants, narrow narrows,
        // and a derive on an owner pairing records (Rule D).
        nip46::Nip46Method::HeartwoodApproveBundle
        | nip46::Nip46Method::HeartwoodOwnerNarrow => true,
        nip46::Nip46Method::HeartwoodDerivePersona => owner_pairing,
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

#[cfg(test)]
mod tests {
    use super::{remote_extension_requires_approval, request_may_mutate_slot_state, unbound_remote_request_denied};
    use heartwood_common::nip46;
    use heartwood_common::policy::ApprovalTier;

    const CLIENT_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111"; // pragma: allow-secret — fixed test vector

    #[test]
    fn unbound_remote_clients_cannot_enter_physical_approval_loops() {
        for method_name in ["sign_event", "heartwood_derive", "heartwood_switch", "heartwood_approve_bundle"] {
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
    fn remote_mutating_extensions_cross_the_central_approval_gate() {
        for method_name in [
            "heartwood_derive",
            "heartwood_derive_persona",
            "heartwood_recover",
            "heartwood_switch",
        ] {
            let method = nip46::Nip46Method::from_str(method_name);
            assert!(
                remote_extension_requires_approval(true, &method, ApprovalTier::ButtonRequired),
                "{method_name} escaped the central remote approval gate",
            );
        }
    }

    #[test]
    fn central_extension_gate_excludes_usb_sign_event_and_remote_crypto() {
        let derive = nip46::Nip46Method::HeartwoodDerive;
        assert!(!remote_extension_requires_approval(false, &derive, ApprovalTier::ButtonRequired));
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
        // An automatic tier never raises the extension card.
        assert!(!remote_extension_requires_approval(true, &derive, ApprovalTier::AutoApprove));
    }

    fn request(method: &str, params: serde_json::Value) -> nip46::Nip46Request {
        serde_json::from_value(serde_json::json!({ "id": "x", "method": method, "params": params })).unwrap()
    }

    #[test]
    fn slot_mutation_snapshot_is_needed_only_for_connect_binding_or_first_sign() {
        let connect = request("connect", serde_json::json!([CLIENT_HEX, "22".repeat(32)]));
        assert!(request_may_mutate_slot_state(&connect, ApprovalTier::AutoApprove, false));

        let reconnect_without_secret = request("connect", serde_json::json!([CLIENT_HEX]));
        assert!(!request_may_mutate_slot_state(&reconnect_without_secret, ApprovalTier::AutoApprove, false));

        let sign = request("sign_event", serde_json::json!([{}]));
        assert!(request_may_mutate_slot_state(&sign, ApprovalTier::ButtonRequired, false));
        assert!(!request_may_mutate_slot_state(&sign, ApprovalTier::AutoApprove, false));

        // One-hold pairing (spec 4.5): the bundle and narrow always may; a
        // persona derive only on an owner pairing (Rule D).
        for (method, owner, expected) in [
            ("heartwood_approve_bundle", false, true),
            ("heartwood_owner_narrow", false, true),
            ("heartwood_owner_status", true, false),
            ("heartwood_derive_persona", true, true),
            ("heartwood_derive_persona", false, false),
        ] {
            assert_eq!(
                request_may_mutate_slot_state(&request(method, serde_json::json!([])), ApprovalTier::AutoApprove, owner),
                expected,
                "{method} owner={owner}"
            );
        }
    }
}
