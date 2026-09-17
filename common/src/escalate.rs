// common/src/escalate.rs
//
// Pure C4 escalation semantics (2026-08-14-c4-c5-escalation-audit-schemas.md
// §1.4): the resolve_approval verdict table and the C5 outcome mapping.
// Host-tested here; the firmware's relay loop supplies the state (park queue,
// transient allows) and calls these to decide.

use crate::policy::ApprovalTier;

/// Seconds the device holds a parked request (the notice's `park-ttl`).
pub const PARK_TTL_SECS: u64 = 600;
/// Default approve-once validity window (schema §1.4).
pub const WINDOW_DEFAULT_SECS: u64 = 600;
/// Maximum approve-once validity window (schema §1.4).
pub const WINDOW_MAX_SECS: u64 = 3600;

/// A guardian verdict action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictAction {
    ApproveOnce,
    ApproveRemember,
    Deny,
}

/// Parse the wire `action` string; anything else is a caller error.
pub fn parse_verdict_action(action: &str) -> Option<VerdictAction> {
    match action {
        "approve-once" => Some(VerdictAction::ApproveOnce),
        "approve-remember" => Some(VerdictAction::ApproveRemember),
        "deny" => Some(VerdictAction::Deny),
        _ => None,
    }
}

/// Clamp the approve-once window to the schema bounds: absent → 600 s,
/// ceiling 3600 s, and a zero survives as the default rather than a
/// zero-length (useless) window.
pub fn clamp_window(window: Option<u64>) -> u64 {
    match window {
        None | Some(0) => WINDOW_DEFAULT_SECS,
        Some(secs) => secs.min(WINDOW_MAX_SECS),
    }
}

/// The `applied` value reported by resolve_approval (schema §1.4 mapping,
/// fixed at Phase 4 build): the strongest effect that actually happened.
/// `completed` — the parked request was signed and its response published;
/// `window` — a transient allow was installed (park expired, or a live
/// completion could not run); `policy` — the remembered policy was written
/// but nothing completed; `none` — nothing could be applied (deny, or an
/// unknown park after a reboot cleared even the expiry record). Never an
/// error in any case.
pub fn applied_value(
    action: VerdictAction,
    completed: bool,
    allow_installed: bool,
    policy_written: bool,
) -> &'static str {
    match action {
        VerdictAction::ApproveOnce => {
            if completed {
                "completed"
            } else if allow_installed {
                "window"
            } else {
                "none"
            }
        }
        VerdictAction::ApproveRemember => {
            if completed {
                "completed"
            } else if policy_written {
                "policy"
            } else {
                "none"
            }
        }
        VerdictAction::Deny => "none",
    }
}

/// C5 outcome for a policy-decided request on a dependant-tagged persona
/// (schema §2): `auto-*` are silent policy decisions; `approved`/`denied`
/// cover button- and C4-resolved interactive outcomes. Returns `None` when
/// the result is not a policy decision at all (e.g. a signing failure after
/// an auto-approve) — those emit nothing.
///
/// `response_error` is the NIP-46 error string, if the response carried one.
/// `park_completion` marks a dispatch that completes a C4-approved park, so
/// its silent tier still records as `approved`.
pub fn audit_outcome(
    tier: ApprovalTier,
    response_error: Option<&str>,
    park_completion: bool,
) -> Option<&'static str> {
    match tier {
        ApprovalTier::Denied => Some("auto-denied"),
        ApprovalTier::AutoApprove | ApprovalTier::OledNotify => match response_error {
            None if park_completion => Some("approved"),
            None => Some("auto-approved"),
            Some(_) => None,
        },
        ApprovalTier::ButtonRequired => match response_error {
            None => Some("approved"),
            Some("user denied") | Some("timeout") => Some("denied"),
            Some(_) => None,
        },
    }
}

/// True for registry personas that belong to a dependant: the C1 manifest
/// derives them under `dependant-N…` names, so the purpose is
/// `nostr:persona:dependant-…`. The C5 rail emits only for these.
pub fn is_dependant_purpose(purpose: &str) -> bool {
    purpose.starts_with("nostr:persona:dependant-")
}

/// Where an inbound relay request goes once its tier and its slot's flags are
/// known (schema §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Straight to the handler: nothing physical is owed, or the handler is
    /// answering a denial.
    Dispatch,
    /// The method's card goes up on the device and the loop carries on (#64).
    Card,
    /// Park it and notify the guardian: nobody is expected to be at the board.
    Park,
}

/// Route one request. `tier` is the planned gate tier; `pinned` marks a method
/// whose own card no slot policy may silence
/// ([`crate::nip46::Nip46Method::pinned_physical`]); `escalate` is the slot
/// flag.
///
/// The pin is read here and not only inside the handler because the two must
/// agree about what is physical. A pinned method whose slot policy lifted the
/// tier still owes a card, so on an `escalate` slot it belongs with the
/// guardian like any other physical ask: otherwise it would fall through to a
/// card on a board nobody is standing at (#160).
pub fn route_request(tier: ApprovalTier, pinned: bool, escalate: bool) -> Route {
    if tier == ApprovalTier::Denied {
        return Route::Dispatch;
    }
    if tier != ApprovalTier::ButtonRequired && !pinned {
        return Route::Dispatch;
    }
    if escalate {
        Route::Park
    } else {
        Route::Card
    }
}

/// What the guardian approved, against what the parked request still is.
///
/// The verdict names a park id, and the park id is the request event's own id,
/// so an approve-once is an approval of ONE request: this client, this
/// method-or-kind, this identity. The tuple is carried here rather than
/// assumed so the rule is testable, and so a guardian app that one day names a
/// method or an identity in the verdict itself meets the same check.
#[derive(Debug, Clone, Copy)]
pub struct ParkVerdict<'a> {
    /// The client the notice named, and the client the park is from.
    pub approved_client_hex: &'a str,
    pub park_client_hex: &'a str,
    /// [`crate::nip59::method_or_kind_key`] of each.
    pub approved_key: &'a str,
    pub park_key: &'a str,
    /// The identity each names; `None` when the request uses no identity key.
    pub approved_identity: Option<&'a [u8; 32]>,
    pub park_identity: Option<&'a [u8; 32]>,
    /// How long the park has been held, against [`PARK_TTL_SECS`].
    pub held_secs: u64,
}

/// How a guardian verdict may be applied to the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkCompletion {
    /// Dispatch the parked request as approved. The verdict IS the physical
    /// approval of this one request, so it answers the method's own card too
    /// and the relay loop never waits on a press nobody is there to give.
    Approved,
    /// Do not dispatch. Install the approve-once window so the client's own
    /// retry is answered, and report `window` rather than `completed`.
    /// `reason` is the log line.
    Window { reason: &'static str },
}

/// Decide what an approve verdict does to its park.
///
/// `Approved` is deliberately the narrow case: it releases exactly the request
/// the guardian was shown and nothing else. Anything that does not match (a
/// different client, a different method or kind, a different identity, or a
/// park that outlived its TTL before the verdict arrived) falls back to the
/// window, which grants no card of its own: the client asks again and meets
/// the gate afresh (and a pinned method meets its card, or parks again).
pub fn park_completion(verdict: &ParkVerdict<'_>) -> ParkCompletion {
    if verdict.held_secs >= PARK_TTL_SECS {
        return ParkCompletion::Window { reason: "park expired before the verdict arrived" };
    }
    if verdict.approved_client_hex != verdict.park_client_hex {
        return ParkCompletion::Window { reason: "verdict names another client" };
    }
    if verdict.approved_key != verdict.park_key {
        return ParkCompletion::Window { reason: "verdict names another method or kind" };
    }
    if verdict.approved_identity != verdict.park_identity {
        return ParkCompletion::Window { reason: "verdict names another identity" };
    }
    ParkCompletion::Approved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_actions_parse_exactly() {
        assert_eq!(parse_verdict_action("approve-once"), Some(VerdictAction::ApproveOnce));
        assert_eq!(
            parse_verdict_action("approve-remember"),
            Some(VerdictAction::ApproveRemember)
        );
        assert_eq!(parse_verdict_action("deny"), Some(VerdictAction::Deny));
        assert_eq!(parse_verdict_action("approve"), None);
        assert_eq!(parse_verdict_action(""), None);
    }

    #[test]
    fn window_clamps_to_schema_bounds() {
        assert_eq!(clamp_window(None), 600);
        assert_eq!(clamp_window(Some(0)), 600);
        assert_eq!(clamp_window(Some(30)), 30);
        assert_eq!(clamp_window(Some(3600)), 3600);
        assert_eq!(clamp_window(Some(86400)), 3600);
    }

    #[test]
    fn applied_mapping_matches_the_ratified_table() {
        use VerdictAction::*;
        // Live park, completion ran.
        assert_eq!(applied_value(ApproveOnce, true, true, false), "completed");
        // Expired park (or failed completion): the allow alone.
        assert_eq!(applied_value(ApproveOnce, false, true, false), "window");
        // Unknown park after a reboot: nothing could be installed.
        assert_eq!(applied_value(ApproveOnce, false, false, false), "none");
        assert_eq!(applied_value(ApproveRemember, true, false, true), "completed");
        assert_eq!(applied_value(ApproveRemember, false, false, true), "policy");
        assert_eq!(applied_value(ApproveRemember, false, false, false), "none");
        assert_eq!(applied_value(Deny, false, false, false), "none");
        assert_eq!(applied_value(Deny, true, false, false), "none");
    }

    #[test]
    fn audit_outcomes_cover_all_four_values_and_skip_non_decisions() {
        use ApprovalTier::*;
        assert_eq!(audit_outcome(Denied, Some("unauthorised"), false), Some("auto-denied"));
        assert_eq!(audit_outcome(AutoApprove, None, false), Some("auto-approved"));
        assert_eq!(audit_outcome(OledNotify, None, false), Some("auto-approved"));
        assert_eq!(audit_outcome(AutoApprove, None, true), Some("approved"));
        assert_eq!(audit_outcome(ButtonRequired, None, false), Some("approved"));
        assert_eq!(audit_outcome(ButtonRequired, Some("user denied"), false), Some("denied"));
        assert_eq!(audit_outcome(ButtonRequired, Some("timeout"), false), Some("denied"));
        // Failures are not policy decisions: nothing is emitted.
        assert_eq!(audit_outcome(AutoApprove, Some("signing failed"), false), None);
        assert_eq!(
            audit_outcome(ButtonRequired, Some("signing/derivation failure"), false),
            None
        );
    }

    #[test]
    fn dependant_purposes_detected_by_prefix() {
        assert!(is_dependant_purpose("nostr:persona:dependant-0-np"));
        assert!(is_dependant_purpose("nostr:persona:dependant-12-persona-1"));
        assert!(!is_dependant_purpose("nostr:persona:natural-person"));
        assert!(!is_dependant_purpose("nostr:persona:gaming"));
        // A guardian persona merely mentioning the word is not a dependant.
        assert!(!is_dependant_purpose("nostr:persona:my-dependant-notes"));
    }

    // ---- #160: a note method on an escalate slot ----------------------

    const CLIENT: &str = "aa";
    const OTHER_CLIENT: &str = "bb";
    const IDENTITY: [u8; 32] = [0x11; 32];
    const OTHER_IDENTITY: [u8; 32] = [0x22; 32];

    fn note_send_park() -> ParkVerdict<'static> {
        ParkVerdict {
            approved_client_hex: CLIENT,
            park_client_hex: CLIENT,
            approved_key: "heartwood_note_send",
            park_key: "heartwood_note_send",
            approved_identity: Some(&IDENTITY),
            park_identity: Some(&IDENTITY),
            held_secs: 4,
        }
    }

    #[test]
    fn a_note_method_on_an_escalate_slot_parks_instead_of_carding() {
        use ApprovalTier::*;
        // The pin makes it physical whatever the slot policy says, so an
        // escalate slot sends it to the guardian rather than to a board
        // nobody is standing at.
        assert_eq!(route_request(ButtonRequired, true, true), Route::Park);
        assert_eq!(route_request(AutoApprove, true, true), Route::Park);
        // A denial is still answered by the handler, never escalated.
        assert_eq!(route_request(Denied, true, true), Route::Dispatch);
    }

    #[test]
    fn the_non_escalate_path_still_raises_the_card() {
        use ApprovalTier::*;
        // No regression: a note send on a normal legacy slot raises SEND NOTE.
        assert_eq!(route_request(ButtonRequired, true, false), Route::Card);
        assert_eq!(route_request(AutoApprove, true, false), Route::Card);
        // And an unpinned method a policy auto-approves is dispatched as ever.
        assert_eq!(route_request(AutoApprove, false, false), Route::Dispatch);
        assert_eq!(route_request(AutoApprove, false, true), Route::Dispatch);
        assert_eq!(route_request(ButtonRequired, false, false), Route::Card);
        assert_eq!(route_request(ButtonRequired, false, true), Route::Park);
    }

    #[test]
    fn a_verdict_completes_the_note_send_it_was_raised_for() {
        assert_eq!(park_completion(&note_send_park()), ParkCompletion::Approved);
    }

    #[test]
    fn a_verdict_completes_nothing_it_did_not_name() {
        let park = note_send_park();
        // Another client's ask.
        assert!(matches!(
            park_completion(&ParkVerdict { park_client_hex: OTHER_CLIENT, ..park }),
            ParkCompletion::Window { .. }
        ));
        // Another method.
        assert!(matches!(
            park_completion(&ParkVerdict { park_key: "heartwood_note_export", ..park }),
            ParkCompletion::Window { .. }
        ));
        // Another kind of the same method.
        assert!(matches!(
            park_completion(&ParkVerdict {
                approved_key: "sign_event:1",
                park_key: "sign_event:4",
                ..park
            }),
            ParkCompletion::Window { .. }
        ));
        // Another identity: the #156 rule holds through escalation too.
        assert!(matches!(
            park_completion(&ParkVerdict { park_identity: Some(&OTHER_IDENTITY), ..park }),
            ParkCompletion::Window { .. }
        ));
        // And a verdict granted for no identity never releases one.
        assert!(matches!(
            park_completion(&ParkVerdict { approved_identity: None, ..park }),
            ParkCompletion::Window { .. }
        ));
    }

    #[test]
    fn a_verdict_after_expiry_leaves_the_window_and_nothing_else() {
        let park = note_send_park();
        assert!(matches!(
            park_completion(&ParkVerdict { held_secs: PARK_TTL_SECS, ..park }),
            ParkCompletion::Window { .. }
        ));
        assert!(matches!(
            park_completion(&ParkVerdict { held_secs: PARK_TTL_SECS + 900, ..park }),
            ParkCompletion::Window { .. }
        ));
        assert_eq!(
            park_completion(&ParkVerdict { held_secs: PARK_TTL_SECS - 1, ..park }),
            ParkCompletion::Approved,
        );
        // An expired park reports `window`, not `completed`.
        assert_eq!(applied_value(VerdictAction::ApproveOnce, false, true, false), "window");
    }

    #[test]
    fn the_pinned_set_is_the_note_disclosures_and_destructions() {
        use crate::nip46::Nip46Method as M;
        for method in [
            M::HeartwoodNoteExport,
            M::HeartwoodNoteSpent,
            M::HeartwoodNoteDiscard,
            M::HeartwoodNoteSend,
            M::HeartwoodNoteRename,
            M::HeartwoodNoteTrust,
        ] {
            assert!(method.pinned_physical(), "{} lost its pin", method.as_str());
        }
        // Note methods that are not disclosures keep the ordinary gate.
        assert!(!M::HeartwoodNoteList.pinned_physical());
        assert!(!M::HeartwoodNoteAddress.pinned_physical());
        // And a non-note button method is not pinned by a policy ceiling.
        assert!(!M::HeartwoodDerive.pinned_physical());
        assert!(!M::SignEvent.pinned_physical());
    }
}
