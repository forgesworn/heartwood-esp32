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
    /// Refuse now, with no card and no park: the method's card is one only a
    /// press at the device answers ([`crate::nip46::Nip46Method::device_press_only`]),
    /// and this slot escalates because nobody is there to give it. Parking it
    /// could only end in a 30 s card nobody presses, holding the relay loop
    /// for the whole window before refusing anyway (#160).
    Refuse,
}

/// Route one request. `tier` is the planned gate tier; `pinned` marks a method
/// whose own card no slot policy may silence
/// ([`crate::nip46::Nip46Method::pinned_physical`]); `device_only` marks one
/// whose card only a press answers
/// ([`crate::nip46::Nip46Method::device_press_only`]); `escalate` is the slot
/// flag.
///
/// The pin is read here and not only inside the handler because the two must
/// agree about what is physical. A pinned method whose slot policy lifted the
/// tier still owes a card, so on an `escalate` slot it belongs with the
/// guardian like any other physical ask: otherwise it would fall through to a
/// card on a board nobody is standing at (#160).
///
/// Escalation never widens what a verdict can do. A device-only method on an
/// escalate slot is refused where it would otherwise have parked, because no
/// verdict may complete it and the park could only end in a dead card.
pub fn route_request(
    tier: ApprovalTier,
    pinned: bool,
    device_only: bool,
    escalate: bool,
) -> Route {
    if tier == ApprovalTier::Denied {
        return Route::Dispatch;
    }
    if tier != ApprovalTier::ButtonRequired && !pinned {
        return Route::Dispatch;
    }
    if !escalate {
        return Route::Card;
    }
    if device_only {
        return Route::Refuse;
    }
    Route::Park
}

/// The refusal a [`Route::Refuse`] answers with: an honest instruction, not a
/// policy error. The request is well formed and the pairing is allowed it; it
/// simply cannot be approved from a phone.
pub const DEVICE_APPROVAL_REQUIRED: &str =
    "this request must be approved at the device; a guardian verdict cannot answer it";

/// Whether a verdict resolves this park: the id it names, on the master whose
/// guardian sent it. A verdict never reaches another master's park, and never
/// one it does not name. This is the cross-check that makes an approve-once an
/// approval of ONE request; `park_completion` decides what may then be done
/// with it.
pub fn park_verdict_matches(
    park_id: &str,
    park_master_slot: u8,
    verdict_park_id: &str,
    verdict_master_slot: u8,
) -> bool {
    park_id == verdict_park_id && park_master_slot == verdict_master_slot
}

/// What an approve verdict is allowed to do with the park it names.
///
/// The park id a verdict carries is the request event's own id
/// ([`park_verdict_matches`] is what pairs them), so an approve-once is an
/// approval of ONE request. This decides whether that approval may also stand
/// in for the card the request owes at the device.
#[derive(Debug, Clone, Copy)]
pub struct ParkVerdict {
    /// How long the park has been held, against [`PARK_TTL_SECS`].
    pub held_secs: u64,
    /// The method's card is one only a device press answers
    /// ([`crate::nip46::Nip46Method::device_press_only`]). Such a request is
    /// refused before it ever parks; this is the second lock on the door.
    pub device_press_only: bool,
    /// The park owes the guardian a preview of what completing it releases:
    /// the amount, mint and recipient a bearer-note card shows. True for
    /// exactly the methods whose card the verdict is about to answer.
    pub needs_preview: bool,
    /// The notice carried that preview. Without it the guardian approved a
    /// method name, not a note movement, so the verdict does not answer the
    /// card and the request falls back to the device.
    pub notice_showed_preview: bool,
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
/// `Approved` is deliberately the narrow case. Anything else falls back to the
/// window, which grants no card of its own: the client asks again and meets
/// the gate afresh at the device, where the card it owes goes up in front of
/// whoever is standing there.
pub fn park_completion(verdict: &ParkVerdict) -> ParkCompletion {
    if verdict.held_secs >= PARK_TTL_SECS {
        return ParkCompletion::Window { reason: "park expired before the verdict arrived" };
    }
    if verdict.device_press_only {
        return ParkCompletion::Window { reason: DEVICE_APPROVAL_REQUIRED };
    }
    if verdict.needs_preview && !verdict.notice_showed_preview {
        return ParkCompletion::Window {
            reason: "the notice showed no preview of what completing it would release",
        };
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

    fn note_send_park() -> ParkVerdict {
        ParkVerdict {
            held_secs: 4,
            device_press_only: false,
            needs_preview: true,
            notice_showed_preview: true,
        }
    }

    #[test]
    fn a_note_method_on_an_escalate_slot_parks_instead_of_carding() {
        use ApprovalTier::*;
        // The pin makes it physical whatever the slot policy says, so an
        // escalate slot sends it to the guardian rather than to a board
        // nobody is standing at.
        assert_eq!(route_request(ButtonRequired, true, false, true), Route::Park);
        assert_eq!(route_request(AutoApprove, true, false, true), Route::Park);
        // A denial is still answered by the handler, never escalated.
        assert_eq!(route_request(Denied, true, false, true), Route::Dispatch);
    }

    #[test]
    fn a_device_only_method_is_refused_fast_and_never_parked() {
        use ApprovalTier::*;
        // heartwood_provision_rendezvous and heartwood_pair_wallet: no
        // verdict can complete them, so an escalate slot must not park them
        // and then hold the loop on a card nobody will press.
        assert_eq!(route_request(ButtonRequired, false, true, true), Route::Refuse);
        assert_eq!(route_request(ButtonRequired, true, true, true), Route::Refuse);
        // Off the escalate path they are exactly as they were: a card.
        assert_eq!(route_request(ButtonRequired, false, true, false), Route::Card);
        // And where no card is owed at all, nothing changes.
        assert_eq!(route_request(AutoApprove, false, true, true), Route::Dispatch);
        assert_eq!(route_request(Denied, false, true, true), Route::Dispatch);
    }

    #[test]
    fn the_device_only_set_is_the_scalar_and_secret_minting_pair() {
        use crate::nip46::Nip46Method as M;
        assert!(M::HeartwoodProvisionRendezvous.device_press_only());
        assert!(M::HeartwoodPairWallet.device_press_only());
        assert!(!M::HeartwoodNoteSend.device_press_only());
        assert!(!M::HeartwoodDerive.device_press_only());
        // And neither may ever have its card answered by a verdict.
        assert!(!M::HeartwoodProvisionRendezvous.verdict_may_answer_card());
        assert!(!M::HeartwoodPairWallet.verdict_may_answer_card());
        assert!(!M::HeartwoodDerive.verdict_may_answer_card());
        assert!(!M::SignEvent.verdict_may_answer_card());
        // A note method that owes no card of its own has nothing for a
        // verdict to answer, and must not be made to carry a preview: it
        // completes on the approve-once window exactly as it always did.
        assert!(!M::HeartwoodNoteList.verdict_may_answer_card());
        assert!(!M::HeartwoodNoteAddress.verdict_may_answer_card());
        assert!(!M::HeartwoodNoteConfirm.verdict_may_answer_card());
        for method in [
            M::HeartwoodNoteSend,
            M::HeartwoodNoteExport,
            M::HeartwoodNoteDiscard,
            M::HeartwoodNoteSpent,
            M::HeartwoodNoteRename,
            M::HeartwoodNoteTrust,
        ] {
            assert!(method.verdict_may_answer_card(), "{}", method.as_str());
        }
    }

    #[test]
    fn the_non_escalate_path_still_raises_the_card() {
        use ApprovalTier::*;
        // No regression: a note send on a normal legacy slot raises SEND NOTE.
        assert_eq!(route_request(ButtonRequired, true, false, false), Route::Card);
        assert_eq!(route_request(AutoApprove, true, false, false), Route::Card);
        // And an unpinned method a policy auto-approves is dispatched as ever.
        assert_eq!(route_request(AutoApprove, false, false, false), Route::Dispatch);
        assert_eq!(route_request(AutoApprove, false, false, true), Route::Dispatch);
        assert_eq!(route_request(ButtonRequired, false, false, false), Route::Card);
        assert_eq!(route_request(ButtonRequired, false, false, true), Route::Park);
    }

    #[test]
    fn a_verdict_completes_the_note_send_it_was_raised_for() {
        assert_eq!(park_completion(&note_send_park()), ParkCompletion::Approved);
    }

    #[test]
    fn a_verdict_never_completes_a_device_only_park() {
        // Belt and braces behind the routing refusal: even if one of these
        // reached the park queue, the verdict does not press its button.
        let park = ParkVerdict { device_press_only: true, ..note_send_park() };
        assert_eq!(
            park_completion(&park),
            ParkCompletion::Window { reason: DEVICE_APPROVAL_REQUIRED },
        );
        // Including one that owes no preview at all, which is the shape a
        // rendezvous provision or a wallet pairing has.
        assert!(matches!(
            park_completion(&ParkVerdict { needs_preview: false, ..park }),
            ParkCompletion::Window { .. }
        ));
    }

    #[test]
    fn a_verdict_without_the_preview_does_not_answer_the_card() {
        // The guardian would have approved a method name, not a note
        // movement: the request falls back to the device instead.
        assert!(matches!(
            park_completion(&ParkVerdict { notice_showed_preview: false, ..note_send_park() }),
            ParkCompletion::Window { .. }
        ));
        // A park that owes no preview (a sign, a crypto method) is unaffected.
        assert_eq!(
            park_completion(&ParkVerdict {
                needs_preview: false,
                notice_showed_preview: false,
                ..note_send_park()
            }),
            ParkCompletion::Approved,
        );
    }

    #[test]
    fn a_verdict_resolves_only_the_park_it_names() {
        assert!(park_verdict_matches("aa", 0, "aa", 0));
        // Another park id on the same master.
        assert!(!park_verdict_matches("aa", 0, "bb", 0));
        // The same id under another master's guardian.
        assert!(!park_verdict_matches("aa", 0, "aa", 1));
        assert!(!park_verdict_matches("aa", 1, "aa", 0));
        // Case is not folded: a park id is an event id, compared as given.
        assert!(!park_verdict_matches("aa", 0, "AA", 0));
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
