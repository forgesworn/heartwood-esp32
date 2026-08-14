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
}
