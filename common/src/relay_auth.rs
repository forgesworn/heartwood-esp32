//! NIP-42 sign-in for the WiFi-standalone relay client.
//!
//! A relay that wants to know who is reading sends `["AUTH", <challenge>]`
//! and may then hold or refuse a subscription until the connection signs in
//! with a kind-22242 event per key. The board answers only a relay it dialled
//! itself, only for that connection's own challenge, and only with this
//! module's fixed event shape: kind 22242, a `relay` tag naming the URL the
//! board dialled (from its own relay list, never anything the relay sent), a
//! `challenge` tag, and empty content. Nothing else can be put in it, so a
//! relay cannot turn the answer into a signature over anything of its
//! choosing, and a website's login challenge relayed through it is bound to a
//! relay URL that website does not expect. No button: the board is answering
//! its own connection, and nobody else can ask it to.
//!
//! A board never volunteers a sign-in: nothing here acts until a relay sends
//! a challenge, so a relay that never asks sees exactly the frames it saw
//! before.
//!
//! This module is the wire shape and the arithmetic only, on a millisecond
//! uptime clock, with no socket or key in sight:
//!
//! * [`parse_challenge`], [`parse_ok`], [`parse_closed`] and
//!   [`closed_reason`] read the relay's frames.
//! * [`auth_event`] builds the one event shape the board signs.
//! * [`RelayAuth`], one per relay connection, decides what follows: sign
//!   now, re-send a subscription the relay closed while it waited for the
//!   sign-in, or give up on the relay for a while. A subscription is re-sent
//!   once per sign-in; a second refusal, a sign-in every key of which was
//!   refused, or an `auth-required:` with no challenge behind it backs off
//!   rather than looping.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::nip46::UnsignedEvent;

/// NIP-42 client authentication event kind.
pub const AUTH_KIND: u64 = 22242;
/// Longest challenge the board will sign. Relays use a UUID or a few dozen
/// hex digits; anything far past that is not a challenge worth a signature.
pub const CHALLENGE_MAX: usize = 256;
/// Distinct challenges answered on one connection. A relay may issue a fresh
/// one, but not make the board sign without end.
pub const CHALLENGES_PER_CONNECTION: u8 = 2;
/// How long the relay has to answer every sign-in event with an `OK`. A
/// missing `OK` counts as a refusal of that key.
pub const OK_WAIT_MS: u64 = 10_000;
/// A subscription closed `auth-required:` before any challenge arrived waits
/// this long for one (a relay may send the challenge just after the
/// closure), then backs off.
pub const CHALLENGE_WAIT_MS: u64 = 5_000;

/// Why a relay closed a subscription, from the machine-readable prefix
/// NIP-01 gives the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedReason {
    /// `auth-required:` — the connection has not signed in.
    AuthRequired,
    /// `restricted:` — the keys signed in may not read this.
    Restricted,
    /// Anything else, handled as any other closure always was.
    Other,
}

/// What the relay loop does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// Re-send these subscriptions: the sign-in they waited for is done.
    Resend(Vec<String>),
    /// Sign-in failed or did not help: drop the connection and leave the
    /// relay alone for a while.
    BackOff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No sign-in attempted on this connection.
    Idle,
    /// Sign-in events sent, `OK`s awaited.
    Sent,
    /// At least one key was accepted.
    SignedIn,
    /// Every key was refused, or none could be signed.
    Failed,
}

/// One connection's sign-in state. Created fresh on every connect.
#[derive(Debug, Clone)]
pub struct RelayAuth {
    phase: Phase,
    /// Sign-in event ids still waiting for the relay's `OK`.
    pending: Vec<String>,
    accepted: u8,
    sent_ms: u64,
    challenges: u8,
    last_challenge: Option<String>,
    /// Subscriptions closed while the sign-in was outstanding.
    waiting: Vec<String>,
    /// Subscriptions already re-sent since the last sign-in.
    resent: Vec<String>,
    /// When a subscription was closed `auth-required:` with no challenge.
    unasked_since: Option<u64>,
}

impl Default for RelayAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayAuth {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            pending: Vec::new(),
            accepted: 0,
            sent_ms: 0,
            challenges: 0,
            last_challenge: None,
            waiting: Vec::new(),
            resent: Vec::new(),
            unasked_since: None,
        }
    }

    /// Whether at least one key is signed in on this connection.
    pub fn signed_in(&self) -> bool {
        self.phase == Phase::SignedIn
    }

    /// Whether the relay has asked this connection to sign in.
    pub fn asked(&self) -> bool {
        self.challenges > 0
    }

    /// The relay sent `challenge`. True when the caller should sign it now
    /// and report what it sent with [`RelayAuth::sent`]; false for a repeat
    /// of the last challenge, one arriving while a sign-in is outstanding,
    /// or one past [`CHALLENGES_PER_CONNECTION`].
    pub fn challenge(&mut self, challenge: &str) -> bool {
        if !valid_challenge(challenge)
            || self.phase == Phase::Sent
            || self.challenges >= CHALLENGES_PER_CONNECTION
            || self.last_challenge.as_deref() == Some(challenge)
        {
            return false;
        }
        self.challenges += 1;
        self.last_challenge = Some(challenge.to_string());
        self.unasked_since = None;
        true
    }

    /// The sign-in events sent for the challenge just accepted, by id. None
    /// at all (no wall clock to stamp them with, no key that would sign) is
    /// a failed sign-in.
    pub fn sent(&mut self, ids: Vec<String>, now_ms: u64) -> Step {
        self.accepted = 0;
        self.resent.clear();
        if ids.is_empty() {
            self.pending.clear();
            return self.finish();
        }
        self.phase = Phase::Sent;
        self.pending = ids;
        self.sent_ms = now_ms;
        Step::Nothing
    }

    /// The relay's `OK` for event `id`. `None` when it is not one of ours, so
    /// the caller handles it as before.
    pub fn ok(&mut self, id: &str, accepted: bool) -> Option<Step> {
        if self.phase != Phase::Sent {
            return None;
        }
        let pos = self.pending.iter().position(|p| p == id)?;
        self.pending.swap_remove(pos);
        if accepted {
            self.accepted = self.accepted.saturating_add(1);
        }
        Some(if self.pending.is_empty() {
            self.finish()
        } else {
            Step::Nothing
        })
    }

    /// The relay closed subscription `sub` for `reason`. `None` when this is
    /// not a sign-in matter and the caller should handle it as before: any
    /// closure that is not `auth-required:` or `restricted:`, and a
    /// `restricted:` from a relay that never asked for a sign-in.
    pub fn closed(&mut self, sub: &str, reason: ClosedReason, now_ms: u64) -> Option<Step> {
        if reason == ClosedReason::Other {
            return None;
        }
        Some(match self.phase {
            Phase::Idle => {
                if reason == ClosedReason::Restricted {
                    return None;
                }
                self.wait_for(sub);
                self.unasked_since.get_or_insert(now_ms);
                Step::Nothing
            }
            Phase::Sent => {
                self.wait_for(sub);
                Step::Nothing
            }
            Phase::SignedIn => {
                if self.resent.iter().any(|s| s == sub) {
                    self.phase = Phase::Failed;
                    Step::BackOff
                } else {
                    self.resent.push(sub.to_string());
                    Step::Resend(vec![sub.to_string()])
                }
            }
            Phase::Failed => Step::BackOff,
        })
    }

    /// Deadlines: `OK`s that never came, and a challenge that never came
    /// after an `auth-required:` closure.
    pub fn tick(&mut self, now_ms: u64) -> Step {
        match self.phase {
            Phase::Sent if now_ms.saturating_sub(self.sent_ms) >= OK_WAIT_MS => {
                self.pending.clear();
                self.finish()
            }
            Phase::Idle
                if self
                    .unasked_since
                    .is_some_and(|t| now_ms.saturating_sub(t) >= CHALLENGE_WAIT_MS) =>
            {
                self.unasked_since = None;
                self.waiting.clear();
                self.phase = Phase::Failed;
                Step::BackOff
            }
            _ => Step::Nothing,
        }
    }

    fn wait_for(&mut self, sub: &str) {
        if !self.waiting.iter().any(|s| s == sub) {
            self.waiting.push(sub.to_string());
        }
    }

    fn finish(&mut self) -> Step {
        let waiting = core::mem::take(&mut self.waiting);
        if self.accepted > 0 {
            self.phase = Phase::SignedIn;
            if waiting.is_empty() {
                return Step::Nothing;
            }
            self.resent.extend(waiting.iter().cloned());
            Step::Resend(waiting)
        } else {
            self.phase = Phase::Failed;
            if waiting.is_empty() {
                // Refused, but nothing has been closed for it: the relay may
                // not need a sign-in for what this connection reads.
                Step::Nothing
            } else {
                Step::BackOff
            }
        }
    }
}

/// Printable ASCII, non-empty, at most [`CHALLENGE_MAX`] bytes.
fn valid_challenge(challenge: &str) -> bool {
    !challenge.is_empty()
        && challenge.len() <= CHALLENGE_MAX
        && challenge.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The challenge from an `["AUTH", <challenge>]` frame, if it is one the
/// board would sign. A NIP-42 `AUTH` from a relay carries exactly a string.
pub fn parse_challenge(raw: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let a = v.as_array()?;
    if a.len() != 2 || a[0].as_str() != Some("AUTH") {
        return None;
    }
    let challenge = a[1].as_str()?;
    valid_challenge(challenge).then(|| challenge.to_string())
}

/// `["OK", <id>, <accepted>, <message>]` as `(id, accepted)`.
pub fn parse_ok(raw: &[u8]) -> Option<(String, bool)> {
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let a = v.as_array()?;
    if a.first()?.as_str() != Some("OK") {
        return None;
    }
    Some((a.get(1)?.as_str()?.to_string(), a.get(2)?.as_bool()?))
}

/// `["CLOSED", <sub>, <message>]` as `(sub, message)`; the message may be
/// absent.
pub fn parse_closed(raw: &[u8]) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let a = v.as_array()?;
    if a.first()?.as_str() != Some("CLOSED") {
        return None;
    }
    let sub = a.get(1)?.as_str()?.to_string();
    let message = a.get(2).and_then(|m| m.as_str()).unwrap_or("").to_string();
    Some((sub, message))
}

/// The machine-readable prefix of a `CLOSED` message.
pub fn closed_reason(message: &str) -> ClosedReason {
    let m = message.trim_start();
    if m.starts_with("auth-required:") {
        ClosedReason::AuthRequired
    } else if m.starts_with("restricted:") {
        ClosedReason::Restricted
    } else {
        ClosedReason::Other
    }
}

/// The sign-in event for `pubkey_hex`: kind 22242, tags exactly
/// `[["relay", relay_url], ["challenge", challenge]]`, empty content. The
/// caller passes the URL it dialled, from its own relay list.
pub fn auth_event(pubkey_hex: &str, relay_url: &str, challenge: &str, created_at: u64) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: pubkey_hex.to_string(),
        created_at,
        kind: AUTH_KIND,
        tags: vec![
            vec!["relay".to_string(), relay_url.to_string()],
            vec!["challenge".to_string(), challenge.to_string()],
        ],
        content: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "wss://relay.example.com";

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| alloc::format!("id{i}")).collect()
    }

    /// A connection that has been challenged and has sent `n` sign-ins.
    fn sent(n: usize) -> RelayAuth {
        let mut a = RelayAuth::new();
        assert!(a.challenge("c1"));
        assert_eq!(a.sent(ids(n), 1_000), Step::Nothing);
        a
    }

    #[test]
    fn auth_event_has_the_fixed_shape_and_nothing_else() {
        let ev = auth_event(&"ab".repeat(32), URL, "chal-123", 1_700_000_000);
        assert_eq!(ev.kind, 22242);
        assert_eq!(ev.content, "");
        assert_eq!(ev.created_at, 1_700_000_000);
        assert_eq!(ev.pubkey, "ab".repeat(32));
        assert_eq!(
            ev.tags,
            vec![
                vec!["relay".to_string(), URL.to_string()],
                vec!["challenge".to_string(), "chal-123".to_string()],
            ]
        );
    }

    #[test]
    fn auth_event_id_is_the_nip01_hash_of_that_shape() {
        let ev = auth_event(&"ab".repeat(32), URL, "c", 1);
        let serialised = alloc::format!(
            r#"[0,"{}",1,22242,[["relay","{URL}"],["challenge","c"]],""]"#,
            "ab".repeat(32)
        );
        use sha2::Digest;
        let want: [u8; 32] = sha2::Sha256::digest(serialised.as_bytes()).into();
        assert_eq!(crate::nip46::compute_event_id(&ev), want);
    }

    #[test]
    fn a_challenge_is_read_only_from_a_well_formed_auth_frame() {
        assert_eq!(parse_challenge(br#"["AUTH","abc123"]"#), Some("abc123".into()));
        assert_eq!(parse_challenge(br#" [ "AUTH" , "abc" ] "#), Some("abc".into()));
        // A client-style AUTH carrying an event, extra elements, or no string.
        assert_eq!(parse_challenge(br#"["AUTH",{"kind":22242}]"#), None);
        assert_eq!(parse_challenge(br#"["AUTH","abc","extra"]"#), None);
        assert_eq!(parse_challenge(br#"["AUTH"]"#), None);
        assert_eq!(parse_challenge(br#"["NOTICE","abc"]"#), None);
        assert_eq!(parse_challenge(b"not json"), None);
        // Empty, over-long, control characters, non-ASCII.
        assert_eq!(parse_challenge(br#"["AUTH",""]"#), None);
        let long = alloc::format!(r#"["AUTH","{}"]"#, "a".repeat(CHALLENGE_MAX + 1));
        assert_eq!(parse_challenge(long.as_bytes()), None);
        let max = alloc::format!(r#"["AUTH","{}"]"#, "a".repeat(CHALLENGE_MAX));
        assert!(parse_challenge(max.as_bytes()).is_some());
        assert_eq!(parse_challenge(br#"["AUTH","a\nb"]"#), None);
        assert_eq!(parse_challenge("[\"AUTH\",\"caf\u{e9}\"]".as_bytes()), None);
    }

    #[test]
    fn ok_and_closed_frames_parse() {
        assert_eq!(parse_ok(br#"["OK","abc",true,""]"#), Some(("abc".into(), true)));
        assert_eq!(
            parse_ok(br#"["OK","abc",false,"restricted: no"]"#),
            Some(("abc".into(), false))
        );
        assert_eq!(parse_ok(br#"["OK","abc"]"#), None);
        assert_eq!(parse_ok(br#"["CLOSED","abc",true]"#), None);
        assert_eq!(
            parse_closed(br#"["CLOSED","hw","auth-required: sign in"]"#),
            Some(("hw".into(), "auth-required: sign in".into()))
        );
        assert_eq!(parse_closed(br#"["CLOSED","hw"]"#), Some(("hw".into(), String::new())));
        assert_eq!(parse_closed(br#"["EOSE","hw"]"#), None);
    }

    #[test]
    fn closed_reasons_follow_the_nip01_prefixes() {
        assert_eq!(closed_reason("auth-required: we only serve signed-in readers"), ClosedReason::AuthRequired);
        assert_eq!(closed_reason("restricted: not on the list"), ClosedReason::Restricted);
        assert_eq!(closed_reason("  restricted:x"), ClosedReason::Restricted);
        assert_eq!(closed_reason("error: shutting down"), ClosedReason::Other);
        assert_eq!(closed_reason("you are restricted: no"), ClosedReason::Other);
        assert_eq!(closed_reason(""), ClosedReason::Other);
    }

    #[test]
    fn nothing_happens_on_a_connection_the_relay_never_challenges() {
        let mut a = RelayAuth::new();
        assert!(!a.asked());
        assert_eq!(a.ok("anything", true), None);
        assert_eq!(a.closed("hw", ClosedReason::Other, 0), None);
        // A `restricted:` from a relay that never asked is its old closure.
        assert_eq!(a.closed("hw", ClosedReason::Restricted, 0), None);
        assert_eq!(a.tick(1_000_000), Step::Nothing);
    }

    #[test]
    fn a_sign_in_that_lands_before_any_closure_needs_no_resend() {
        let mut a = sent(2);
        assert_eq!(a.ok("id0", true), Some(Step::Nothing));
        assert_eq!(a.ok("id1", false), Some(Step::Nothing));
        assert!(a.signed_in());
    }

    #[test]
    fn a_closure_while_signing_is_resent_once_the_oks_arrive() {
        let mut a = sent(2);
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 1_500), Some(Step::Nothing));
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 1_600), Some(Step::Nothing));
        assert_eq!(a.ok("id0", true), Some(Step::Nothing));
        assert_eq!(a.ok("id1", true), Some(Step::Resend(vec!["hw".into()])));
        // The resent REQ refused again: back off, never a second resend.
        assert_eq!(a.closed("hw", ClosedReason::Restricted, 2_000), Some(Step::BackOff));
        assert_eq!(a.closed("hw", ClosedReason::Restricted, 2_100), Some(Step::BackOff));
    }

    #[test]
    fn a_closure_after_sign_in_is_resent_once_then_backs_off() {
        let mut a = sent(1);
        assert_eq!(a.ok("id0", true), Some(Step::Nothing));
        assert_eq!(
            a.closed("hw", ClosedReason::Restricted, 2_000),
            Some(Step::Resend(vec!["hw".into()]))
        );
        // A different subscription gets its own one resend.
        assert_eq!(
            a.closed("wrappage", ClosedReason::AuthRequired, 2_100),
            Some(Step::Resend(vec!["wrappage".into()]))
        );
        assert_eq!(a.closed("hw", ClosedReason::Restricted, 2_200), Some(Step::BackOff));
        // Other closures keep their old handling throughout.
        assert_eq!(a.closed("hw", ClosedReason::Other, 2_300), None);
    }

    #[test]
    fn every_key_refused_backs_off_only_once_something_was_closed() {
        let mut a = sent(2);
        assert_eq!(a.ok("id0", false), Some(Step::Nothing));
        assert_eq!(a.ok("id1", false), Some(Step::Nothing));
        assert!(!a.signed_in());
        // The relay may not need a sign-in at all; only a closure says so.
        assert_eq!(a.closed("hw", ClosedReason::Restricted, 2_000), Some(Step::BackOff));

        let mut b = sent(1);
        assert_eq!(b.closed("hw", ClosedReason::AuthRequired, 1_100), Some(Step::Nothing));
        assert_eq!(b.ok("id0", false), Some(Step::BackOff));
    }

    #[test]
    fn missing_oks_count_as_refusals_after_the_wait() {
        let mut a = sent(2);
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 1_200), Some(Step::Nothing));
        assert_eq!(a.ok("id0", true), Some(Step::Nothing));
        assert_eq!(a.tick(1_000 + OK_WAIT_MS - 1), Step::Nothing);
        // One key accepted, the other never answered: signed in.
        assert_eq!(a.tick(1_000 + OK_WAIT_MS), Step::Resend(vec!["hw".into()]));
        assert!(a.signed_in());
        // A late OK is no longer ours.
        assert_eq!(a.ok("id1", true), None);

        let mut b = sent(1);
        assert_eq!(b.closed("hw", ClosedReason::AuthRequired, 1_200), Some(Step::Nothing));
        assert_eq!(b.tick(1_000 + OK_WAIT_MS), Step::BackOff);
    }

    #[test]
    fn auth_required_with_no_challenge_waits_then_backs_off() {
        let mut a = RelayAuth::new();
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 10_000), Some(Step::Nothing));
        assert_eq!(a.tick(10_000 + CHALLENGE_WAIT_MS - 1), Step::Nothing);
        assert_eq!(a.tick(10_000 + CHALLENGE_WAIT_MS), Step::BackOff);
        // Once failed, a further refusal backs off too; nothing loops.
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 20_000), Some(Step::BackOff));
    }

    #[test]
    fn a_challenge_after_the_closure_rescues_it() {
        let mut a = RelayAuth::new();
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 10_000), Some(Step::Nothing));
        assert!(a.challenge("late"));
        assert_eq!(a.sent(ids(1), 11_000), Step::Nothing);
        // The challenge deadline no longer applies.
        assert_eq!(a.tick(10_000 + CHALLENGE_WAIT_MS), Step::Nothing);
        assert_eq!(a.ok("id0", true), Some(Step::Resend(vec!["hw".into()])));
    }

    #[test]
    fn a_sign_in_with_nothing_signed_is_a_failure() {
        let mut a = RelayAuth::new();
        assert!(a.challenge("c"));
        assert_eq!(a.sent(Vec::new(), 0), Step::Nothing);
        assert!(!a.signed_in());
        assert_eq!(a.closed("hw", ClosedReason::AuthRequired, 1), Some(Step::BackOff));

        let mut b = RelayAuth::new();
        assert_eq!(b.closed("hw", ClosedReason::AuthRequired, 0), Some(Step::Nothing));
        assert!(b.challenge("c"));
        assert_eq!(b.sent(Vec::new(), 1), Step::BackOff);
    }

    #[test]
    fn challenges_are_bounded_per_connection() {
        let mut a = RelayAuth::new();
        assert!(a.challenge("c1"));
        // Not while a sign-in is outstanding.
        a.sent(ids(1), 0);
        assert!(!a.challenge("c2"));
        a.ok("id0", true);
        // Never the same challenge twice.
        assert!(!a.challenge("c1"));
        assert!(a.challenge("c2"));
        a.sent(ids(1), 0);
        a.ok("id0", true);
        // And no more than CHALLENGES_PER_CONNECTION in all.
        assert!(!a.challenge("c3"));
        assert!(!RelayAuth::new().challenge(""));
    }

    #[test]
    fn a_fresh_sign_in_gives_each_subscription_a_fresh_resend() {
        let mut a = sent(1);
        a.ok("id0", true);
        assert_eq!(
            a.closed("hw", ClosedReason::Restricted, 0),
            Some(Step::Resend(vec!["hw".into()]))
        );
        assert!(a.challenge("c2"));
        a.sent(ids(1), 0);
        a.ok("id0", true);
        assert_eq!(
            a.closed("hw", ClosedReason::Restricted, 0),
            Some(Step::Resend(vec!["hw".into()]))
        );
    }

    #[test]
    fn oks_for_other_events_are_left_alone() {
        let mut a = sent(1);
        assert_eq!(a.ok("someone-elses", true), None);
        assert_eq!(a.ok("id0", true), Some(Step::Nothing));
        assert_eq!(a.ok("id0", true), None);
    }
}
