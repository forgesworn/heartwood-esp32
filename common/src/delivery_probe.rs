//! Delivery self-check for the WiFi-standalone relay loop: prove delivery,
//! not liveness.
//!
//! The relay loop's keepalive (a WebSocket ping every 20 s, a re-REQ every
//! 2 min (40 s until 2026-10-08), a 50 s silence limit) proves that the
//! socket is alive. It does not
//! prove that the subscription still delivers EVENTs: pongs and the EOSE each
//! re-REQ provokes keep `last_rx` fresh on a session that has gone deaf. That
//! was the field failure of 2026-10-07: a T-Display on beta.25 showed
//! "online", the button worked, the relay-health watchdog never fired, and an
//! unpaired client's `ping` went unanswered on all four configured relays
//! until the board was power-cycled.
//!
//! So every few minutes each live session publishes a probe that its own
//! subscription must deliver back: a kind-24133 event (the very filter that
//! carries NIP-46 requests), authored by a per-boot ephemeral key and p-tagged
//! to that same key, which [`nip46_p_values`] adds to the `#p` list of the
//! live kind-24133 filter. It therefore travels through exactly the
//! subscription that carries requests, yet is addressed to nobody else: no
//! other signer serving the same identities ever receives it. A probe
//! published on session S has to come back on
//! session S, because S is what is being proven. Two probes in a row not seen
//! within [`PROBE_WAIT_MS`] each drop the session, and the loop's ordinary
//! reconnect and rotation path redials it.
//!
//! This module is the arithmetic only, on a millisecond uptime clock, with no
//! socket, key or event in sight:
//!
//! * [`SessionProbe`]: one per relay session, created fresh on every connect.
//!   When to send, when a probe is overdue, the miss count, the reset on
//!   delivery, and the credit for a loop that was held (a cable card, a TLS
//!   dial, a publish-only connection), which, like the silence limit's
//!   `silence_from`, never counts against the relay.
//! * [`SelfCheckLedger`]: one per boot. Counts self-check redials for
//!   `get_status`, and decides when redialling has stopped helping and the
//!   board should take the relay-health watchdog's controlled restart, which
//!   is the replug owners had been doing by hand.
//!
//! Two failure directions are weighed against each other here. A relay that
//! never echoes an event back to the connection that published it (or that
//! refuses an unknown author with `OK false`) must not cost the board a
//! redial every few minutes, let alone a restart loop; and a board that has
//! genuinely gone deaf must not wait for a human. Hence: a refused probe makes
//! the session's self-check inert rather than a miss; a relay that has not
//! delivered a probe this boot gets one redial, not an endless series; and the
//! escalation only fires when a relay that HAS delivered this boot is among
//! the failures, so a board whose relays have never echoed never restarts.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// First probe this long after the subscription goes out: past the connect
/// burst (EOSE, the wrap catch-up) without leaving a fresh session unproven
/// for long.
pub const FIRST_PROBE_MS: u64 = 30_000;
/// Probe cadence on a session that keeps delivering.
pub const PROBE_INTERVAL_MS: u64 = 180_000;
/// How long a probe may take to come back before it counts as a miss. A
/// healthy relay echoes in well under a second (an unpaired client's `ping`
/// round trip is about 0.7 s); this is slack for a slow relay, not a timeout
/// anyone should ever approach.
pub const PROBE_WAIT_MS: u64 = 20_000;
/// After a miss, the next probe goes out this soon rather than a whole
/// interval later, so a deaf session is caught in minutes, not ten.
pub const RETRY_AFTER_MISS_MS: u64 = 30_000;
/// A probe the loop chose not to send (no wall clock to stamp it with, a
/// heap below the publish guard) is tried again after this. Never a miss.
pub const DEFER_MS: u64 = 15_000;
/// Consecutive misses that drop the session.
pub const MISS_LIMIT: u8 = 2;
/// A gap this long between two idle ticks of one session means the loop was
/// held (a cable card, a TLS dial, a publish-only round): the wait restarts
/// from now. An idle session ticks about once a second, so nothing honest
/// comes near it.
pub const STALL_MS: u64 = 5_000;
/// Self-check redials in a row, with no probe delivered on any session in
/// between, after which the board restarts.
pub const ESCALATE_AFTER: u8 = 3;
/// Relays remembered by the ledger (delivered, or given their one unproven
/// redial). Configured relays plus a pinned one fit comfortably.
pub const LEDGER_RELAYS_MAX: usize = 8;
/// The probe's nonce tag: `["hwprobe", "<decimal nonce>"]`. It makes each
/// probe's id distinct and names which probe came back.
pub const PROBE_TAG: &str = "hwprobe";
/// The probe's content. Kind 24133 is ephemeral and relays accept arbitrary
/// content for it; nothing reads this, so it says what the event is to anyone
/// looking at relay traffic. Recognition is by author, never by content.
pub const PROBE_CONTENT: &str = "heartwood delivery self-check";
/// The crash crumb's capacity (`firmware/src/crash_crumb.rs` `CAP`).
pub const CRUMB_MAX: usize = 48;
/// Every escalation crumb starts with this: `init_crash_context` (main.rs)
/// keeps a crumb across a software restart only under this prefix, so a
/// controlled restart reaches `get_status.crashed_during` attributed.
pub const WATCHDOG_CRUMB_PREFIX: &str = "relay watchdog";

/// What is going on that a probe must not compete with or be judged across.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Suppress {
    /// An approval card, or a result screen held after one, owns the screen.
    pub card: bool,
    /// A firmware update is being streamed over the cable.
    pub ota: bool,
    /// The board is serving a network trial, whose own deadline owns recovery.
    pub trial: bool,
}

impl Suppress {
    pub fn any(self) -> bool {
        self.card || self.ota || self.trial
    }
}

/// What the session should do on this idle tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing to do.
    Idle,
    /// Publish a probe now, then report [`SessionProbe::sent`] or
    /// [`SessionProbe::skipped`].
    Send,
    /// A probe was not seen in time; `misses` in a row so far, short of
    /// [`MISS_LIMIT`]. The next probe goes out after [`RETRY_AFTER_MISS_MS`].
    Missed { misses: u8 },
    /// [`MISS_LIMIT`] probes in a row were not seen: drop and redial.
    Redial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outstanding {
    nonce: u32,
    /// When the wait started, moved on by a credit.
    waited_from: u64,
}

/// One relay session's delivery self-check. Created with the session, so a
/// reconnect always starts clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProbe {
    started: u64,
    next_due: u64,
    outstanding: Option<Outstanding>,
    /// The last probe counted as a miss: if it turns up late it still proves
    /// the subscription delivers, so it is accepted as a delivery.
    late: Option<u32>,
    misses: u8,
    last_tick: u64,
    last_delivered: Option<u64>,
    inert: bool,
}

impl SessionProbe {
    /// A fresh session whose subscription went out at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            started: now_ms,
            next_due: now_ms.saturating_add(FIRST_PROBE_MS),
            outstanding: None,
            late: None,
            misses: 0,
            last_tick: now_ms,
            last_delivered: None,
            inert: false,
        }
    }

    /// Step the self-check on one idle tick of the session.
    pub fn tick(&mut self, now_ms: u64, suppress: Suppress) -> Tick {
        if now_ms.saturating_sub(self.last_tick) > STALL_MS {
            self.credit(now_ms);
        }
        self.last_tick = now_ms;
        if self.inert {
            return Tick::Idle;
        }
        if suppress.any() {
            // Neither send nor judge: an outstanding wait restarts once the
            // card, the update or the trial is over.
            if let Some(o) = self.outstanding.as_mut() {
                o.waited_from = now_ms;
            }
            return Tick::Idle;
        }
        if let Some(o) = self.outstanding {
            if now_ms.saturating_sub(o.waited_from) < PROBE_WAIT_MS {
                return Tick::Idle;
            }
            self.outstanding = None;
            self.late = Some(o.nonce);
            self.misses = self.misses.saturating_add(1);
            if self.misses >= MISS_LIMIT {
                return Tick::Redial;
            }
            self.next_due = now_ms.saturating_add(RETRY_AFTER_MISS_MS);
            return Tick::Missed {
                misses: self.misses,
            };
        }
        if now_ms >= self.next_due {
            Tick::Send
        } else {
            Tick::Idle
        }
    }

    /// The probe with `nonce` went out at `now_ms`.
    pub fn sent(&mut self, nonce: u32, now_ms: u64) {
        self.outstanding = Some(Outstanding {
            nonce,
            waited_from: now_ms,
        });
    }

    /// The loop chose not to send the probe it was asked for (no clock, a
    /// tight heap). Not a miss: try again shortly.
    pub fn skipped(&mut self, now_ms: u64) {
        self.next_due = now_ms.saturating_add(DEFER_MS);
    }

    /// A probe with `nonce` came back on this session. True when it was this
    /// session's (outstanding, or the one just counted missed): the misses
    /// reset and the next probe is a full interval away. Anything else (an
    /// older probe, another session's) is ignored and answers false.
    pub fn delivered(&mut self, nonce: u32, now_ms: u64) -> bool {
        let ours = self.outstanding.is_some_and(|o| o.nonce == nonce) || self.late == Some(nonce);
        if !ours {
            return false;
        }
        self.outstanding = None;
        self.late = None;
        self.misses = 0;
        self.last_delivered = Some(now_ms);
        self.next_due = now_ms.saturating_add(PROBE_INTERVAL_MS);
        true
    }

    /// The relay answered `OK false` to the probe with `nonce`: it will not
    /// carry it, so it can never come back. The self-check goes inert for
    /// this session (a reconnect starts a fresh one) rather than counting a
    /// refusal as deafness. True when `nonce` was the outstanding probe.
    pub fn refused(&mut self, nonce: u32) -> bool {
        match self.outstanding {
            Some(o) if o.nonce == nonce => {}
            _ => return false,
        }
        self.outstanding = None;
        self.inert = true;
        true
    }

    /// Stop probing on this session (see [`SelfCheckLedger::on_redial_due`]).
    pub fn go_inert(&mut self) {
        self.outstanding = None;
        self.misses = 0;
        self.inert = true;
    }

    /// The loop was held with nothing reading this session: whatever wait is
    /// outstanding starts again from `now_ms`, exactly as the silence limit's
    /// `silence_from` is moved on.
    pub fn credit(&mut self, now_ms: u64) {
        if let Some(o) = self.outstanding.as_mut() {
            o.waited_from = now_ms;
        }
        self.last_tick = now_ms;
    }

    /// When the session this belongs to connected (the uptime it was made at).
    pub fn connected_ms(&self) -> u64 {
        self.started
    }

    /// The nonce of the probe in flight, if any.
    pub fn outstanding_nonce(&self) -> Option<u32> {
        self.outstanding.map(|o| o.nonce)
    }

    pub fn misses(&self) -> u8 {
        self.misses
    }

    pub fn is_inert(&self) -> bool {
        self.inert
    }

    /// Milliseconds since this session last had a probe delivered, or since
    /// it connected when none has been yet.
    pub fn since_delivered_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_delivered.unwrap_or(self.started))
    }

    /// Whether any probe has been delivered on this session.
    pub fn ever_delivered(&self) -> bool {
        self.last_delivered.is_some()
    }
}

/// What to do with a session that has just missed [`MISS_LIMIT`] probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissAction {
    /// Drop the session and redial. `escalate`: redialling has stopped
    /// helping; take the controlled restart instead.
    Redial { escalate: bool },
    /// This relay has never delivered a probe this boot and has already had
    /// its one redial for it: it probably does not echo an event back to the
    /// connection that published it. Leave the session up and stop probing
    /// it, rather than churn it every few minutes.
    Inert,
}

/// The boot-wide record of self-check redials, for `get_status` and the
/// escalation. RAM only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfCheckLedger {
    redials: u32,
    streak: u8,
    streak_has_proven: bool,
    last_reason: Option<String>,
    /// Hosts that delivered a probe this boot.
    proven: Vec<String>,
    /// Hosts never proven that have had their one redial.
    unproven_redialled: Vec<String>,
}

fn remember(list: &mut Vec<String>, host: &str) {
    if list.iter().any(|h| h == host) {
        return;
    }
    if list.len() >= LEDGER_RELAYS_MAX {
        list.remove(0);
    }
    list.push(host.to_string());
}

impl SelfCheckLedger {
    pub const fn new() -> Self {
        Self {
            redials: 0,
            streak: 0,
            streak_has_proven: false,
            last_reason: None,
            proven: Vec::new(),
            unproven_redialled: Vec::new(),
        }
    }

    /// A probe came back on a session to `host`: the board can hear, so the
    /// run of redials towards an escalation is over.
    pub fn delivered(&mut self, host: &str) {
        self.streak = 0;
        self.streak_has_proven = false;
        remember(&mut self.proven, host);
    }

    /// A session to `host` missed [`MISS_LIMIT`] probes in a row.
    pub fn on_redial_due(&mut self, host: &str) -> MissAction {
        let proven = self.proven.iter().any(|h| h == host);
        if !proven {
            if self.unproven_redialled.iter().any(|h| h == host) {
                return MissAction::Inert;
            }
            remember(&mut self.unproven_redialled, host);
        }
        self.redials = self.redials.saturating_add(1);
        self.streak = self.streak.saturating_add(1);
        self.streak_has_proven |= proven;
        MissAction::Redial {
            escalate: self.streak >= ESCALATE_AFTER && self.streak_has_proven,
        }
    }

    /// Record why the last self-check redial happened, for `get_status`.
    pub fn set_reason(&mut self, reason: String) {
        self.last_reason = Some(reason);
    }

    /// Self-check redials since boot.
    pub fn redials(&self) -> u32 {
        self.redials
    }

    /// Self-check redials in a row with no probe delivered in between.
    pub fn streak(&self) -> u8 {
        self.streak
    }

    pub fn last_reason(&self) -> Option<&str> {
        self.last_reason.as_deref()
    }
}

/// The `#p` values of the live kind-24133 filter: every served identity, in
/// the order given, then the probe key, so the probe is delivered through
/// that same filter object. Values are bare lowercase hex; the caller quotes
/// them. A served identity equal to the probe key (it cannot be, the key is
/// fresh per boot, but nothing here relies on it) is not listed twice.
pub fn nip46_p_values(served: &[String], probe_pk_hex: &str) -> Vec<String> {
    let mut values: Vec<String> = Vec::with_capacity(served.len() + 1);
    for pk in served {
        if !values.iter().any(|v| v == pk) {
            values.push(pk.clone());
        }
    }
    if !values.iter().any(|v| v == probe_pk_hex) {
        values.push(probe_pk_hex.to_string());
    }
    values
}

/// The probe's tags: the `p` tag naming the probe key itself (so no served
/// identity, and so no other signer of it, is ever addressed), and the nonce.
pub fn probe_tags(probe_pk_hex: &str, nonce: u32) -> Vec<Vec<String>> {
    alloc::vec![
        alloc::vec!["p".to_string(), probe_pk_hex.to_string()],
        alloc::vec![PROBE_TAG.to_string(), format!("{nonce}")],
    ]
}

/// The nonce of a probe, from its tags. `None` when there is no well-formed
/// nonce tag (never a probe of ours, whoever signed it).
pub fn probe_nonce(tags: &[Vec<String>]) -> Option<u32> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == PROBE_TAG)
        .and_then(|t| t[1].parse::<u32>().ok())
}

/// The nonce of one of our probes: authored by the probe key, p-tagged to the
/// probe key, with a well-formed nonce tag. `None` for anything else. (The
/// caller has already verified the event's signature.)
pub fn our_probe_nonce(author_hex: &str, tags: &[Vec<String>], probe_pk_hex: &str) -> Option<u32> {
    if author_hex != probe_pk_hex {
        return None;
    }
    let addressed_to_probe = tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == probe_pk_hex);
    if !addressed_to_probe {
        return None;
    }
    probe_nonce(tags)
}

/// One line describing a self-check redial: the full form goes to the log and
/// to `get_status`'s `last_reason`; [`fit_crumb`] cuts it for the crumb.
/// `relay_index` is the relay's place in the configured list, `None` for a
/// pinned relay.
pub fn redial_reason(
    host: &str,
    relay_index: Option<usize>,
    since_delivered_s: u64,
    last_rx_age_s: u64,
    resubs: u32,
    free_heap: u32,
    largest_block: u32,
) -> String {
    let index = match relay_index {
        Some(i) => format!("{i}"),
        None => "p".to_string(),
    };
    format!(
        "selfcheck {host} r{index} d{since_delivered_s}s rx{last_rx_age_s}s q{resubs} h{}k/{}k",
        free_heap / 1024,
        largest_block / 1024
    )
}

/// The crash crumb for a self-check redial, within [`CRUMB_MAX`]: the host is
/// cut short (its start kept) so that the numbers, which are the evidence,
/// always fit.
pub fn redial_crumb(
    host: &str,
    relay_index: Option<usize>,
    since_delivered_s: u64,
    last_rx_age_s: u64,
    resubs: u32,
    free_heap: u32,
    largest_block: u32,
) -> String {
    let tail = redial_reason(
        "",
        relay_index,
        since_delivered_s,
        last_rx_age_s,
        resubs,
        free_heap,
        largest_block,
    );
    // `tail` is "selfcheck  r..." with an empty host: the host goes between.
    let room = CRUMB_MAX.saturating_sub(tail.len());
    let host: String = host.chars().take(room).collect();
    let full = redial_reason(
        &host,
        relay_index,
        since_delivered_s,
        last_rx_age_s,
        resubs,
        free_heap,
        largest_block,
    );
    fit_crumb(&full)
}

/// The crumb for the escalation restart. Starts with
/// [`WATCHDOG_CRUMB_PREFIX`] so it survives the software restart.
pub fn escalation_crumb(streak: u8, since_delivered_s: u64, largest_block: u32) -> String {
    fit_crumb(&format!(
        "{WATCHDOG_CRUMB_PREFIX}: selfcheck x{streak} d{since_delivered_s}s {}k",
        largest_block / 1024
    ))
}

/// Cut `s` to at most [`CRUMB_MAX`] bytes on a character boundary.
pub fn fit_crumb(s: &str) -> String {
    let mut end = s.len().min(CRUMB_MAX);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Suppress = Suppress {
        card: false,
        ota: false,
        trial: false,
    };

    /// Tick a session once a second from `from` to `to` inclusive, returning
    /// the first non-idle outcome and when it happened.
    fn run(p: &mut SessionProbe, from: u64, to: u64, suppress: Suppress) -> Option<(u64, Tick)> {
        let mut t = from;
        while t <= to {
            match p.tick(t, suppress) {
                Tick::Idle => {}
                other => return Some((t, other)),
            }
            t += 1_000;
        }
        None
    }

    #[test]
    fn a_fresh_session_starts_clean_and_probes_after_the_first_delay() {
        let mut p = SessionProbe::new(100_000);
        assert_eq!(p.misses(), 0);
        assert_eq!(p.outstanding_nonce(), None);
        assert!(!p.ever_delivered());
        assert!(!p.is_inert());
        let (at, tick) = run(&mut p, 100_000, 400_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        assert_eq!(at, 100_000 + FIRST_PROBE_MS);
    }

    #[test]
    fn delivery_resets_misses_and_schedules_a_full_interval() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(1, t);
        let (t, tick) = run(&mut p, t, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        assert_eq!(p.misses(), 1);
        let (t, tick) = run(&mut p, t, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        p.sent(2, t);
        assert!(p.delivered(2, t + 500));
        assert_eq!(p.misses(), 0);
        assert!(p.ever_delivered());
        assert_eq!(p.since_delivered_ms(t + 1_500), 1_000);
        // Ticks land on whole seconds here, so the first one at or past the
        // interval after the delivery.
        let (next, tick) = run(&mut p, t + 1_000, t + 400_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        assert_eq!(next, t + 1_000 + PROBE_INTERVAL_MS);
    }

    #[test]
    fn two_misses_in_a_row_redial() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(1, t);
        let (t1, tick) = run(&mut p, t, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        assert_eq!(t1, t + PROBE_WAIT_MS);
        let (t2, tick) = run(&mut p, t1, t1 + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        assert_eq!(t2, t1 + RETRY_AFTER_MISS_MS);
        p.sent(2, t2);
        let (_, tick) = run(&mut p, t2, t2 + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Redial);
    }

    #[test]
    fn one_miss_then_a_delivery_does_not_redial() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(1, t);
        let (t, tick) = run(&mut p, t, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        let (t, _) = run(&mut p, t, t + 60_000, NONE).unwrap();
        p.sent(2, t);
        assert!(p.delivered(2, t + 700));
        // Nothing but a scheduled probe for the next interval, and that one
        // delivered too: never a redial.
        let (t, tick) = run(&mut p, t + 1_000, t + 400_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        p.sent(3, t);
        assert!(p.delivered(3, t + 700));
        assert_eq!(run(&mut p, t + 1_000, t + 100_000, NONE), None);
    }

    #[test]
    fn a_late_echo_of_the_missed_probe_still_counts_as_delivery() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(7, t);
        let (t, tick) = run(&mut p, t, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        assert!(p.delivered(7, t + 3_000));
        assert_eq!(p.misses(), 0);
    }

    #[test]
    fn someone_elses_nonce_is_ignored() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(4, t);
        // Another session's probe (or a stale one) proves nothing here.
        assert!(!p.delivered(5, t + 100));
        assert!(!p.delivered(3, t + 100));
        assert_eq!(p.outstanding_nonce(), Some(4));
    }

    #[test]
    fn a_blocked_loop_credit_does_not_count_as_a_miss() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(1, t);
        // A cable card holds the loop for 55 s with nothing reading.
        p.credit(t + 55_000);
        assert_eq!(p.tick(t + 55_500, NONE), Tick::Idle);
        // The full wait runs again from the credit.
        let (when, tick) = run(&mut p, t + 56_000, t + 120_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        assert_eq!(when, t + 55_000 + PROBE_WAIT_MS);
    }

    #[test]
    fn a_stall_between_ticks_is_credited_without_being_told() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(1, t);
        p.tick(t + 1_000, NONE);
        // A 30 s TLS dial on another session: the next tick of this one is
        // the first in 30 s, past the wait, and must not be a miss.
        assert_eq!(p.tick(t + 31_000, NONE), Tick::Idle);
        let (when, tick) = run(&mut p, t + 32_000, t + 120_000, NONE).unwrap();
        assert_eq!(tick, Tick::Missed { misses: 1 });
        assert_eq!(when, t + 31_000 + PROBE_WAIT_MS);
    }

    #[test]
    fn nothing_is_sent_or_judged_during_a_card_an_update_or_a_trial() {
        for suppress in [
            Suppress { card: true, ..NONE },
            Suppress { ota: true, ..NONE },
            Suppress {
                trial: true,
                ..NONE
            },
        ] {
            assert!(suppress.any());
            let mut p = SessionProbe::new(0);
            assert_eq!(run(&mut p, 0, 600_000, suppress), None, "{suppress:?} sent");
            // Once it is over, the overdue probe goes out at once.
            assert_eq!(p.tick(601_000, NONE), Tick::Send);
            // An outstanding probe is not judged under one either, and its
            // wait restarts when it ends.
            p.sent(1, 601_000);
            assert_eq!(
                run(&mut p, 602_000, 700_000, suppress),
                None,
                "{suppress:?} judged"
            );
            let (when, tick) = run(&mut p, 701_000, 800_000, NONE).unwrap();
            assert_eq!(tick, Tick::Missed { misses: 1 });
            assert_eq!(when, 700_000 + PROBE_WAIT_MS);
        }
    }

    #[test]
    fn a_skipped_probe_is_not_a_miss_and_is_retried_soon() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.skipped(t);
        assert_eq!(p.misses(), 0);
        let (when, tick) = run(&mut p, t + 1_000, t + 60_000, NONE).unwrap();
        assert_eq!(tick, Tick::Send);
        assert_eq!(when, t + DEFER_MS);
    }

    #[test]
    fn a_refused_probe_makes_the_session_inert_not_deaf() {
        let mut p = SessionProbe::new(0);
        let (t, _) = run(&mut p, 0, 60_000, NONE).unwrap();
        p.sent(9, t);
        assert!(!p.refused(8));
        assert!(p.refused(9));
        assert!(p.is_inert());
        assert_eq!(run(&mut p, t, t + 3_600_000, NONE), None);
        // A reconnect is a new SessionProbe, which probes again.
        let mut fresh = SessionProbe::new(t);
        assert!(!fresh.is_inert());
        assert_eq!(run(&mut fresh, t, t + 60_000, NONE).unwrap().1, Tick::Send);
    }

    #[test]
    fn ledger_escalates_after_three_redials_with_no_delivery_between() {
        let mut l = SelfCheckLedger::new();
        l.delivered("a");
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: true });
        assert_eq!(l.redials(), 3);
    }

    #[test]
    fn ledger_delivery_anywhere_ends_the_streak() {
        let mut l = SelfCheckLedger::new();
        l.delivered("a");
        l.delivered("b");
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        l.delivered("b");
        assert_eq!(l.streak(), 0);
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        assert_eq!(l.redials(), 3);
    }

    #[test]
    fn ledger_counts_redials_across_relays_rotation_picks() {
        // Proven on a; rotation moves the primary to b and c, which have not
        // delivered this boot, and each fails in turn: one redial each, and
        // the third escalates because a proven relay is in the run.
        let mut l = SelfCheckLedger::new();
        l.delivered("a");
        assert_eq!(l.on_redial_due("a"), MissAction::Redial { escalate: false });
        assert_eq!(l.on_redial_due("b"), MissAction::Redial { escalate: false });
        assert_eq!(l.on_redial_due("c"), MissAction::Redial { escalate: true });
    }

    #[test]
    fn ledger_never_restarts_a_board_whose_relays_have_never_echoed() {
        let mut l = SelfCheckLedger::new();
        // One redial per never-proven relay, then inert, and no escalation
        // however many there are.
        for host in ["a", "b", "c", "d", "e"] {
            assert_eq!(
                l.on_redial_due(host),
                MissAction::Redial { escalate: false }
            );
            assert_eq!(l.on_redial_due(host), MissAction::Inert);
        }
        assert_eq!(l.redials(), 5);
    }

    #[test]
    fn ledger_reason_is_kept_for_status() {
        let mut l = SelfCheckLedger::new();
        assert_eq!(l.last_reason(), None);
        l.set_reason("selfcheck x".into());
        assert_eq!(l.last_reason(), Some("selfcheck x"));
    }

    #[test]
    fn ledger_memory_is_bounded() {
        let mut l = SelfCheckLedger::new();
        for i in 0..(LEDGER_RELAYS_MAX * 3) {
            l.delivered(&format!("relay{i}"));
            let _ = l.on_redial_due(&format!("other{i}"));
        }
        assert!(l.proven.len() <= LEDGER_RELAYS_MAX);
        assert!(l.unproven_redialled.len() <= LEDGER_RELAYS_MAX);
    }

    #[test]
    fn the_probe_key_joins_the_nip46_filter_after_every_served_identity() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let probe = "cc".repeat(32);
        let values = nip46_p_values(&[a.clone(), b.clone()], &probe);
        assert_eq!(values, alloc::vec![a.clone(), b.clone(), probe.clone()]);
        // No served identity yet: the probe key alone keeps the filter live.
        assert_eq!(nip46_p_values(&[], &probe), alloc::vec![probe.clone()]);
        // Never listed twice.
        let values = nip46_p_values(&[a.clone(), probe.clone(), a.clone()], &probe);
        assert_eq!(values, alloc::vec![a, probe]);
    }

    #[test]
    fn a_probe_is_ours_only_by_our_author_and_addressed_to_our_key() {
        let probe = "cc".repeat(32);
        let master = "aa".repeat(32);
        let tags = probe_tags(&probe, 42);
        assert_eq!(tags[0], alloc::vec!["p".to_string(), probe.clone()]);
        assert_eq!(our_probe_nonce(&probe, &tags, &probe), Some(42));
        // Someone else's key, however tagged.
        assert_eq!(our_probe_nonce(&master, &tags, &probe), None);
        // Our key, but addressed to a served identity (a client request
        // shape): not a probe.
        let to_master = probe_tags(&master, 42);
        assert_eq!(our_probe_nonce(&probe, &to_master, &probe), None);
        // No nonce.
        let bare = alloc::vec![alloc::vec!["p".to_string(), probe.clone()]];
        assert_eq!(our_probe_nonce(&probe, &bare, &probe), None);
    }

    #[test]
    fn probe_tags_round_trip_their_nonce() {
        let p = "ab".repeat(32);
        let tags = probe_tags(&p, 4_000_000_001);
        assert_eq!(tags[0], alloc::vec!["p".to_string(), p.clone()]);
        assert_eq!(probe_nonce(&tags), Some(4_000_000_001));
        assert_eq!(probe_nonce(&[alloc::vec!["p".to_string(), p]]), None);
        assert_eq!(
            probe_nonce(&[alloc::vec![PROBE_TAG.to_string(), "x".to_string()]]),
            None
        );
        assert_eq!(probe_nonce(&[alloc::vec![PROBE_TAG.to_string()]]), None);
    }

    #[test]
    fn crumbs_fit_and_keep_the_evidence() {
        let long = "a-very-long-relay-hostname.example.co.uk";
        let c = redial_crumb(long, Some(3), 412, 9, 11, 98_304, 31_744);
        assert!(c.len() <= CRUMB_MAX, "{c} is {} bytes", c.len());
        assert!(c.starts_with("selfcheck a-very"));
        assert!(c.ends_with("r3 d412s rx9s q11 h96k/31k"), "{c}");
        let c = redial_crumb("nos.lol", None, 0, 0, 0, 0, 0);
        assert_eq!(c, "selfcheck nos.lol rp d0s rx0s q0 h0k/0k");
        // Extreme numbers may cost the host entirely, but never overflow.
        let c = redial_crumb(
            long,
            Some(usize::MAX),
            u64::MAX,
            u64::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        );
        assert!(c.len() <= CRUMB_MAX);
        let e = escalation_crumb(3, 1_234, 40_960);
        assert!(e.starts_with(WATCHDOG_CRUMB_PREFIX));
        assert!(e.len() <= CRUMB_MAX);
        assert_eq!(e, "relay watchdog: selfcheck x3 d1234s 40k");
        let full = redial_reason(long, Some(0), 1, 2, 3, 4_096, 2_048);
        assert_eq!(full, format!("selfcheck {long} r0 d1s rx2s q3 h4k/2k"));
    }

    #[test]
    fn fit_crumb_respects_char_boundaries() {
        let s = "é".repeat(40);
        let c = fit_crumb(&s);
        assert!(c.len() <= CRUMB_MAX);
        assert!(s.starts_with(&c));
    }
}
