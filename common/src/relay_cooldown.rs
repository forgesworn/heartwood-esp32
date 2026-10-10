//! Relay cooldown for the WiFi-standalone relay loop: stop dialling a relay
//! that has said it is refusing us.
//!
//! A relay that rate-limits a client says so, in a `NOTICE`, in the `CLOSED`
//! for a subscription, in the `OK false` for a publish, or with an HTTP 429 on
//! the WebSocket upgrade. The loop used to treat every one of those as an
//! ordinary drop: a `CLOSED` reconnected at once and re-sent the connect-time
//! REQ (catch-up included), and a primary that failed rotated back round to
//! the same relay a few seconds later. Against a relay that counts violations
//! that is the worst possible answer, and on 2026-10-08 relay.damus.io was
//! found answering `banned: too many rate-limit violations` to the owner's
//! home address. What tripped it is not known; this makes sure the board is
//! never what keeps it tripped.
//!
//! So a refusal cools that relay for a while: no secondary or pinned session
//! dials it, and the primary rotation passes it by. The one exception is the
//! board's own reachability. When every configured relay is cooling, the
//! primary still dials the one whose cooldown ends soonest, because a board
//! with no session at all takes the relay-health watchdog's restart, which
//! would forget every cooldown and dial them all again.
//!
//! This module is the arithmetic only, on a millisecond uptime clock, with no
//! socket in sight: [`classify`] reads a relay's own words, and
//! [`RelayCooldowns`] remembers which hosts are cooling until when.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// How long a relay that rate-limited us is left alone.
pub const THROTTLED_MS: u64 = 15 * 60_000;
/// How long a relay that says it has banned us is left alone.
pub const BANNED_MS: u64 = 60 * 60_000;
/// Hosts remembered at once. Configured relays plus a pinned one fit; past
/// that, the cooldown ending soonest makes room.
pub const COOLDOWN_RELAYS_MAX: usize = 8;

/// What a relay's refusal amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Rate-limited: NIP-01's `rate-limited:` prefix, or the same in words,
    /// or an HTTP 429 on the upgrade.
    Throttled,
    /// The relay says the client is banned (relay.damus.io's
    /// `banned: too many rate-limit violations, try again later`).
    Banned,
}

impl Refusal {
    pub fn cooldown_ms(self) -> u64 {
        match self {
            Refusal::Throttled => THROTTLED_MS,
            Refusal::Banned => BANNED_MS,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Refusal::Throttled => "rate-limited",
            Refusal::Banned => "banned",
        }
    }
}

/// Read a relay's message for a refusal of the client itself. `message` is
/// the human-readable part of a `NOTICE`, a `CLOSED` or an `OK false`, or the
/// error text of a failed WebSocket upgrade (which carries the status line).
///
/// Deliberately narrow. `blocked:`, `restricted:` and `auth-required:` are
/// about an event or an author (an allowlisted relay refusing the delivery
/// probe's throwaway key, say) and keep their existing handling; only the
/// relay saying it is limiting or has banned this client counts.
pub fn classify(message: &str) -> Option<Refusal> {
    let m = message.to_ascii_lowercase();
    if m.contains("banned") {
        return Some(Refusal::Banned);
    }
    let throttled = m.trim_start().starts_with("rate-limited:")
        || m.contains("rate-limit")
        || m.contains("rate limit")
        || m.contains("ratelimit")
        || m.contains("too many requests")
        || m.contains(" 429 ");
    throttled.then_some(Refusal::Throttled)
}

/// What [`RelayCooldowns::pick`] chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick {
    /// Index into the hosts passed in.
    pub index: usize,
    /// Every host was cooling, so this is the one ending soonest, not a free
    /// one. The caller should space such dials out.
    pub all_cooling: bool,
}

/// Hosts that refused us, and until when (uptime ms). RAM only: a restart
/// forgets them, which is why the loop must never be driven to one by them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayCooldowns {
    entries: Vec<(String, u64)>,
}

impl RelayCooldowns {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Cool `host` for `refusal`'s span from `now_ms`. A cooldown already
    /// running longer is kept, never shortened. Returns when it ends.
    pub fn cool(&mut self, host: &str, refusal: Refusal, now_ms: u64) -> u64 {
        let until = now_ms.saturating_add(refusal.cooldown_ms());
        self.entries.retain(|(_, end)| *end > now_ms);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(h, _)| h.eq_ignore_ascii_case(host))
        {
            entry.1 = entry.1.max(until);
            return entry.1;
        }
        if self.entries.len() >= COOLDOWN_RELAYS_MAX {
            if let Some(pos) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, end))| *end)
                .map(|(i, _)| i)
            {
                self.entries.swap_remove(pos);
            }
        }
        self.entries.push((host.to_string(), until));
        until
    }

    /// How much longer `host` is cooling; 0 when it is not.
    pub fn remaining_ms(&self, host: &str, now_ms: u64) -> u64 {
        self.entries
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(host))
            .map_or(0, |(_, end)| end.saturating_sub(now_ms))
    }

    pub fn cooling(&self, host: &str, now_ms: u64) -> bool {
        self.remaining_ms(host, now_ms) > 0
    }

    /// The primary's next relay: from `start`, in rotation order, the first
    /// host not cooling; when every host is cooling, the one whose cooldown
    /// ends soonest (the earliest in rotation order on a tie). Never none, so
    /// the board always has something to dial. `None` only for no hosts.
    pub fn pick(&self, hosts: &[&str], start: usize, now_ms: u64) -> Option<Pick> {
        let n = hosts.len();
        if n == 0 {
            return None;
        }
        let order = (0..n).map(|k| (start + k) % n);
        if let Some(index) = order.clone().find(|&i| !self.cooling(hosts[i], now_ms)) {
            return Some(Pick {
                index,
                all_cooling: false,
            });
        }
        let index = order
            .min_by_key(|&i| self.remaining_ms(hosts[i], now_ms))
            .unwrap_or(start % n);
        Some(Pick {
            index,
            all_cooling: true,
        })
    }

    /// Hosts cooling now, for status reporting.
    pub fn cooling_hosts(&self, now_ms: u64) -> impl Iterator<Item = (&str, u64)> {
        self.entries
            .iter()
            .filter(move |(_, end)| *end > now_ms)
            .map(move |(h, end)| (h.as_str(), end - now_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reads_the_relays_own_words() {
        assert_eq!(
            classify("banned: too many rate-limit violations, try again later"),
            Some(Refusal::Banned)
        );
        assert_eq!(
            classify("rate-limited: slow down there chief"),
            Some(Refusal::Throttled)
        );
        assert_eq!(classify("Rate limit exceeded"), Some(Refusal::Throttled));
        assert_eq!(
            classify("error: too many requests"),
            Some(Refusal::Throttled)
        );
        assert_eq!(
            classify("ws handshake not 101: HTTP/1.1 429 Too Many Requests"),
            Some(Refusal::Throttled)
        );
    }

    #[test]
    fn classify_leaves_event_and_author_refusals_alone() {
        for m in [
            "blocked: pubkey not on the allowlist",
            "restricted: paid relay",
            "auth-required: please authenticate",
            "invalid: event creation date is too far off",
            "duplicate: already have this event",
            "error: shutting down idle subscription",
            "",
        ] {
            assert_eq!(classify(m), None, "{m}");
        }
    }

    #[test]
    fn a_cooled_host_cools_for_its_span_then_frees() {
        let mut c = RelayCooldowns::new();
        let until = c.cool("relay.damus.io", Refusal::Banned, 1_000);
        assert_eq!(until, 1_000 + BANNED_MS);
        assert!(c.cooling("relay.damus.io", 1_000));
        assert!(c.cooling("RELAY.DAMUS.IO", until - 1));
        assert!(!c.cooling("relay.damus.io", until));
        assert!(!c.cooling("relay.primal.net", 1_000));
    }

    #[test]
    fn a_shorter_refusal_never_shortens_a_longer_cooldown() {
        let mut c = RelayCooldowns::new();
        let banned = c.cool("a", Refusal::Banned, 0);
        assert_eq!(c.cool("a", Refusal::Throttled, 60_000), banned);
        let mut t = RelayCooldowns::new();
        t.cool("a", Refusal::Throttled, 0);
        assert_eq!(t.cool("a", Refusal::Banned, 60_000), 60_000 + BANNED_MS);
    }

    #[test]
    fn the_table_is_bounded_and_evicts_what_ends_soonest() {
        let mut c = RelayCooldowns::new();
        c.cool("soon", Refusal::Throttled, 0);
        for i in 0..COOLDOWN_RELAYS_MAX - 1 {
            c.cool(&alloc::format!("h{i}"), Refusal::Banned, 0);
        }
        c.cool("new", Refusal::Banned, 0);
        assert_eq!(c.entries.len(), COOLDOWN_RELAYS_MAX);
        assert!(!c.cooling("soon", 1));
        assert!(c.cooling("new", 1));
    }

    #[test]
    fn pick_passes_cooling_relays_by_in_rotation_order() {
        let hosts = [
            "relay.trotters.cc",
            "relay.damus.io",
            "relay.primal.net",
            "nos.lol",
        ];
        let mut c = RelayCooldowns::new();
        c.cool("relay.damus.io", Refusal::Banned, 0);
        assert_eq!(
            c.pick(&hosts, 1, 10),
            Some(Pick {
                index: 2,
                all_cooling: false
            })
        );
        assert_eq!(
            c.pick(&hosts, 0, 10),
            Some(Pick {
                index: 0,
                all_cooling: false
            })
        );
        assert_eq!(
            c.pick(&hosts, 5, 10),
            Some(Pick {
                index: 2,
                all_cooling: false
            })
        );
    }

    #[test]
    fn pick_never_leaves_the_board_with_nothing_to_dial() {
        let hosts = ["a", "b", "c"];
        let mut c = RelayCooldowns::new();
        c.cool("a", Refusal::Banned, 0);
        c.cool("b", Refusal::Throttled, 0);
        c.cool("c", Refusal::Banned, 0);
        assert_eq!(
            c.pick(&hosts, 0, 10),
            Some(Pick {
                index: 1,
                all_cooling: true
            })
        );
        // Once b's cooldown ends it is simply free again.
        assert_eq!(
            c.pick(&hosts, 0, THROTTLED_MS),
            Some(Pick {
                index: 1,
                all_cooling: false
            })
        );
        assert_eq!(c.pick(&[], 0, 0), None);
    }

    #[test]
    fn a_tie_goes_to_the_earliest_in_rotation_order() {
        let hosts = ["a", "b"];
        let mut c = RelayCooldowns::new();
        c.cool("a", Refusal::Banned, 0);
        c.cool("b", Refusal::Banned, 0);
        assert_eq!(
            c.pick(&hosts, 1, 10),
            Some(Pick {
                index: 1,
                all_cooling: true
            })
        );
    }

    #[test]
    fn cooling_hosts_lists_only_live_cooldowns() {
        let mut c = RelayCooldowns::new();
        c.cool("a", Refusal::Throttled, 0);
        c.cool("b", Refusal::Banned, 0);
        let live: Vec<_> = c.cooling_hosts(THROTTLED_MS).collect();
        assert_eq!(live, [("b", BANNED_MS - THROTTLED_MS)]);
    }
}
