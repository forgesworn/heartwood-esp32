//! Pinned relays for the WiFi-standalone relay loop: which pins survive a
//! prune, and how the primary rotation treats a relay a pin already serves.
//!
//! A nostrconnect pairing that names a relay the board is not on dials it and
//! pins it, so the board keeps serving the relay the app listens on. The pin
//! names the client slot that created it, and lives exactly as long as that
//! slot.
//!
//! A pin on a CONFIGURED relay is kept too. The primary rotation serves one
//! configured relay at a time, so "configured" does not mean "served": a
//! pairing that named a configured relay other than the live primary is
//! dialled and pinned, and dropping that pin on the next pass closed the
//! app's relay straight after its ACK (2026-11-27).
//!
//! The primary rotation shares the pin's retry deadline for a fresh dial.
//! When its pick is a relay a live pinned session already serves, it can
//! promote the session in place. The pin record stays so the app's relay
//! can reconnect if the primary rotates away after a drop.

use alloc::vec::Vec;

use crate::relay_cooldown::{Pick, RelayCooldowns};

/// Two relay URLs naming the same endpoint, ignoring case, a trailing
/// slash, and the default WSS port on a root URL.
pub fn same_relay(a: &str, b: &str) -> bool {
    fn endpoint(url: &str) -> &str {
        let url = url.trim().trim_end_matches('/');
        if url
            .get(..6)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("wss://"))
            && !url[6..].contains(['/', '?', '#'])
        {
            url.strip_suffix(":443").unwrap_or(url)
        } else {
            url
        }
    }
    endpoint(a).eq_ignore_ascii_case(endpoint(b))
}

/// Drop the pins whose creating slot no longer exists (revoked). A pin's
/// relay being in the configured set is no reason to drop it (see the module
/// docs). Returns true when the list changed.
pub fn prune_pins<P>(pins: &mut Vec<P>, slot_alive: impl Fn(&P) -> bool) -> bool {
    let before = pins.len();
    pins.retain(|p| slot_alive(p));
    pins.len() != before
}

/// What the loop does about a missing primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryStep {
    /// Dial the configured relay the rotation picked.
    Dial(Pick),
    /// The picked relay already has live session `session` to promote.
    Promote { session: usize, pick: Pick },
    /// No configured endpoint is eligible yet.
    Idle,
}

/// The primary's next step, with no primary live. `configured` are the
/// relay URLs in rotation order and `hosts` their hosts (for the cooldowns);
/// `live` are the URLs of the live sessions, all of them pinned or secondary
/// since there is no primary. `ready_to_dial` checks the pin retry deadline
/// for a new connection.
pub fn primary_step(
    configured: &[&str],
    hosts: &[&str],
    live: &[&str],
    cooldowns: &RelayCooldowns,
    start: usize,
    now_ms: u64,
    ready_to_dial: impl Fn(&str) -> bool,
) -> PrimaryStep {
    let live_for = |url: &str| live.iter().position(|l| same_relay(l, url));
    let Some(pick) = cooldowns.pick_eligible(hosts, start, now_ms, |index| {
        let url = configured[index];
        ready_to_dial(url) || live_for(url).is_some()
    }) else {
        return PrimaryStep::Idle;
    };
    match live_for(configured[pick.index]) {
        Some(session) => PrimaryStep::Promote { session, pick },
        None => PrimaryStep::Dial(pick),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_cooldown::Refusal;
    use alloc::vec;

    /// A pin as the loop holds it: the (master, slot) it serves.
    struct Pin {
        ms: u8,
        si: u8,
    }

    fn pin(ms: u8, si: u8) -> Pin {
        Pin { ms, si }
    }

    #[test]
    fn a_pin_lives_exactly_as_long_as_its_slot() {
        let mut pins = vec![pin(0, 3), pin(1, 2)];
        // Both slots paired: nothing changes.
        assert!(!prune_pins(&mut pins, |p| [(0, 3), (1, 2)].contains(&(p.ms, p.si))));
        assert_eq!(pins.len(), 2);
        // Slot (0, 3) revoked. A slot index alive under another master does
        // not count.
        assert!(prune_pins(&mut pins, |p| [(1, 2), (1, 3)].contains(&(p.ms, p.si))));
        assert_eq!((pins[0].ms, pins[0].si), (1, 2));
        assert!(prune_pins(&mut pins, |_| false));
        assert!(pins.is_empty());
    }

    const A: &str = "wss://relay.ditto.pub";
    const B: &str = "wss://relay.primal.net";
    const C: &str = "wss://nostr.net";
    const APP: &str = "wss://relay.app.example";

    fn rotation_pick(index: usize) -> Pick {
        Pick {
            index,
            all_cooling: false,
        }
    }

    fn step(configured: &[&str], live: &[&str], c: &RelayCooldowns, start: usize) -> PrimaryStep {
        let hosts: Vec<&str> = configured
            .iter()
            .map(|u| u.trim_start_matches("wss://").trim_end_matches('/'))
            .collect();
        primary_step(configured, &hosts, live, c, start, 10, |_| true)
    }

    #[test]
    fn a_failover_onto_the_pinned_relay_promotes_its_session() {
        // Configured [A, B], the pin on B is live, the primary on A dropped
        // and the rotation moved on to B: B becomes the primary in place.
        let c = RelayCooldowns::new();
        assert_eq!(
            step(&[A, B], &[B], &c, 1),
            PrimaryStep::Promote {
                session: 0,
                pick: rotation_pick(1),
            }
        );
        // A refused us and is cooling: the rotation passes it by onto B.
        let mut c = RelayCooldowns::new();
        c.cool("relay.ditto.pub", Refusal::Banned, 0);
        assert_eq!(
            step(&[A, B], &[B], &c, 0),
            PrimaryStep::Promote {
                session: 0,
                pick: rotation_pick(1),
            }
        );
    }

    #[test]
    fn spelling_variants_of_one_relay_are_promoted_not_redialled() {
        let c = RelayCooldowns::new();
        for live in [
            "WSS://relay.primal.net/",
            "wss://Relay.Primal.Net",
            " wss://relay.primal.net/ ",
            "wss://relay.primal.net:443/",
        ] {
            assert_eq!(
                step(&[A, B], &[APP, live], &c, 1),
                PrimaryStep::Promote {
                    session: 1,
                    pick: rotation_pick(1),
                },
                "{live}"
            );
        }
    }

    #[test]
    fn default_port_aliases_only_match_root_wss_urls() {
        assert!(same_relay(B, "WSS://Relay.Primal.Net:443/"));
        assert!(!same_relay(B, "wss://relay.primal.net:444/"));
        assert!(!same_relay(B, "wss://relay.primal.net:443/other"));
    }

    #[test]
    fn primary_waits_for_a_dropped_pins_retry_deadline() {
        let c = RelayCooldowns::new();
        let hosts = ["relay.primal.net", "relay.ditto.pub"];
        let pin_ready_at = 30_000;
        let pick = |configured: &[&str], hosts: &[&str], now_ms| {
            primary_step(configured, hosts, &[], &c, 0, now_ms, |url| {
                !same_relay(url, B) || now_ms >= pin_ready_at
            })
        };
        assert_eq!(
            pick(&[B, A], &hosts, 6_000),
            PrimaryStep::Dial(rotation_pick(1))
        );
        assert_eq!(pick(&[B], &hosts[..1], 6_000), PrimaryStep::Idle);
        assert_eq!(
            pick(&[B, A], &hosts, pin_ready_at),
            PrimaryStep::Dial(rotation_pick(0))
        );
    }

    #[test]
    fn cooldown_fallback_only_probes_a_relay_eligible_to_dial() {
        let mut c = RelayCooldowns::new();
        let hosts = ["relay.primal.net", "relay.ditto.pub"];
        c.cool(hosts[0], Refusal::Throttled, 0);
        c.cool(hosts[1], Refusal::Banned, 0);
        assert_eq!(
            primary_step(&[B, A], &hosts, &[], &c, 0, 10, |url| url != B),
            PrimaryStep::Dial(Pick {
                index: 1,
                all_cooling: true
            })
        );
    }

    #[test]
    fn with_nothing_served_the_rotation_dials_its_pick() {
        let c = RelayCooldowns::new();
        assert_eq!(
            step(&[A, B, C], &[], &c, 1),
            PrimaryStep::Dial(Pick {
                index: 1,
                all_cooling: false
            })
        );
        // A pin elsewhere in the set does not move the rotation.
        assert_eq!(
            step(&[A, B, C], &[C], &c, 0),
            PrimaryStep::Dial(Pick {
                index: 0,
                all_cooling: false
            })
        );
        assert_eq!(step(&[], &[], &c, 0), PrimaryStep::Idle);
    }

    #[test]
    fn a_pin_on_an_unconfigured_relay_is_never_promoted() {
        let c = RelayCooldowns::new();
        for start in 0..2 {
            assert!(matches!(
                step(&[A, B], &[APP], &c, start),
                PrimaryStep::Dial(_)
            ));
        }
    }
}
