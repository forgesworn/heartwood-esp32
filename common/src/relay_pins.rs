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
//! The primary rotation is unchanged by a pin: it picks as ever. When its
//! pick is a relay a live pinned session already serves, that session is
//! promoted to the primary in place (no second socket to one relay). The pin
//! record stays, so if the promoted session later drops and the rotation
//! moves on, the pin's own redial brings the app's relay back.

use alloc::vec::Vec;

use crate::relay_cooldown::{Pick, RelayCooldowns};

/// Two relay URLs naming the same endpoint, ignoring case and a trailing
/// slash. The relay loop's one comparison for "the same relay".
pub fn same_relay(a: &str, b: &str) -> bool {
    let norm = |u: &str| u.trim().trim_end_matches('/').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Drop the pins whose creating slot no longer exists (revoked). A pin's
/// relay being in the configured set is no reason to drop it (see the module
/// docs). Returns true when the list changed.
pub fn prune_pins<P>(pins: &mut Vec<P>, slot_alive: impl Fn(&P) -> bool) -> bool {
    let before = pins.len();
    pins.retain(|p| slot_alive(p));
    pins.len() != before
}

/// Which pin, if any, a dropped session's failure is charged to (an index
/// into `pin_urls`): the pin on the same relay. `dropped` is the session's
/// URL and whether it was still flagged pinned when it dropped. The flag does
/// not decide it: a pinned session promoted to the primary has it cleared,
/// and its drops must still back the pin's redial off. One drop, one charge.
pub fn pin_charged_by_drop(pin_urls: &[&str], dropped: (&str, bool)) -> Option<usize> {
    let (url, _still_flagged_pinned) = dropped;
    pin_urls.iter().position(|p| same_relay(p, url))
}

/// What the loop does about a missing primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryStep {
    /// Dial the configured relay the rotation picked.
    Dial(Pick),
    /// The picked relay (`relay`, an index into the configured set) already
    /// has live session `session`: make that session the primary rather than
    /// open a second socket to the same relay.
    Promote { session: usize, relay: usize },
    /// Nothing configured to serve.
    Idle,
}

/// The primary's next step, with no primary live. `configured` are the
/// relay URLs in rotation order and `hosts` their hosts (for the cooldowns);
/// `live` are the URLs of the live sessions, all of them pinned or secondary
/// since there is no primary. `start` is where the rotation stands.
pub fn primary_step(
    configured: &[&str],
    hosts: &[&str],
    live: &[&str],
    cooldowns: &RelayCooldowns,
    start: usize,
    now_ms: u64,
) -> PrimaryStep {
    let Some(pick) = cooldowns.pick(hosts, start, now_ms) else {
        return PrimaryStep::Idle;
    };
    match live
        .iter()
        .position(|l| same_relay(l, configured[pick.index]))
    {
        Some(session) => PrimaryStep::Promote {
            session,
            relay: pick.index,
        },
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

    #[test]
    fn a_promoted_session_dropping_charges_its_pin() {
        // B was promoted from its pin to the primary (flag cleared) and
        // dropped: the pin's backoff must still grow, or a flapping B is
        // redialled at once, forever.
        assert_eq!(pin_charged_by_drop(&[APP, B], (B, false)), Some(1));
    }

    #[test]
    fn a_pinned_session_dropping_charges_its_pin_once() {
        // One charge per drop, to the one pin on that relay.
        assert_eq!(pin_charged_by_drop(&[B, APP], (B, true)), Some(0));
        assert_eq!(pin_charged_by_drop(&[APP], (APP, true)), Some(0));
    }

    #[test]
    fn a_drop_on_a_relay_with_no_pin_charges_nothing() {
        assert_eq!(pin_charged_by_drop(&[B], (A, false)), None);
        assert_eq!(pin_charged_by_drop(&[], (A, false)), None);
    }

    #[test]
    fn a_drop_matches_its_pin_across_spellings() {
        for dropped in [
            "WSS://relay.primal.net/",
            "wss://Relay.Primal.Net",
            " wss://relay.primal.net/ ",
        ] {
            assert_eq!(
                pin_charged_by_drop(&[APP, B], (dropped, false)),
                Some(1),
                "{dropped}"
            );
        }
    }

    const A: &str = "wss://relay.ditto.pub";
    const B: &str = "wss://relay.primal.net";
    const C: &str = "wss://nostr.net";
    const APP: &str = "wss://relay.app.example";

    fn step(configured: &[&str], live: &[&str], c: &RelayCooldowns, start: usize) -> PrimaryStep {
        let hosts: Vec<&str> = configured
            .iter()
            .map(|u| u.trim_start_matches("wss://").trim_end_matches('/'))
            .collect();
        primary_step(configured, &hosts, live, c, start, 10)
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
                relay: 1
            }
        );
        // A trial whose candidate set is B alone: the pinned session is the
        // primary, not a reason to have none.
        assert_eq!(
            step(&[B], &[B], &c, 0),
            PrimaryStep::Promote {
                session: 0,
                relay: 0
            }
        );
        // A refused us and is cooling: the rotation passes it by onto B.
        let mut c = RelayCooldowns::new();
        c.cool("relay.ditto.pub", Refusal::Banned, 0);
        assert_eq!(
            step(&[A, B], &[B], &c, 0),
            PrimaryStep::Promote {
                session: 0,
                relay: 1
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
        ] {
            assert_eq!(
                step(&[A, B], &[APP, live], &c, 1),
                PrimaryStep::Promote {
                    session: 1,
                    relay: 1
                },
                "{live}"
            );
        }
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
