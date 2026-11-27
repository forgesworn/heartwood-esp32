//! Pinned relays for the WiFi-standalone relay loop: which pins survive a
//! prune.
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
//! app's relay straight after its ACK (2026-11-27). The loop's primary
//! rotation passes by a relay a pin already serves
//! (`RelayCooldowns::pick_except`), so the two never double up.

use alloc::vec::Vec;

/// Drop the pins whose creating slot no longer exists (revoked). A pin's
/// relay being in the configured set is no reason to drop it (see the module
/// docs). Returns true when the list changed.
pub fn prune_pins<P>(pins: &mut Vec<P>, slot_alive: impl Fn(&P) -> bool) -> bool {
    let before = pins.len();
    pins.retain(|p| slot_alive(p));
    pins.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;

    /// A pin as the loop holds it: its relay and the (master, slot) it serves.
    struct Pin {
        url: &'static str,
        ms: u8,
        si: u8,
    }

    fn pin(url: &'static str, ms: u8, si: u8) -> Pin {
        Pin { url, ms, si }
    }

    const DITTO: &str = "wss://relay.ditto.pub";
    const PRIMAL: &str = "wss://relay.primal.net";
    const APP: &str = "wss://relay.app.example";

    fn configured() -> Vec<String> {
        [DITTO, PRIMAL, "wss://nostr.net"]
            .iter()
            .map(|r| r.to_string())
            .collect()
    }

    /// Prune `pins` with only the slots in `alive` existing, on a board
    /// configured with [`configured`]. The configured set is part of the
    /// scenario, not an input: the prune must not consult it.
    fn prune(pins: &mut Vec<Pin>, alive: &[(u8, u8)]) -> bool {
        let cfg = configured();
        assert!(cfg.iter().any(|r| r == PRIMAL) && !cfg.iter().any(|r| r == APP));
        prune_pins(pins, |p| alive.contains(&(p.ms, p.si)))
    }

    #[test]
    fn a_pin_on_a_configured_relay_lives_while_its_slot_does() {
        // The field case: ditto is the primary, primal is configured but not
        // live, and the app named primal. The pin is the only thing that
        // keeps the board on the relay the app listens on.
        let mut pins = vec![pin(PRIMAL, 0, 3)];
        assert!(!prune(&mut pins, &[(0, 3)]));
        assert_eq!(pins.len(), 1);
        // Spelling differences do not change the answer.
        let mut pins = vec![pin("WSS://relay.primal.net/", 0, 3)];
        assert!(!prune(&mut pins, &[(0, 3)]));
        assert_eq!(pins.len(), 1);
    }

    #[test]
    fn a_revoked_slot_takes_its_pin_with_it() {
        let mut pins = vec![pin(APP, 0, 3), pin(PRIMAL, 1, 2)];
        // Slot (0, 3) revoked; (1, 2) still paired. A slot index alive under
        // another master does not count.
        assert!(prune(&mut pins, &[(1, 2), (1, 3)]));
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].url, PRIMAL);
        assert!(prune(&mut pins, &[]));
        assert!(pins.is_empty());
    }

    #[test]
    fn a_pin_on_an_unconfigured_relay_lives_while_its_slot_does() {
        let mut pins = vec![pin(APP, 0, 3)];
        assert!(!prune(&mut pins, &[(0, 3)]));
        assert_eq!(pins.len(), 1);
    }
}
