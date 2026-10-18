// firmware/src/card_hold.rs
//
// How long a card's hold must last, and what a press means, for every card
// the device shows: the interactive loop (approval.rs) and the relay's
// deferred cards (relay.rs `tick_button_card`) both judge a press here.
//
// One-hold pairing (signet-plans 2026-10-17 spec 4.2): the FULL ACCESS card
// asks for a 5 s hold, every other card keeps 2 s. A press shorter than the
// card's hold declines it, whichever card it is.
//
// No esp-idf dependencies on purpose: ui-preview compiles this file verbatim
// (`#[path]`) and its tests pin both thresholds.

/// The hold that approves every card except FULL ACCESS.
pub const CARD_HOLD_MS: u32 = 2_000;

/// The hold that approves the FULL ACCESS card.
pub const FULL_ACCESS_HOLD_MS: u32 = heartwood_common::owner_pairing::FULL_ACCESS_HOLD_MS as u32;

/// The hold a card needs: [`FULL_ACCESS_HOLD_MS`] for the FULL ACCESS card,
/// [`CARD_HOLD_MS`] for every other.
pub const fn hold_ms(full_access: bool) -> u32 {
    if full_access {
        FULL_ACCESS_HOLD_MS
    } else {
        CARD_HOLD_MS
    }
}

/// What a press has decided so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    /// Nothing yet: the button is up with no press, or still down short of
    /// the hold.
    Pending,
    /// Held for the whole hold.
    Approved,
    /// Let go before the hold was reached: a short press declines.
    Declined,
}

/// Judge a press against a card's hold. `held_ms` is how long the button has
/// been down so far (0 when up); `released_ms` the length of a press that has
/// just ended, if one has.
pub fn judge(hold: u32, held_ms: u32, released_ms: Option<u32>) -> Press {
    if held_ms >= hold {
        return Press::Approved;
    }
    match released_ms {
        Some(ms) if ms >= hold => Press::Approved,
        Some(_) => Press::Declined,
        None => Press::Pending,
    }
}

/// The hold's progress, 0 to 100, for the bar.
pub fn hold_pct(hold: u32, held_ms: u32) -> u32 {
    (held_ms.saturating_mul(100) / hold.max(1)).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_access_card_needs_five_seconds_and_every_other_card_two() {
        assert_eq!(hold_ms(true), 5_000);
        assert_eq!(hold_ms(false), 2_000);
        assert_eq!(u64::from(FULL_ACCESS_HOLD_MS), heartwood_common::owner_pairing::FULL_ACCESS_HOLD_MS);
    }

    #[test]
    fn a_two_second_hold_does_not_approve_full_access_and_a_short_press_declines() {
        let full = hold_ms(true);
        // Still down at 2 s (or 4.99 s): nothing yet.
        assert_eq!(judge(full, 2_000, None), Press::Pending);
        assert_eq!(judge(full, 4_999, None), Press::Pending);
        // Let go at 2 s: declined, never approved.
        assert_eq!(judge(full, 0, Some(2_000)), Press::Declined);
        assert_eq!(judge(full, 0, Some(4_999)), Press::Declined);
        // A tap declines.
        assert_eq!(judge(full, 0, Some(80)), Press::Declined);
        // The full hold, down or just released, approves.
        assert_eq!(judge(full, 5_000, None), Press::Approved);
        assert_eq!(judge(full, 0, Some(5_000)), Press::Approved);
        // No press: nothing.
        assert_eq!(judge(full, 0, None), Press::Pending);
    }

    #[test]
    fn every_other_card_keeps_its_two_second_hold() {
        let card = hold_ms(false);
        assert_eq!(judge(card, 2_000, None), Press::Approved);
        assert_eq!(judge(card, 0, Some(2_000)), Press::Approved);
        assert_eq!(judge(card, 1_999, None), Press::Pending);
        assert_eq!(judge(card, 0, Some(1_999)), Press::Declined);
    }

    #[test]
    fn the_bar_fills_over_the_card_own_hold() {
        assert_eq!(hold_pct(hold_ms(true), 2_500), 50);
        assert_eq!(hold_pct(hold_ms(false), 1_000), 50);
        assert_eq!(hold_pct(hold_ms(true), 9_000), 100);
    }
}
