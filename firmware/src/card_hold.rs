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

/// The FULL ACCESS card's three words, as its hold sees them. They are drawn
/// only on the hold screen, so a hold counts only for the time they have been
/// on the glass (review m1): a press measured between two loop passes, or one
/// that began before the hold screen was drawn, must not approve on time the
/// owner never saw the words for.
///
/// Measured on the button sampler's own clock, not between loop passes: the
/// press's length is read just after the hold screen is drawn, and the words
/// have been up for the press's length now minus that reading.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WordsShown {
    held_at_draw: Option<u32>,
}

impl WordsShown {
    /// The hold screen has just been drawn, and the button has now been down
    /// `held_ms` (read after the draw). Only the first draw of a press
    /// starts the count; a reading of 0 (let go during the draw) starts
    /// nothing.
    pub fn drawn(&mut self, held_ms: u32) {
        if held_ms > 0 && self.held_at_draw.is_none() {
            self.held_at_draw = Some(held_ms);
        }
    }

    /// Something else covered the words: the count starts again at the next
    /// draw of the hold screen.
    pub fn hidden(&mut self) {
        self.held_at_draw = None;
    }

    /// Whether the words have been drawn during this press.
    pub fn shown(&self) -> bool {
        self.held_at_draw.is_some()
    }

    /// How long the words have been on screen, for a press now `held_ms`
    /// long (or one that ended at that length); 0 before they were drawn.
    pub fn shown_ms(&self, held_ms: u32) -> u32 {
        self.held_at_draw.map_or(0, |at| held_ms.saturating_sub(at))
    }
}

/// Judge a press on the FULL ACCESS card: as [`judge`], but only the time
/// its words have been on screen counts towards the hold.
///
/// - Still down: approved once the words have been up for the whole hold.
/// - Let go: approved only if the words were up for the whole hold before
///   the release; any other release declines, including one the words were
///   never drawn for, however long the press was.
/// - Up with no release recorded after the words were shown: the press
///   ended unmeasured, which declines (review m3) rather than leaving the
///   card waiting for its window to run out.
pub fn judge_full_access(hold: u32, words: WordsShown, held_ms: u32, released_ms: Option<u32>) -> Press {
    if let Some(released) = released_ms {
        return if words.shown() && words.shown_ms(released) >= hold {
            Press::Approved
        } else {
            Press::Declined
        };
    }
    if held_ms > 0 {
        return if words.shown() && words.shown_ms(held_ms) >= hold {
            Press::Approved
        } else {
            Press::Pending
        };
    }
    if words.shown() {
        Press::Declined
    } else {
        Press::Pending
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
    fn full_access_counts_only_the_time_the_words_were_on_screen() {
        let full = hold_ms(true);
        let mut words = WordsShown::default();
        // A long press the words were never drawn for: never approves.
        assert_eq!(judge_full_access(full, words, 0, Some(6_000)), Press::Declined);
        assert_eq!(judge_full_access(full, words, 9_000, None), Press::Pending);
        assert_eq!(judge_full_access(full, words, 0, None), Press::Pending);

        // The loop stalled 3 s into the press, then drew the hold screen.
        words.drawn(3_000);
        // A second draw in the same press does not move the start.
        words.drawn(3_500);
        assert_eq!(words.shown_ms(3_500), 500);
        // Held 5 s in all, but the words up only 2 s: not yet.
        assert_eq!(judge_full_access(full, words, 5_000, None), Press::Pending);
        // Let go at 7.9 s (words up 4.9 s): declined.
        assert_eq!(judge_full_access(full, words, 0, Some(7_999)), Press::Declined);
        // Words up the whole 5 s: approved, held or just released.
        assert_eq!(judge_full_access(full, words, 8_000, None), Press::Approved);
        assert_eq!(judge_full_access(full, words, 0, Some(8_000)), Press::Approved);
        // Up with no release recorded after the words were shown: declined.
        assert_eq!(judge_full_access(full, words, 0, None), Press::Declined);

        // Covered by another screen: the count starts again at the next draw.
        words.hidden();
        assert!(!words.shown());
        words.drawn(6_000);
        assert_eq!(judge_full_access(full, words, 10_999, None), Press::Pending);
        assert_eq!(judge_full_access(full, words, 11_000, None), Press::Approved);

        // Let go during the draw (a reading of 0): nothing starts.
        let mut late = WordsShown::default();
        late.drawn(0);
        assert!(!late.shown());
        assert_eq!(judge_full_access(full, late, 0, Some(5_200)), Press::Declined);
    }

    #[test]
    fn the_bar_fills_over_the_card_own_hold() {
        assert_eq!(hold_pct(hold_ms(true), 2_500), 50);
        assert_eq!(hold_pct(hold_ms(false), 1_000), 50);
        assert_eq!(hold_pct(hold_ms(true), 9_000), 100);
    }
}
