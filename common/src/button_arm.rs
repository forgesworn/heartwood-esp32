//! When a cable approval card starts listening to the A button.
//!
//! Every card run by `firmware/src/approval.rs` arms only once A has been
//! seen up for [`SETTLE_UP_MS`] since the card went up: a hold already down
//! when it appears (the tail of an earlier decision, a pinned GPIO 0, a hold
//! the owner began for a relay card that a cable recovery command has just
//! taken off the screen) never counts towards this one. Pure, so the rule is
//! host-tested; the loop feeds it one read of the pin per pass.

/// How long A must read up, with no read down in between, before a card
/// arms. The same 30 ms the approval loop debounces its press edges with, so
/// one bouncing read cannot arm it.
pub const SETTLE_UP_MS: u64 = 30;

/// The arming state of one card. Armed stays armed: once the button has been
/// seen up, the next press is the owner's answer to this card, and the loop
/// times its hold from there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ButtonArm {
    /// When A last read down, in ms since the card went up. The card going
    /// up counts as a down read, so a button up from the start still needs
    /// its full [`SETTLE_UP_MS`].
    last_down_ms: u64,
    armed: bool,
}

impl ButtonArm {
    /// One read of A at `now_ms` (ms since the card went up; never earlier
    /// than the last read). Returns whether A has now been up for
    /// [`SETTLE_UP_MS`] since it was last seen down, which also arms the card.
    pub fn settled_up(&mut self, now_ms: u64, down: bool) -> bool {
        if down {
            self.last_down_ms = now_ms;
        }
        let settled = now_ms.saturating_sub(self.last_down_ms) >= SETTLE_UP_MS;
        self.armed |= settled;
        settled
    }

    /// Whether a press may now answer the card.
    pub fn armed(&self) -> bool {
        self.armed
    }
}

/// A card whose press may count only once its content has been read: the
/// firmware's approval loops step one of these every pass and ignore the A
/// button (a tap declines nothing, a hold starts nothing) until it is armed.
/// B, the explicit "no", still cancels.
pub trait CardGate {
    /// One look at the card, `elapsed_ms` since it went up, with the button
    /// down or not; returns the page to have on screen.
    fn step(&mut self, elapsed_ms: u64, button_down: bool) -> usize;
    /// Something else was drawn over the card and it is back: the page on
    /// screen starts its dwell again.
    fn restart_page(&mut self, elapsed_ms: u64);
    /// The page on screen.
    fn page(&self) -> usize;
    /// Whether a press may now answer the card.
    fn armed(&self) -> bool;
}

/// Pages that turn on their own, each on screen for `page_ms`, round and
/// round, arming the card once every page has had one full dwell and the
/// button is up: a hold can never rest on part of what it approves. A card
/// of one page has nothing to turn and arms at once (the loop's own
/// [`ButtonArm`] still needs the button seen up). The unlock phone's enrol
/// card has its own gate with a floor of its own
/// (`phone_unlock::EnrolGate`); this is the general one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageGate {
    pages: usize,
    page_ms: u64,
    page: usize,
    /// When the page on screen was first drawn; `None` before the first look.
    page_since_ms: Option<u64>,
    /// Pages that have completed a full dwell (at most `pages`).
    dwelt: usize,
    armed: bool,
}

impl PageGate {
    /// `pages` of at least one, each shown for `page_secs`.
    pub fn new(pages: usize, page_secs: u32) -> Self {
        let pages = pages.max(1);
        PageGate {
            pages,
            page_ms: u64::from(page_secs) * 1000,
            page: 0,
            page_since_ms: None,
            dwelt: 0,
            armed: pages == 1,
        }
    }

    pub fn pages(&self) -> usize {
        self.pages
    }
}

impl CardGate for PageGate {
    fn step(&mut self, elapsed_ms: u64, button_down: bool) -> usize {
        if self.pages == 1 {
            return 0;
        }
        match self.page_since_ms {
            None => self.page_since_ms = Some(elapsed_ms),
            Some(since) if elapsed_ms.saturating_sub(since) >= self.page_ms => {
                self.dwelt = (self.dwelt + 1).min(self.pages);
                self.page = (self.page + 1) % self.pages;
                self.page_since_ms = Some(elapsed_ms);
            }
            Some(_) => {}
        }
        if self.dwelt >= self.pages && !button_down {
            self.armed = true;
        }
        self.page
    }

    fn restart_page(&mut self, elapsed_ms: u64) {
        if self.page_since_ms.is_some() {
            self.page_since_ms = Some(elapsed_ms);
        }
    }

    fn page(&self) -> usize {
        self.page
    }

    fn armed(&self) -> bool {
        self.armed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_page_card_is_armed_from_the_start() {
        let mut gate = PageGate::new(1, 3);
        assert!(gate.armed());
        assert_eq!(gate.step(0, true), 0);
        assert!(gate.armed());
        // and zero pages is one
        assert_eq!(PageGate::new(0, 3).pages(), 1);
    }

    #[test]
    fn a_paged_card_arms_only_once_every_page_has_had_its_dwell() {
        let mut gate = PageGate::new(3, 3);
        let mut seen = std::vec::Vec::new();
        let mut t = 0;
        while t < 9_000 {
            seen.push(gate.step(t, false));
            assert!(!gate.armed(), "armed at {t} ms, before the last page's dwell");
            t += 20;
        }
        // Each page was on screen, in order, for its full 3 s.
        assert!(seen.contains(&0) && seen.contains(&1) && seen.contains(&2));
        assert_eq!(gate.step(9_000, false), 0, "round again");
        assert!(gate.armed());
        // Armed stays armed, and the pages keep turning.
        assert_eq!(gate.step(12_000, true), 1);
        assert!(gate.armed());
    }

    #[test]
    fn a_stalled_loop_turns_one_page_at_a_time() {
        // A pass that took 20 s still moves on one page, so no page is
        // skipped and the gate never arms on pages that were never shown.
        let mut gate = PageGate::new(4, 3);
        gate.step(0, false);
        assert_eq!(gate.step(20_000, false), 1);
        assert!(!gate.armed());
    }

    #[test]
    fn a_held_button_keeps_a_read_card_unarmed_until_it_is_let_go() {
        let mut gate = PageGate::new(2, 3);
        for t in (0..=6_000).step_by(20) {
            gate.step(t, true);
        }
        assert!(!gate.armed());
        gate.step(6_020, false);
        assert!(gate.armed());
    }

    #[test]
    fn a_card_drawn_over_starts_its_page_again() {
        let mut gate = PageGate::new(2, 3);
        gate.step(0, false);
        gate.step(2_900, false);
        gate.restart_page(2_900);
        assert_eq!(gate.step(3_000, false), 0, "the hidden time did not count");
        assert_eq!(gate.step(5_900, false), 1);
    }

    /// Feed reads every `step` ms from `from` to `to` inclusive.
    fn feed(arm: &mut ButtonArm, from: u64, to: u64, step: u64, down: bool) {
        let mut t = from;
        while t <= to {
            arm.settled_up(t, down);
            t += step;
        }
    }

    #[test]
    fn a_hold_down_when_the_card_appears_never_arms_it() {
        let mut arm = ButtonArm::default();
        feed(&mut arm, 0, 45_000, 20, true);
        assert!(!arm.armed(), "a hold that outlasts the card never answers it");
    }

    #[test]
    fn a_release_arms_the_card_once_it_has_settled() {
        let mut arm = ButtonArm::default();
        feed(&mut arm, 0, 100, 20, true);
        assert!(!arm.settled_up(120, false), "20 ms up is not yet settled");
        assert!(!arm.armed());
        assert!(arm.settled_up(130, false));
        assert!(arm.armed());
    }

    #[test]
    fn a_bouncing_release_starts_the_settle_again() {
        let mut arm = ButtonArm::default();
        arm.settled_up(100, true);
        arm.settled_up(110, false);
        arm.settled_up(120, true); // bounce
        arm.settled_up(130, false);
        assert!(!arm.settled_up(140, false), "20 ms since the bounce");
        assert!(!arm.armed());
        assert!(arm.settled_up(150, false));
        assert!(arm.armed());
    }

    #[test]
    fn a_button_up_from_the_start_still_needs_the_full_settle() {
        let mut arm = ButtonArm::default();
        assert!(!arm.settled_up(0, false));
        assert!(!arm.settled_up(20, false));
        assert!(arm.settled_up(30, false));
        assert!(arm.armed());
    }

    #[test]
    fn armed_stays_armed_through_the_answering_press() {
        let mut arm = ButtonArm::default();
        feed(&mut arm, 0, 60, 20, false);
        assert!(arm.armed());
        feed(&mut arm, 80, 2_200, 20, true);
        assert!(arm.armed(), "the press after arming is the answer, not a reset");
    }
}
