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

#[cfg(test)]
mod tests {
    use super::*;

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
