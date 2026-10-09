//! Home relay return for the WiFi-standalone relay loop: get back to the first
//! configured relay after the rotation has moved off it.
//!
//! The relay list is an ordered preference, but the loop's rotation never
//! treated it as one: once a drop moved the primary on to relay 2, the board
//! stayed on whatever kept working, indefinitely. On a board that holds two
//! sessions the secondary might happen to land back on relay 1; on a
//! T-Display (no PSRAM) the heap rarely spares a second TLS session, so the
//! board sits on one relay that may not be relay 1 for a day. Field case,
//! 2026-10-08/09: a board moved off relay.trotters.cc at 21:51 and served
//! relay.primal.net alone all night, while a client that knows only relay 1
//! (a single-relay bunker URI) could not reach it at all.
//!
//! So relay 1 is the home relay. While no session is on it, every
//! [`RETRY_MS`] (backing off to [`RETRY_MAX_MS`] while it keeps failing) the
//! loop tries to get back, in the cheapest way the board can afford:
//!
//! * [`HomeAction::DialSecondary`]: a second session fits, so dial home beside
//!   the primary. Nothing live is given up.
//! * [`HomeAction::FreeSecondary`]: the second slot is held by another relay.
//!   The secondary is only redundancy, so close it; the next pass dials home
//!   into the freed slot.
//! * [`HomeAction::SwapPrimary`]: one session is all the board can hold. Drop
//!   the primary and dial home; if home fails, the ordinary rotation carries
//!   on from there, so the cost of a failed return is one reconnect.
//!
//! Never while a card is open, an update or a network trial runs, or home is
//! cooling after refusing us (`relay_cooldown`). Arithmetic only, on a
//! millisecond uptime clock.

/// How long the board stays off home before the first attempt to return, and
/// between attempts while they succeed in getting nowhere.
pub const RETRY_MS: u64 = 15 * 60_000;
/// The longest wait between attempts while home keeps failing.
pub const RETRY_MAX_MS: u64 = 2 * 60 * 60_000;

/// What the loop sees on this pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HomeState {
    /// Configured relays. Home is the first; with fewer than two there is
    /// nothing to return to.
    pub relays: usize,
    /// A session (primary, secondary or pinned) is on home now.
    pub home_live: bool,
    /// Home refused us and is cooling.
    pub home_cooling: bool,
    /// A card is open, an OTA or a network trial runs, a relay update round
    /// is under way, or a session runs degraded: leave the sessions alone.
    pub suppress: bool,
    /// The second slot is free and the heap can spare a secondary session.
    pub secondary_fits: bool,
    /// A secondary session is live on a relay other than home.
    pub secondary_elsewhere: bool,
}

/// What the loop should do about home on this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeAction {
    Nothing,
    DialSecondary,
    FreeSecondary,
    SwapPrimary,
}

/// One per relay loop run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeReturn {
    next_due: u64,
    attempts: u8,
}

impl HomeReturn {
    /// Starts the clock: a board that boots off home (home down at boot)
    /// waits a full [`RETRY_MS`] before its first attempt.
    pub fn new(now_ms: u64) -> Self {
        Self {
            next_due: now_ms.saturating_add(RETRY_MS),
            attempts: 0,
        }
    }

    /// Attempts made since home was last live, for logging.
    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Decide this pass. Keeps the clock honest as a side effect: while home
    /// is live the next attempt is pushed a full [`RETRY_MS`] out, so a board
    /// that has just left home stays off it that long before coming back.
    pub fn step(&mut self, now_ms: u64, s: HomeState) -> HomeAction {
        if s.relays < 2 {
            return HomeAction::Nothing;
        }
        if s.home_live {
            self.attempts = 0;
            self.next_due = now_ms.saturating_add(RETRY_MS);
            return HomeAction::Nothing;
        }
        if s.suppress || s.home_cooling || now_ms < self.next_due {
            return HomeAction::Nothing;
        }
        if s.secondary_fits {
            self.attempted(now_ms);
            HomeAction::DialSecondary
        } else if s.secondary_elsewhere {
            // Not an attempt yet: the slot it frees is dialled next pass.
            HomeAction::FreeSecondary
        } else {
            self.attempted(now_ms);
            HomeAction::SwapPrimary
        }
    }

    fn attempted(&mut self, now_ms: u64) {
        self.attempts = self.attempts.saturating_add(1);
        let shift = u32::from(self.attempts.saturating_sub(1).min(3));
        let wait = (RETRY_MS << shift).min(RETRY_MAX_MS);
        self.next_due = now_ms.saturating_add(wait);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    fn away() -> HomeState {
        HomeState {
            relays: 4,
            ..HomeState::default()
        }
    }

    #[test]
    fn waits_a_full_interval_after_boot_before_trying() {
        let mut h = HomeReturn::new(0);
        assert_eq!(h.step(RETRY_MS - 1, away()), HomeAction::Nothing);
        assert_eq!(h.step(RETRY_MS, away()), HomeAction::SwapPrimary);
    }

    #[test]
    fn picks_the_cheapest_way_home() {
        let mut h = HomeReturn::new(0);
        let fits = HomeState {
            secondary_fits: true,
            ..away()
        };
        assert_eq!(h.step(RETRY_MS, fits), HomeAction::DialSecondary);

        let mut h = HomeReturn::new(0);
        let elsewhere = HomeState {
            secondary_elsewhere: true,
            ..away()
        };
        assert_eq!(h.step(RETRY_MS, elsewhere), HomeAction::FreeSecondary);
        // Freeing is not an attempt: with the slot now free, home is dialled
        // on the very next pass.
        let freed = HomeState {
            secondary_fits: true,
            ..away()
        };
        assert_eq!(h.step(RETRY_MS + 1_000, freed), HomeAction::DialSecondary);
    }

    #[test]
    fn freed_slot_that_does_not_fit_swaps_the_primary() {
        let mut h = HomeReturn::new(0);
        let elsewhere = HomeState {
            secondary_elsewhere: true,
            ..away()
        };
        assert_eq!(h.step(RETRY_MS, elsewhere), HomeAction::FreeSecondary);
        assert_eq!(h.step(RETRY_MS + 1_000, away()), HomeAction::SwapPrimary);
    }

    #[test]
    fn backs_off_while_home_keeps_failing_then_resets_once_home() {
        let mut h = HomeReturn::new(0);
        let mut t = RETRY_MS;
        assert_eq!(h.step(t, away()), HomeAction::SwapPrimary);
        let mut gaps = alloc::vec::Vec::new();
        for _ in 0..5 {
            let last = t;
            loop {
                t += MIN;
                if h.step(t, away()) == HomeAction::SwapPrimary {
                    break;
                }
            }
            gaps.push((t - last) / MIN);
        }
        assert_eq!(gaps, [15, 30, 60, 120, 120]);
        assert_eq!(h.attempts(), 6);

        let home = HomeState {
            home_live: true,
            ..away()
        };
        assert_eq!(h.step(t, home), HomeAction::Nothing);
        assert_eq!(h.attempts(), 0);
        // Left home again: a full interval before the first return.
        assert_eq!(h.step(t + RETRY_MS - 1, away()), HomeAction::Nothing);
        assert_eq!(h.step(t + RETRY_MS, away()), HomeAction::SwapPrimary);
    }

    #[test]
    fn leaves_the_sessions_alone_when_it_should() {
        for s in [
            HomeState {
                relays: 1,
                ..away()
            },
            HomeState {
                home_live: true,
                ..away()
            },
            HomeState {
                home_cooling: true,
                ..away()
            },
            HomeState {
                suppress: true,
                ..away()
            },
        ] {
            let mut h = HomeReturn::new(0);
            assert_eq!(h.step(RETRY_MS * 10, s), HomeAction::Nothing, "{s:?}");
        }
    }

    #[test]
    fn a_suppressed_attempt_runs_as_soon_as_the_suppression_ends() {
        let mut h = HomeReturn::new(0);
        let busy = HomeState {
            suppress: true,
            ..away()
        };
        assert_eq!(h.step(RETRY_MS, busy), HomeAction::Nothing);
        assert_eq!(h.step(RETRY_MS + 30_000, away()), HomeAction::SwapPrimary);
    }
}
