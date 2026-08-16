//! Pure reply-timestamp arithmetic for a signer that has no wall clock.
//!
//! The device never learns the real time. All it has is a monotonic uptime
//! counter and the `created_at` its clients and relays put on the events it
//! receives. Replies used to carry the *request's* own `created_at`, so a
//! reply published after a 45-second approval window was stamped 45 seconds in
//! the past (#64) — visibly wrong to anyone reading the conversation, and
//! worse the longer the operator took to press the button.
//!
//! Two independent estimates are combined here:
//!
//! * how long we actually held the request, measured on the uptime counter and
//!   added to the request's own stamp — immune to anything another client says;
//! * the freshest `created_at` observed from any relay event, projected forward
//!   by uptime — which corrects a client whose own clock runs slow.
//!
//! The observed estimate is only allowed to raise the stamp, and only within
//! [`MAX_OBSERVED_SKEW_SECS`]. Without that cap one client stamping a request
//! far in the future would drag every other client's replies along with it.

/// How far ahead of our own held-for estimate the observed clock may pull a
/// reply stamp. Honest clock skew between clients is seconds; anything beyond
/// this is a broken or lying peer, so its idea of "now" is ignored rather than
/// propagated onto replies we send to everyone else.
pub const MAX_OBSERVED_SKEW_SECS: u64 = 900;

/// Freshest wall-clock reading observed from the relays, anchored to the
/// uptime at which it was seen so it can be projected forward.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplyClock {
    observed: u64,
    observed_at_uptime: u64,
}

impl ReplyClock {
    /// A clock that has observed nothing yet.
    pub const fn new() -> Self {
        Self {
            observed: 0,
            observed_at_uptime: 0,
        }
    }

    /// Record the `created_at` of an event just received from a relay.
    ///
    /// Only readings ahead of the current projection move the clock, so a
    /// backdated event (a NIP-59 seal jitters up to two days into the past)
    /// never drags it backwards.
    pub fn observe(&mut self, created_at: u64, uptime_secs: u64) {
        if created_at > self.projected(uptime_secs) {
            self.observed = created_at;
            self.observed_at_uptime = uptime_secs;
        }
    }

    /// The clock's estimate of the current wall time, or 0 when nothing has
    /// been observed yet (a device that has just booted and not yet read an
    /// event has no opinion, and callers fall back to their own estimate).
    pub fn projected(&self, uptime_secs: u64) -> u64 {
        if self.observed == 0 {
            return 0;
        }
        self.observed
            .saturating_add(uptime_secs.saturating_sub(self.observed_at_uptime))
    }

    /// Stamp for a reply to a request that carried `request_created_at` and
    /// was received at `received_uptime`, being published now at
    /// `now_uptime`.
    ///
    /// Never earlier than the request itself, so a reply cannot predate the
    /// thing it answers.
    pub fn stamp(&self, request_created_at: u64, received_uptime: u64, now_uptime: u64) -> u64 {
        let held = now_uptime.saturating_sub(received_uptime);
        let own = request_created_at.saturating_add(held);
        let projected = self.projected(now_uptime);
        if projected > own && projected - own <= MAX_OBSERVED_SKEW_SECS {
            projected
        } else {
            own
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: u64 = 1_700_000_000;

    #[test]
    fn a_reply_held_for_an_approval_window_is_stamped_when_it_is_sent() {
        let clock = ReplyClock::new();
        // Request received at uptime 100, button pressed 45 s later.
        assert_eq!(clock.stamp(REQ, 100, 145), REQ + 45);
    }

    #[test]
    fn an_immediate_reply_keeps_the_requests_own_stamp() {
        let clock = ReplyClock::new();
        assert_eq!(clock.stamp(REQ, 100, 100), REQ);
    }

    #[test]
    fn a_reply_never_predates_the_request_it_answers() {
        let clock = ReplyClock::new();
        // Uptime cannot really go backwards, but the arithmetic must not
        // underflow into a stamp before the request if it ever appears to.
        assert_eq!(clock.stamp(REQ, 200, 100), REQ);
    }

    #[test]
    fn an_unobserved_clock_has_no_opinion_and_does_not_zero_the_stamp() {
        let clock = ReplyClock::new();
        assert_eq!(clock.projected(5_000), 0);
        assert_eq!(clock.stamp(REQ, 100, 130), REQ + 30);
    }

    #[test]
    fn the_observed_clock_corrects_a_client_running_slow() {
        let mut clock = ReplyClock::new();
        // Another client's event says the real time is 60 s later than this
        // client thinks, seen at uptime 100.
        clock.observe(REQ + 60, 100);
        // Our own estimate after a 10 s hold is REQ + 10; the observed clock
        // projects REQ + 70, which is fresher and plausible.
        assert_eq!(clock.stamp(REQ, 100, 110), REQ + 70);
    }

    #[test]
    fn a_client_stamping_far_in_the_future_cannot_drag_other_replies_with_it() {
        let mut clock = ReplyClock::new();
        clock.observe(REQ + MAX_OBSERVED_SKEW_SECS + 1, 100);
        // Beyond the cap the observed reading is ignored entirely and the
        // reply falls back to our own held-for estimate.
        assert_eq!(clock.stamp(REQ, 100, 110), REQ + 10);
    }

    #[test]
    fn an_observation_exactly_at_the_cap_is_still_trusted() {
        let mut clock = ReplyClock::new();
        clock.observe(REQ + MAX_OBSERVED_SKEW_SECS, 100);
        assert_eq!(clock.stamp(REQ, 100, 100), REQ + MAX_OBSERVED_SKEW_SECS);
    }

    #[test]
    fn a_backdated_event_never_drags_the_clock_backwards() {
        let mut clock = ReplyClock::new();
        clock.observe(REQ, 100);
        // A NIP-59 seal jitters up to two days into the past.
        clock.observe(REQ - 172_800, 101);
        assert_eq!(clock.projected(101), REQ + 1);
    }

    #[test]
    fn the_observed_reading_projects_forward_with_uptime() {
        let mut clock = ReplyClock::new();
        clock.observe(REQ, 100);
        assert_eq!(clock.projected(100), REQ);
        assert_eq!(clock.projected(160), REQ + 60);
    }

    #[test]
    fn a_fresher_reading_re_anchors_the_projection() {
        let mut clock = ReplyClock::new();
        clock.observe(REQ, 100);
        // 30 s of uptime later a relay hands us an event stamped 90 s ahead of
        // the first: the clock re-anchors rather than keeping the stale base.
        clock.observe(REQ + 90, 130);
        assert_eq!(clock.projected(130), REQ + 90);
        assert_eq!(clock.projected(140), REQ + 100);
    }

    #[test]
    fn saturating_arithmetic_holds_at_the_top_of_the_range() {
        let mut clock = ReplyClock::new();
        clock.observe(u64::MAX, 10);
        assert_eq!(clock.projected(u64::MAX), u64::MAX);
        assert_eq!(clock.stamp(u64::MAX, 0, u64::MAX), u64::MAX);
    }
}
