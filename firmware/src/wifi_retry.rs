//! Shared retry cursor for locked and unlocked WiFi operation.
//! A timed-out join can still be running in the driver. Cancel it before
//! changing credentials, and never connect if applying credentials failed.

pub trait Station {
    type Error;
    fn disconnect(&mut self) -> Result<(), Self::Error>;
    fn configure(&mut self, index: usize) -> Result<(), Self::Error>;
    fn connect(&mut self) -> Result<(), Self::Error>;
}

#[derive(Default)]
pub struct WifiRetry {
    index: usize,
    joined: bool,
    order: Vec<usize>,
    position: usize,
}

impl WifiRetry {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn needs_join(&self, link_up: bool) -> bool {
        !self.joined || !link_up
    }

    pub fn needs_scan(&self, link_up: bool) -> bool {
        self.order.is_empty() || (self.joined && !link_up)
    }

    /// Visible saved networks first, strongest first. Stable ties and unseen
    /// (including hidden) networks retain saved order. A whole round is tried
    /// before rescanning, so one strong AP with bad credentials cannot starve
    /// the weaker working networks.
    pub fn rank(&mut self, strengths: &[Option<i8>]) {
        self.order = (0..strengths.len()).collect();
        self.order.sort_by(|a, b| strengths[*b].cmp(&strengths[*a]));
        self.position = 0;
        self.index = self.order.first().copied().unwrap_or(0);
        self.joined = false;
    }

    pub fn prefer(&mut self, index: usize) {
        if self.order.contains(&index) {
            self.order.retain(|i| *i != index);
            self.order.insert(0, index);
            self.position = 0;
            self.index = index;
            self.joined = false;
        }
    }

    pub fn mark_joined(&mut self) {
        self.joined = true;
    }

    /// The caller supplies a nonempty candidate list and advances on failure
    /// (including association or DHCP timeout after this call succeeds).
    pub fn start<S: Station>(&self, station: &mut S) -> Result<(), S::Error> {
        station.disconnect()?;
        station.configure(self.index)?;
        station.connect()
    }

    pub fn advance(&mut self, count: usize) {
        if self.order.is_empty() {
            self.index = (self.index + 1) % count.max(1);
        } else {
            self.position += 1;
            if self.position == self.order.len() {
                self.order.clear();
                self.index = 0;
            } else {
                self.index = self.order[self.position];
            }
        }
        // A late IP event from the failed attempt must not let the caller
        // skip applying the next candidate's credentials during backoff.
        self.joined = false;
    }
}

/// Two consecutive surveys must agree on a meaningfully stronger saved AP.
/// Failed targets are suppressed for five minutes, avoiding repeated drops of
/// a working link for a strong network whose credentials are no longer valid.
#[derive(Default)]
pub struct Roam {
    candidate: Option<usize>,
    blocked: Vec<(usize, u64)>,
}

impl Roam {
    pub fn failed(&mut self, index: usize, now: u64) {
        self.blocked
            .retain(|(i, until)| *i != index && *until > now);
        self.blocked.push((index, now + 300));
        self.candidate = None;
    }

    pub fn observe(
        &mut self,
        strengths: &[Option<i8>],
        current: usize,
        rssi: i8,
        now: u64,
    ) -> Option<usize> {
        self.blocked.retain(|(_, until)| *until > now);
        let best = strengths
            .iter()
            .enumerate()
            .filter(|(i, value)| {
                *i != current
                    && value.is_some()
                    && !self.blocked.iter().any(|(blocked, _)| blocked == i)
            })
            .max_by_key(|(_, value)| **value)
            .and_then(|(i, value)| ((value.unwrap() as i16) >= rssi as i16 + 10).then_some(i));
        let confirmed = best.is_some() && best == self.candidate;
        self.candidate = best;
        if confirmed {
            best
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        self.candidate = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Radio {
        busy: bool,
        selected: usize,
        attempts: Vec<usize>,
        reject_config: bool,
        reject_disconnect: bool,
    }

    impl Station for Radio {
        type Error = &'static str;
        fn disconnect(&mut self) -> Result<(), Self::Error> {
            if self.reject_disconnect {
                return Err("disconnect failed");
            }
            self.busy = false;
            Ok(())
        }
        fn configure(&mut self, index: usize) -> Result<(), Self::Error> {
            if self.busy || self.reject_config {
                return Err("configuration rejected");
            }
            self.selected = index;
            Ok(())
        }
        fn connect(&mut self) -> Result<(), Self::Error> {
            self.busy = true;
            self.attempts.push(self.selected);
            Ok(())
        }
    }

    #[test]
    fn timed_out_attempt_is_cancelled_before_trying_next_network() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        for _ in 0..4 {
            retry.start(&mut radio).unwrap();
            // Association or DHCP times out while the radio is still busy.
            retry.advance(3);
        }
        assert_eq!(radio.attempts, [0, 1, 2, 0]);
    }

    #[test]
    fn rejected_credentials_never_reconnect_previous_network() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        retry.start(&mut radio).unwrap();
        retry.advance(3);
        radio.reject_config = true;
        assert!(retry.start(&mut radio).is_err());
        assert_eq!(radio.attempts, [0]);
        retry.advance(3);
        radio.reject_config = false;
        retry.start(&mut radio).unwrap();
        assert_eq!(radio.attempts, [0, 2]);
    }

    #[test]
    fn cancellation_failure_does_not_change_credentials_or_connect() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        retry.start(&mut radio).unwrap();
        retry.advance(2);
        radio.reject_disconnect = true;
        assert!(retry.start(&mut radio).is_err());
        assert_eq!(radio.selected, 0);
        assert_eq!(radio.attempts, [0]);
    }

    #[test]
    fn unlocked_phase_retains_fallback_and_rotates_from_it_on_location_change() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        {
            let locked_retry = &mut retry;
            locked_retry.start(&mut radio).unwrap();
            locked_retry.advance(3);
            locked_retry.start(&mut radio).unwrap();
            locked_retry.mark_joined();
        }
        assert_eq!(retry.index(), 1);
        assert!(!retry.needs_join(true));
        assert!(retry.needs_join(false));
        // The cursor survives the phase handoff; a later survey can replace
        // its ordering without losing the shared association state.
        retry.start(&mut radio).unwrap();
        retry.advance(3);
        assert!(retry.needs_join(true));
        retry.start(&mut radio).unwrap();
        assert_eq!(radio.attempts, [0, 1, 1, 2]);
    }

    #[test]
    fn single_network_is_retried_after_cancelling_stalled_join() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        retry.start(&mut radio).unwrap();
        retry.advance(1);
        retry.start(&mut radio).unwrap();
        assert_eq!(radio.attempts, [0, 0]);
    }

    #[test]
    fn late_ip_from_failed_candidate_cannot_skip_next_attempt() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        retry.start(&mut radio).unwrap();
        retry.mark_joined();
        // The AP is lost; reconnect fails, then its old IP event arrives
        // during backoff. The next candidate must still be configured.
        assert!(retry.needs_join(false));
        retry.advance(2);
        assert!(retry.needs_join(true));
        retry.start(&mut radio).unwrap();
        retry.mark_joined();
        assert!(!retry.needs_join(true));
        assert_eq!(radio.attempts, [0, 1]);
    }
    #[test]
    fn strongest_visible_first_with_hidden_fallback_and_stable_ties() {
        let mut retry = WifiRetry::default();
        retry.rank(&[None, Some(-70), Some(-40), Some(-70), None]);
        let mut order = Vec::new();
        for _ in 0..5 {
            order.push(retry.index());
            retry.advance(5);
        }
        assert_eq!(order, [2, 1, 3, 0, 4]);
        assert!(retry.needs_scan(false));
    }

    #[test]
    fn lost_link_rescans_instead_of_preferring_last_location() {
        let mut retry = WifiRetry::default();
        retry.rank(&[Some(-40), Some(-70)]);
        retry.mark_joined();
        assert!(!retry.needs_scan(true));
        assert!(retry.needs_scan(false));
        retry.rank(&[None, Some(-50)]);
        assert_eq!(retry.index(), 1);
        assert!(retry.needs_join(true));
    }

    #[test]
    fn roaming_needs_two_clear_wins_and_suppresses_failed_targets() {
        let mut roam = Roam::default();
        let strengths = [Some(-60), Some(-45)];
        assert_eq!(roam.observe(&strengths, 0, -60, 0), None);
        assert_eq!(roam.observe(&strengths, 0, -60, 30), Some(1));
        roam.failed(1, 30);
        assert_eq!(roam.observe(&strengths, 0, -60, 100), None);
        assert_eq!(roam.observe(&strengths, 0, -60, 330), None);
        assert_eq!(roam.observe(&strengths, 0, -60, 360), Some(1));
        assert_eq!(roam.observe(&[Some(-60), Some(-55)], 0, -60, 390), None);
        assert_eq!(roam.observe(&strengths, 0, -60, 420), None);
    }
    #[test]
    fn bad_strongest_ap_does_not_starve_working_fallback() {
        let mut retry = WifiRetry::default();
        let mut radio = Radio::default();
        retry.rank(&[Some(-75), Some(-40), None]);
        retry.start(&mut radio).unwrap();
        retry.advance(3);
        assert!(!retry.needs_scan(false));
        retry.start(&mut radio).unwrap();
        assert_eq!(radio.attempts, [1, 0]);
        retry.mark_joined();
        assert!(!retry.needs_join(true));
    }

    #[test]
    fn roaming_avoids_blocked_strongest_and_preserves_fallbacks() {
        let mut roam = Roam::default();
        let scores = [Some(-80), Some(-30), Some(-50)];
        roam.failed(1, 0);
        assert_eq!(roam.observe(&scores, 0, -80, 30), None);
        assert_eq!(roam.observe(&scores, 0, -80, 60), Some(2));
        let mut retry = WifiRetry::default();
        retry.rank(&scores);
        retry.prefer(2);
        assert_eq!(retry.index(), 2);
        retry.advance(3);
        assert_eq!(retry.index(), 1);
        retry.advance(3);
        assert_eq!(retry.index(), 0);
        roam.reset();
        assert_eq!(roam.observe(&scores, 0, -80, 90), None);
    }
}
