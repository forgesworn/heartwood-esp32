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
}

impl WifiRetry {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn needs_join(&self, link_up: bool) -> bool {
        !self.joined || !link_up
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
        self.index = (self.index + 1) % count.max(1);
        // A late IP event from the failed attempt must not let the caller
        // skip applying the next candidate's credentials during backoff.
        self.joined = false;
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
        // At the new location, first retry the last working network, then
        // move to the next saved network if that fails.
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
}
