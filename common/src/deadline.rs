//! Pure deadline-budget arithmetic shared with bounded firmware I/O.

use core::time::Duration;

/// Return the whole milliseconds remaining in one fixed budget.
///
/// The value rounds up so a positive sub-millisecond remainder never becomes a
/// zero-duration wait. `None` means the original budget is exhausted; callers
/// must not start another I/O operation.
pub fn remaining_timeout_ms(budget: Duration, elapsed: Duration) -> Option<i64> {
    let remaining = budget.checked_sub(elapsed)?;
    if remaining.is_zero() {
        return None;
    }
    let rounded_ms = remaining.as_nanos().saturating_add(999_999) / 1_000_000;
    Some(rounded_ms.min(i64::MAX as u128) as i64)
}

/// One result from a nonblocking I/O call, stripped of platform error details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonblockingIoEvent {
    /// The call transferred this many bytes. Zero is treated as a closed stream.
    Progress(usize),
    /// The TLS/socket state machine needs to be called again after yielding.
    WouldBlock,
    /// A non-retryable transport or protocol error occurred.
    Failed,
}

/// Deadline-aware action for one nonblocking I/O result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineIoAction {
    Progress(usize),
    Retry,
    Closed,
    Failed,
    DeadlineExceeded,
}

/// Classify a nonblocking I/O result against the original absolute deadline.
///
/// Deadline expiry wins even when the last call reports progress. This prevents
/// trickled bytes at the boundary from turning one fixed budget into a series of
/// fresh per-call budgets.
pub fn deadline_io_action(
    budget: Duration,
    elapsed: Duration,
    event: NonblockingIoEvent,
) -> DeadlineIoAction {
    if remaining_timeout_ms(budget, elapsed).is_none() {
        return DeadlineIoAction::DeadlineExceeded;
    }
    match event {
        NonblockingIoEvent::Progress(0) => DeadlineIoAction::Closed,
        NonblockingIoEvent::Progress(n) => DeadlineIoAction::Progress(n),
        NonblockingIoEvent::WouldBlock => DeadlineIoAction::Retry,
        NonblockingIoEvent::Failed => DeadlineIoAction::Failed,
    }
}

/// Match the resumable errors returned by a nonblocking EspTls read/write.
///
/// `want_read` and `want_write` are already negative mbedTLS return codes.
/// POSIX/lwIP errno constants are positive, but EspTls wraps a raw negative I/O
/// return unchanged, so only their negated forms are accepted here. The async
/// connect API can synthesize a positive EWOULDBLOCK, but this read/write helper
/// deliberately does not broaden that separate behavior into the upgrade loop.
pub fn retryable_tls_io_code(
    code: i32,
    want_read: i32,
    want_write: i32,
    eagain_errno: i32,
    ewouldblock_errno: i32,
) -> bool {
    code == want_read || code == want_write || code == -eagain_errno || code == -ewouldblock_errno
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_budget_decreases_instead_of_resetting_per_operation() {
        let budget = Duration::from_secs(10);
        assert_eq!(remaining_timeout_ms(budget, Duration::ZERO), Some(10_000));
        assert_eq!(
            remaining_timeout_ms(budget, Duration::from_millis(3_250)),
            Some(6_750)
        );
        assert_eq!(
            remaining_timeout_ms(budget, Duration::from_millis(9_999)),
            Some(1)
        );
    }

    #[test]
    fn trickled_progress_cannot_extend_the_original_deadline() {
        let budget = Duration::from_secs(10);
        let samples = [1_000, 4_000, 7_000, 9_000];
        let remaining = samples
            .map(|elapsed| remaining_timeout_ms(budget, Duration::from_millis(elapsed)).unwrap());
        assert_eq!(remaining, [9_000, 6_000, 3_000, 1_000]);
        assert_eq!(remaining_timeout_ms(budget, Duration::from_secs(10)), None);
    }

    #[test]
    fn positive_sub_millisecond_remainder_rounds_up() {
        assert_eq!(
            remaining_timeout_ms(Duration::from_millis(1), Duration::from_micros(999)),
            Some(1)
        );
    }

    #[test]
    fn exhausted_or_overrun_budget_has_no_timeout_left() {
        let budget = Duration::from_secs(10);
        assert_eq!(remaining_timeout_ms(budget, budget), None);
        assert_eq!(
            remaining_timeout_ms(budget, budget + Duration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn nonblocking_retry_is_allowed_only_before_the_original_deadline() {
        let budget = Duration::from_secs(10);
        assert_eq!(
            deadline_io_action(
                budget,
                Duration::from_millis(9_999),
                NonblockingIoEvent::WouldBlock,
            ),
            DeadlineIoAction::Retry,
        );
        assert_eq!(
            deadline_io_action(
                budget,
                Duration::from_secs(10),
                NonblockingIoEvent::WouldBlock,
            ),
            DeadlineIoAction::DeadlineExceeded,
        );
    }

    #[test]
    fn progress_at_the_deadline_is_rejected_even_after_trickled_bytes() {
        let budget = Duration::from_secs(10);
        let actions = [
            (1_000, NonblockingIoEvent::Progress(1)),
            (4_000, NonblockingIoEvent::WouldBlock),
            (7_000, NonblockingIoEvent::Progress(1)),
            (9_999, NonblockingIoEvent::Progress(1)),
            (10_000, NonblockingIoEvent::Progress(1)),
        ]
        .map(|(elapsed_ms, event)| {
            deadline_io_action(budget, Duration::from_millis(elapsed_ms), event)
        });
        assert_eq!(
            actions,
            [
                DeadlineIoAction::Progress(1),
                DeadlineIoAction::Retry,
                DeadlineIoAction::Progress(1),
                DeadlineIoAction::Progress(1),
                DeadlineIoAction::DeadlineExceeded,
            ],
        );
    }

    #[test]
    fn zero_length_and_fatal_results_are_distinct_before_deadline() {
        let budget = Duration::from_secs(10);
        assert_eq!(
            deadline_io_action(
                budget,
                Duration::from_secs(1),
                NonblockingIoEvent::Progress(0),
            ),
            DeadlineIoAction::Closed,
        );
        assert_eq!(
            deadline_io_action(budget, Duration::from_secs(1), NonblockingIoEvent::Failed,),
            DeadlineIoAction::Failed,
        );
    }

    #[test]
    fn tls_retry_classifier_accepts_wants_and_negative_errno_only() {
        const WANT_READ: i32 = -0x6900;
        const WANT_WRITE: i32 = -0x6880;
        const EAGAIN: i32 = 11;
        const EWOULDBLOCK: i32 = 11;
        for code in [WANT_READ, WANT_WRITE, -EAGAIN, -EWOULDBLOCK] {
            assert!(retryable_tls_io_code(
                code,
                WANT_READ,
                WANT_WRITE,
                EAGAIN,
                EWOULDBLOCK,
            ));
        }
        assert!(!retryable_tls_io_code(
            EAGAIN,
            WANT_READ,
            WANT_WRITE,
            EAGAIN,
            EWOULDBLOCK,
        ));
        assert!(!retryable_tls_io_code(
            -1,
            WANT_READ,
            WANT_WRITE,
            EAGAIN,
            EWOULDBLOCK,
        ));
    }
}
