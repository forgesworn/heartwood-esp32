//! Parse the `Date` header of an HTTP response into a Unix timestamp.
//!
//! The signer has no wall clock, and every relay it talks to hands it one for
//! free: RFC 9110 requires an origin server with a clock to send `Date` on any
//! response it can, and the WebSocket upgrade that opens a relay session is
//! exactly such a response. Measured against the four relays this firmware
//! ships pointed at, all four sent it and all four agreed with the host clock
//! to within one second.
//!
//! That beats the alternative it replaces. Asking a relay for its newest stored
//! note and reading that note's `created_at` works on a busy relay and quietly
//! fails on a quiet one: measured 2026-09-07, one relay's freshest note was
//! 345 s old, and an ephemeral event stamped that far in the past is rejected as
//! expired — the very failure the clock exists to avoid. `Date` is generated at
//! response time, so it is fresh by construction however quiet the relay is.
//!
//! Only the IMF-fixdate form is accepted (`Sun, 06 Nov 1994 08:49:37 GMT`).
//! RFC 9110 requires senders to use it and permits recipients to reject the two
//! obsolete formats; a signer parsing dates off the network is not the place to
//! be generous. Anything unexpected returns `None`, and the caller then has no
//! clock rather than a wrong one.

/// Fixed layout of an IMF-fixdate, which is why byte offsets are safe below:
/// `Sun, 06 Nov 1994 08:49:37 GMT` is always exactly this long.
const IMF_FIXDATE_LEN: usize = 29;

/// Parse an IMF-fixdate into seconds since the Unix epoch.
///
/// Returns `None` for any other shape, an unknown month, an out-of-range field,
/// or a day that does not exist in that month.
pub fn parse_http_date(value: &str) -> Option<u64> {
    let s = value.trim();
    if s.len() != IMF_FIXDATE_LEN || !s.ends_with(" GMT") {
        return None;
    }
    let b = s.as_bytes();
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    //  0123456789...
    if b[3] != b',' || b[4] != b' ' || b[7] != b' ' || b[11] != b' ' || b[16] != b' ' {
        return None;
    }
    if b[19] != b':' || b[22] != b':' {
        return None;
    }

    let day = two_digits(&b[5..7])?;
    let month = month_from_name(&s[8..11])?;
    let year = four_digits(&b[12..16])?;
    let hour = two_digits(&b[17..19])?;
    let min = two_digits(&b[20..22])?;
    let sec = two_digits(&b[23..25])?;

    // A leap second (:60) is legal in the grammar and has no Unix timestamp.
    // Clamp rather than reject: the caller wants "roughly now", and refusing a
    // clock over one second would be a worse trade.
    let sec = if sec == 60 { 59 } else { sec };
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }

    let days = days_from_civil(year as i64, month, day);
    // Dates before 1970 have no business in a relay's Date header and would
    // make the return type signed for no benefit.
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + u64::from(hour) * 3_600 + u64::from(min) * 60 + u64::from(sec))
}

fn two_digits(b: &[u8]) -> Option<u32> {
    if !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
}

fn four_digits(b: &[u8]) -> Option<u32> {
    let mut n = 0u32;
    for byte in b {
        if !byte.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u32::from(byte - b'0');
    }
    Some(n)
}

fn month_from_name(name: &str) -> Option<u32> {
    Some(match name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian date. Hinnant's
/// `days_from_civil`: exact for every date in range, no tables, no loops.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_rfc_example() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
    }

    #[test]
    fn parses_the_epoch_itself() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    }

    #[test]
    fn parses_a_real_relay_response() {
        // Captured from all four configured relays, 2026-09-07.
        assert_eq!(parse_http_date("Mon, 07 Sep 2026 19:50:27 GMT"), Some(1_788_810_627));
    }

    #[test]
    fn handles_a_leap_day_and_a_year_end() {
        assert_eq!(parse_http_date("Tue, 29 Feb 2028 12:00:00 GMT"), Some(1_835_438_400));
        assert_eq!(parse_http_date("Wed, 31 Dec 2025 23:59:59 GMT"), Some(1_767_225_599));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // Header values arrive with the leading space after the colon.
        assert_eq!(parse_http_date(" Sun, 06 Nov 1994 08:49:37 GMT "), Some(784_111_777));
    }

    #[test]
    fn a_leap_second_clamps_rather_than_failing() {
        // :60 is legal in the grammar and has no Unix timestamp. Losing one
        // second beats losing the clock.
        assert_eq!(parse_http_date("Wed, 31 Dec 2025 23:59:60 GMT"), Some(1_767_225_599));
    }

    #[test]
    fn the_obsolete_formats_are_refused() {
        // RFC 850 and asctime. Senders must not use them; a signer need not
        // accept them.
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), None);
    }

    #[test]
    fn rubbish_is_refused_rather_than_guessed() {
        assert_eq!(parse_http_date(""), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date("Sun, 06 Xxx 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 0X Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 31 Nov 1994 08:49:37 GMT"), None); // no 31 Nov
        assert_eq!(parse_http_date("Sun, 29 Feb 2027 08:49:37 GMT"), None); // not a leap year
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 24:49:37 GMT"), None);
    }
}
