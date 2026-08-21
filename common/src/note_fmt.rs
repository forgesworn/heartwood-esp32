//! How a bearer-note amount and its mint are drawn on an approval card.
//!
//! Kept apart from the drawing code, and host-tested, for the reason
//! lnurl-vault's `src/proto/note_display.h` gives for the same split: this is
//! the part with something to get wrong. An amount rendered a factor of a
//! thousand out, or with its digits ungrouped so 21000 and 210000 look alike,
//! or with its leading digits clipped off the edge of the panel, is a wrong
//! number on the one screen where the owner is deciding whether to hand over
//! money.
//!
//! The rules are dni's, followed deliberately so a person who has used either
//! device reads the same amount the same way:
//!
//!  - **Sats when the amount is a whole number of them, msat otherwise.**
//!    Rounding a sub-sat remainder away shows an amount the note does not
//!    carry, and truncating toward zero shows 999 msat as nothing at all.
//!  - **Digits grouped in threes**, because the failure that matters here is
//!    misreading a magnitude, not misreading a digit.
//!  - **"1 sat", not "1 sats".** The screen is read by a person.

use alloc::format;
use alloc::string::{String, ToString};

/// Characters that fit across the narrowest panel we draw a card on: the
/// 128 px Heltec OLED at `FONT_5X8`. The T-Display fits more; a line sized
/// for the small board is correct on both, and the alternative is a card
/// that reads correctly on the bench board and clips on the handed-out one.
pub const CARD_LINE_CHARS: usize = 25;

/// `value`'s digits, grouped in threes with spaces.
fn grouped(value: u64) -> String {
    let mut rev = String::new();
    let mut v = value;
    if v == 0 {
        rev.push('0');
    }
    while v > 0 {
        if !rev.is_empty() && rev.chars().filter(|c| *c != ' ').count() % 3 == 0 {
            rev.push(' ');
        }
        rev.push((b'0' + (v % 10) as u8) as char);
        v /= 10;
    }
    rev.chars().rev().collect()
}

/// A note's value as a person should read it. See the module header.
///
/// ```text
///       0 ->  "0 sats"
///    1000 ->  "1 sat"
///   21000 ->  "21 sats"
/// 2100000 ->  "2 100 sats"
///    1500 ->  "1 500 msat"
/// ```
pub fn format_amount(msat: u64) -> String {
    if msat % 1000 != 0 {
        return format!("{} msat", grouped(msat));
    }
    let sats = msat / 1000;
    let unit = if sats == 1 { "sat" } else { "sats" };
    format!("{} {unit}", grouped(sats))
}

/// The mint, as much of it as a card line can carry.
///
/// The withdraw path is dropped: it carries no identity, and the characters
/// are better spent on the host. What remains is elided from the LEFT,
/// because a host is decided by its tail — cutting the end instead is
/// exactly what makes `mint.forgesworn.dev` and `mint.forgesworn.evil.com`
/// read the same at the edge of a panel.
pub fn elide_host(host: &str, max: usize) -> String {
    let bare = host.split('/').next().unwrap_or(host);
    let len = bare.chars().count();
    if len <= max || max < 3 {
        return bare.to_string();
    }
    let tail: String = bare.chars().skip(len - (max - 2)).collect();
    format!("..{tail}")
}

/// The money line of a note card: the amount, and the mint it is drawn on.
///
/// Returns one line when both fit, two when they do not. The amount is never
/// the field that gets elided — a clipped host is a host the owner must look
/// harder at, a clipped amount is a wrong number.
pub fn amount_and_host(msat: u64, host: &str, max: usize) -> String {
    let amount = format_amount(msat);
    let inline_host = elide_host(host, max);
    let inline = format!("{amount} @ {inline_host}");
    if inline.chars().count() <= max {
        return inline;
    }
    format!("{amount}\n@ {}", elide_host(host, max.saturating_sub(2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_follow_the_reference_rules() {
        // The five cases lnurl-vault's note_display.h documents.
        assert_eq!(format_amount(0), "0 sats");
        assert_eq!(format_amount(1_000), "1 sat");
        assert_eq!(format_amount(21_000), "21 sats");
        assert_eq!(format_amount(2_100_000), "2 100 sats");
        // The header there says "1500 msat"; its own grouped() writes
        // "1 500 msat". The code is the reference, not the comment.
        assert_eq!(format_amount(1_500), "1 500 msat");
    }

    #[test]
    fn a_sub_sat_note_is_never_shown_as_nothing() {
        // The bug this module replaces: 999 / 1000 == 0, drawn as "0 sats"
        // on a card releasing a note that is worth something.
        assert_eq!(format_amount(999), "999 msat");
        assert_eq!(format_amount(1), "1 msat");
        assert_eq!(format_amount(1_999), "1 999 msat");
    }

    #[test]
    fn magnitudes_do_not_look_alike() {
        assert_eq!(format_amount(21_000_000), "21 000 sats");
        assert_eq!(format_amount(210_000_000), "210 000 sats");
        assert_eq!(format_amount(2_100_000_000), "2 100 000 sats");
    }

    #[test]
    fn a_host_is_elided_from_the_left_and_loses_its_path() {
        assert_eq!(elide_host("mint.example/w", 25), "mint.example");
        // The lookalike case: the tail is what survives.
        let long = "mint.forgesworn.evil.example.com/w";
        let out = elide_host(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.ends_with("evil.example.com"));
        assert!(out.starts_with(".."));
    }

    #[test]
    fn the_amount_is_never_the_field_that_gets_clipped() {
        let one = amount_and_host(21_000, "mint.example/w", 25);
        assert_eq!(one, "21 sats @ mint.example");

        // Too long inline: the amount keeps a whole line to itself.
        let two = amount_and_host(1_110_000, "mint.forgesworn.dev/w", 25);
        let (first, second) = two.split_once('\n').expect("two lines");
        assert_eq!(first, "1 110 sats");
        assert!(second.contains("forgesworn.dev"));
        for line in two.lines() {
            assert!(line.chars().count() <= 25, "line too wide: {line}");
        }
    }
}
