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
/// The whole withdraw endpoint, path and all, because that is what the field
/// is (PR #77): `mint.example/w` and `mint.example/u/alice/w` are different
/// endpoints holding different people's money, and a card that shows only
/// `mint.example` cannot tell one tenant of a shared mint from another.
///
/// Two parts of the string decide identity and neither may be cut: the tail
/// of the HOSTNAME (the registrable domain and TLD — cutting the end is
/// exactly what makes `mint.forgesworn.dev` and `mint.forgesworn.evil.com`
/// read the same at the edge of a panel) and the path (which tenant). So the
/// characters come out of the middle of the hostname, which is the only part
/// that identifies nothing.
pub fn elide_host(host: &str, max: usize) -> String {
    let len = host.chars().count();
    if len <= max || max < 3 {
        return host.to_string();
    }
    let (name, path) = match host.find('/') {
        Some(i) => host.split_at(i),
        None => (host, ""),
    };
    // What is left for the hostname once the path and the ".." are paid for.
    let room = max.saturating_sub(path.chars().count() + 2);
    if room >= 2 {
        let name_len = name.chars().count();
        let keep: String = name.chars().skip(name_len.saturating_sub(room)).collect();
        return format!("..{keep}{path}");
    }
    // The path alone will not fit. Keep its tail, which is the tenant: a
    // wrong tenant is a wrong recipient, a truncated one is merely ugly.
    let tail: String = host.chars().skip(len - (max - 2)).collect();
    format!("..{tail}")
}

/// The money line of a note card, forced onto ONE line, for a card whose
/// second line is already spoken for (a send names its recipient there).
///
/// The host gives up the characters, never the amount: a shortened host
/// still shows the domain and the tenant, a clipped amount is a wrong
/// number.
/// If there is not even room for a useful host, the amount goes alone.
pub fn amount_and_host_line(msat: u64, host: &str, max: usize) -> String {
    let amount = format_amount(msat);
    let room = max.saturating_sub(amount.chars().count() + 3);
    if room < 6 {
        return amount;
    }
    format!("{amount} @ {}", elide_host(host, room))
}

/// The money line of a note card: the amount, and the mint it is drawn on.
///
/// Returns one line when both fit, two when they do not, so a long host
/// costs a line rather than costing the owner the host. Only for cards with
/// a spare line; use [`amount_and_host_line`] where the second is taken.
pub fn amount_and_host(msat: u64, host: &str, max: usize) -> String {
    let amount = format_amount(msat);
    let inline = format!("{amount} @ {}", elide_host(host, max));
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
    fn a_host_keeps_its_domain_tld_and_path() {
        assert_eq!(elide_host("mint.example/w", 25), "mint.example/w");
        // The lookalike case: the tail is what survives.
        let long = "mint.forgesworn.evil.example.com/w";
        let out = elide_host(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.starts_with(".."));
        // Domain, TLD and path all survive; the subdomain pays.
        assert_eq!(out, "..evil.example.com/w");
    }

    #[test]
    fn a_one_line_card_gives_up_host_characters_not_amount_ones() {
        // A send card's second line is the recipient, so the money has to
        // fit on one line whatever the host costs.
        let out = amount_and_host_line(1_110_000, "mint.forgesworn.dev/w", 25);
        assert_eq!(out.chars().count(), 25);
        assert!(out.starts_with("1 110 sats @ "));
        // Elided from the left, so the registrable domain and TLD survive.
        assert!(out.ends_with("worn.dev/w"), "{out}");
        assert!(out.contains(" @ .."));
        assert!(!out.contains('\n'));

        // No room for a host worth reading: the amount goes alone rather
        // than sharing a line with two characters of mint.
        assert_eq!(amount_and_host_line(2_100_000_000, "mint.example", 16), "2 100 000 sats");
    }

    #[test]
    fn two_tenants_of_one_mint_never_render_the_same() {
        // The reason the path stays (PR #77): these are different endpoints
        // holding different people's money.
        let alice = elide_host("mint.example.com/u/alice/w", 23);
        let bob = elide_host("mint.example.com/u/bob/w", 23);
        assert_ne!(alice, bob);
        assert!(alice.ends_with("/u/alice/w"), "{alice}");
        assert!(bob.ends_with("/u/bob/w"), "{bob}");
        // And the TLD is still there to check the mint itself against.
        assert!(alice.contains(".com"), "{alice}");
    }

    #[test]
    fn the_amount_is_never_the_field_that_gets_clipped() {
        let one = amount_and_host(21_000, "mint.example/w", 25);
        assert_eq!(one, "21 sats @ mint.example/w");

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
