//! A bearer note as a NIP-59 rumor: the LUD-25 note URL is the content, so
//! any LNURLcash wallet can paste it, and the tags repeat what the URL says
//! so a card can be drawn without parsing it
//! (docs/plans/2026-08-21-cash-over-nostr-design.md).
//!
//! The device seals and opens these without the secret ever crossing the
//! host boundary: `build_note_rumor` feeds `nip59::gift_wrap`, and
//! `parse_note_rumor` reads what `nip59::unwrap` hands back.
//!
//! Strict in what it sends, liberal in what it accepts: the device always
//! sends [`NOTE_KIND`], and also opens a NIP-17 DM ([`DM_KIND`]) whose text
//! is one note in any of the forms LUD-25 names (`lnurlw://`, `https://`, or
//! bech32 `LNURL1...`, with or without a `lightning:` prefix), because that
//! is what a stranger on an ordinary Nostr client can send today.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

use zeroize::Zeroize;

use crate::hex::{hex_decode, hex_encode};
use crate::nip46::UnsignedEvent;
use crate::note_store::{MAX_HOST_LEN, SECRET_LEN};

/// Rumor kind. Provisional: regular-event range, unused by any NIP at the
/// time of writing. Never published bare, so a clash costs nothing on the
/// wire, only in a client's content parser.
pub const NOTE_KIND: u64 = 2525;
/// NIP-17 private direct message. Accepted when its text is exactly one
/// note; never sent.
pub const DM_KIND: u64 = 14;

/// What a note rumor carries. The secret is zeroised on drop.
pub struct NoteRumor {
    pub secret: [u8; SECRET_LEN],
    /// The withdraw endpoint without scheme, as the locker stores it
    /// (`mint.example/w`).
    pub host: String,
    pub amount_msat: u64,
}

impl Drop for NoteRumor {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// `lnurlw://{host}?k1={secret}&amount={msat}` -- the LUD-17 form, which
/// resolves to http or https by host and so works for an .onion or a dev
/// mint where a hardcoded https would not.
pub fn note_url(host: &str, secret: &[u8; SECRET_LEN], amount_msat: u64) -> String {
    format!("lnurlw://{host}?k1={}&amount={amount_msat}", hex_encode(secret))
}

pub fn build_note_rumor(
    author_pk_hex: &str,
    recipient_pk: &[u8; 32],
    secret: &[u8; SECRET_LEN],
    host: &str,
    amount_msat: u64,
    created_at: u64,
) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: author_pk_hex.to_string(),
        created_at,
        kind: NOTE_KIND,
        tags: vec![
            vec!["p".to_string(), hex_encode(recipient_pk)],
            vec!["amount".to_string(), format!("{amount_msat}")],
            vec!["u".to_string(), host.to_string()],
        ],
        content: note_url(host, secret, amount_msat),
    }
}

/// Read a note out of an opened rumor. The URL is authoritative; the tags
/// only fill in an amount the URL lacks. Anything without a 32-byte `k1`
/// and a positive amount is refused -- the device cannot ask the mint, so a
/// note it cannot describe on the card is one it cannot ask the owner about.
///
/// A [`NOTE_KIND`] rumor's whole content is the note. A [`DM_KIND`] rumor
/// is prose: its whitespace-separated tokens are tried in turn, and it is a
/// note only if exactly one of them is -- two would be ambiguous, and a
/// parser that hunts inside text is a parser that can be led.
pub fn parse_note_rumor(rumor: &UnsignedEvent) -> Result<NoteRumor, &'static str> {
    match rumor.kind {
        NOTE_KIND => parse_note_text(&rumor.content, tag_value(rumor, "amount")),
        DM_KIND => {
            let mut found: Option<NoteRumor> = None;
            for token in rumor.content.split_whitespace() {
                let token = token.trim_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | '(' | ')' | '<' | '>' | '"' | '\''));
                if let Ok(note) = parse_note_text(token, None) {
                    if found.is_some() {
                        return Err("more than one note in the message");
                    }
                    found = Some(note);
                }
            }
            found.ok_or("no note in the message")
        }
        _ => Err("not a note rumor"),
    }
}

/// One note in any LUD-25 form. `amount_tag` stands in for an amount the
/// URL lacks (a [`NOTE_KIND`] rumor repeats it as a tag; a DM has none).
fn parse_note_text(text: &str, amount_tag: Option<&str>) -> Result<NoteRumor, &'static str> {
    let text = strip_prefix_ci(text, "lightning:").unwrap_or(text);
    let decoded;
    let url = if text.len() >= 6 && text[..6].eq_ignore_ascii_case("lnurl1") {
        decoded = decode_lnurl(text)?;
        decoded.as_str()
    } else {
        text
    };
    let rest = strip_scheme(url).ok_or("content is not a note URL")?;
    let (host, query) = rest.split_once('?').ok_or("note URL has no query")?;
    if host.is_empty() || host.len() > MAX_HOST_LEN || host.contains('@') {
        return Err("bad host");
    }
    let mut k1_hex: Option<&str> = None;
    let mut amount: Option<u64> = None;
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("k1", v)) => k1_hex = Some(v),
            Some(("amount", v)) => amount = v.parse().ok(),
            _ => {}
        }
    }
    let k1_hex = k1_hex.ok_or("note URL has no k1")?;
    if k1_hex.len() != SECRET_LEN * 2 {
        return Err("k1 is not 32 bytes");
    }
    let lowered = k1_hex.to_ascii_lowercase();
    let mut bytes = hex_decode(&lowered).map_err(|_| "k1 is not hex")?;
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let amount_msat = amount
        .or_else(|| amount_tag.and_then(|v| v.parse().ok()))
        .filter(|a| *a > 0)
        .ok_or("no amount")?;
    Ok(NoteRumor { secret, host: host.to_string(), amount_msat })
}

/// LUD-01: the URL's bytes, bech32 with hrp `lnurl`, no length limit.
fn decode_lnurl(text: &str) -> Result<String, &'static str> {
    let (hrp, bytes) = bech32::decode(text).map_err(|_| "bad bech32")?;
    if !hrp.as_str().eq_ignore_ascii_case("lnurl") {
        return Err("bech32 is not an lnurl");
    }
    let mut bytes = bytes;
    let url = core::str::from_utf8(&bytes).map(|s| s.to_string());
    bytes.zeroize();
    url.map_err(|_| "lnurl is not utf-8")
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn strip_scheme(url: &str) -> Option<&str> {
    for scheme in ["lnurlw://", "https://", "http://"] {
        if let Some(rest) = strip_prefix_ci(url, scheme) {
            return Some(rest);
        }
    }
    None
}

fn tag_value<'a>(rumor: &'a UnsignedEvent, name: &str) -> Option<&'a str> {
    rumor
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk() -> String {
        "c".repeat(64)
    }

    #[test]
    fn rumor_round_trips() {
        let secret = [0xab; SECRET_LEN];
        let rumor = build_note_rumor(&pk(), &[0xdd; 32], &secret, "mint.example/w", 21_000, 7);
        assert_eq!(rumor.kind, NOTE_KIND);
        assert_eq!(
            rumor.content,
            format!("lnurlw://mint.example/w?k1={}&amount=21000", "ab".repeat(32))
        );
        assert_eq!(rumor.tags[0], vec!["p", &"dd".repeat(32)]);
        let parsed = parse_note_rumor(&rumor).unwrap();
        assert_eq!(parsed.secret, secret);
        assert_eq!(parsed.host, "mint.example/w");
        assert_eq!(parsed.amount_msat, 21_000);
    }

    fn with_content(content: &str) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: pk(),
            created_at: 1,
            kind: NOTE_KIND,
            tags: vec![],
            content: content.to_string(),
        }
    }

    #[test]
    fn accepts_wallet_built_https_form_and_uppercase_k1() {
        let k1 = "AB".repeat(32);
        let parsed =
            parse_note_rumor(&with_content(&format!("https://mint.example/w?amount=5&k1={k1}")))
                .unwrap();
        assert_eq!(parsed.secret, [0xab; SECRET_LEN]);
        assert_eq!(parsed.amount_msat, 5);
    }

    #[test]
    fn amount_tag_fills_in_for_a_url_without_one() {
        let mut rumor = with_content(&format!("lnurlw://m.example/w?k1={}", "01".repeat(32)));
        assert_eq!(parse_note_rumor(&rumor).err(), Some("no amount"));
        rumor.tags.push(vec!["amount".to_string(), "1234".to_string()]);
        assert_eq!(parse_note_rumor(&rumor).unwrap().amount_msat, 1234);
    }

    #[test]
    fn refuses_what_it_cannot_describe() {
        let k1 = "01".repeat(32);
        for bad in [
            format!("ftp://m.example/w?k1={k1}&amount=1"),
            format!("lnurlw://m.example/w?amount=1"),
            format!("lnurlw://m.example/w?k1={}&amount=1", "01".repeat(31)),
            format!("lnurlw://m.example/w?k1={}&amount=1", "zz".repeat(32)),
            format!("lnurlw://m.example/w?k1={k1}&amount=0"),
            format!("lnurlw://?k1={k1}&amount=1"),
            format!("lnurlw://user@m.example/w?k1={k1}&amount=1"),
            format!("lnurlw://{}/w?k1={k1}&amount=1", "h".repeat(70)),
        ] {
            assert!(parse_note_rumor(&with_content(&bad)).is_err(), "{bad}");
        }
        let mut wrong_kind = with_content(&format!("lnurlw://m.example/w?k1={k1}&amount=1"));
        wrong_kind.kind = 1;
        assert!(parse_note_rumor(&wrong_kind).is_err());
    }

    fn lnurl_of(url: &str) -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("lnurl").unwrap(), url.as_bytes()).unwrap()
    }

    fn dm(content: &str) -> UnsignedEvent {
        let mut r = with_content(content);
        r.kind = DM_KIND;
        r
    }

    #[test]
    fn every_lud25_form_parses_with_or_without_a_lightning_prefix() {
        let k1 = "ab".repeat(32);
        let url = format!("https://mint.example/w?k1={k1}&amount=21000");
        let lnurl = lnurl_of(&url);
        assert!(lnurl.len() > 90, "an lnurl is longer than a segwit address; the decoder must not cap it");
        for form in [
            url.clone(),
            format!("lnurlw://mint.example/w?k1={k1}&amount=21000"),
            lnurl.clone(),
            lnurl.to_uppercase(),
            format!("lightning:{lnurl}"),
            format!("LIGHTNING:{}", lnurl.to_uppercase()),
            format!("lightning:{url}"),
        ] {
            let parsed = parse_note_rumor(&with_content(&form)).unwrap_or_else(|e| panic!("{form}: {e}"));
            assert_eq!(parsed.secret, [0xab; SECRET_LEN]);
            assert_eq!(parsed.host, "mint.example/w");
            assert_eq!(parsed.amount_msat, 21_000);
        }
    }

    #[test]
    fn a_bech32_that_is_not_an_lnurl_is_refused() {
        let npub = bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("npub").unwrap(), &[7u8; 32]).unwrap();
        assert!(parse_note_rumor(&with_content(&npub)).is_err());
        assert!(parse_note_rumor(&with_content("lnurl1notreallybech32")).is_err());
        let lnurl = lnurl_of("https://mint.example/w?amount=1");
        assert_eq!(parse_note_rumor(&with_content(&lnurl)).err(), Some("note URL has no k1"));
    }

    #[test]
    fn a_dm_with_exactly_one_note_in_its_text_is_a_note() {
        let k1 = "cd".repeat(32);
        let url = format!("lnurlw://mint.example/w?k1={k1}&amount=5000");
        for text in [
            url.clone(),
            format!("here you go: {url}"),
            format!("{url}\n\n(5 sats, enjoy!)"),
            format!("sent you some sats {}.", lnurl_of(&format!("https://mint.example/w?k1={k1}&amount=5000"))),
            format!("<{url}>"),
        ] {
            let parsed = parse_note_rumor(&dm(&text)).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(parsed.secret, [0xcd; SECRET_LEN]);
            assert_eq!(parsed.amount_msat, 5_000);
        }
    }

    #[test]
    fn a_dm_with_no_note_or_two_notes_is_not_a_note() {
        let k1 = "cd".repeat(32);
        let url = format!("lnurlw://mint.example/w?k1={k1}&amount=5000");
        assert_eq!(parse_note_rumor(&dm("hello, how are you?")).err(), Some("no note in the message"));
        assert_eq!(parse_note_rumor(&dm("")).err(), Some("no note in the message"));
        assert_eq!(
            parse_note_rumor(&dm(&format!("{url} or {}", url.replace("cd", "ef")))).err(),
            Some("more than one note in the message")
        );
        // A DM has no amount tag to fall back on: the URL must carry it.
        let mut no_amount = dm(&format!("lnurlw://mint.example/w?k1={k1}"));
        no_amount.tags.push(vec!["amount".to_string(), "1".to_string()]);
        assert_eq!(parse_note_rumor(&no_amount).err(), Some("no note in the message"));
    }

    #[test]
    fn a_note_rumor_is_still_the_whole_content() {
        let k1 = "cd".repeat(32);
        let url = format!("lnurlw://mint.example/w?k1={k1}&amount=5000");
        assert!(parse_note_rumor(&with_content(&format!("here you go: {url}"))).is_err());
    }
}
