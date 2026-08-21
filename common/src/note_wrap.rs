//! A bearer note as a NIP-59 rumor: the LUD-25 note URL is the content, so
//! any LNURLcash wallet can paste it, and the tags repeat what the URL says
//! so a card can be drawn without parsing it
//! (docs/plans/2026-08-21-cash-over-nostr-design.md).
//!
//! The device seals and opens these without the secret ever crossing the
//! host boundary: `build_note_rumor` feeds `nip59::gift_wrap`, and
//! `parse_note_rumor` reads what `nip59::unwrap` hands back.

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
pub fn parse_note_rumor(rumor: &UnsignedEvent) -> Result<NoteRumor, &'static str> {
    if rumor.kind != NOTE_KIND {
        return Err("not a note rumor");
    }
    let rest = strip_scheme(&rumor.content).ok_or("content is not a note URL")?;
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
        .or_else(|| tag_value(rumor, "amount").and_then(|v| v.parse().ok()))
        .filter(|a| *a > 0)
        .ok_or("no amount")?;
    Ok(NoteRumor { secret, host: host.to_string(), amount_msat })
}

fn strip_scheme(url: &str) -> Option<&str> {
    for scheme in ["lnurlw://", "https://", "http://"] {
        if url.len() >= scheme.len() && url[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Some(&url[scheme.len()..]);
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
}
