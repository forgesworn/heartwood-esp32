// common/src/encoding.rs
//
// bech32 npub encoding. Matches heartwood-core byte-for-byte.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


use bech32::{Bech32, Bech32m, Hrp};

/// Encode a 32-byte public key as a Nostr `npub1...` bech32 string.
pub fn encode_npub(public_key: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").expect("valid hrp");
    bech32::encode::<Bech32>(hrp, public_key).expect("valid encoding")
}

/// Decode a Nostr `npub1...` string to its 32-byte public key. Strict: a
/// bech32 checksum (not bech32m), the `npub` prefix, a single case, zero
/// padding and exactly 32 bytes, so no two strings name one key. Surrounding
/// whitespace is not accepted.
pub fn decode_npub(value: &str) -> Option<[u8; 32]> {
    let checked = bech32::primitives::decode::CheckedHrpstring::new::<Bech32>(value).ok()?;
    if checked.hrp() != Hrp::parse("npub").ok()? {
        return None;
    }
    checked.validate_segwit_padding().ok()?;
    let bytes: Vec<u8> = checked.byte_iter().collect();
    bytes.try_into().ok()
}

// ---- LUD-25 ----
//
// Four bech32m strings, each a fixed payload: `cp1` a note's 32-byte output
// key `Q`, `ck1` a key-path spend of it, `Q || sig` (96 bytes, the note's
// bearer credential), `cs1` a mint's 65-byte recoverable certificate, and
// `cx1` a watch-only branch, x-only key then chain code. Byte-identical to
// lnurl-wallet's `recoverableNotes.ts`; `cp1`, `cs1` and `cx1` are also
// graded against lnurlcash-kit's `part2.json`.
//
// A `ck1` from before spends were bound to a mint is a bare 65-byte
// recoverable signature. Mints following the reference still accept one, so
// it still decodes here ([`Ck1::Legacy`]); nothing here makes a new one
// except `cash_key::legacy_ck1_of`.
//
// Strict on the way in, as BIP-350 and the reference mint are: a bech32 (not
// bech32m) checksum, a mixed-case string or a payload of the wrong length is
// not that type. `ck1`, `cs1` and `cx1` are longer than BIP-173's 90
// characters, which LUD-25 deliberately does not adopt; the generic encoder
// here allows them and the segwit one would not.

fn encode_fixed(hrp: &str, bytes: &[u8]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse(hrp).expect("valid hrp"), bytes).expect("valid encoding")
}

fn decode_payload(hrp: &str, value: &str) -> Option<Vec<u8>> {
    let checked = bech32::primitives::decode::CheckedHrpstring::new::<Bech32m>(value.trim()).ok()?;
    if checked.hrp() != Hrp::parse(hrp).ok()? {
        return None;
    }
    // BIP-173's padding rule, which is not only segwit's: at most four
    // leftover bits, all zero. Without it two strings would name one key.
    checked.validate_segwit_padding().ok()?;
    Some(checked.byte_iter().collect())
}

fn decode_fixed<const N: usize>(hrp: &str, value: &str) -> Option<[u8; N]> {
    decode_payload(hrp, value)?.try_into().ok()
}

pub fn encode_cp1(pubkey_x_only: &[u8; 32]) -> String {
    encode_fixed("cp", pubkey_x_only)
}

pub fn decode_cp1(value: &str) -> Option<[u8; 32]> {
    decode_fixed::<32>("cp", value)
}

/// A `ck1`, in either of the two shapes a mint following the reference
/// accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ck1 {
    /// `Q || sig`: a BIP-340 signature by `Q` over the canonical spend's
    /// key-path sighash for one mint (`taproot::key_path_sighash`).
    KeyPath { output_key: [u8; 32], signature: [u8; 64] },
    /// `r || s || recovery id` over the fixed Lightning message "LNURLcash".
    /// Deprecated: bound to no mint, and carries no `Q` (the mint recovers
    /// it). Still accepted, so a note spent with one stays spendable.
    Legacy([u8; 65]),
}

pub fn encode_ck1(output_key: &[u8; 32], signature: &[u8; 64]) -> String {
    let mut payload = [0u8; 96];
    payload[..32].copy_from_slice(output_key);
    payload[32..].copy_from_slice(signature);
    let encoded = encode_fixed("ck", &payload);
    zeroize::Zeroize::zeroize(&mut payload);
    encoded
}

/// The deprecated 65-byte `ck1`. See [`Ck1::Legacy`].
pub fn encode_legacy_ck1(signature: &[u8; 65]) -> String {
    encode_fixed("ck", signature)
}

/// Either shape, told apart by length, as the reference mint tells them.
/// Anything else under `ck` is not a `ck1`.
pub fn decode_ck1(value: &str) -> Option<Ck1> {
    let payload = decode_payload("ck", value)?;
    match payload.len() {
        96 => {
            let mut output_key = [0u8; 32];
            let mut signature = [0u8; 64];
            output_key.copy_from_slice(&payload[..32]);
            signature.copy_from_slice(&payload[32..]);
            Some(Ck1::KeyPath { output_key, signature })
        }
        65 => payload.try_into().ok().map(Ck1::Legacy),
        _ => None,
    }
}

/// A mint's certificate, `r || s || recovery id`, in either shape a mint
/// sends. LUD-25's `cs1` names the certified amount in its human-readable
/// part the way a BOLT-11 invoice does (`cs10n1...` is 1000 msat); a mint
/// from before that sent a bare `cs1...`. The locker keeps either and never
/// interprets it: the wallet checks it against the mint's key.
pub fn decode_cs1(value: &str) -> Option<[u8; 65]> {
    decode_cs1_with_amount(value).map(|(signature, _)| signature)
}

/// [`decode_cs1`], with the amount in msat its human-readable part names:
/// `None` for the older bare `cs`, which names none. lnurl-wallet's
/// `decodeCs1WithAmount` and `decodeCs1` together, the one refusing exactly
/// what the other two refuse.
pub fn decode_cs1_with_amount(value: &str) -> Option<([u8; 65], Option<u64>)> {
    let checked = bech32::primitives::decode::CheckedHrpstring::new::<Bech32m>(value.trim()).ok()?;
    let hrp = checked.hrp().to_lowercase();
    let amount_msat = cs1_amount_msat(hrp.strip_prefix("cs")?)?;
    checked.validate_segwit_padding().ok()?;
    let bytes: Vec<u8> = checked.byte_iter().collect();
    Some((bytes.try_into().ok()?, amount_msat))
}

/// A BOLT-11 amount, `<digits>[m|u|n|p]` of a bitcoin, as msat: `Some(None)`
/// when there is none at all, `None` when it is not an exact msat amount (a
/// `p` count that is not a multiple of ten, an overflow, anything else).
fn cs1_amount_msat(suffix: &str) -> Option<Option<u64>> {
    if suffix.is_empty() {
        return Some(None);
    }
    // msat per counted unit; `p` is a tenth of one, handled below.
    let (digits, per_unit) = match suffix.as_bytes()[suffix.len() - 1] {
        b'm' => (&suffix[..suffix.len() - 1], Some(100_000_000)),
        b'u' => (&suffix[..suffix.len() - 1], Some(100_000)),
        b'n' => (&suffix[..suffix.len() - 1], Some(100)),
        b'p' => (&suffix[..suffix.len() - 1], None),
        _ => (suffix, Some(100_000_000_000)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let count: u64 = digits.parse().ok()?;
    let msat = match per_unit {
        Some(per_unit) => count.checked_mul(per_unit)?,
        None if count % 10 == 0 => count / 10,
        None => return None,
    };
    Some(Some(msat))
}

pub fn encode_cx1(pubkey_x_only: &[u8; 32], chain_code: &[u8; 32]) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(pubkey_x_only);
    bytes[32..].copy_from_slice(chain_code);
    encode_fixed("cx", &bytes)
}

pub fn decode_cx1(value: &str) -> Option<([u8; 32], [u8; 32])> {
    let bytes = decode_fixed::<64>("cx", value)?;
    let mut pubkey = [0u8; 32];
    let mut chain_code = [0u8; 32];
    pubkey.copy_from_slice(&bytes[..32]);
    chain_code.copy_from_slice(&bytes[32..]);
    Some((pubkey, chain_code))
}

/// Short, OLED-safe label for a signing client that supplied no name: the
/// first 12 characters of its npub plus an ASCII ".." marker (the OLED font
/// has no Unicode ellipsis). Self-asserted client names take priority
/// upstream; this is only the anonymous fallback, and it identifies — it
/// does not authenticate.
pub fn client_fallback_label(public_key: &[u8; 32]) -> String {
    let npub = encode_npub(public_key);
    format!("{}..", &npub[..12])
}

/// Characters an identity label may take on a card. With a space and
/// [`short_npub`]'s 15 an identity line fits the narrowest panel's 25
/// small-font columns.
pub const IDENTITY_LABEL_CHARS: usize = 9;

/// A short, OLED-safe npub for approval cards: `npub1` plus the first eight
/// data characters and an ASCII `..`.
pub fn short_npub(public_key: &[u8; 32]) -> String {
    let npub = encode_npub(public_key);
    format!("{}..", &npub[..13])
}

/// The label an approval card gives an identity, at most
/// [`IDENTITY_LABEL_CHARS`] printable ASCII characters.
///
/// `name` is a registered persona's name, or the served identity's label.
/// Otherwise the purpose's last `:` segment stands in. An identity that is not
/// in the persona registry (`registered == false`, a child a context derives)
/// is marked with a leading `?` and, when its index is not 0, keeps a `#index`
/// suffix through truncation, so two children of one purpose never read the
/// same. A label that comes out empty falls back to the first eight npub data
/// characters (after `npub1`). A display aid only: the npub identifies.
pub fn identity_label(
    name: Option<&str>,
    purpose: Option<&str>,
    index: u32,
    registered: bool,
    public_key: &[u8; 32],
) -> String {
    let base = name
        .filter(|name| !name.is_empty())
        .or_else(|| purpose.map(|purpose| purpose.rsplit(':').next().unwrap_or(purpose)))
        .unwrap_or("");
    let clean = |text: &str, room: usize| -> String {
        text.chars()
            .map(|ch| if ch.is_ascii_graphic() { ch } else { '_' })
            .take(room)
            .collect()
    };
    let unregistered = !registered && purpose.is_some();
    let suffix = if unregistered && index != 0 { format!("#{index}") } else { String::new() };
    let prefix = if unregistered { "?" } else { "" };
    let room = IDENTITY_LABEL_CHARS.saturating_sub(prefix.len() + suffix.len());
    let body = clean(base, room);
    if body.is_empty() {
        let npub = encode_npub(public_key);
        return format!("{prefix}{}", &npub[5..13]);
    }
    format!("{prefix}{body}{suffix}")
}

/// The card line naming an identity: its label, then its short npub.
pub fn identity_card_line(label: &str, public_key: &[u8; 32]) -> String {
    format!("{label} {}", short_npub(public_key))
}

/// Columns an approval card heading may take: the narrowest panel's header
/// font. `SIGN AS ` plus a 12-character label and `?` fills it exactly.
pub const HEADING_CHARS: usize = 21;

/// An approval card heading: `prefix`, a space, the label cut by characters to
/// whatever the prefix leaves of [`HEADING_CHARS`], and `?`. The prefixes in
/// use are `SIGN AS` (actions of the served identity), `ALLOW AS` (let this
/// app act as an identity), `NPUB AS` (disclose one derived pubkey) and
/// `LIST IDS FOR` (let this app read the identity list).
pub fn card_heading(prefix: &str, label: &str) -> String {
    let room = HEADING_CHARS.saturating_sub(prefix.len() + 2);
    let label: String = label.chars().take(room).collect();
    format!("{prefix} {label}?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_heading_fits_the_header_for_every_prefix() {
        assert_eq!(card_heading("SIGN AS", "Alice"), "SIGN AS Alice?");
        // The historical 12-character served label still fits SIGN AS exactly.
        assert_eq!(card_heading("SIGN AS", "abcdefghijklmnop"), "SIGN AS abcdefghijkl?");
        assert_eq!(card_heading("ALLOW AS", "natural-p"), "ALLOW AS natural-p?");
        assert_eq!(card_heading("NPUB AS", "natural-p"), "NPUB AS natural-p?");
        assert_eq!(card_heading("LIST IDS FOR", "Bark browser"), "LIST IDS FOR Bark br?");
        for prefix in ["SIGN AS", "ALLOW AS", "NPUB AS", "LIST IDS FOR"] {
            let heading = card_heading(prefix, "a-very-long-identity-label");
            assert!(heading.chars().count() <= HEADING_CHARS, "{heading}");
            // Every identity label fits whole.
            let label = "?abcdefgh";
            assert!(card_heading(prefix, label).contains(label) || prefix == "LIST IDS FOR");
        }
        // Cut by characters, never mid-codepoint.
        assert_eq!(card_heading("SIGN AS", "ééééééééééééé"), "SIGN AS éééééééééééé?");
    }

    #[test]
    fn identity_labels_mark_unregistered_children_and_fall_back_to_the_npub() {
        let pubkey = [0x42u8; 32];
        let npub = encode_npub(&pubkey);
        assert_eq!(short_npub(&pubkey), format!("{}..", &npub[..13]));
        assert_eq!(short_npub(&pubkey).len(), 15);

        // Registered persona: its name, else its purpose tail.
        assert_eq!(identity_label(Some("Dad"), Some("nostr:persona:dad"), 0, true, &pubkey), "Dad");
        assert_eq!(identity_label(None, Some("nostr:persona:natural-person"), 0, true, &pubkey), "natural-p");
        // Served identity with no registry entry: its label.
        assert_eq!(identity_label(Some("Heartwood"), None, 0, true, &pubkey), "Heartwood");
        // Unregistered child: marked, index kept through truncation.
        assert_eq!(identity_label(None, Some("nostr:persona:natural-person"), 0, false, &pubkey), "?natural-");
        assert_eq!(identity_label(None, Some("nostr:persona:natural-person"), 3, false, &pubkey), "?natura#3");
        assert_eq!(identity_label(None, Some("social"), 12, false, &pubkey), "?socia#12");
        // Non-ASCII and spaces never reach the card.
        assert_eq!(identity_label(Some("Dad's phone é"), None, 0, true, &pubkey), "Dad's_pho");
        // Empty: eight npub data characters, still marked when unregistered.
        assert_eq!(identity_label(Some(""), None, 0, true, &pubkey), &npub[5..13]);
        assert_eq!(identity_label(None, Some(""), 0, false, &pubkey), format!("?{}", &npub[5..13]));
        for label in [
            identity_label(None, Some("nostr:persona:natural-person"), 4_000_000_000, false, &pubkey),
            identity_label(Some("a-very-long-name"), None, 0, true, &pubkey),
        ] {
            assert!(label.chars().count() <= IDENTITY_LABEL_CHARS, "{label}");
            assert!(label.is_ascii());
        }

        let line = identity_card_line("natural-p", &pubkey);
        assert_eq!(line, format!("natural-p {}", short_npub(&pubkey)));
        assert!(line.len() <= 25);
    }

    #[test]
    fn decode_npub_round_trips_and_is_strict() {
        let pubkey = [0x5au8; 32];
        let npub = encode_npub(&pubkey);
        assert_eq!(decode_npub(&npub), Some(pubkey));
        // All-uppercase is the same bech32 string; mixed case is not.
        assert_eq!(decode_npub(&npub.to_uppercase()), Some(pubkey));
        let mut mixed = npub.clone();
        mixed.replace_range(5..6, &npub[5..6].to_uppercase());
        assert_eq!(decode_npub(&mixed), None);
        // Wrong prefix, bad checksum, bech32m, wrong length, whitespace.
        let nsec = bech32::encode::<Bech32>(Hrp::parse("nsec").unwrap(), &pubkey).unwrap();
        assert_eq!(decode_npub(&nsec), None);
        let mut broken = npub.clone();
        let last = if broken.ends_with('q') { "p" } else { "q" };
        broken.replace_range(broken.len() - 1.., last);
        assert_eq!(decode_npub(&broken), None);
        let m = bech32::encode::<Bech32m>(Hrp::parse("npub").unwrap(), &pubkey).unwrap();
        assert_eq!(decode_npub(&m), None);
        let short = bech32::encode::<Bech32>(Hrp::parse("npub").unwrap(), &pubkey[..31]).unwrap();
        assert_eq!(decode_npub(&short), None);
        assert_eq!(decode_npub(&format!(" {npub}")), None);
        assert_eq!(decode_npub(""), None);
    }

    #[test]
    fn test_encode_npub_structure() {
        let pubkey = [0u8; 32];
        let npub = encode_npub(&pubkey);
        assert!(npub.starts_with("npub1"));
        assert_eq!(npub.len(), 63);
    }

    #[test]
    fn client_fallback_label_is_truncated_ascii_npub() {
        let pubkey = [0x7eu8; 32];
        let label = client_fallback_label(&pubkey);
        let full = encode_npub(&pubkey);
        assert_eq!(label, format!("{}..", &full[..12]));
        assert!(label.starts_with("npub1"));
        assert_eq!(label.len(), 14);
        assert!(label.is_ascii());
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let bytes = crate::hex::hex_decode(text).expect("hex");
        bytes.try_into().expect("length")
    }

    // lnurlcash-kit test/vectors/part2.json, read from the fixture rather than
    // pasted here: the first branch, its first note and the first certificate.
    fn part2() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap()
    }

    fn text<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    #[test]
    fn part2_strings_match_the_kit() {
        let vectors = part2();
        let branch = &vectors["branches"][0];
        let note = &branch["notes"][0];
        let pk = unhex::<32>(text(note, "notePubkey"));
        assert_eq!(encode_cp1(&pk), text(note, "cp1"));
        assert_eq!(decode_cp1(text(note, "cp1")), Some(pk));

        // part2.json's ck1s are the deprecated recoverable shape.
        let sig = unhex::<65>(text(note, "ownershipSignature"));
        assert_eq!(encode_legacy_ck1(&sig), text(note, "ck1"));
        assert_eq!(decode_ck1(text(note, "ck1")), Some(Ck1::Legacy(sig)));

        let cert = &vectors["certificates"][0];
        assert_eq!(decode_cs1(text(cert, "cs1")), Some(unhex(text(cert, "signature"))));

        let pubkey = unhex::<32>(text(branch, "branchPubkey"));
        let chain = unhex::<32>(text(branch, "chainCode"));
        assert_eq!(encode_cx1(&pubkey, &chain), text(branch, "cx1"));
        assert_eq!(decode_cx1(text(branch, "cx1")), Some((pubkey, chain)));
    }

    #[test]
    fn part2_strings_are_read_strictly() {
        let vectors = part2();
        let note = &vectors["branches"][0]["notes"][0];
        let cp1 = text(note, "cp1");
        // all uppercase is the same string (BIP-350)
        assert_eq!(decode_cp1(&cp1.to_uppercase()), Some(unhex(text(note, "notePubkey"))));
        // and each of part2.json's invalid cases is refused
        for bad in [
            "ck1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhs89dv0n", // wrong hrp
            "cp1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsq3mc027", // 33 bytes
            "cp1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsg6nv0s", // bech32 checksum
            "cp1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsaxrq2q", // corrupted
            "cp1k5hqh8wD88KAZD70Fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsaxrq2j", // mixed case
        ] {
            assert_eq!(decode_cp1(bad), None, "{bad}");
        }
        assert_eq!(decode_ck1(cp1), None, "a cp1 is not a ck1");
        assert_eq!(
            decode_cx1("cx1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsnvwp55"),
            None,
            "32 bytes is not a cx1"
        );
    }

    #[test]
    fn a_cs1_carries_its_amount_as_bolt11_does() {
        // LUD-25 test vectors 4 and 5: the amount rides in the
        // human-readable part, and the payload is the same 65 bytes.
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lud25-taproot.json")).unwrap();
        let mut certificates: Vec<(&str, &str, u64)> = vectors["vector4"]["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (text(c, "cs1"), text(c, "signature"), c["amountMsat"].as_u64().unwrap()))
            .collect();
        let v5 = &vectors["vector5"];
        certificates.push((text(v5, "cs1"), text(v5, "certificate"), v5["amountMsat"].as_u64().unwrap()));
        for (cs1, signature, amount) in certificates {
            let signature = unhex::<65>(signature);
            assert_eq!(decode_cs1_with_amount(cs1), Some((signature, Some(amount))), "{cs1}");
            assert_eq!(decode_cs1(cs1), Some(signature));
            assert_eq!(decode_cs1(&cs1.to_uppercase()), Some(signature));
        }
        // The older bare `cs` still decodes, and names no amount.
        let vectors = part2();
        let legacy = text(&vectors["certificates"][0], "cs1");
        assert!(matches!(decode_cs1_with_amount(legacy), Some((_, None))));

        // Every BOLT-11 multiplier, and what is not an exact msat amount.
        assert_eq!(cs1_amount_msat("1"), Some(Some(100_000_000_000)));
        assert_eq!(cs1_amount_msat("2m"), Some(Some(200_000_000)));
        assert_eq!(cs1_amount_msat("210u"), Some(Some(21_000_000)));
        assert_eq!(cs1_amount_msat("10n"), Some(Some(1_000)));
        assert_eq!(cs1_amount_msat("12340p"), Some(Some(1_234)));
        assert_eq!(cs1_amount_msat("12345p"), None, "a fraction of a msat");
        for bad in ["m", "n1", "10x", "+10n", "1 0n", "99999999999999999999n"] {
            assert_eq!(cs1_amount_msat(bad), None, "{bad}");
        }
        // Another prefix is not a certificate at all.
        let hrp = Hrp::parse("cx10n").unwrap();
        let other = bech32::encode::<Bech32m>(hrp, &[1u8; 65]).unwrap();
        assert_eq!(decode_cs1(&other), None);
    }

    #[test]
    fn a_key_path_ck1_is_q_then_the_signature() {
        // LUD-25 test vector 3's ck1, from the fixture.
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/lud25-taproot.json")).unwrap();
        let v = &vectors["vector3"];
        let q = unhex::<32>(text(v, "outputKey"));
        let sig = unhex::<64>(text(v, "signature"));
        let ck1 = encode_ck1(&q, &sig);
        assert_eq!(ck1, text(v, "ck1"));
        assert_eq!(ck1.len(), 163);
        assert_eq!(decode_ck1(&ck1), Some(Ck1::KeyPath { output_key: q, signature: sig }));
        assert_eq!(decode_ck1(&ck1.to_uppercase()), decode_ck1(&ck1));

        // Only 96 and 65 bytes are a ck1: 64 (a bare signature, no Q) and
        // 97 are not, and neither is a cp1's 32.
        let hrp = Hrp::parse("ck").unwrap();
        for len in [0usize, 32, 64, 66, 95, 97] {
            let odd = bech32::encode::<Bech32m>(hrp, &vec![7u8; len]).unwrap();
            assert_eq!(decode_ck1(&odd), None, "{len} bytes");
        }
        // A bech32 (not bech32m) checksum is not one either.
        let mut payload = q.to_vec();
        payload.extend_from_slice(&sig);
        let bech32 = bech32::encode::<Bech32>(hrp, &payload).unwrap();
        assert_eq!(decode_ck1(&bech32), None);
    }
}
