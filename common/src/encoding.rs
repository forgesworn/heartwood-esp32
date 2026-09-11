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

// ---- LUD-25 Part 2 ----
//
// Four bech32m strings, each a fixed payload: `cp1` a note's x-only public
// key, `ck1` its 65-byte ownership signature (the note's bearer credential),
// `cs1` a mint's certificate in the same layout, and `cx1` a watch-only
// branch, x-only key then chain code. Byte-identical to lnurlcash-kit's
// `recoverable.ts` and graded against its `part2.json`.
//
// Strict on the way in, as BIP-350 and the reference mint are: a bech32 (not
// bech32m) checksum, a mixed-case string or a payload of the wrong length is
// not that type. `ck1`, `cs1` and `cx1` are longer than BIP-173's 90
// characters, which LUD-25 deliberately does not adopt; the generic encoder
// here allows them and the segwit one would not.

fn encode_fixed(hrp: &str, bytes: &[u8]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse(hrp).expect("valid hrp"), bytes).expect("valid encoding")
}

fn decode_fixed<const N: usize>(hrp: &str, value: &str) -> Option<[u8; N]> {
    let checked = bech32::primitives::decode::CheckedHrpstring::new::<Bech32m>(value.trim()).ok()?;
    if checked.hrp() != Hrp::parse(hrp).ok()? {
        return None;
    }
    // BIP-173's padding rule, which is not only segwit's: at most four
    // leftover bits, all zero. Without it two strings would name one key.
    checked.validate_segwit_padding().ok()?;
    let bytes: Vec<u8> = checked.byte_iter().collect();
    bytes.try_into().ok()
}

pub fn encode_cp1(pubkey_x_only: &[u8; 32]) -> String {
    encode_fixed("cp", pubkey_x_only)
}

pub fn decode_cp1(value: &str) -> Option<[u8; 32]> {
    decode_fixed::<32>("cp", value)
}

pub fn encode_ck1(signature: &[u8; 65]) -> String {
    encode_fixed("ck", signature)
}

pub fn decode_ck1(value: &str) -> Option<[u8; 65]> {
    decode_fixed::<65>("ck", value)
}

pub fn decode_cs1(value: &str) -> Option<[u8; 65]> {
    decode_fixed::<65>("cs", value)
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

#[cfg(test)]
mod tests {
    use super::*;

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

        let sig = unhex::<65>(text(note, "ownershipSignature"));
        assert_eq!(encode_ck1(&sig), text(note, "ck1"));
        assert_eq!(decode_ck1(text(note, "ck1")), Some(sig));

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
}
