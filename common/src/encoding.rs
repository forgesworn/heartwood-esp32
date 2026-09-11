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

    // lnurlcash-kit test/vectors/part2.json: the first branch's first note
    // and the first certificate.
    const CP1: &str = "cp1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsaxrq2j";
    const PK: &str = "b52e0b9dcd39edd137cf4b6794d0d2a55f13c9aa968078394d49159651b5a02f";

    #[test]
    fn part2_strings_match_the_kit() {
        assert_eq!(encode_cp1(&unhex(PK)), CP1);
        assert_eq!(decode_cp1(CP1), Some(unhex(PK)));

        let sig = "3853442fd24808335884a4216f12ab2ffbc25a7208a53ea54e08415247ba3b2732a8cc4f77d3beac0abd79127abe9a4a005a9518e2560b3f2f98ac0cd2ee4ba500";
        let ck1 = "ck18pf5gt7jfqyrxkyy5ssk7y4t9lauyknjpzjnaf2wppq4y3a68vnn92xvfama804vp27hjyn6h6dy5qz6j5vwy4st8uhe3tqv6thyhfgq0xh4cd";
        assert_eq!(encode_ck1(&unhex(sig)), ck1);
        assert_eq!(decode_ck1(ck1), Some(unhex(sig)));

        let cert = "b2c850964a82eee8d33ed8ca321fe500c15f9fa42e7e57416542e27596aacfb67c3e8206fff2acf0260c7d27d2b63f0fa9e36a1bfc2b19924d5e9db6c1187b5300";
        let cs1 = "cs1kty9p9j2sthw35e7mr9ry8l9qrq4l8ay9el9wst9gt38t942e7m8c05zqmll9t8sycx86f7jkclsl20rdgdlc2cejfx4a8dkcyv8k5cqte7psz";
        assert_eq!(decode_cs1(cs1), Some(unhex(cert)));

        let cx1 = "cx1wanzqvp77mazu95h0ry7jlxr084fxg6w5w2dk07t4p25hpenqwhdw5wyjc7fn7eapr4jukq0vmcuz3372fy6js6kw77sj50qdaldcmqz9cgz5";
        let pubkey = unhex::<32>("776620303ef6fa2e169778c9e97cc379ea93234ea394db3fcba8554b873303ae");
        let chain = unhex::<32>("d751c4963c99fb3d08eb2e580f66f1c1463e5249a9435677bd0951e06f7edc6c");
        assert_eq!(encode_cx1(&pubkey, &chain), cx1);
        assert_eq!(decode_cx1(cx1), Some((pubkey, chain)));
    }

    #[test]
    fn part2_strings_are_read_strictly() {
        // all uppercase is the same string (BIP-350)
        assert_eq!(decode_cp1(&CP1.to_uppercase()), Some(unhex(PK)));
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
        assert_eq!(decode_ck1(CP1), None, "a cp1 is not a ck1");
        assert_eq!(
            decode_cx1("cx1k5hqh8wd88kazd70fdnef5xj54038jd2j6q8sw2dfy2ev5d45qhsnvwp55"),
            None,
            "32 bytes is not a cx1"
        );
    }
}
