// common/src/encoding.rs
//
// bech32 npub encoding. Matches heartwood-core byte-for-byte.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


use bech32::{Bech32, Hrp};

/// Encode a 32-byte public key as a Nostr `npub1...` bech32 string.
pub fn encode_npub(public_key: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").expect("valid hrp");
    bech32::encode::<Bech32>(hrp, public_key).expect("valid encoding")
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
}
