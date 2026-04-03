// common/src/encoding.rs
//
// bech32 npub encoding. Matches heartwood-core byte-for-byte.

use bech32::{Bech32, Hrp};

/// Encode a 32-byte public key as a Nostr `npub1...` bech32 string.
pub fn encode_npub(public_key: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").expect("valid hrp");
    bech32::encode::<Bech32>(hrp, public_key).expect("valid encoding")
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
}
