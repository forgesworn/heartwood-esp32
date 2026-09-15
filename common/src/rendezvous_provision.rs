//! Canonical plaintext for the bounded rendezvous-child hand-off.
//!
//! This module intentionally has no decrypt or generic key-export API. The
//! firmware derives one child, serialises it directly into this short-lived
//! record, and passes the returned string straight to NIP-44 encryption for
//! the approved target device.

use alloc::{format, string::String};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::hex::hex_encode;

/// Encode the exact version-1 provision plaintext defined by Vennel's
/// rendezvous provisioning contract. Every string interpolated here is made
/// from fixed-size binary values or the parser's already-canonical nonce, so
/// no JSON escaping or caller-controlled field can alter the shape.
///
/// `child_secret` is represented only in the returned plaintext. Callers must
/// encrypt it to the target before making any response and must zeroise their
/// local derived key after use.
pub fn encode_record(issuer_pubkey: &[u8; 32], target_device_pubkey: &[u8; 32], rendezvous_pubkey: &[u8; 32], index: u32, nonce: &str, expires_at: u64, child_secret: &[u8; 32]) -> String {
    format!(
        "{{\"v\":1,\"p\":\"{}\",\"d\":\"{}\",\"rz\":\"{}\",\"u\":\"rendezvous\",\"i\":{},\"n\":\"{}\",\"e\":{},\"k\":\"{}\"}}",
        hex_encode(issuer_pubkey), hex_encode(target_device_pubkey), hex_encode(rendezvous_pubkey), index, nonce, expires_at, URL_SAFE_NO_PAD.encode(child_secret),
    )
}

#[cfg(test)]
mod tests {
    use super::encode_record;

    #[test]
    fn record_is_compact_canonical_and_uses_unpadded_base64url_for_the_scalar() {
        let record = encode_record(&[0x01; 32], &[0x02; 32], &[0x03; 32], 7, "AAECAwQFBgcICQoLDA0ODw", 1_700_000_000, &[0xff; 32]);
        assert_eq!(record, concat!("{\"v\":1,\"p\":\"0101010101010101010101010101010101010101010101010101010101010101\",", "\"d\":\"0202020202020202020202020202020202020202020202020202020202020202\",", "\"rz\":\"0303030303030303030303030303030303030303030303030303030303030303\",", "\"u\":\"rendezvous\",\"i\":7,\"n\":\"AAECAwQFBgcICQoLDA0ODw\",\"e\":1700000000,", "\"k\":\"__________________________________________8\"}"));
        assert!(!record.contains(' '));
        assert!(!record.contains('='));
    }
}
