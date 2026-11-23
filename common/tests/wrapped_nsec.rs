#![cfg(feature = "wrapped-nsec")]
use heartwood_common::{
    derive,
    encoding::encode_npub,
    wrapped_nsec::{unwrap_nsec, wrap_nsec},
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/wrapped-nsec-v1.json")).unwrap()
}

#[test]
fn stored_slot_key_must_match_the_displayed_identity_before_root_conversion() {
    use heartwood_common::wrapped_nsec::verify_slot_key;
    let expected = encode_npub(&[
        0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61, 0x5d,
        0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07, 0x58,
        0x71, 0xaa,
    ]);
    assert!(verify_slot_key(&[0x11; 32], &expected).is_ok());
    for corrupt in [[0x33; 32], [0u8; 32]] {
        assert!(verify_slot_key(&corrupt, &expected).is_err());
    }
    let converted = derive::nsec_to_tree_root(&[0x11; 32]).unwrap();
    assert!(verify_slot_key(&converted, &expected).is_err());
}

#[test]
fn shared_vector_preserves_exact_raw_key() {
    let root = derive::nsec_to_tree_root(&[0x11; 32]).unwrap();
    let record = wrap_nsec(&root, &[0x22; 32], |bytes| {
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(record, fixture()["record"]);
    let expected = encode_npub(&derive::public_key_xonly(&[0x22; 32]).unwrap());
    let restored = unwrap_nsec(&root, &record, Some(&expected)).unwrap();
    assert_eq!(*restored.private_key, [0x22; 32]);
    assert_eq!(restored.npub, expected);
}

#[test]
fn rejects_wrong_root_expected_identity_and_every_changed_byte() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let v = fixture();
    let record = v["record"].as_str().unwrap();
    let root = derive::nsec_to_tree_root(&[0x11; 32]).unwrap();
    assert!(unwrap_nsec(&[0x33; 32], record, None).is_err());
    assert!(unwrap_nsec(&root, record, Some("npub1wrong")).is_err());
    let original = URL_SAFE_NO_PAD.decode(&record[6..]).unwrap();
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert!(unwrap_nsec(
            &root,
            &format!("nstw1:{}", URL_SAFE_NO_PAD.encode(changed)),
            None
        )
        .is_err());
    }
    for bad in [
        format!("{record}="),
        format!(" {record}"),
        record[..180].to_string(),
        "x".repeat(1024),
    ] {
        assert!(unwrap_nsec(&root, &bad, None).is_err());
    }
}

#[test]
fn entropy_failure_and_invalid_scalars_never_export() {
    assert!(wrap_nsec(&[0x11; 32], &[0x22; 32], |_| Err(())).is_err());
    for raw in [[0u8; 32], [0xff; 32]] {
        assert!(wrap_nsec(&[0x11; 32], &raw, |b| {
            b.fill(7);
            Ok(())
        })
        .is_err());
    }
}

#[test]
fn authenticated_invalid_scalar_and_inconsistent_public_key_are_refused() {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;
    let root = derive::nsec_to_tree_root(&[0x11; 32]).unwrap();
    let mut header = [0u8; 51];
    header[..7].copy_from_slice(b"NSTW\x01\x01\x01");
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&header[7..39]), root.as_ref())
        .expand(b"nsec-tree/wrapped-nsec/v1", key.as_mut())
        .unwrap();
    for raw in [[0u8; 32], [0xff; 32], [0x22; 32]] {
        let mut payload = Zeroizing::new([0u8; 64]);
        payload[..32].copy_from_slice(&raw); // Deliberately invalid/mismatched public half.
        let nonce = Nonce::from([0u8; 12]);
        let encrypted = Aes256Gcm::new_from_slice(key.as_ref())
            .unwrap()
            .encrypt(
                &nonce,
                Payload {
                    msg: payload.as_ref(),
                    aad: &header,
                },
            )
            .unwrap();
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&encrypted);
        assert!(unwrap_nsec(
            &root,
            &format!("nstw1:{}", URL_SAFE_NO_PAD.encode(bytes)),
            None
        )
        .is_err());
    }
}
