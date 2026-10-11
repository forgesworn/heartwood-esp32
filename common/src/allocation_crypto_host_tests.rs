//! Runs the actual firmware crypto path and shared strict receipt codec.
use super::*;

#[cfg(not(feature = "allocation-crypto-selfcheck-fail"))]
#[test]
fn boot_known_answers_pass_and_writer_derivation_is_exact() {
    assert!(known_answer());
    assert!(backend_ready());
    assert!(writer_matches(&KAT_SEED, &KAT_PUBLIC));
    let mut wrong = KAT_PUBLIC;
    wrong[0] ^= 1;
    assert!(!writer_matches(&KAT_SEED, &wrong));
    // Even the matching public key cannot make a prohibited zero seed eligible.
    let zero = Zeroizing::new([0; 32]);
    let public = SigningKey::from_bytes(&zero).verifying_key().to_bytes();
    assert!(!writer_matches(&zero, &public));
}

#[cfg(not(feature = "allocation-crypto-selfcheck-fail"))]
#[test]
fn independent_history_receipt_binds_status_subject_sequence_and_digest() {
    let receipt = ClearedReceipt(WitnessReceipt::parse(&KAT_RECEIPT).unwrap());
    assert_eq!(
        historical_receipt(
            &KAT_RECEIPT,
            &KAT_WITNESS,
            &receipt.0.subject,
            0,
            &receipt.0.digest
        ),
        Ok(())
    );
    let mut wrong = receipt.0.subject;
    wrong[0] ^= 1;
    assert_eq!(
        historical_receipt(&KAT_RECEIPT, &KAT_WITNESS, &wrong, 0, &receipt.0.digest),
        Err(InventoryHold::Binding)
    );
    let mut wrong = receipt.0.digest;
    wrong[0] ^= 1;
    assert_eq!(
        historical_receipt(&KAT_RECEIPT, &KAT_WITNESS, &receipt.0.subject, 0, &wrong),
        Err(InventoryHold::Binding)
    );
    assert_eq!(
        historical_receipt(
            &KAT_RECEIPT,
            &KAT_WITNESS,
            &receipt.0.subject,
            1,
            &receipt.0.digest
        ),
        Err(InventoryHold::Binding)
    );
    for status in [1, 2, 255] {
        let mut b = KAT_RECEIPT;
        b[1] = status;
        assert_eq!(
            historical_receipt(&b, &KAT_WITNESS, &receipt.0.subject, 0, &receipt.0.digest),
            Err(InventoryHold::Binding)
        );
    }
    let mut witness = KAT_WITNESS;
    witness[0] ^= 1;
    assert_eq!(
        historical_receipt(
            &KAT_RECEIPT,
            &witness,
            &receipt.0.subject,
            0,
            &receipt.0.digest
        ),
        Err(InventoryHold::Signature)
    );
}

#[cfg(not(feature = "allocation-crypto-selfcheck-fail"))]
#[test]
fn every_receipt_bit_and_truncation_is_rejected_in_the_actual_history_gate() {
    let receipt = ClearedReceipt(WitnessReceipt::parse(&KAT_RECEIPT).unwrap());
    for bit in 0..170 * 8 {
        let mut b = KAT_RECEIPT;
        b[bit / 8] ^= 1 << (bit % 8);
        assert!(
            historical_receipt(&b, &KAT_WITNESS, &receipt.0.subject, 0, &receipt.0.digest).is_err(),
            "bit {bit}"
        );
    }
    for n in 0..170 {
        assert!(historical_receipt(
            &KAT_RECEIPT[..n],
            &KAT_WITNESS,
            &receipt.0.subject,
            0,
            &receipt.0.digest
        )
        .is_err());
    }
    let mut extra = KAT_RECEIPT.to_vec();
    extra.push(0);
    assert_eq!(
        historical_receipt(
            &extra,
            &KAT_WITNESS,
            &receipt.0.subject,
            0,
            &receipt.0.digest
        ),
        Err(InventoryHold::Binding)
    );
}

#[cfg(not(feature = "allocation-crypto-selfcheck-fail"))]
#[test]
fn weak_keys_identity_signature_and_zero_challenge_never_authorize_history() {
    let receipt = ClearedReceipt(WitnessReceipt::parse(&KAT_RECEIPT).unwrap());
    let mut weak = [255; 32];
    weak[0] = 236;
    weak[31] = 127;
    assert_eq!(
        historical_receipt(
            &KAT_RECEIPT,
            &weak,
            &receipt.0.subject,
            0,
            &receipt.0.digest
        ),
        Err(InventoryHold::Signature)
    );
    let mut b = KAT_RECEIPT;
    b[106..].fill(0);
    b[106] = 1;
    assert_eq!(
        historical_receipt(&b, &KAT_WITNESS, &receipt.0.subject, 0, &receipt.0.digest),
        Err(InventoryHold::Signature)
    );
    b[74..106].fill(0);
    assert_eq!(
        historical_receipt(&b, &KAT_WITNESS, &receipt.0.subject, 0, &receipt.0.digest),
        Err(InventoryHold::Binding)
    );
}

#[cfg(feature = "allocation-crypto-selfcheck-fail")]
#[test]
fn injected_backend_failure_is_cached_and_never_uses_a_fallback() {
    assert!(!known_answer());
    assert!(!backend_ready());
    assert!(!backend_ready());
    assert_eq!(
        historical_receipt(&KAT_RECEIPT, &KAT_WITNESS, &[1; 32], 0, &[2; 32]),
        Err(InventoryHold::Crypto)
    );
}
