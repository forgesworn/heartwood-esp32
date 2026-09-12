#![cfg(feature = "mnemonic")]

use heartwood_common::recovery_words::{
    create_mnemonic_recovery_words, create_nsec_recovery_words, decode_recovery_words,
    restore_recovery_words, RecoveryKind,
};
use heartwood_common::types::MasterMode;

const ZERO_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZERO_TYPED: &str =
    "edge obtain doll auto level leave morning abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const RAW_ONE_TYPED: &str =
    "edge obtain lizard frost kitten own grit abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel";
const TREE_ONE_TYPED: &str =
    "edge obtain seed afford today police pyramid abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel";

#[test]
fn mnemonic_vector_matches_nsec_tree_and_sapwood() {
    let words = create_mnemonic_recovery_words(ZERO_PHRASE, "").unwrap();
    assert_eq!(words.as_str(), ZERO_TYPED);
    assert_eq!(words.split_whitespace().count(), 19);

    let decoded = decode_recovery_words(&words).unwrap();
    assert_eq!(decoded.kind, RecoveryKind::NsecTreeMnemonicV1);
    assert!(!decoded.passphrase_required);

    let restored = restore_recovery_words(&words, "").unwrap();
    assert_eq!(restored.mode, MasterMode::TreeMnemonic);
}

#[test]
fn raw_and_tree_nsec_vectors_are_distinct_and_restore_their_modes() {
    let mut one = [0u8; 32];
    one[31] = 1;

    let raw = create_nsec_recovery_words(&one, false).unwrap();
    let tree = create_nsec_recovery_words(&one, true).unwrap();
    assert_eq!(raw.as_str(), RAW_ONE_TYPED);
    assert_eq!(tree.as_str(), TREE_ONE_TYPED);
    assert_eq!(raw.split_whitespace().count(), 31);

    assert_eq!(
        restore_recovery_words(&raw, "").unwrap().mode,
        MasterMode::Bunker
    );
    assert_eq!(
        restore_recovery_words(&tree, "").unwrap().mode,
        MasterMode::TreeNsec
    );
}

#[test]
fn bare_bip39_and_tampering_are_rejected() {
    assert!(decode_recovery_words(ZERO_PHRASE).is_err());
    let tampered = ZERO_TYPED.replacen("morning", "motion", 1);
    assert!(decode_recovery_words(&tampered).is_err());
}

#[test]
fn passphrase_requirement_and_fingerprint_are_checked() {
    let words = create_mnemonic_recovery_words(ZERO_PHRASE, "correct horse").unwrap();
    assert!(decode_recovery_words(&words).unwrap().passphrase_required);
    assert!(restore_recovery_words(&words, "").is_err());
    assert!(restore_recovery_words(&words, "wrong").is_err());
    assert!(restore_recovery_words(&words, "correct horse").is_ok());
}

#[test]
fn every_supported_mnemonic_payload_strength_roundtrips() {
    for (entropy_len, expected_words) in [(16, 19), (20, 22), (24, 25), (28, 28), (32, 31)] {
        let entropy: Vec<u8> = (0..entropy_len)
            .map(|index| (entropy_len + index) as u8)
            .collect();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let words = create_mnemonic_recovery_words(&mnemonic.to_string(), "").unwrap();
        let restored = restore_recovery_words(&words, "").unwrap();

        assert_eq!(words.split_whitespace().count(), expected_words);
        assert_eq!(restored.mode, MasterMode::TreeMnemonic);
    }
}

#[test]
fn invalid_nsec_scalar_is_rejected_for_both_nsec_kinds() {
    let zero = [0u8; 32];
    assert!(create_nsec_recovery_words(&zero, false).is_err());
    assert!(create_nsec_recovery_words(&zero, true).is_err());
}

/// The labels on the device's word-walk screen are only honest if words 1-2
/// really are constant. Pin that against every kind, so a format change that
/// moves the fingerprint earlier fails here rather than silently turning the
/// "ALWAYS THESE 2 WORDS" caption into a lie.
#[test]
fn first_two_words_are_constant_across_kinds_and_keys() {
    let mut sequences = vec![
        create_mnemonic_recovery_words(ZERO_PHRASE, "")
            .unwrap()
            .to_string(),
        create_mnemonic_recovery_words(ZERO_PHRASE, "trezor")
            .unwrap()
            .to_string(),
    ];
    for tail in 1u8..=8 {
        let mut nsec = [0u8; 32];
        nsec[31] = tail;
        sequences.push(
            create_nsec_recovery_words(&nsec, false)
                .unwrap()
                .to_string(),
        );
        sequences.push(create_nsec_recovery_words(&nsec, true).unwrap().to_string());
    }

    for sequence in &sequences {
        let words: Vec<&str> = sequence.split_whitespace().collect();
        assert_eq!(&words[..2], &["edge", "obtain"], "prefix moved: {sequence}");
    }
}

#[test]
fn word_roles_split_format_header_and_secret() {
    use heartwood_common::recovery_words::{recovery_word_role, RecoveryWordRole};

    for total in [19usize, 31] {
        assert_eq!(recovery_word_role(1, total), Some(RecoveryWordRole::Format));
        assert_eq!(recovery_word_role(2, total), Some(RecoveryWordRole::Format));
        assert_eq!(recovery_word_role(3, total), Some(RecoveryWordRole::Header));
        assert_eq!(recovery_word_role(7, total), Some(RecoveryWordRole::Header));
        assert_eq!(recovery_word_role(8, total), Some(RecoveryWordRole::Secret));
        assert_eq!(
            recovery_word_role(total, total),
            Some(RecoveryWordRole::Secret)
        );
        // Out of range labels nothing rather than labelling wrongly.
        assert_eq!(recovery_word_role(0, total), None);
        assert_eq!(recovery_word_role(total + 1, total), None);
    }

    // A bare 12-word mnemonic is not an envelope: no word carries a role.
    assert_eq!(recovery_word_role(1, 12), None);
    assert_eq!(recovery_word_role(1, 24), None);
}

/// The walk-through labels come from the same envelope length the encoder
/// produces. If one moves without the other the screen mislabels the payload,
/// so tie them together here.
#[test]
fn every_generated_word_carries_a_role() {
    use heartwood_common::recovery_words::{recovery_word_role, RecoveryWordRole};

    let words = create_mnemonic_recovery_words(ZERO_PHRASE, "").unwrap();
    let parts: Vec<&str> = words.split_whitespace().collect();
    let total = parts.len();
    let secrets = (1..=total)
        .filter(|i| recovery_word_role(*i, total) == Some(RecoveryWordRole::Secret))
        .count();
    assert_eq!(secrets, 12, "payload words must all be labelled secret");
    assert!((1..=total).all(|i| recovery_word_role(i, total).is_some()));
}
