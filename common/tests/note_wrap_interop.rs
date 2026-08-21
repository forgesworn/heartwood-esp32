//! The same wrap opens on the signer and in the wallet. One fixture comes
//! from notecase's `wrapNote` (nostr-tools nip59); the other is produced
//! here for notecase's test to open. Both sides use the fixed keys
//! 0x11.. (sender) and 0x22.. (recipient).

#![cfg(all(feature = "nip46", feature = "nip44", feature = "k256-backend"))]

use heartwood_common::hex::{hex_decode, hex_encode};
use heartwood_common::nip46::{SignedEvent, UnsignedEvent};
use heartwood_common::nip59;
use heartwood_common::note_wrap;

fn key(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = [seed; 32];
    let sk = k256::schnorr::SigningKey::from_bytes(&secret).unwrap();
    (secret, sk.verifying_key().to_bytes().into())
}

fn k256_sign(secret: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], &'static str> {
    let sk = k256::schnorr::SigningKey::from_bytes(secret).map_err(|_| "bad key")?;
    Ok(sk.sign_raw(hash, &[0u8; 32]).map_err(|_| "sign failed")?.to_bytes())
}

#[test]
fn a_wrap_from_the_wallet_opens_on_the_device() {
    let raw = include_str!("fixtures/note_wrap_from_wallet.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let wrap: SignedEvent = serde_json::from_value(fixture["wrap"].clone()).unwrap();
    let recipient: [u8; 32] = hex_decode(fixture["recipient_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let opened = nip59::unwrap(&wrap, &recipient).expect("wallet wrap opens");
    assert_eq!(hex_encode(&opened.sender), fixture["sender"].as_str().unwrap());
    let note = note_wrap::parse_note_rumor(&opened.rumor).expect("rumor is a note");
    assert_eq!(note.secret, [0xab; 32]);
    assert_eq!(note.host, "mint.example/w");
    assert_eq!(note.amount_msat, 21_000);
    assert_eq!(opened.rumor.content, fixture["url"].as_str().unwrap());
}

#[test]
fn a_wrap_from_the_device_is_written_for_the_wallet() {
    let (author_sk, author_pk) = key(0x11);
    let (_, recipient_pk) = key(0x22);
    let (eph_sk, eph_pk) = key(0x33);
    let secret = [0xcd; 32];
    let rumor: UnsignedEvent = note_wrap::build_note_rumor(
        &hex_encode(&author_pk),
        &recipient_pk,
        &secret,
        "mint.example/w",
        4_200,
        1_700_000_000,
    );
    let wrap = nip59::gift_wrap(
        &rumor,
        &author_sk,
        &recipient_pk,
        &eph_sk,
        &eph_pk,
        nip59::WrapTimes { seal_created_at: 1_699_999_000, wrap_created_at: 1_699_998_000 },
        None,
        &[0x01; 32],
        &[0x02; 32],
        &k256_sign,
    )
    .unwrap();
    let out = serde_json::json!({
        "wrap": wrap,
        "sender": hex_encode(&author_pk),
        "recipient_secret": "22".repeat(32),
        "url": rumor.content,
        "amount_msat": 4_200,
    });
    // Deterministic inputs, deterministic file: a stale copy in the wallet
    // repo shows up as a diff here, not as a silent drift.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/note_wrap_from_device.json");
    std::fs::write(path, serde_json::to_string(&out).unwrap()).unwrap();
    // And it opens here too.
    let (recipient_sk, _) = key(0x22);
    let opened = nip59::unwrap(&wrap, &recipient_sk).unwrap();
    assert_eq!(note_wrap::parse_note_rumor(&opened.rumor).unwrap().secret, secret);
}
