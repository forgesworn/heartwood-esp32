//! Executes the actual private firmware decoder, not a copy of its policy.
use super::*;
use serde_json::Value;

struct Fixture {
    root: NormalizedMasterRootV1,
    issuer: [u8; 32],
    v: Value,
}
fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn fixture() -> Fixture {
    let v: Value =
        serde_json::from_str(include_str!("../tests/fixtures/allocation-journal-v1.json")).unwrap();
    Fixture {
        root: NormalizedMasterRootV1(Zeroizing::new(bytes(&v["root"]).try_into().unwrap())),
        issuer: bytes(&v["issuer"]).try_into().unwrap(),
        v,
    }
}
fn inventory(f: &Fixture, generations: &[usize], records: usize) -> Vec<(String, Vec<u8>)> {
    let mut b = vec![("anchor".into(), bytes(&f.v["anchor"]))];
    for &g in generations {
        let s = &f.v["snapshots"][g - 1];
        b.push((
            format!("snap{}", s["slot"].as_u64().unwrap()),
            bytes(&s["sealed"]),
        ));
    }
    for n in 1..=records {
        b.push((
            format!("m{n:02}"),
            bytes(&f.v["manifests"][n - 1]["sealed"]),
        ));
    }
    b
}
fn scan(f: &Fixture, b: &[(String, Vec<u8>)]) -> Result<Report, InventoryHold> {
    let refs: Vec<_> = b
        .iter()
        .map(|(k, v)| StoredBlob { key: k, bytes: v })
        .collect();
    inspect(&f.root, &f.issuer, &refs)
}
// Sealing/nonce injection exists ONLY in this test module; no production API.
fn seal(k: &[u8; 32], header: &[u8], nonce: &[u8], plain: &[u8], associated: &[u8]) -> Vec<u8> {
    let mut data = plain.to_vec();
    let tag = XChaCha20Poly1305::new(k.into())
        .encrypt_in_place_detached(&XNonce::from(array::<24>(nonce, 0)), associated, &mut data)
        .unwrap();
    [header, &data, &tag[..]].concat()
}
fn reseal_anchor(f: &Fixture, plain: &[u8]) -> Vec<u8> {
    let header = bytes(&f.v["anchor"])[..29].to_vec();
    let codec = Codec::new(&f.root, &f.issuer).unwrap();
    let k = key(&f.root, &[b"HW allocation anchor key v1\0"]);
    seal(
        &k,
        &header,
        &header[5..],
        plain,
        &aad(&[
            b"HW allocation anchor aad v1\0",
            codec.subject.as_ref(),
            &f.issuer,
            &header,
        ]),
    )
}
fn reseal_snapshot(f: &Fixture, g: usize, plain: &[u8]) -> Vec<u8> {
    let frame = bytes(&f.v["snapshots"][g - 1]["sealed"]);
    let header = &frame[..30];
    let pins = bytes(&f.v["pins_hash"]);
    let k = key(&f.root, &[b"HW allocation snapshot key v1\0", &pins]);
    seal(
        &k,
        header,
        &header[6..],
        plain,
        &aad(&[b"HW allocation snapshot aad v1\0", &pins, header]),
    )
}
fn reseal_manifest(f: &Fixture, n: usize, plain: &[u8]) -> Vec<u8> {
    let pins = bytes(&f.v["pins_hash"]);
    let id = hash(&[b"HW allocation manifest v1\0", &pins, plain]);
    let mut header = bytes(&f.v["manifests"][n - 1]["sealed"])[..62].to_vec();
    header[6..38].copy_from_slice(&id);
    let k = key(&f.root, &[b"HW allocation manifest key v1\0", &pins]);
    seal(
        &k,
        &header,
        &header[38..],
        plain,
        &aad(&[b"HW allocation manifest aad v1\0", &pins, &header]),
    )
}
fn replace(b: &mut [(String, Vec<u8>)], key: &str, v: Vec<u8>) {
    b.iter_mut().find(|(k, _)| k == key).unwrap().1 = v;
}

#[test]
fn independent_sodium_vectors_match_all_three_object_kinds_byte_for_byte() {
    let f = fixture();
    let codec = Codec::new(&f.root, &f.issuer).unwrap();
    let a = codec.anchor(&bytes(&f.v["anchor"])).unwrap();
    assert_eq!(a.0.as_ref(), bytes(&f.v["anchor_plaintext"]));
    assert_eq!(reseal_anchor(&f, a.0.as_ref()), bytes(&f.v["anchor"]));
    assert_eq!(namespace(&f.root), f.v["namespace"].as_str().unwrap());
    assert_eq!(namespace(&f.root).len(), 15);
    for g in 1..=9 {
        let s = &f.v["snapshots"][g - 1];
        let frame = bytes(&s["sealed"]);
        let decoded = codec
            .snapshot(&frame, s["slot"].as_u64().unwrap() as u8, &a)
            .unwrap();
        assert_eq!(decoded.data.as_ref(), bytes(&s["plaintext"]));
        assert_eq!(reseal_snapshot(&f, g, decoded.data.as_ref()), frame);
    }
    for n in 1..=3 {
        let m = &f.v["manifests"][n - 1];
        let frame = bytes(&m["sealed"]);
        let decoded = codec.manifest(&frame, n as u8, &a).unwrap();
        assert_eq!(decoded.data.as_ref(), bytes(&m["plaintext"]));
        assert_eq!(decoded.id.as_slice(), bytes(&m["id"]));
        assert_eq!(reseal_manifest(&f, n, decoded.data.as_ref()), frame);
    }
}

#[test]
fn every_adjacent_transition_and_terminal_record_is_retained() {
    let f = fixture();
    for g in 2..=9 {
        let count = if g < 4 { 1 } else { 2 };
        let r = scan(&f, &inventory(&f, &[g - 1, g], count)).unwrap();
        assert_eq!(r.layout, Layout::PairedNeedsWitness);
        assert_eq!(r.snapshots_present, 2);
        assert_eq!(r.retained_records, count as u8);
        assert_eq!(r.pending, g % 2 == 0);
        assert_eq!(r.orphan_ordinal, None);
        let log = format!("{r:?}");
        assert!(log.contains("derived_writer_verified: false"));
        assert!(log.contains("witness_signatures_verified: false"));
    }
    // Even terminal entries remain full records; expiry is never consulted.
    assert_eq!(
        scan(&f, &inventory(&f, &[8, 9], 2))
            .unwrap()
            .retained_records,
        2
    );
}

#[test]
fn absent_data_is_never_genesis_and_lone_or_orphan_is_reconciliation_only() {
    let f = fixture();
    assert_eq!(scan(&f, &[]).unwrap_err(), InventoryHold::Missing);
    assert_eq!(
        scan(&f, &inventory(&f, &[], 0)).unwrap_err(),
        InventoryHold::Missing
    );
    let lone = scan(&f, &inventory(&f, &[1], 0)).unwrap();
    assert_eq!(lone.layout, Layout::LoneNeedsWitness);
    let lone_pending = scan(&f, &inventory(&f, &[2], 1)).unwrap();
    assert!(lone_pending.pending);
    assert_eq!(lone_pending.layout, Layout::LoneNeedsWitness);
    let orphan = scan(&f, &inventory(&f, &[8, 9], 3)).unwrap();
    assert_eq!(orphan.layout, Layout::OrphanNeedsWitness);
    assert_eq!(orphan.orphan_ordinal, Some(3));
    assert_eq!(
        scan(&f, &inventory(&f, &[1], 2)).unwrap_err(),
        InventoryHold::Records
    );
    assert_eq!(
        scan(&f, &inventory(&f, &[2], 2)).unwrap_err(),
        InventoryHold::Records
    );
}

#[test]
fn all_bits_in_all_stored_objects_are_authenticated_with_no_valid_slot_fallback() {
    let f = fixture();
    let base = inventory(&f, &[1, 2], 1);
    for index in 0..base.len() {
        for bit in 0..base[index].1.len() * 8 {
            let mut b = base.clone();
            b[index].1[bit / 8] ^= 1 << (bit % 8);
            assert!(scan(&f, &b).is_err(), "object {index}, bit {bit}");
        }
    }
}

#[test]
fn every_truncation_and_extra_byte_holds() {
    let f = fixture();
    let base = inventory(&f, &[1, 2], 1);
    for index in 0..base.len() {
        for len in 0..base[index].1.len() {
            let mut b = base.clone();
            b[index].1.truncate(len);
            assert!(scan(&f, &b).is_err());
        }
        let mut b = base.clone();
        b[index].1.push(0);
        assert!(scan(&f, &b).is_err());
    }
}

#[test]
fn wrong_root_issuer_namespace_key_position_and_unknown_keys_hold() {
    let f = fixture();
    let base = inventory(&f, &[1, 2], 1);
    let refs: Vec<_> = base
        .iter()
        .map(|(k, b)| StoredBlob { key: k, bytes: b })
        .collect();
    assert!(inspect(
        &NormalizedMasterRootV1(Zeroizing::new([2; 32])),
        &f.issuer,
        &refs
    )
    .is_err());
    assert!(inspect(&f.root, &[2; 32], &refs).is_err());
    for bad in ["m00", "m33", "m1", "m001", "m-1", "mＡ", "head", "other"] {
        let mut b = base.clone();
        b.push((bad.into(), vec![1]));
        assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Format);
    }
    let mut b = base.clone();
    let x = b[1].1.clone();
    b[1].1 = b[2].1.clone();
    b[2].1 = x;
    assert!(scan(&f, &b).is_err());
    let mut b = base.clone();
    b.push(b[0].clone());
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Format);
    let mut b = inventory(&f, &[3, 4], 2);
    b.retain(|(k, _)| k != "m01");
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Records);
}

#[test]
fn authenticated_but_wrong_manifest_binding_or_request_identity_holds() {
    let f = fixture();
    for at in [6, 38, 70, 102, 134, 166, 198, 230] {
        let mut p = bytes(&f.v["manifests"][0]["plaintext"]);
        p[at..at + 32].fill(0);
        let mut b = inventory(&f, &[1], 1);
        replace(&mut b, "m01", reseal_manifest(&f, 1, &p));
        assert!(scan(&f, &b).is_err());
    }
    for at in [38, 70, 166, 198] {
        let mut p = bytes(&f.v["manifests"][1]["plaintext"]);
        let old = bytes(&f.v["manifests"][0]["plaintext"]);
        p[at..at + 32].copy_from_slice(&old[at..at + 32]);
        let mut b = inventory(&f, &[3], 2);
        replace(&mut b, "m02", reseal_manifest(&f, 2, &p));
        // This is an orphan, so no snapshot set-hash mismatch masks the duplicate.
        assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Records);
    }
    for (start, end) in [(6, 38), (230, 262)] {
        let mut p = bytes(&f.v["manifests"][0]["plaintext"]);
        p[start..end].fill(7);
        let mut b = inventory(&f, &[1], 1);
        replace(&mut b, "m01", reseal_manifest(&f, 1, &p));
        assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Binding);
    }
    let mut p = bytes(&f.v["manifests"][0]["plaintext"]);
    let t = p[262..270].to_vec();
    p[270..278].copy_from_slice(&t);
    let mut b = inventory(&f, &[1], 1);
    replace(&mut b, "m01", reseal_manifest(&f, 1, &p));
    assert!(scan(&f, &b).is_err());
}

#[test]
fn authenticated_invalid_snapshots_cannot_fall_back() {
    let f = fixture();
    for at in [
        0, 4, 5, 14, 46, 78, 86, 118, 119, 120, 152, 160, 192, 224, 288, 289, 321, 353, 354, 386,
        418, 419, 420,
    ] {
        let mut p = bytes(&f.v["snapshots"][1]["plaintext"]);
        p[at] ^= 0x80;
        let mut b = inventory(&f, &[1, 2], 1);
        replace(&mut b, "snap1", reseal_snapshot(&f, 2, &p));
        assert!(scan(&f, &b).is_err(), "offset {at}");
    }
    for (start, end) in [(192, 224), (224, 288)] {
        let mut p = bytes(&f.v["snapshots"][1]["plaintext"]);
        p[start..end].fill(0);
        let mut b = inventory(&f, &[1, 2], 1);
        replace(&mut b, "snap1", reseal_snapshot(&f, 2, &p));
        assert!(scan(&f, &b).is_err());
    }
    assert_eq!(
        scan(&f, &inventory(&f, &[1, 4], 2)).unwrap_err(),
        InventoryHold::Chain
    );
    assert_eq!(
        scan(&f, &inventory(&f, &[2, 4], 2)).unwrap_err(),
        InventoryHold::Format
    ); // duplicate physical key
}

#[test]
fn generation_one_is_exact_genesis_and_receipts_are_not_crypto_authority() {
    let f = fixture();
    for at in [5, 6, 14, 78, 86, 118, 192, 224, 288, 353, 418, 419, 420] {
        let mut p = bytes(&f.v["snapshots"][0]["plaintext"]);
        p[at] ^= 1;
        let mut b = inventory(&f, &[1], 0);
        replace(&mut b, "snap0", reseal_snapshot(&f, 1, &p));
        assert!(scan(&f, &b).is_err());
    }
    // Nonzero signature mutations are deliberately NOT verified here. The
    // report must stay non-authoritative even when local AEAD is authentic.
    let mut p = bytes(&f.v["snapshots"][2]["plaintext"]);
    p[224] ^= 1;
    let mut b = inventory(&f, &[3], 1);
    replace(&mut b, "snap0", reseal_snapshot(&f, 3, &p));
    assert_eq!(scan(&f, &b).unwrap().layout, Layout::LoneNeedsWitness);
}

#[test]
fn immutable_set_root_is_checked_for_both_old_and_new_snapshot() {
    let f = fixture();
    let mut p = bytes(&f.v["manifests"][0]["plaintext"]);
    p[38] ^= 1;
    let mut b = inventory(&f, &[3, 4], 2);
    replace(&mut b, "m01", reseal_manifest(&f, 1, &p));
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Records);
    let mut b = inventory(&f, &[8, 9], 2);
    b.retain(|(k, _)| k != "m02");
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Records);
}

#[test]
fn erase_before_set_cut_inventory_never_grants_release() {
    let f = fixture();
    // Cut before immutable record: committed genesis only.
    assert_eq!(
        scan(&f, &inventory(&f, &[1], 0)).unwrap().layout,
        Layout::LoneNeedsWitness
    );
    // Complete record before pending frame: exact orphan, never a new salt.
    assert_eq!(
        scan(&f, &inventory(&f, &[1], 1)).unwrap().orphan_ordinal,
        Some(1)
    );
    // Pending durable before CAS; lost reply changes no local bytes.
    assert!(scan(&f, &inventory(&f, &[1, 2], 1)).unwrap().pending);
    // Promotion erases inactive snap0 before set: pending snap1 remains.
    assert_eq!(
        scan(&f, &inventory(&f, &[2], 1)).unwrap().layout,
        Layout::LoneNeedsWitness
    );
    // Partial/invalid set is HOLD rather than fallback to pending snap1.
    let mut b = inventory(&f, &[2], 1);
    b.push(("snap0".into(), vec![1; 100]));
    assert!(scan(&f, &b).is_err());
    // Complete promoted frame; still requires a fresh strict witness gate.
    assert_eq!(
        scan(&f, &inventory(&f, &[2, 3], 1)).unwrap().layout,
        Layout::PairedNeedsWitness
    );
    // Simultaneous local rollback is indistinguishable to a local decoder.
    assert_eq!(
        scan(&f, &inventory(&f, &[1], 0)).unwrap().layout,
        Layout::LoneNeedsWitness
    );
}

#[test]
fn capacity_diagnostic_is_only_a_lower_bound_and_never_a_32_record_fit_promise() {
    assert_eq!(minimum_entries(0).unwrap(), 54);
    assert_eq!(minimum_entries(32).unwrap(), 502);
    assert!(minimum_entries(32).unwrap() > 3 * 126);
    assert_eq!(minimum_entries(33).unwrap_err(), InventoryHold::Records);
}

#[test]
fn authenticated_transition_cannot_skip_a_witness_sequence_or_reuse_receipt() {
    let f = fixture();
    // Both sequence fields agree structurally, so only the pair's exact +1
    // transition rule can reject this (signature remains deliberately unchecked).
    let mut p = bytes(&f.v["snapshots"][2]["plaintext"]);
    p[78..86].copy_from_slice(&2u64.to_be_bytes());
    p[152..160].copy_from_slice(&2u64.to_be_bytes());
    let mut b = inventory(&f, &[2, 3], 1);
    replace(&mut b, "snap0", reseal_snapshot(&f, 3, &p));
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Chain);
    // A pending frame must retain even the historical receipt exactly.
    let mut p = bytes(&f.v["snapshots"][1]["plaintext"]);
    p[224] ^= 1;
    let mut b = inventory(&f, &[1, 2], 1);
    replace(&mut b, "snap1", reseal_snapshot(&f, 2, &p));
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Chain);
}

#[test]
fn anchor_semantics_hold_even_with_an_authentic_aead_tag() {
    let f = fixture();
    for at in [0, 4, 5, 69, 165, 197, 229, 261, 262, 263, 295, 303] {
        let mut p = bytes(&f.v["anchor_plaintext"]);
        p[at] ^= 1;
        let mut b = inventory(&f, &[1], 0);
        replace(&mut b, "anchor", reseal_anchor(&f, &p));
        assert_eq!(
            scan(&f, &b).unwrap_err(),
            InventoryHold::Binding,
            "offset {at}"
        );
    }
    for (start, end) in [(37, 69), (335, 367), (367, 431)] {
        let mut p = bytes(&f.v["anchor_plaintext"]);
        p[start..end].fill(0);
        let mut b = inventory(&f, &[1], 0);
        replace(&mut b, "anchor", reseal_anchor(&f, &p));
        assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Binding);
    }
}

#[test]
fn terminal_lifecycle_cannot_be_resurrected_or_another_record_changed() {
    let f = fixture();
    // Generation 8 retires ordinal2. Resurrecting abandoned ordinal1 is
    // forbidden even after updating the candidate digest to agree.
    let mut p = bytes(&f.v["snapshots"][7]["plaintext"]);
    p[386] = 1;
    let pins: [u8; 32] = bytes(&f.v["pins_hash"]).try_into().unwrap();
    let d = state_digest(&pins, &p[353..418]);
    p[420..452].copy_from_slice(&d);
    let mut b = inventory(&f, &[7, 8], 2);
    replace(&mut b, "snap1", reseal_snapshot(&f, 8, &p));
    assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Records);
}

#[test]
fn zero_nonces_are_refused_for_every_object_kind() {
    let f = fixture();
    let base = inventory(&f, &[1, 2], 1);
    for (index, start, end) in [(0, 5, 29), (1, 6, 30), (2, 6, 30), (3, 38, 62)] {
        let mut b = base.clone();
        b[index].1[start..end].fill(0);
        assert_eq!(scan(&f, &b).unwrap_err(), InventoryHold::Format);
    }
}
