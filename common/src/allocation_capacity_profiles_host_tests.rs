//! Independent maximum-history frames, checked by the real firmware codec.
//! These tests provide valid inputs for the SDK cold-cut harness. They are not
//! storage measurements, physical acceptance or production authority.
use super::*;
fn subjects() -> Vec<Fixture> {
    let v: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-capacity-profiles-v1.json"
    ))
    .unwrap();
    v["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fixture {
            root: NormalizedMasterRootV1(Zeroizing::new(bytes(&v["root"]).try_into().unwrap())),
            issuer: bytes(&v["issuer"]).try_into().unwrap(),
            v: v.clone(),
        })
        .collect()
}
#[test]
fn eight_distinct_public_roots_match_actual_namespace_and_genesis() {
    let profiles = subjects();
    let mut namespaces = Vec::new();
    for (index, f) in profiles.iter().enumerate() {
        assert_eq!(*f.root.0, [(index + 1) as u8; 32]);
        assert_eq!(
            heartwood_common::derive::public_key_xonly(&f.root.0).unwrap(),
            f.issuer
        );
        let ns = namespace(&f.root);
        assert_eq!(ns, f.v["namespace"].as_str().unwrap());
        assert!(!namespaces.contains(&ns));
        namespaces.push(ns);
        assert_eq!(bytes(&f.v["anchor"]).len(), ANCHOR_FRAME);
        assert_eq!(f.v["manifests"].as_array().unwrap().len(), 32);
        assert_eq!(f.v["snapshots"].as_array().unwrap().len(), 129);
        let r = scan(f, &inventory(f, &[1], 0)).unwrap();
        assert_eq!(r.layout, Layout::LoneNeedsWitness);
        assert_eq!(r.retained_records, 0);
    }
}
#[test]
fn every_adjacent_append_and_retirement_at_full_history_authenticates() {
    for f in subjects() {
        for generation in 2..=129 {
            let p = bytes(&f.v["snapshots"][generation - 1]["plaintext"]);
            let records = if p[5] == 1 { p[353] } else { p[288] } as usize;
            let r = scan(&f, &inventory(&f, &[generation - 1, generation], records)).unwrap();
            assert_eq!(r.layout, Layout::PairedNeedsWitness);
            assert_eq!(r.snapshots_present, 2);
            assert_eq!(r.retained_records, records as u8);
            assert_eq!(r.pending, p[5] == 1);
            assert_eq!(r.orphan_ordinal, None);
        }
        // Terminal history is permanent: every record remains present at g129.
        let r = scan(&f, &inventory(&f, &[128, 129], 32)).unwrap();
        assert_eq!(r.retained_records, 32);
        assert!(!r.pending);
    }
}
#[test]
fn final_record_orphan_pending_and_promoted_profiles_remain_witness_gated() {
    for f in subjects() {
        let r = scan(&f, &inventory(&f, &[62, 63], 31)).unwrap();
        assert_eq!(r.retained_records, 31);
        assert!(!r.pending);
        let orphan = scan(&f, &inventory(&f, &[62, 63], 32)).unwrap();
        assert_eq!(orphan.layout, Layout::OrphanNeedsWitness);
        assert_eq!(orphan.orphan_ordinal, Some(32));
        let pending = scan(&f, &inventory(&f, &[63, 64], 32)).unwrap();
        assert!(pending.pending);
        assert_eq!(pending.retained_records, 32);
        let promoted = scan(&f, &inventory(&f, &[64, 65], 32)).unwrap();
        assert!(!promoted.pending);
        assert_eq!(promoted.retained_records, 32);
        assert!(format!("{promoted:?}").contains("fresh_witness_authority: false"));
    }
}
#[test]
fn maximum_history_missing_corrupt_rebound_and_extra_records_never_fall_back() {
    let profiles = subjects();
    for (index, f) in profiles.iter().enumerate() {
        let mut b = inventory(f, &[64, 65], 32);
        b.retain(|(k, _)| k != "m32");
        assert!(scan(f, &b).is_err());
        let mut b = inventory(f, &[64, 65], 32);
        b.iter_mut().find(|(k, _)| k == "snap0").unwrap().1[497] ^= 1;
        assert_eq!(scan(f, &b).unwrap_err(), InventoryHold::Authentication);
        let mut b = inventory(f, &[128, 129], 32);
        b.push(("m33".into(), bytes(&f.v["manifests"][31]["sealed"])));
        assert_eq!(scan(f, &b).unwrap_err(), InventoryHold::Format);
        let b = inventory(f, &[64, 65], 32);
        let other = &profiles[(index + 1) % 8];
        assert!(scan(other, &b).is_err());
        let mut lone = inventory(f, &[64, 65], 32);
        lone.retain(|(k, _)| k != "snap0");
        let r = scan(f, &lone).unwrap();
        assert_eq!(r.layout, Layout::LoneNeedsWitness);
        assert!(r.pending);
    }
}
