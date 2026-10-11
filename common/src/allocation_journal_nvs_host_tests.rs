use super::*;
use crate::allocation_nvs_host_sys as sys;

fn decode_blob(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn setup(
    generations: &[usize],
    records: usize,
) -> (LoadedMaster, EspNvs<NvsDefault>, String, Vec<sys::Entry>) {
    held_data_key::forget();
    let mut m = master();
    m.secret = [1; 32];
    m.mode = MasterMode::TreeNsec;
    m.derivation_version = 1;
    m.pubkey = derive::public_key_xonly(&m.secret).unwrap();
    let nvs = stored(&m);
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/allocation-journal-v1.json")).unwrap();
    let ns = v["namespace"].as_str().unwrap().to_owned();
    let mut entries = vec![sys::entry(
        &ns,
        "anchor",
        decode_blob(v["anchor"].as_str().unwrap()),
    )];
    for &g in generations {
        let s = &v["snapshots"][g - 1];
        entries.push(sys::entry(
            &ns,
            &format!("snap{}", s["slot"].as_u64().unwrap()),
            decode_blob(s["sealed"].as_str().unwrap()),
        ));
    }
    for n in 1..=records {
        entries.push(sys::entry(
            &ns,
            &format!("m{n:02}"),
            decode_blob(v["manifests"][n - 1]["sealed"].as_str().unwrap()),
        ));
    }
    (m, nvs, ns, entries)
}
fn clean() {
    sys::checked(|s| {
        assert_eq!(s.live_handles, 0);
        assert_eq!(s.live_iterators, 0);
    });
}
fn fault(op: &'static str, nth: usize, err: i32, null: bool, length: Option<usize>) -> sys::Fault {
    sys::Fault {
        op,
        nth,
        err,
        null,
        length,
    }
}

#[test]
fn actual_adapter_reads_terminal_records_twice_and_only_returns_local_report() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[8, 9], 2);
    let mut reverse = e.clone();
    reverse.reverse();
    sys::reset(ns, vec![e, reverse], None);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    let r = h.inspect_persisted_journal().unwrap();
    assert_eq!(r.retained_records, 2);
    assert_eq!(r.layout, journal::Layout::PairedNeedsWitness);
    assert!(format!("{r:?}").contains("witness_signatures_verified: false"));
    assert!(h
        .nvs
        .backend
        .take_log()
        .iter()
        .all(|(_, op)| *op != NvsOp::SetBlob && *op != NvsOp::Remove));
    sys::checked(|s| {
        assert_eq!(s.finds, 2);
        assert_eq!(s.calls.iter().filter(|&&x| x == "read").count(), 10);
    });
    clean();
}
#[test]
fn missing_namespace_or_both_snapshots_never_initializes() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[], 0);
    sys::reset(
        ns.clone(),
        vec![e.clone()],
        Some(fault("open", 1, sys::ESP_ERR_NVS_NOT_FOUND, true, None)),
    );
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    assert_eq!(
        h.inspect_persisted_journal().unwrap_err(),
        InventoryHold::Missing
    );
    clean();
    sys::reset(ns.clone(), vec![vec![]], None);
    assert_eq!(
        h.inspect_persisted_journal().unwrap_err(),
        InventoryHold::Missing
    );
    clean();
    sys::reset(ns, vec![e], None);
    assert_eq!(
        h.inspect_persisted_journal().unwrap_err(),
        InventoryHold::Missing
    );
    clean();
}
#[test]
fn every_raw_error_including_final_next_is_hold_and_resources_are_released() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for (op, count) in [
        ("open", 1),
        ("find", 2),
        ("info", 8),
        ("length", 8),
        ("read", 8),
        ("next", 8),
    ] {
        for nth in 1..=count {
            for null in [false, true] {
                // open/find output ownership differs; invalid open success is
                // tested separately. Failed opens never own a handle.
                let null = if op == "open" { true } else { null };
                sys::reset(
                    ns.clone(),
                    vec![e.clone()],
                    Some(fault(op, nth, sys::ESP_ERR_INVALID_ARG, null, None)),
                );
                assert_eq!(
                    h.inspect_persisted_journal().unwrap_err(),
                    InventoryHold::Storage,
                    "{op}#{nth}"
                );
                clean();
            }
        }
    }
}
#[test]
fn malformed_entry_unknown_key_wrong_namespace_type_and_duplicates_hold() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for kind in 0..5 {
        let mut broken = e.clone();
        match kind {
            0 => broken[0].info.key.fill(b'a' as _),
            1 => broken[0] = sys::entry(&ns, "unknown", vec![0; 476]),
            2 => broken[0].info.namespace_name[0] = b'b' as _,
            3 => broken[0].info.type_ = 1,
            4 => broken.push(broken[0].clone()),
            _ => unreachable!(),
        }
        sys::reset(ns.clone(), vec![broken], None);
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Format
        );
        clean();
    }
}
#[test]
fn exact_lengths_bound_allocation_and_short_successful_read_is_hold() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for n in [0, 475, 477, usize::MAX] {
        sys::reset(
            ns.clone(),
            vec![e.clone()],
            Some(fault("length", 1, sys::ESP_OK, true, Some(n))),
        );
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Format
        );
        sys::checked(|s| assert!(!s.calls.contains(&"read")));
        clean();
    }
    sys::reset(
        ns,
        vec![e],
        Some(fault("read", 1, sys::ESP_OK, true, Some(475))),
    );
    assert_eq!(
        h.inspect_persisted_journal().unwrap_err(),
        InventoryHold::Format
    );
    clean();
}
#[test]
fn two_complete_scans_detect_changed_or_disappeared_records() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for mode in 0..2 {
        let mut second = e.clone();
        if mode == 0 {
            second[0].bytes[40] ^= 1;
        } else {
            second.pop();
        }
        sys::reset(ns.clone(), vec![e.clone(), second], None);
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Changed
        );
        clean();
    }
}
#[test]
fn iterator_pointer_status_contradictions_hold() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for f in [
        fault("open", 1, sys::ESP_OK, true, None),
        fault("find", 1, sys::ESP_OK, true, None),
        fault("find", 1, sys::ESP_ERR_NVS_NOT_FOUND, false, None),
        fault("next", 1, sys::ESP_OK, true, None),
        fault("next", 1, sys::ESP_ERR_NVS_NOT_FOUND, false, None),
    ] {
        sys::reset(ns.clone(), vec![e.clone()], Some(f));
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Storage
        );
        clean();
    }
}
#[test]
fn observed_custody_drift_refuses_before_any_journal_open() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1], 0);
    sys::reset(ns, vec![e], None);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    h.nvs.backend.seed("master_0_deriv", &[0]);
    assert_eq!(
        h.inspect_persisted_journal().unwrap_err(),
        InventoryHold::Custody
    );
    sys::checked(|s| assert!(s.calls.is_empty()));
    clean();
}

#[test]
fn custody_is_rechecked_after_successful_inventory_and_after_storage_error() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1], 0);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for f in [
        None,
        Some(fault("find", 2, sys::ESP_ERR_INVALID_ARG, true, None)),
    ] {
        // The existing fault queue poisons consecutive matching calls. Return
        // the correct width during the first custody check, then fail the next
        // check, after the adapter has completed or failed its second scan.
        h.nvs
            .backend
            .fail_once(NvsOp::BlobLen, "master_0_deriv", FaultKind::OversizeLen(1));
        h.nvs
            .backend
            .fail_once(NvsOp::BlobLen, "master_0_deriv", FaultKind::ReadError);
        sys::reset(ns.clone(), vec![e.clone()], f);
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Custody
        );
        sys::checked(|s| assert_eq!(s.finds, 2));
        clean();
    }
}

#[test]
fn present_corrupt_snapshot_is_never_replaced_by_the_other_valid_slot() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[1, 2], 1);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    for index in [1, 2] {
        let mut broken = e.clone();
        broken[index].bytes[40] ^= 1;
        sys::reset(ns.clone(), vec![broken], None);
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Authentication
        );
        sys::checked(|s| assert_eq!(s.finds, 2));
        clean();
    }
}

#[test]
fn actual_adapter_retains_orphan_and_refuses_missing_permanent_manifest() {
    let _serial = SERIAL.lock().unwrap();
    let (mut m, mut nvs, ns, e) = setup(&[8, 9], 3);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    sys::reset(ns.clone(), vec![e.clone()], None);
    let r = h.inspect_persisted_journal().unwrap();
    assert_eq!(r.layout, journal::Layout::OrphanNeedsWitness);
    assert_eq!(r.orphan_ordinal, Some(3));
    assert_eq!(r.retained_records, 3);
    clean();
    for index in [3, 4] {
        let mut missing = e.clone();
        missing.remove(index);
        sys::reset(ns.clone(), vec![missing], None);
        assert_eq!(
            h.inspect_persisted_journal().unwrap_err(),
            InventoryHold::Records
        );
        clean();
    }
}
