use super::super::tests::{master, stored, SERIAL};
use super::*;
use crate::{allocation_nvs_host_sys as nvs, allocation_partition_host_sys as sdk, held_data_key};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
fn profiles() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-partition-profiles-v1.json"
    ))
    .unwrap()
}
fn setup(profile: usize, addressable: u32) {
    nvs::reset(String::new(), vec![vec![]], None);
    BOOT.store(VIRGIN, Ordering::SeqCst); // Test-only simulated fresh boot.
    let v = profiles();
    let p = &v["profiles"][profile];
    sdk::reset(
        BASE64
            .decode(p["successorBase64"].as_str().unwrap())
            .unwrap(),
        p["flashBytes"].as_u64().unwrap() as u32,
        addressable,
        p["newOffset"].as_u64().unwrap() as u32,
    );
}
fn clean() {
    sdk::checked(|s| assert_eq!(s.live_iterators, 0));
    nvs::checked(|s| {
        assert_eq!(s.live_handles, 0);
        assert_eq!(s.live_iterators, 0);
        assert!(s.mutations.is_empty());
    });
}
fn expect_hold(board: Board) {
    assert!(AllocationPartition::acquire_for_board(board).is_err());
    assert_eq!(BOOT.load(Ordering::SeqCst), POISONED);
    let calls = sdk::checked(|s| s.calls.len());
    assert!(AllocationPartition::acquire_for_board(board).is_err());
    assert_eq!(sdk::checked(|s| s.calls.len()), calls);
    clean();
}
fn entries() -> (
    super::super::LoadedMaster,
    esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    String,
    Vec<nvs::Entry>,
) {
    held_data_key::forget();
    let mut m = master();
    m.secret = [1; 32];
    m.mode = heartwood_common::types::MasterMode::TreeNsec;
    m.derivation_version = 1;
    m.pubkey = heartwood_common::derive::public_key_xonly(&m.secret).unwrap();
    let stored = stored(&m);
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/allocation-journal-v1.json")).unwrap();
    let ns = v["namespace"].as_str().unwrap().to_owned();
    let decode = |s: &str| {
        s.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    };
    let mut out = vec![nvs::entry(
        &ns,
        "anchor",
        decode(v["anchor"].as_str().unwrap()),
    )];
    for g in [8, 9] {
        let s = &v["snapshots"][g - 1];
        out.push(nvs::entry(
            &ns,
            &format!("snap{}", s["slot"].as_u64().unwrap()),
            decode(s["sealed"].as_str().unwrap()),
        ));
    }
    for n in 1..=2 {
        out.push(nvs::entry(
            &ns,
            &format!("m{n:02}"),
            decode(v["manifests"][n - 1]["sealed"].as_str().unwrap()),
        ));
    }
    (m, stored, ns, out)
}
#[test]
fn exact_five_profiles_and_board_geometry_matrix() {
    let _serial = SERIAL.lock().unwrap();
    for profile in 0..5 {
        for board in [Board::V3, Board::V4, Board::TDisplay, Board::C6] {
            let valid = match profile {
                0 => matches!(board, Board::V3 | Board::V4),
                1 | 3 | 4 => board == Board::V4,
                2 => matches!(board, Board::TDisplay | Board::C6),
                _ => false,
            };
            let physical = profiles()["profiles"][profile]["flashBytes"]
                .as_u64()
                .unwrap() as u32;
            for header in [0, 4 * MIB, 8 * MIB, 16 * MIB, 32 * MIB] {
                setup(profile, header);
                let accepted = valid
                    && header <= physical
                    && header >= if profile == 2 { 0x360000 } else { 0x460000 };
                if accepted {
                    let owner = AllocationPartition::acquire_for_board(board).unwrap();
                    owner.recheck().unwrap();
                    drop(owner);
                    assert_eq!(BOOT.load(Ordering::SeqCst), RETIRED);
                    clean();
                } else {
                    expect_hold(board);
                    assert_eq!(
                        sdk::checked(|s| s.calls.iter().filter(|&&c| c == "init").count()),
                        0
                    );
                }
            }
        }
    }
}
#[test]
fn every_capture_byte_and_predecessor_refuse_before_init() {
    let _serial = SERIAL.lock().unwrap();
    setup(0, 8 * MIB);
    let pristine = sdk::checked(|s| s.table.clone());
    for pos in 0..4096 {
        setup(0, 8 * MIB);
        sdk::change(|s| {
            s.table = pristine.clone();
            s.table[pos] ^= 1;
        });
        expect_hold(Board::V3);
        assert!(!sdk::checked(|s| s.calls.contains(&"init")));
    }
    setup(0, 8 * MIB);
    sdk::change(|s| {
        s.table = BASE64
            .decode(
                profiles()["profiles"][0]["predecessorBase64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
    });
    expect_hold(Board::V3);
}
#[test]
fn every_descriptor_field_and_duplicates_are_hold() {
    let _serial = SERIAL.lock().unwrap();
    for field in 0..11 {
        setup(0, 8 * MIB);
        sdk::change(|s| {
            let p = &mut s.descriptors[0];
            match field {
                0 => p.flash_chip = ptr::null_mut(),
                1 => p.type_ = 0,
                2 => p.subtype = 0,
                3 => p.address ^= 4096,
                4 => p.size -= 4096,
                5 => p.erase_size = 8192,
                6 => p.label[0] = b'x' as _,
                7 => p.label[16] = 1,
                8 => p.encrypted = true,
                9 => p.readonly = true,
                _ => s.descriptors.push(s.descriptors[0].clone()),
            }
        });
        expect_hold(Board::V3);
        assert!(!sdk::checked(|s| s.calls.contains(&"init")));
    }
    setup(0, 8 * MIB);
    sdk::change(|s| s.descriptors.clear());
    expect_hold(Board::V3);
}
#[test]
fn every_flash_read_acquisition_cut_and_sdk_error_poison_without_retry() {
    let _serial = SERIAL.lock().unwrap();
    for nth in 1..=48 {
        setup(0, 8 * MIB);
        sdk::change(|s| {
            s.fault = Some(sdk::Fault {
                op: "flash-read",
                nth,
                error: -1,
            })
        });
        expect_hold(Board::V3);
        assert_eq!(
            sdk::checked(|s| s.calls.iter().filter(|&&c| c == "init").count()),
            usize::from(nth > 32)
        );
    }
    for op in ["physical", "addressable", "part-get", "init"] {
        for nth in 1..=if op == "init" { 1 } else { 3 } {
            for error in [-1, 0x110d, 0x1110] {
                setup(0, 8 * MIB);
                sdk::change(|s| s.fault = Some(sdk::Fault { op, nth, error }));
                expect_hold(Board::V3);
            }
        }
    }
}
#[test]
fn owner_lifetime_and_observed_init_drift_are_permanent() {
    let _serial = SERIAL.lock().unwrap();
    setup(0, 8 * MIB);
    let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
    let before = sdk::checked(|s| s.calls.len());
    assert!(AllocationPartition::acquire_for_board(Board::V3).is_err());
    assert_eq!(sdk::checked(|s| s.calls.len()), before);
    owner.recheck().unwrap();
    drop(owner);
    assert_eq!(BOOT.load(Ordering::SeqCst), RETIRED);
    assert!(AllocationPartition::acquire_for_board(Board::V3).is_err());
    clean();
    for mutation in [
        sdk::Mutation::Table,
        sdk::Mutation::Physical,
        sdk::Mutation::Addressable,
        sdk::Mutation::Descriptor,
    ] {
        for op in ["physical", "init"] {
            setup(0, 8 * MIB);
            sdk::change(|s| {
                s.hook = Some(sdk::Hook {
                    op,
                    nth: if op == "physical" { 2 } else { 1 },
                    mutation,
                })
            });
            expect_hold(Board::V3);
        }
    }
}
#[test]
fn rooted_custom_reader_authenticates_double_inventory_and_closes_before_final_check() {
    let _serial = SERIAL.lock().unwrap();
    setup(0, 8 * MIB);
    let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
    let (mut m, mut storage, ns, e) = entries();
    let mut reverse = e.clone();
    reverse.reverse();
    nvs::reset(ns, vec![e, reverse], None);
    let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
    let r = owner.inspect(&root).unwrap();
    assert_eq!(r.retained_records, 2);
    assert_eq!(r.layout, journal::Layout::PairedNeedsWitness);
    assert_eq!(nvs::checked(|s| s.finds), 2);
    assert!(sdk::checked(|s| s.close_checks) > 0);
    assert_eq!(BOOT.load(Ordering::SeqCst), LIVE);
    clean();
}
#[test]
fn every_inventory_error_closes_and_per_operation_layout_drift_poison_is_hold() {
    let _serial = SERIAL.lock().unwrap();
    for op in ["open", "find", "info", "length", "read", "next"] {
        for nth in 1..=if op == "open" {
            1
        } else if op == "find" {
            2
        } else {
            10
        } {
            setup(0, 8 * MIB);
            let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
            let (mut m, mut storage, ns, e) = entries();
            nvs::reset(
                ns,
                vec![e],
                Some(nvs::Fault {
                    op,
                    nth,
                    err: -1,
                    null: op == "open",
                    length: None,
                }),
            );
            let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
            assert_eq!(owner.inspect(&root).unwrap_err(), InventoryHold::Storage);
            clean();
            if op != "open" {
                assert!(sdk::checked(|s| s.close_checks) > 0);
            }
        }
    }
    for op in [
        "nvs:open",
        "nvs:find",
        "nvs:info",
        "nvs:length",
        "nvs:read",
        "nvs:next",
        "nvs:release",
        "nvs:close",
    ] {
        setup(0, 8 * MIB);
        let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
        let (mut m, mut storage, ns, e) = entries();
        nvs::reset(ns, vec![e], None);
        sdk::change(|s| {
            s.hook = Some(sdk::Hook {
                op,
                nth: 1,
                mutation: sdk::Mutation::Table,
            })
        });
        let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
        assert!(owner.inspect(&root).is_err());
        assert_eq!(BOOT.load(Ordering::SeqCst), POISONED);
        clean();
        assert!(owner.recheck().is_err());
    }
}
#[test]
fn missing_and_error_with_nonzero_handle_and_custody_failure_remain_hold() {
    let _serial = SERIAL.lock().unwrap();
    for err in [-1, sdk::ESP_ERR_NVS_NOT_FOUND] {
        for nonzero in [false, true] {
            setup(0, 8 * MIB);
            let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
            let (mut m, mut storage, ns, e) = entries();
            nvs::reset(ns, vec![e], None);
            sdk::change(|s| {
                if nonzero {
                    s.open_error_handle = Some(err)
                } else {
                    s.fault = Some(sdk::Fault {
                        op: "custom-open",
                        nth: 1,
                        error: err,
                    })
                }
            });
            let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
            assert_eq!(
                owner.inspect(&root).unwrap_err(),
                if err == sdk::ESP_ERR_NVS_NOT_FOUND && !nonzero {
                    InventoryHold::Missing
                } else {
                    InventoryHold::Storage
                }
            );
            clean();
        }
    }
    setup(0, 8 * MIB);
    let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
    let (mut m, mut storage, ns, e) = entries();
    nvs::reset(ns, vec![e], None);
    let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
    root.nvs.backend.seed("master_0_deriv", &[0]);
    assert_eq!(owner.inspect(&root).unwrap_err(), InventoryHold::Custody);
    assert!(!sdk::checked(|s| s.calls.contains(&"custom-open")));
    clean();
    sdk::change(|s| s.table[4095] ^= 1);
    assert!(owner.inspect(&root).is_err());
    assert_eq!(BOOT.load(Ordering::SeqCst), POISONED);
    clean();
}

#[test]
fn every_live_identity_read_cut_poisons_and_closes_an_open_handle() {
    let _serial = SERIAL.lock().unwrap();
    for cut in 1..=16 {
        setup(0, 8 * MIB);
        let owner = AllocationPartition::acquire_for_board(Board::V3).unwrap();
        let (mut m, mut storage, ns, e) = entries();
        nvs::reset(ns, vec![e], None);
        // Three successful inspections of identity occur before the first
        // in-handle collector call. Fail any of its sixteen bounded reads.
        let prior = sdk::checked(|s| s.calls.iter().filter(|&&c| c == "flash-read").count());
        sdk::change(|s| {
            s.fault = Some(sdk::Fault {
                op: "flash-read",
                nth: prior + 3 * 16 + cut,
                error: -1,
            })
        });
        let root = HeldAllocationRoot::hold(&mut storage, &mut m).unwrap();
        assert!(owner.inspect(&root).is_err());
        assert_eq!(BOOT.load(Ordering::SeqCst), POISONED);
        nvs::checked(|s| {
            assert!(s.calls.contains(&"open"));
            assert!(s.calls.contains(&"close"));
            assert!(!s.calls.contains(&"find"));
        });
        clean();
        drop(owner);
        assert_eq!(BOOT.load(Ordering::SeqCst), POISONED);
        assert!(AllocationPartition::acquire_for_board(Board::V3).is_err());
    }
}
