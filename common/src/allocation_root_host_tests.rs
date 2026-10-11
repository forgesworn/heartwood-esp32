//! Tests execute the actual firmware source with synthetic keys and mock NVS.
use super::*;
use crate::firmware_policy_host_tests::{FaultKind, NvsOp};
use crate::held_data_key;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn journal_inventory_uses_held_root_and_never_writes_or_initializes() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let mut m = master();
    m.secret = [1; 32];
    m.mode = MasterMode::TreeNsec;
    m.derivation_version = 1;
    m.pubkey = derive::public_key_xonly(&m.secret).unwrap();
    let mut nvs = stored(&m);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/allocation-journal-v1.json")).unwrap();
    assert_eq!(
        h.journal_namespace().unwrap(),
        v["namespace"].as_str().unwrap()
    );
    assert_eq!(h.inspect_journal(&[]).unwrap_err(), InventoryHold::Missing);
    let hex = v["anchor"].as_str().unwrap();
    let anchor: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(
        h.inspect_journal(&[StoredBlob {
            key: "anchor",
            bytes: &anchor
        }])
        .unwrap_err(),
        InventoryHold::Missing
    );
    assert!(h
        .nvs
        .backend
        .take_log()
        .iter()
        .all(|(_, op)| *op != NvsOp::SetBlob && *op != NvsOp::Remove));
    h.nvs.backend.seed("master_0_deriv", &[0]);
    assert_eq!(h.inspect_journal(&[]).unwrap_err(), InventoryHold::Custody);
    assert_eq!(h.journal_namespace().unwrap_err(), InventoryHold::Custody);
}
fn scalar(n: u8) -> [u8; 32] {
    let mut s = [0; 32];
    s[31] = n;
    s
}
fn master() -> LoadedMaster {
    let secret = scalar(1);
    LoadedMaster {
        slot: 0,
        secret,
        label: "synthetic".into(),
        mode: MasterMode::Bunker,
        derivation_version: 0,
        pubkey: derive::public_key_xonly(&secret).unwrap(),
        locked: false,
        operator: None,
    }
}
fn stored(m: &LoadedMaster) -> EspNvs<NvsDefault> {
    let nvs = EspNvs::new();
    nvs.backend.seed("master_count", &[m.slot + 1]);
    let p = format!("master_{}", m.slot);
    nvs.backend.seed(&format!("{p}_mode"), &[m.mode as u8]);
    nvs.backend
        .seed(&format!("{p}_deriv"), &[m.derivation_version]);
    nvs.backend.seed(&format!("{p}_pubkey"), &m.pubkey);
    nvs.backend.seed(&format!("{p}_secret"), &m.secret);
    nvs
}
fn refuses(nvs: &mut EspNvs<NvsDefault>, m: &mut LoadedMaster) {
    assert!(HeldAllocationRoot::hold(nvs, m).is_err());
}
fn decode(s: &str) -> [u8; 32] {
    let mut out = [0; 32];
    assert_eq!(s.len(), 64);
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn actual_root_matches_independent_vectors() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-writer-namespace-v1.json"
    ))
    .unwrap();
    for v in vectors["cases"].as_array().unwrap() {
        let l = &v["loaded"];
        let mut m = master();
        m.secret = decode(l["masterSecretHex"].as_str().unwrap());
        m.mode =
            MasterMode::from_u8(u8::from_str_radix(l["modeHex"].as_str().unwrap(), 16).unwrap())
                .unwrap();
        m.derivation_version =
            u8::from_str_radix(l["derivationVersionHex"].as_str().unwrap(), 16).unwrap();
        m.pubkey = decode(l["storedIssuerHex"].as_str().unwrap());
        m.slot = l["slot"].as_u64().unwrap() as u8;
        let mut nvs = stored(&m);
        let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
        assert_eq!(*h.root.0, decode(v["normalizedRootHex"].as_str().unwrap()));
        assert_eq!(*h.issuer(), decode(l["storedIssuerHex"].as_str().unwrap()));
        h.recheck().unwrap();
        assert!(h
            .nvs
            .backend
            .take_log()
            .iter()
            .all(|(_, op)| *op != NvsOp::SetBlob && *op != NvsOp::Remove));
    }
}

#[test]
fn missing_malformed_original_metadata_never_uses_legacy_fallback() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    for (key, width) in [
        ("master_count", 1),
        ("master_0_mode", 1),
        ("master_0_deriv", 1),
        ("master_0_pubkey", 32),
        ("master_0_secret", 32),
    ] {
        for size in [0, width - 1, width + 1] {
            let mut m = master();
            let mut nvs = stored(&m);
            nvs.backend.seed(key, &vec![0; size]);
            refuses(&mut nvs, &mut m);
        }
        let mut m = master();
        let mut nvs = stored(&m);
        nvs.remove(key).unwrap();
        refuses(&mut nvs, &mut m);
    }
    for (key, bytes) in [
        ("master_count", vec![9]),
        ("master_0_mode", vec![3]),
        ("master_0_deriv", vec![1]),
        ("master_0_pubkey", vec![0; 32]),
        ("rm_journal", vec![]),
    ] {
        let mut m = master();
        let mut nvs = stored(&m);
        nvs.backend.seed(key, &bytes);
        refuses(&mut nvs, &mut m);
    }
}

#[test]
fn invalid_locked_or_different_loaded_master_holds() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    for mutation in 0..7 {
        let mut m = master();
        let mut nvs = stored(&m);
        match mutation {
            0 => m.locked = true,
            1 => m.secret = [0; 32],
            2 => m.secret = [255; 32],
            3 => m.secret = scalar(2),
            4 => m.mode = MasterMode::TreeNsec,
            5 => m.derivation_version = 1,
            _ => m.slot = 8,
        }
        refuses(&mut nvs, &mut m);
    }
}

#[test]
fn same_xonly_public_key_cannot_substitute_the_other_scalar() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let mut m = master();
    let mut nvs = stored(&m);
    // Public mathematical curve order minus one; no real credentials.
    let neg = decode(concat!(
        "fffffffffffffffffffffffffffffffe",
        "baaedce6af48a03bbfd25e8cd0364140"
    ));
    assert_eq!(derive::public_key_xonly(&neg).unwrap(), m.pubkey);
    m.secret = neg;
    refuses(&mut nvs, &mut m);
}

#[test]
fn every_storage_failure_holds_without_writes() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    for key in [
        "master_count",
        "rm_journal",
        "master_0_mode",
        "master_0_deriv",
        "master_0_pubkey",
        "m0_seed_enc",
        "master_0_secret",
    ] {
        let mut m = master();
        let mut nvs = stored(&m);
        nvs.backend
            .fail_once(NvsOp::BlobLen, key, FaultKind::ReadError);
        refuses(&mut nvs, &mut m);
    }
    for key in [
        "master_count",
        "master_0_mode",
        "master_0_deriv",
        "master_0_pubkey",
        "master_0_secret",
    ] {
        let mut m = master();
        let mut nvs = stored(&m);
        nvs.backend
            .fail_once(NvsOp::GetBlob, key, FaultKind::ReadError);
        refuses(&mut nvs, &mut m);
        assert!(nvs
            .backend
            .take_log()
            .iter()
            .all(|(_, op)| *op != NvsOp::SetBlob && *op != NvsOp::Remove));
    }
}

fn encrypted(m: &LoadedMaster, key: &[u8; 32]) -> EspNvs<NvsDefault> {
    let mut nvs = stored(m);
    nvs.remove("master_0_secret").unwrap();
    let blob = data_key::seal(
        key,
        data_key::Purpose::Seed,
        &m.secret,
        &[3; data_key::NONCE_LEN],
    );
    nvs.backend.seed("m0_seed_enc", &blob);
    nvs
}

#[test]
fn encrypted_seed_requires_held_key_authenticated_exact_bytes_and_no_shadow() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let key = [7; 32];
    let mut m = master();
    let mut nvs = encrypted(&m, &key);
    refuses(&mut nvs, &mut m);
    held_data_key::remember([8; 32]);
    refuses(&mut nvs, &mut m);
    held_data_key::remember(key);
    {
        let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
        h.recheck().unwrap();
    }
    for mutation in 0..5 {
        let mut m = master();
        let mut nvs = encrypted(&m, &key);
        match mutation {
            0 => nvs.backend.seed("m0_seed_enc", &[0; data_key::SEALED_LEN]),
            1 => nvs.backend.seed("m0_seed_enc", &[0; 92]), // old direct-PIN format holds
            2 => nvs.backend.seed("master_0_secret", &m.secret),
            3 => {
                let blob = data_key::seal(
                    &key,
                    data_key::Purpose::Seed,
                    &scalar(2),
                    &[3; data_key::NONCE_LEN],
                );
                nvs.backend.seed("m0_seed_enc", &blob);
            }
            _ => {
                let blob = data_key::seal(
                    &key,
                    data_key::Purpose::NoteKey,
                    &m.secret,
                    &[3; data_key::NONCE_LEN],
                );
                nvs.backend.seed("m0_seed_enc", &blob);
            }
        }
        refuses(&mut nvs, &mut m);
    }
    held_data_key::forget();
}

#[test]
fn mixed_at_rest_state_cannot_downgrade_to_plaintext() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let mut m = master();
    let mut nvs = stored(&m);
    nvs.backend.seed("master_count", &[2]);
    nvs.backend.seed("m1_seed_enc", &[0]);
    refuses(&mut nvs, &mut m);
}

#[test]
fn recheck_detects_durable_drift_and_never_replaces_root() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    for key in [
        "master_count",
        "master_0_mode",
        "master_0_deriv",
        "master_0_pubkey",
        "master_0_secret",
        "rm_journal",
        "m0_seed_enc",
    ] {
        let mut m = master();
        let mut nvs = stored(&m);
        let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
        h.nvs.backend.seed(key, &[255]);
        assert!(h.recheck().is_err());
    }
}

#[test]
fn concurrent_or_nested_custody_holds_then_drop_releases() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    let mut m = master();
    let mut nvs = stored(&m);
    let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
    let mut other = master();
    let mut other_nvs = stored(&other);
    assert!(matches!(
        HeldAllocationRoot::hold(&mut other_nvs, &mut other),
        Err(Hold::Busy)
    ));
    drop(h);
    assert!(HeldAllocationRoot::hold(&mut other_nvs, &mut other).is_ok());
    held_data_key::forget();
}

#[test]
fn encrypted_selected_checks_every_other_counted_slot() {
    let _serial = SERIAL.lock().unwrap();
    let key = [7; 32];
    held_data_key::remember(key);
    for mutation in 0..5 {
        let mut m = master();
        let mut nvs = encrypted(&m, &key);
        nvs.backend.seed("master_count", &[2]);
        let valid = data_key::seal(
            &key,
            data_key::Purpose::Seed,
            &scalar(2),
            &[4; data_key::NONCE_LEN],
        );
        match mutation {
            0 => nvs.backend.seed("master_1_secret", &scalar(2)), // missing encryption
            1 => nvs.backend.seed("m1_seed_enc", &[0; data_key::SEALED_LEN]),
            2 => nvs.backend.seed("m1_seed_enc", &[0; 92]),
            3 => {
                nvs.backend.seed("m1_seed_enc", &valid);
                nvs.backend.seed("master_1_secret", &scalar(2));
            }
            _ => {
                let wrong_key = data_key::seal(
                    &[8; 32],
                    data_key::Purpose::Seed,
                    &scalar(2),
                    &[4; data_key::NONCE_LEN],
                );
                nvs.backend.seed("m1_seed_enc", &wrong_key);
            }
        }
        refuses(&mut nvs, &mut m);
    }
    let mut m = master();
    let mut nvs = encrypted(&m, &key);
    nvs.backend.seed("master_count", &[2]);
    let valid = data_key::seal(
        &key,
        data_key::Purpose::Seed,
        &scalar(2),
        &[4; data_key::NONCE_LEN],
    );
    nvs.backend.seed("m1_seed_enc", &valid);
    {
        let h = HeldAllocationRoot::hold(&mut nvs, &mut m).unwrap();
        h.recheck().unwrap();
    }
    nvs.backend
        .fail_once(NvsOp::BlobLen, "m1_seed_enc", FaultKind::ReadError);
    refuses(&mut nvs, &mut m);
    nvs.backend
        .fail_once(NvsOp::GetBlob, "m1_seed_enc", FaultKind::ReadError);
    refuses(&mut nvs, &mut m);
    held_data_key::forget();
}

#[test]
fn same_width_corruption_during_read_holds() {
    let _serial = SERIAL.lock().unwrap();
    held_data_key::forget();
    for key in [
        "master_count",
        "master_0_mode",
        "master_0_deriv",
        "master_0_pubkey",
        "master_0_secret",
    ] {
        let mut m = master();
        let mut nvs = stored(&m);
        nvs.backend
            .fail_once(NvsOp::GetBlob, key, FaultKind::CorruptReadBackOnce);
        refuses(&mut nvs, &mut m);
    }
    let key = [7; 32];
    held_data_key::remember(key);
    let mut m = master();
    let mut nvs = encrypted(&m, &key);
    nvs.backend.fail_once(
        NvsOp::GetBlob,
        "m0_seed_enc",
        FaultKind::CorruptReadBackOnce,
    );
    refuses(&mut nvs, &mut m);
    held_data_key::forget();
}
