//! Fixed public record32 states, reported by the actual private codec.
//! Local promotion is still witness-gated and never usable authority.
use super::*;

fn states() -> [(&'static str, Value); 3] {
    [
        (
            "exact-orphan",
            serde_json::json!({"generations":[62,63],"records":32}),
        ),
        (
            "exact-pending",
            serde_json::json!({"generations":[63,64],"records":32}),
        ),
        (
            "exact-promoted",
            serde_json::json!({"generations":[64,65],"records":32}),
        ),
    ]
}

pub(super) fn classify(f: &Fixture, c: &Value) -> Value {
    // Bad recipes are harness failures. SDK/codec errors are total HOLD and do
    // not pass a partial inventory to the authenticated decoder.
    let allowed = c["allowedStates"].as_array().unwrap();
    assert!(!allowed.is_empty() && allowed.len() <= 3);
    let states = states();
    let mut labels = std::collections::BTreeSet::new();
    for label in allowed {
        let label = label.as_str().unwrap();
        assert!(states.iter().any(|(name, _)| *name == label));
        assert!(labels.insert(label), "duplicate allowed state");
    }
    let b = match captured(f, c) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"class":"HOLD","detail":e,"report":null,"authority":false})
        }
    };
    let list: Vec<_> = b.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let report = match scan(f, &list) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::json!({"class":"HOLD","detail":format!("codec {e:?}"),"report":null,"authority":false})
        }
    };
    let mut outcome = "HOLD";
    for (label, spec) in &states {
        if labels.contains(label) && b == expected(f, spec) {
            // Verify typed codec semantics as well as exact authenticated bytes.
            let valid = report.snapshots_present == 2
                && report.retained_records == 32
                && match *label {
                    "exact-orphan" => {
                        report.layout == Layout::OrphanNeedsWitness
                            && !report.pending
                            && report.orphan_ordinal == Some(32)
                    }
                    "exact-pending" => {
                        report.layout == Layout::PairedNeedsWitness
                            && report.pending
                            && report.orphan_ordinal.is_none()
                    }
                    "exact-promoted" => {
                        report.layout == Layout::PairedNeedsWitness
                            && !report.pending
                            && report.orphan_ordinal.is_none()
                    }
                    _ => unreachable!(),
                };
            if valid {
                outcome = label;
            }
        }
    }
    serde_json::json!({"class":outcome,"detail":"fixed public record32 states only","report":{
        "layout":format!("{:?}",report.layout),"snapshotsPresent":report.snapshots_present,
        "retainedRecords":report.retained_records,"pending":report.pending,"orphanOrdinal":report.orphan_ordinal
    },"authority":false})
}

fn typed(mut c: Value, allowed: &[&str]) -> Value {
    c["allowedStates"] = serde_json::json!(allowed);
    c
}

#[test]
fn sdk_recovery_fixed_orphan_pending_promoted_have_typed_semantics_without_authority() {
    for f in profiles() {
        for (label, generations, layout, pending, orphan) in [
            (
                "exact-orphan",
                [62, 63],
                "OrphanNeedsWitness",
                false,
                Some(32),
            ),
            ("exact-pending", [63, 64], "PairedNeedsWitness", true, None),
            (
                "exact-promoted",
                [64, 65],
                "PairedNeedsWitness",
                false,
                None,
            ),
        ] {
            let c = typed(capture(&f, &generations, 32), &[label]);
            let r = classify(&f, &c);
            assert_eq!(r["class"], label);
            assert_eq!(r["report"]["layout"], layout);
            assert_eq!(r["report"]["snapshotsPresent"], 2);
            assert_eq!(r["report"]["retainedRecords"], 32);
            assert_eq!(r["report"]["pending"], pending);
            assert_eq!(r["report"]["orphanOrdinal"], serde_json::json!(orphan));
            assert_eq!(r["authority"], false);
        }
    }
}

#[test]
fn sdk_recovery_rejects_off_phase_lone_corrupt_newer_and_partial_sdk_inventory() {
    let f = profiles().remove(0);
    let pending = typed(
        capture(&f, &[63, 64], 32),
        &["exact-pending", "exact-promoted"],
    );
    let orphan = typed(
        capture(&f, &[62, 63], 32),
        &["exact-pending", "exact-promoted"],
    );
    assert_eq!(classify(&f, &orphan)["class"], "HOLD");
    for field in ["initStatus", "openStatus", "enumerationStatus"] {
        let mut c = pending.clone();
        if field == "initStatus" {
            c[field] = 0x6001.into();
        } else {
            c["namespace"][field] = 0x6001.into();
        }
        let r = classify(&f, &c);
        assert_eq!(r["class"], "HOLD");
        assert!(r["report"].is_null());
    }
    let mut c = pending.clone();
    c["namespace"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["key"] != "snap0");
    let r = classify(&f, &c);
    assert_eq!(r["class"], "HOLD");
    assert_eq!(r["report"]["layout"], "LoneNeedsWitness");
    let mut c = pending;
    let e = c["namespace"]["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["key"] == "snap1")
        .unwrap();
    let mut data = decode_hex(&e["hex"]).unwrap();
    data[497] ^= 1;
    e["hex"] = data
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into();
    let r = classify(&f, &c);
    assert_eq!(r["class"], "HOLD");
    assert!(r["report"].is_null());
    assert_eq!(r["authority"], false);
}
