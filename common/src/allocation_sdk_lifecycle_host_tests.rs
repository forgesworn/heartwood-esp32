//! Public fixture lifecycle states only; no namespace/genesis authority.
use super::*;

struct State {
    name: &'static str,
    generations: &'static [usize],
    records: usize,
    layout: &'static str,
    pending: bool,
    orphan: Option<u8>,
}
fn states() -> [State; 7] {
    [
        State {
            name: "exact-local-genesis",
            generations: &[1],
            records: 0,
            layout: "LoneNeedsWitness",
            pending: false,
            orphan: None,
        },
        State {
            name: "exact-orphan-first",
            generations: &[1],
            records: 1,
            layout: "OrphanNeedsWitness",
            pending: false,
            orphan: Some(1),
        },
        State {
            name: "exact-first-pending",
            generations: &[1, 2],
            records: 1,
            layout: "PairedNeedsWitness",
            pending: true,
            orphan: None,
        },
        State {
            name: "exact-first-promoted",
            generations: &[2, 3],
            records: 1,
            layout: "PairedNeedsWitness",
            pending: false,
            orphan: None,
        },
        State {
            name: "exact-pre-final-retirement",
            generations: &[126, 127],
            records: 32,
            layout: "PairedNeedsWitness",
            pending: false,
            orphan: None,
        },
        State {
            name: "exact-final-retirement-pending",
            generations: &[127, 128],
            records: 32,
            layout: "PairedNeedsWitness",
            pending: true,
            orphan: None,
        },
        State {
            name: "exact-final-retirement-promoted",
            generations: &[128, 129],
            records: 32,
            layout: "PairedNeedsWitness",
            pending: false,
            orphan: None,
        },
    ]
}
fn hold(detail: &str, state: Option<&str>) -> Value {
    serde_json::json!({"class":"HOLD","localState":state,"detail":detail,"report":null,"authority":false})
}
pub(super) fn classify(f: &Fixture, c: &Value) -> Value {
    let states = states();
    let allowed = c["allowedLifecycleStates"].as_array().unwrap();
    assert!(!allowed.is_empty() && allowed.len() <= 3);
    let mut labels = std::collections::BTreeSet::new();
    for label in allowed {
        let label = label.as_str().unwrap();
        assert!(
            states.iter().any(|s| s.name == label)
                || ["absent-HOLD", "empty-namespace-HOLD", "anchor-only-HOLD"].contains(&label)
        );
        assert!(labels.insert(label), "duplicate lifecycle recipe state");
    }
    let ns = &c["namespace"];
    // Expected absence is one exact SDK shape, never a genesis or reset proof.
    if labels.contains("absent-HOLD")
        && c["initStatus"].as_i64() == Some(0)
        && ns["namespace"].as_str() == Some(namespace(&f.root).as_str())
        && ns["openStatus"].as_i64() == Some(0x1102)
        && ns["enumerationStatus"].as_i64() == Some(0x1102)
        && ns["entries"]
            .as_array()
            .is_some_and(|entries| entries.is_empty())
    {
        return hold(
            "expected target namespace absent; never genesis authority",
            Some("absent-HOLD"),
        );
    }
    let b = match captured(f, c) {
        Ok(b) => b,
        Err(e) => return hold(e, None),
    };
    let list: Vec<_> = b.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let report = match scan(f, &list) {
        Ok(r) => r,
        Err(e) => {
            // Even canonical anchor-only must reach the real decoder and
            // authenticate its anchor before its missing-snapshot HOLD.
            let local = if e == InventoryHold::Missing
                && b.is_empty()
                && labels.contains("empty-namespace-HOLD")
            {
                Some("empty-namespace-HOLD")
            } else if e == InventoryHold::Missing
                && labels.contains("anchor-only-HOLD")
                && b == expected(f, &serde_json::json!({"generations":[],"records":0}))
            {
                Some("anchor-only-HOLD")
            } else {
                None
            };
            return hold(&format!("codec {e:?}"), local);
        }
    };
    let mut outcome = "HOLD";
    for state in states {
        if labels.contains(state.name)
            && b == expected(
                f,
                &serde_json::json!({"generations":state.generations,"records":state.records}),
            )
            && format!("{:?}", report.layout) == state.layout
            && report.snapshots_present as usize == state.generations.len()
            && report.retained_records as usize == state.records
            && report.pending == state.pending
            && report.orphan_ordinal == state.orphan
        {
            outcome = state.name;
        }
    }
    serde_json::json!({"class":outcome,"localState":if outcome=="HOLD" {None} else {Some(outcome)},"detail":"fixed public lifecycle bytes only","report":{
        "layout":format!("{:?}",report.layout),"snapshotsPresent":report.snapshots_present,
        "retainedRecords":report.retained_records,"pending":report.pending,"orphanOrdinal":report.orphan_ordinal
    },"authority":false})
}
fn typed(mut c: Value, allowed: &[&str]) -> Value {
    c["allowedLifecycleStates"] = serde_json::json!(allowed);
    c
}
#[test]
fn sdk_lifecycle_fixed_genesis_first_append_and_terminal_retirement_remain_without_authority() {
    for f in profiles() {
        for s in states() {
            let c = typed(capture(&f, s.generations, s.records), &[s.name]);
            let r = classify(&f, &c);
            assert_eq!(r["class"], s.name);
            assert_eq!(r["localState"], s.name);
            assert_eq!(r["report"]["layout"], s.layout);
            assert_eq!(r["report"]["retainedRecords"], s.records);
            assert_eq!(r["report"]["snapshotsPresent"], s.generations.len());
            assert_eq!(r["report"]["pending"], s.pending);
            assert_eq!(r["report"]["orphanOrdinal"], serde_json::json!(s.orphan));
            assert_eq!(r["authority"], false);
        }
    }
}
#[test]
fn sdk_lifecycle_expected_absent_empty_anchor_are_hold_and_never_genesis() {
    let f = profiles().remove(0);
    let absent = serde_json::json!({"initStatus":0,"namespace":{"namespace":namespace(&f.root),"openStatus":0x1102,"enumerationStatus":0x1102,"entries":[]},"allowedLifecycleStates":["absent-HOLD"]});
    let r = classify(&f, &absent);
    assert_eq!(r["class"], "HOLD");
    assert_eq!(r["localState"], "absent-HOLD");
    assert_eq!(r["authority"], false);
    for field in ["initStatus", "openStatus", "enumerationStatus"] {
        let mut c = absent.clone();
        if field == "initStatus" {
            c[field] = 0x6001.into();
        } else {
            c["namespace"][field] = 0x6001.into();
        }
        assert!(classify(&f, &c)["localState"].is_null());
    }
    let mut c = absent.clone();
    c["namespace"]["namespace"] = "wrong".into();
    assert!(classify(&f, &c)["localState"].is_null());
    let mut c = absent;
    c["namespace"]["entries"] = capture(&f, &[1], 0)["namespace"]["entries"].clone();
    assert!(classify(&f, &c)["localState"].is_null());
    let mut empty = typed(capture(&f, &[], 0), &["empty-namespace-HOLD"]);
    empty["namespace"]["entries"] = serde_json::json!([]);
    assert_eq!(classify(&f, &empty)["localState"], "empty-namespace-HOLD");
    let anchor = typed(capture(&f, &[], 0), &["anchor-only-HOLD"]);
    assert_eq!(classify(&f, &anchor)["localState"], "anchor-only-HOLD");
    assert_eq!(classify(&f, &anchor)["class"], "HOLD");
}
#[test]
fn sdk_lifecycle_refuses_off_phase_corrupt_newer_and_manifest_reclaim() {
    let f = profiles().remove(0);
    let genesis = typed(capture(&f, &[1], 0), &["exact-first-promoted"]);
    assert_eq!(classify(&f, &genesis)["class"], "HOLD");
    let mut terminal = typed(
        capture(&f, &[128, 129], 32),
        &["exact-final-retirement-promoted"],
    );
    terminal["namespace"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["key"] != "m32");
    assert_eq!(classify(&f, &terminal)["class"], "HOLD");
    let mut c = typed(
        capture(&f, &[2, 3], 1),
        &["exact-first-pending", "exact-first-promoted"],
    );
    let e = c["namespace"]["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["key"] == "snap0")
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
    assert_eq!(r["authority"], false);
    assert!(r["localState"].is_null());
}
