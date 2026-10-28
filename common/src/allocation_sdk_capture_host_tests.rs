//! Test-only bridge from pinned SDK captures to the actual private codec.
//! Exact old/new describes local bytes only; neither is fresh authority.
use super::*;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

#[path = "allocation_sdk_lifecycle_host_tests.rs"]
mod sdk_lifecycle;
#[path = "allocation_sdk_recovery_host_tests.rs"]
mod sdk_recovery;

fn profiles() -> Vec<Fixture> {
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
fn decode_hex(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    if s.len() % 2 != 0 || s.len() > 996 {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            if !c
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            {
                return None;
            }
            u8::from_str_radix(core::str::from_utf8(c).ok()?, 16).ok()
        })
        .collect()
}
fn captured(f: &Fixture, c: &Value) -> Result<BTreeMap<String, Vec<u8>>, &'static str> {
    let ns = &c["namespace"];
    if c["initStatus"].as_i64() != Some(0)
        || ns["openStatus"].as_i64() != Some(0)
        || ns["enumerationStatus"].as_i64() != Some(0x1102)
    {
        return Err("SDK status");
    }
    if ns["namespace"].as_str() != Some(namespace(&f.root).as_str()) {
        return Err("namespace binding");
    }
    let entries = ns["entries"].as_array().ok_or("entries")?;
    if entries.len() > 35 {
        return Err("entry count");
    }
    let mut b = BTreeMap::new();
    for e in entries {
        let k = e["key"].as_str().ok_or("key")?;
        let width = expected_blob_width(k).ok_or("unknown key")?;
        if e["type"].as_u64() != Some(0x42) || e["size"].as_u64() != Some(width as u64) {
            return Err("type or width");
        }
        let data = decode_hex(&e["hex"]).ok_or("hex")?;
        if data.len() != width || b.insert(k.to_owned(), data).is_some() {
            return Err("duplicate or length");
        }
    }
    Ok(b)
}
fn expected(f: &Fixture, spec: &Value) -> BTreeMap<String, Vec<u8>> {
    if spec.is_null() {
        return BTreeMap::new();
    }
    let records = spec["records"].as_u64().unwrap() as usize;
    assert!(records <= 32);
    let gens: Vec<_> = spec["generations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            let g = g.as_u64().unwrap() as usize;
            assert!((1..=129).contains(&g));
            g
        })
        .collect();
    assert!(gens.len() <= 2);
    let entries = inventory(f, &gens, records);
    let count = entries.len();
    let result: BTreeMap<_, _> = entries.into_iter().collect();
    assert_eq!(result.len(), count, "duplicate expected snapshot slot");
    result
}
fn classify(f: &Fixture, c: &Value) -> (&'static str, String) {
    let b = match captured(f, c) {
        Ok(b) => b,
        Err(e) => return ("HOLD", e.into()),
    };
    let list: Vec<_> = b.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    match scan(f, &list) {
        Err(e) => ("HOLD", format!("codec {e:?}")),
        Ok(report) => {
            let outcome = if !c["new"].is_null() && b == expected(f, &c["new"]) {
                "exact-new"
            } else if !c["old"].is_null() && b == expected(f, &c["old"]) {
                "exact-old"
            } else {
                "HOLD"
            };
            (outcome, format!("{report:?}"))
        }
    }
}
fn capture(f: &Fixture, gens: &[usize], records: usize) -> Value {
    let entries: Vec<_> = inventory(f, gens, records)
        .into_iter()
        .map(|(k, b)| {
            let hex: String = b.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::json!({"key":k,"type":0x42,"size":b.len(),"hex":hex})
        })
        .collect();
    serde_json::json!({"initStatus":0,"namespace":{"namespace":namespace(&f.root),"openStatus":0,"enumerationStatus":0x1102,"entries":entries},"old":{"generations":[62,63],"records":31},"new":{"generations":[62,63],"records":32}})
}
#[test]
fn sdk_capture_requires_exact_authenticated_old_or_new_and_never_authority() {
    for f in profiles() {
        let old = capture(&f, &[62, 63], 31);
        assert_eq!(classify(&f, &old).0, "exact-old");
        let new = capture(&f, &[62, 63], 32);
        let (outcome, detail) = classify(&f, &new);
        assert_eq!(outcome, "exact-new");
        assert!(detail.contains("fresh_witness_authority: false"));
        let pending = capture(&f, &[63, 64], 32);
        assert_eq!(classify(&f, &pending).0, "HOLD", "valid off-path bytes");
    }
}
#[test]
fn sdk_capture_rejects_status_binding_type_width_duplicates_and_corrupt_newer() {
    let f = profiles().remove(0);
    let base = capture(&f, &[62, 63], 31);
    for path in ["initStatus", "openStatus", "enumerationStatus"] {
        let mut c = base.clone();
        if path == "initStatus" {
            c[path] = 1.into();
        } else {
            c["namespace"][path] = 1.into();
        }
        assert_eq!(classify(&f, &c).0, "HOLD");
    }
    for (field, value) in [
        ("type", 1.into()),
        ("size", 1.into()),
        ("key", "m33".into()),
        ("hex", "ab".into()),
        ("hex", "GG".into()),
    ] {
        let mut c = base.clone();
        c["namespace"]["entries"][0][field] = value;
        assert_eq!(classify(&f, &c).0, "HOLD");
    }
    let mut c = base.clone();
    c["namespace"]["namespace"] = "wrong".into();
    assert_eq!(classify(&f, &c).0, "HOLD");
    let mut c = base.clone();
    let entry = c["namespace"]["entries"][0].clone();
    c["namespace"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(entry);
    assert_eq!(classify(&f, &c).0, "HOLD");
    let mut c = base;
    // g63 is the newer slot; intact g62 cannot excuse corrupt g63.
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
    assert_eq!(classify(&f, &c).0, "HOLD");
}
#[test]
fn sdk_capacity_inventory_batch() {
    // Ordinary CI has no external captures. Always exercise a real-codec case
    // before the optional offline input, so this test cannot silently do nothing.
    let profiles = profiles();
    assert_eq!(
        classify(&profiles[0], &capture(&profiles[0], &[62, 63], 32)).0,
        "exact-new"
    );
    let Ok(path) = std::env::var("HW_ALLOCATION_SDK_CAPTURE_INPUT") else {
        return;
    };
    let output = std::env::var("HW_ALLOCATION_SDK_CAPTURE_OUTPUT").unwrap();
    assert_ne!(path, output);
    let input = std::fs::File::open(path).unwrap();
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    let mut count = 0;
    for line in std::io::BufReader::new(input).lines() {
        let line = line.unwrap();
        assert!(line.len() <= 65536, "bounded public capture line");
        let c: Value = serde_json::from_str(&line).unwrap();
        let index = c["profile"].as_u64().unwrap() as usize;
        assert!(index < 8);
        let mut result = if c.get("allowedLifecycleStates").is_some() {
            sdk_lifecycle::classify(&profiles[index], &c)
        } else if c.get("allowedStates").is_some() {
            sdk_recovery::classify(&profiles[index], &c)
        } else {
            let (outcome, detail) = classify(&profiles[index], &c);
            serde_json::json!({"class":outcome,"detail":detail,"authority":false})
        };
        if let Some(expected) = c["expectedClass"].as_str() {
            assert_eq!(result["class"].as_str().unwrap(), expected);
        }
        if let Some(expected) = c.get("expectedLocalState") {
            assert_eq!(&result["localState"], expected);
        }
        result["index"] = count.into();
        writeln!(output, "{result}").unwrap();
        count += 1;
    }
    assert!(count > 0);
    output.sync_all().unwrap();
    eprintln!("classified {count} cold SDK inventories; no authority");
}
