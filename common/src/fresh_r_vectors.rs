//! PUBLIC SYNTHETIC mathematical vectors only; compiled solely inside nip44 tests.
//! No firmware KDF, entropy, manifest constructor or authorization API is added.
use super::*;
use crate::derive;
use serde_json::Value;
use sha2::Digest;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/fresh-r-kdf-v1.json")).unwrap()
}
fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn array(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

#[test]
fn fresh_r_exact_hkdf_bytes_and_perturbations() {
    let v = fixture();
    assert_eq!(
        hex(&v["domain"]),
        b"VMLS/1 fresh rendezvous allocation scalar\0"
    );
    let schema: [u8; 32] = sha2::Sha256::digest(b"HW allocation journal schema v1\0").into();
    assert_eq!(schema, array(&v["schema"]));
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    for c in cases {
        let info = [hex(&c["domain"]), hex(&c["schema"])].concat();
        assert_eq!(info, hex(&c["info"]));
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&hex(&c["salt"])), &hex(&c["root"]));
        assert_eq!(prk.as_slice(), hex(&c["prk"]));
        let mut d = [0; 32];
        hk.expand(&info, &mut d).unwrap();
        assert_eq!(d, array(&c["candidate"]), "{}", c["name"]);
    }
    let baseline = &cases[0]["candidate"];
    for i in [1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        assert_ne!(baseline, &cases[i]["candidate"]);
    }
    // Inputs marked ineligible still have mathematical HKDF output. These
    // checks do not assert an implemented custody/entropy/schema gate.
    assert!(cases[7..]
        .iter()
        .all(|c| !c["contractInputEligible"].as_bool().unwrap()));
}

#[test]
fn fresh_r_original_scalar_and_both_public_parities() {
    let v = fixture();
    let mut seen = [false; 2];
    for c in v["cases"].as_array().unwrap() {
        let d = array(&c["candidate"]);
        assert_eq!(
            derive::public_key_xonly(&d).is_ok(),
            c["scalarValid"].as_bool().unwrap()
        );
        if !c["scalarValid"].as_bool().unwrap() {
            continue;
        }
        let expected = hex(&c["compressed"]);
        assert_eq!(
            derive::backend::compressed_pubkey(&d).unwrap().as_slice(),
            expected
        );
        assert_eq!(derive::public_key_xonly(&d).unwrap(), array(&c["R"]));
        let neg = array(&c["negatedScalar"]);
        assert_ne!(d, neg);
        assert_eq!(derive::backend::negate(&d).unwrap(), neg);
        assert_eq!(derive::public_key_xonly(&neg).unwrap(), array(&c["R"]));
        if c["contractInputEligible"].as_bool().unwrap() {
            seen[(expected[0] - 2) as usize] = true;
        }
    }
    assert_eq!(seen, [true, true]);
}

#[test]
fn fresh_r_backend_refuses_zero_and_out_of_range_without_reduction() {
    let v = fixture();
    assert_eq!(v["scalarBoundaries"].as_array().unwrap().len(), 6);
    for b in v["scalarBoundaries"].as_array().unwrap() {
        let d = array(&b["candidate"]);
        let valid = b["scalarValid"].as_bool().unwrap();
        let public = derive::public_key_xonly(&d);
        assert_eq!(public.is_ok(), valid, "{}", b["name"]);
        assert_eq!(derive::backend::compressed_pubkey(&d).is_ok(), valid);
        if valid {
            assert_eq!(public.unwrap(), array(&b["R"]));
        }
    }
}

#[test]
fn fresh_r_bunker_normalization_and_tree_aliases_are_exact() {
    let v = fixture();
    let b = &v["bunker"];
    let raw = array(&b["raw"]);
    let normalized = derive::nsec_to_tree_root(&raw).unwrap();
    assert_eq!(*normalized, array(&b["normalizedRoot"]));
    assert_eq!(
        derive::public_key_xonly(&raw).unwrap(),
        array(&b["rawIssuer"])
    );
    assert_eq!(
        derive::public_key_xonly(&normalized).unwrap(),
        array(&b["normalizedIssuer"])
    );
    assert_ne!(b["rawIssuer"], b["normalizedIssuer"]);
    let cases = v["cases"].as_array().unwrap();
    for i in [3, 4, 5] {
        assert_eq!(array(&cases[i]["root"]), *normalized);
        assert_eq!(cases[i]["candidate"], cases[3]["candidate"]);
        assert_eq!(cases[i]["R"], cases[3]["R"]);
    }
    assert_ne!(cases[6]["candidate"], cases[3]["candidate"]);
    // Identical root-derived child bytes do not bypass journal issuer binding.
}

#[test]
fn fresh_r_actual_ecdh_and_pinned_vmls_introduction_match_independent_vectors() {
    let v = fixture();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(v["introduction"].as_array().unwrap().len(), 36);
    for e in v["introduction"].as_array().unwrap() {
        let c = cases.iter().find(|c| c["name"] == e["case"]).unwrap();
        let peer = array(&e["peerScalar"]);
        let peer_r = array(&e["peerR"]);
        assert_eq!(derive::public_key_xonly(&peer).unwrap(), peer_r);
        let expected_x = array(&e["sharedX"]);
        // Call the actual existing private ECDH adapter on each backend.
        let x = ecdh_shared_x(&array(&c["candidate"]), &peer_r).unwrap();
        assert_eq!(x, expected_x);
        assert_eq!(
            ecdh_shared_x(&array(&c["negatedScalar"]), &peer_r).unwrap(),
            x
        );
        assert_eq!(ecdh_shared_x(&peer, &array(&c["R"])).unwrap(), x);
        let recipient = array(&e["recipientR"]);
        assert_eq!(
            recipient,
            if e["recipient"] == "peer" {
                peer_r
            } else {
                array(&c["R"])
            }
        );
        let counter: u64 = e["counter"].as_str().unwrap().parse().unwrap();
        let intro = vmls_core::derive::introduction(&x, &recipient, counter);
        assert_eq!(intro.mailbox, array(&e["mailbox"]));
        assert_eq!(intro.record_secret, array(&e["recordSecret"]));
        assert_ne!(intro.mailbox, intro.record_secret);
    }
}
