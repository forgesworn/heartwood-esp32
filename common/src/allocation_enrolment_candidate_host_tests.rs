//! Public independent framing vectors, never admission or physical authority.
use super::*;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-enrolment-candidate-v1.json"
    ))
    .unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
        .collect()
}
fn baseline() -> Vec<u8> {
    hex(fixture()["vectors"][1]["candidate"].as_str().unwrap())
}
fn reject(bytes: &[u8], error: FrameError) {
    assert_eq!(UnverifiedCandidate::parse(bytes).err(), Some(error));
}
fn reseal_hashes(b: &mut [u8]) {
    let route = hash(&[b"HW allocation route v1\0", &[1], &b[170..202]]);
    b[202..234].copy_from_slice(&route);
    let pins = hash(&[b"HW allocation pins v1\0", &b[37..266]]);
    let records = hash(&[b"HW allocation record set v1\0", &pins, &[0]]);
    let genesis = hash(&[b"HW allocation state v1\0", &pins, &[0], &records, &[0; 32]]);
    b[266..298].copy_from_slice(&genesis);
}

#[test]
fn enrolment_independent_complete_frames_and_digests_match() {
    for v in fixture()["vectors"].as_array().unwrap() {
        let bytes = hex(v["candidate"].as_str().unwrap());
        let frame = UnverifiedCandidate::parse(&bytes).unwrap();
        assert_eq!(
            frame.digest().as_slice(),
            hex(v["candidateSHA256"].as_str().unwrap())
        );
        assert_eq!(
            u64::from_be_bytes(bytes[427..435].try_into().unwrap()),
            v["requested_lifetime_seconds"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        );
        assert!(frame.exactly_matches(&UnverifiedCandidate::parse(&bytes).unwrap()));
    }
}

#[test]
fn enrolment_bounds_version_purpose_and_relative_zero_are_refused() {
    let b = baseline();
    for length in 0..BYTES {
        reject(&b[..length], FrameError::Length);
    }
    let mut extra = b.clone();
    extra.push(0);
    reject(&extra, FrameError::Length);
    for at in [0, 1, 2, 3, 4, 37, 38, 39, 40, 41] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        reject(&bad, FrameError::Format);
    }
    for value in 0..=255 {
        if value == 1 {
            continue;
        }
        let mut bad = b.clone();
        bad[298] = value;
        reject(&bad, FrameError::Format);
    }
    let mut bad = b;
    bad[427..435].fill(0);
    reject(&bad, FrameError::Binding);
}

#[test]
fn enrolment_opaque_fields_are_nonzero_bindings_not_points() {
    for at in [5, 42, 138, 331, 363, 395] {
        let mut b = baseline();
        b[at..at + 32].fill(0);
        reseal_hashes(&mut b);
        reject(&b, FrameError::Binding);
        let mut b = baseline();
        b[at..at + 32].fill(255);
        reseal_hashes(&mut b);
        // Nonpoint bytes are valid opaque syntax, never authenticated ownership.
        assert!(UnverifiedCandidate::parse(&b).is_ok());
    }
}

#[test]
fn enrolment_rejects_nonpoints_weak_noncanonical_and_equal_ed_keys() {
    let invalid_x = [255; 32];
    for at in [106, 299] {
        let mut b = baseline();
        b[at..at + 32].copy_from_slice(&invalid_x);
        reseal_hashes(&mut b);
        reject(&b, FrameError::Point);
    }
    let noncanonical = hex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); // PUBLIC y=3+p; pragma: allow-secret
    // Independent y=3+p encoding: dalek can decompress it to a nonweak point,
    // but canonical recompression is y=3, so it must not enter this frame.
    let decoded = VerifyingKey::from_bytes(noncanonical.as_slice().try_into().unwrap()).unwrap();
    assert!(!decoded.is_weak());
    assert_ne!(
        decoded.to_edwards().compress().as_bytes().as_slice(),
        noncanonical
    );
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut order_two = [255; 32];
    order_two[0] = 236;
    order_two[31] = 127;
    for at in [74, 170] {
        for key in [
            identity.as_slice(),
            order_two.as_slice(),
            noncanonical.as_slice(),
        ] {
            let mut b = baseline();
            b[at..at + 32].copy_from_slice(key);
            reseal_hashes(&mut b);
            reject(&b, FrameError::Point);
        }
    }
    let mut b = baseline();
    let witness = b[170..202].to_vec();
    b[74..106].copy_from_slice(&witness);
    reseal_hashes(&mut b);
    reject(&b, FrameError::Binding);
}

#[test]
fn enrolment_schema_route_and_genesis_are_complete_public_constraints() {
    for range in [234..266, 202..234, 266..298] {
        for at in range {
            let mut b = baseline();
            b[at] ^= 1;
            reject(&b, FrameError::Binding);
        }
    }
}

#[test]
fn enrolment_every_byte_changes_commitment_and_never_becomes_exact_retry() {
    for v in fixture()["vectors"].as_array().unwrap() {
        let b = hex(v["candidate"].as_str().unwrap());
        let base = UnverifiedCandidate::parse(&b).unwrap();
        for at in 0..BYTES {
            let mut changed = b.clone();
            changed[at] ^= 1;
            assert_ne!(hash(&[TAG, &changed]), base.digest());
            if let Ok(other) = UnverifiedCandidate::parse(&changed) {
                assert!(!base.exactly_matches(&other));
            }
        }
    }
}

#[test]
fn enrolment_valid_changed_bindings_are_syntax_only_and_not_retries() {
    let b = baseline();
    let base = UnverifiedCandidate::parse(&b).unwrap();
    for at in [5, 42, 138, 331, 363, 395, 434] {
        let mut changed = b.clone();
        changed[at] ^= 1;
        reseal_hashes(&mut changed);
        let other = UnverifiedCandidate::parse(&changed).unwrap();
        assert!(!base.exactly_matches(&other));
        assert_ne!(base.digest(), other.digest());
    }
    // A valid different x-only target remains parseable, but is another operation.
    let mut changed = b;
    let issuer = changed[106..138].to_vec();
    changed[299..331].copy_from_slice(&issuer);
    assert!(!base.exactly_matches(&UnverifiedCandidate::parse(&changed).unwrap()));
}
