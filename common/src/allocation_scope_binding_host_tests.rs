//! Independent public syntax vectors; no scope, service or physical authority.
use super::*;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-scope-binding-body-v1.json"
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
    hex(fixture()["bodyHex"].as_str().unwrap())
}
fn reject(bytes: &[u8], error: FrameError) {
    assert_eq!(UnverifiedScopeBinding::parse(bytes).err(), Some(error));
}

#[test]
fn scope_binding_independent_complete_body_digest_and_retry_match() {
    let f = fixture();
    assert_eq!(f["bodyBytes"], BYTES);
    assert_eq!(f["exhaustiveSingleByteSubstitutions"], 67065);
    let b = baseline();
    let parsed = UnverifiedScopeBinding::parse(&b).unwrap();
    assert_eq!(
        parsed.digest().as_slice(),
        hex(f["digest"].as_str().unwrap())
    );
    assert!(parsed.exactly_matches(&UnverifiedScopeBinding::parse(&b).unwrap()));
}

#[test]
fn scope_binding_all_lengths_prefixes_versions_and_policies_are_bounded() {
    let b = baseline();
    for length in 0..BYTES {
        reject(&b[..length], FrameError::Length);
    }
    let mut extra = b.clone();
    extra.push(0);
    reject(&extra, FrameError::Length);
    for at in [0, 1, 2, 3, 4, 261, 262] {
        for value in 0..=255 {
            if value == b[at] {
                continue;
            }
            let mut bad = b.clone();
            bad[at] = value;
            reject(&bad, FrameError::Format);
        }
    }
    // Existing snapshot/seed magic must not be interpreted as a scope body.
    let mut wrong = b;
    wrong[..5].copy_from_slice(b"HWSC\x01");
    reject(&wrong, FrameError::Format);
}

#[test]
fn scope_binding_opaque_bindings_require_nonzero_not_point_syntax() {
    for at in (5..229).step_by(32) {
        let mut b = baseline();
        b[at..at + 32].fill(0);
        reject(&b, FrameError::Binding);
        let mut b = baseline();
        b[at..at + 32].fill(255);
        assert!(UnverifiedScopeBinding::parse(&b).is_ok());
    }
}

#[test]
fn scope_binding_equal_authority_bindings_and_wrong_schema_are_refused() {
    let mut b = baseline();
    let allocator = b[165..197].to_vec();
    b[197..229].copy_from_slice(&allocator);
    reject(&b, FrameError::Binding);
    for at in 229..261 {
        let mut b = baseline();
        b[at] ^= 1;
        reject(&b, FrameError::Binding);
    }
    let mut b = baseline();
    b[229..261].fill(0);
    reject(&b, FrameError::Binding);
}

#[test]
fn scope_binding_all_67065_substitutions_change_digest_and_exact_retry() {
    let b = baseline();
    let base = UnverifiedScopeBinding::parse(&b).unwrap();
    let mut total = 0;
    let mut syntax_only = 0;
    for at in 0..BYTES {
        for replacement in 0..=255 {
            if replacement == b[at] {
                continue;
            }
            let mut changed = b.clone();
            changed[at] = replacement;
            assert_ne!(hash(&[TAG, &changed]), base.digest());
            let parsed = UnverifiedScopeBinding::parse(&changed);
            assert_eq!(parsed.is_ok(), (5..229).contains(&at));
            if let Ok(other) = parsed {
                assert!(!base.exactly_matches(&other));
                assert_ne!(base.digest(), other.digest());
                syntax_only += 1;
            }
            total += 1;
        }
    }
    assert_eq!(total, 67065);
    assert_eq!(syntax_only, 57120);
}

#[test]
fn scope_binding_digest_fits_candidate_without_creating_scope_authority() {
    let body = UnverifiedScopeBinding::parse(&baseline()).unwrap();
    let candidate: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/allocation-enrolment-candidate-v1.json"
    ))
    .unwrap();
    let mut bytes = hex(candidate["vectors"][1]["candidate"].as_str().unwrap());
    let old =
        crate::allocation_root::enrolment_candidate::UnverifiedCandidate::parse(&bytes).unwrap();
    bytes[5..37].copy_from_slice(&body.digest());
    let new =
        crate::allocation_root::enrolment_candidate::UnverifiedCandidate::parse(&bytes).unwrap();
    assert!(!old.exactly_matches(&new));
    assert_ne!(old.digest(), new.digest());
    // Both results remain unverified syntax. No pins, capacity or scope grant.
}
