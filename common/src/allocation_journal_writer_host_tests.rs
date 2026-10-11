//! Real controller, synthetic preinstalled history and hardware-only boundaries.
use super::super::super::tests::{encrypted, master, stored, SERIAL};
use super::*;
use crate::{allocation_nvs_host_sys as sys, held_data_key};
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::{derive, types::MasterMode};
use serde_json::Value;

fn bytes(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
struct Rig {
    master: crate::master_identity::LoadedMaster,
    nvs: EspNvs<NvsDefault>,
    v: Value,
    ns: String,
}
impl Rig {
    fn new(generations: &[usize], records: usize) -> Self {
        hardware::reset();
        held_data_key::forget();
        let mut m = master();
        m.secret = [1; 32];
        m.mode = MasterMode::TreeNsec;
        m.derivation_version = 1;
        m.pubkey = derive::public_key_xonly(&m.secret).unwrap();
        let nvs = encrypted(&m, &[7; 32]);
        held_data_key::remember([7; 32]);
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/allocation-journal-v1.json"))
                .unwrap();
        let ns = v["namespace"].as_str().unwrap().to_owned();
        let mut entries = vec![sys::entry(&ns, "anchor", bytes(&v["anchor"]))];
        for &g in generations {
            let s = &v["snapshots"][g - 1];
            entries.push(sys::entry(
                &ns,
                &format!("snap{}", s["slot"].as_u64().unwrap()),
                bytes(&s["sealed"]),
            ));
        }
        for n in 1..=records {
            entries.push(sys::entry(
                &ns,
                &format!("m{n:02}"),
                bytes(&v["manifests"][n - 1]["sealed"]),
            ));
        }
        sys::reset(ns.clone(), vec![entries], None);
        sys::enable_writes(sys::WriteEffect::Old);
        Self {
            master: m,
            nvs,
            v,
            ns,
        }
    }
    fn root(&mut self) -> HeldAllocationRoot<'_> {
        HeldAllocationRoot::hold(&mut self.nvs, &mut self.master).unwrap()
    }
    fn inputs(&self) -> (EnrolmentPins, MeasuredCapacity) {
        let a = bytes(&self.v["anchor_plaintext"]);
        (
            EnrolmentPins {
                descriptor: array(&a, 0),
                genesis_digest: array(&a, 229),
                genesis_receipt: array(&a, 261),
            },
            MeasuredCapacity {
                partition: "nvs",
                namespace: self.ns.clone(),
                max_records: 32,
                remaining_writes: 100,
            },
        )
    }
    fn open(&mut self) -> Controller<'_> {
        let (p, c) = self.inputs();
        Controller::open(self.root(), p, c).unwrap()
    }
    fn authorised(&self, n: usize) -> AuthorisedManifest {
        AuthorisedManifest {
            data: Zeroizing::new(
                bytes(&self.v["manifests"][n - 1]["plaintext"])
                    .try_into()
                    .unwrap(),
            ),
        }
    }
}
fn receipt(a: &Attempt, seq: u64, digest: [u8; 32], status: WitnessStatus) -> Vec<u8> {
    let env = ForwardedRequest::verified(
        a.envelope(),
        if a.advance {
            vmls_core::allocation_witness::Method::Advance
        } else {
            vmls_core::allocation_witness::Method::Read
        },
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let subject = match env.request() {
        Request::Read(r) => r.subject,
        Request::Advance(r) => r.subject,
    };
    let mut r = WitnessReceipt {
        status,
        subject,
        seq,
        digest,
        challenge: a.challenge,
        signature: [0; 64],
    };
    r.signature = SigningKey::from_bytes(&[9; 32])
        .sign(&r.digest_to_sign())
        .to_bytes();
    r.encode().to_vec()
}
// Token fetch and transport each take place AFTER dropping actual root custody.
fn prepare(r: &mut Rig, context: Context, advance: bool, token: u8) -> Attempt {
    assert!(held_data_key::current().is_some());
    context.prepare(r.root(), [token; 32], advance).unwrap()
}
fn fresh<'a>(r: &'a mut Rig, c: Context) -> Controller<'a> {
    let a = prepare(r, c, false, 5);
    let l = load_for_attempt(r, &a);
    let b = receipt(&a, l.0, l.1, WitnessStatus::Current);
    a.accept(r.root(), 200, &b).unwrap()
}
fn load_for_attempt(r: &mut Rig, a: &Attempt) -> (u64, [u8; 32]) {
    let root = r.root();
    let inv = read_inventory(&root, &a.context.bindings.namespace).unwrap();
    let l = load(&root, &inv).unwrap();
    (l.latest.seq(), *l.latest.active_digest())
}
fn snapshot_entries() -> Vec<(String, Vec<u8>)> {
    sys::checked(|s| {
        s.passes[0]
            .iter()
            .map(|e| {
                (
                    unsafe { std::ffi::CStr::from_ptr(e.info.key.as_ptr()) }
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    e.bytes.clone(),
                )
            })
            .collect()
    })
}
fn clean() {
    sys::checked(|s| {
        assert_eq!(s.live_handles, 0);
        assert_eq!(s.live_iterators, 0);
    });
}
fn fault(op: &'static str, nth: usize) -> sys::Fault {
    sys::Fault {
        op,
        nth,
        err: sys::ESP_ERR_INVALID_ARG,
        null: true,
        length: None,
    }
}

#[test]
fn append_requires_fresh_authority_then_advances_and_preserves_every_record() {
    let _serial = SERIAL.lock().unwrap();
    let mut r = Rig::new(&[1], 0);
    let manifest = r.authorised(1);
    let before = snapshot_entries();
    let mut c = r.open();
    assert_eq!(c.append(manifest).err(), Some(Error::Freshness));
    assert_eq!(snapshot_entries(), before);
    let context = c.detach().unwrap();
    let manifest = r.authorised(1);
    let mut c = fresh(&mut r, context);
    c.append(manifest).unwrap();
    let pending = load(&c.root, &c.inventory).unwrap();
    assert_eq!(pending.latest.phase(), 1);
    let candidate = *pending.latest.candidate_digest();
    let seq = pending.latest.seq() + 1;
    let context = c.detach().unwrap();
    let a = prepare(&mut r, context, true, 6);
    assert!(held_data_key::current().is_some());
    clean();
    let b = receipt(&a, seq, candidate, WitnessStatus::Current);
    let mut c = a.accept(r.root(), 200, &b).unwrap();
    let l = load(&c.root, &c.inventory).unwrap();
    assert_eq!(l.latest.phase(), 0);
    assert_eq!(l.latest.seq(), 1);
    assert!(c.grant.is_none());
    assert_eq!(
        c.lifecycle(AuthorisedLifecycle {
            ordinal: 1,
            kind: 2
        })
        .err(),
        Some(Error::Freshness)
    );
    let final_entries = snapshot_entries();
    assert_eq!(
        before[0],
        final_entries
            .iter()
            .find(|(k, _)| k == "anchor")
            .unwrap()
            .clone()
    );
    sys::checked(|s| assert_eq!(s.mutations, vec!["m01", "snap1", "snap0"]));
    drop(c);
    clean();
}

#[test]
fn orphan_recovery_handles_active_and_already_advanced_without_replacing_manifest() {
    let _serial = SERIAL.lock().unwrap();
    for ahead in [false, true] {
        for generations in [vec![1], vec![2, 3]] {
            let records = if generations == vec![1] { 1 } else { 2 };
            let mut r = Rig::new(&generations, records);
            let original = snapshot_entries();
            let c = r.open();
            let l = load(&c.root, &c.inventory).unwrap();
            let ordinal = l.orphan.unwrap();
            let seq = l.latest.seq() + u64::from(ahead);
            let digest = if ahead {
                state_digest(&l.anchor.pins(), &candidate(&l, 1, ordinal).unwrap())
            } else {
                *l.latest.active_digest()
            };
            let context = c.detach().unwrap();
            let a = prepare(&mut r, context, false, 5);
            let b = receipt(&a, seq, digest, WitnessStatus::Current);
            let c = a.accept(r.root(), 200, &b).unwrap();
            let l = load(&c.root, &c.inventory).unwrap();
            assert_eq!(l.latest.phase(), if ahead { 0 } else { 1 });
            assert_eq!(l.latest.seq(), seq);
            for (k, v) in original
                .iter()
                .filter(|(k, _)| k == "anchor" || k.starts_with('m'))
            {
                assert_eq!(blob(&c.inventory, k), Some(v.as_slice()));
            }
            sys::checked(|s| {
                assert_eq!(s.mutations.len(), if ahead { 2 } else { 1 });
                assert!(s.mutations.iter().all(|k| k.starts_with("snap")));
            });
            drop(c);
            clean();
        }
    }
}

#[test]
fn lifecycle_keeps_terminal_burned_values_and_cannot_repeat_terminal_operation() {
    let _serial = SERIAL.lock().unwrap();
    for kind in [2, 3] {
        let mut r = Rig::new(&[2, 3], 1);
        let manifest_before = snapshot_entries()
            .into_iter()
            .find(|(k, _)| k == "m01")
            .unwrap();
        let context = r.open().detach().unwrap();
        let mut c = fresh(&mut r, context);
        c.lifecycle(AuthorisedLifecycle { ordinal: 1, kind })
            .unwrap();
        let l = load(&c.root, &c.inventory).unwrap();
        let digest = *l.latest.candidate_digest();
        let seq = l.latest.seq() + 1;
        let context = c.detach().unwrap();
        let a = prepare(&mut r, context, true, 6);
        let b = receipt(&a, seq, digest, WitnessStatus::Current);
        let c = a.accept(r.root(), 200, &b).unwrap();
        assert_eq!(
            blob(&c.inventory, "m01"),
            Some(manifest_before.1.as_slice())
        );
        let context = c.detach().unwrap();
        let a = prepare(&mut r, context, false, 7);
        let l = load_for_attempt(&mut r, &a);
        let b = receipt(&a, l.0, l.1, WitnessStatus::Current);
        let mut c = a.accept(r.root(), 200, &b).unwrap();
        assert_eq!(
            c.lifecycle(AuthorisedLifecycle { ordinal: 1, kind }).err(),
            Some(Error::Inventory(InventoryHold::Records))
        );
        drop(c);
        clean();
    }
}

#[test]
fn lost_reply_uses_fresh_request_and_exact_persisted_operation() {
    let _serial = SERIAL.lock().unwrap();
    let mut r = Rig::new(&[1, 2], 1);
    let original = snapshot_entries();
    let context = r.open().detach().unwrap();
    let c = fresh(&mut r, context);
    let context = c.detach().unwrap();
    let a = prepare(&mut r, context, true, 6);
    let first = a.envelope().to_vec();
    drop(a);
    clean();
    let retry_context = r.open().detach().unwrap();
    let read = prepare(&mut r, retry_context, false, 7);
    let active = load_for_attempt(&mut r, &read);
    let read_bytes = receipt(&read, active.0, active.1, WitnessStatus::Current);
    let c = read.accept(r.root(), 200, &read_bytes).unwrap();
    let detached = c.detach().unwrap();
    let retry = prepare(&mut r, detached, true, 8);
    let witness = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let old = ForwardedRequest::verified(
        &first,
        vmls_core::allocation_witness::Method::Advance,
        &witness,
    )
    .unwrap();
    let new = ForwardedRequest::verified(
        retry.envelope(),
        vmls_core::allocation_witness::Method::Advance,
        &witness,
    )
    .unwrap();
    let (Request::Advance(old), Request::Advance(new)) = (old.request(), new.request()) else {
        panic!("expected CAS")
    };
    assert_eq!(old.subject, new.subject);
    assert_eq!(old.expected_seq, new.expected_seq);
    assert_eq!(old.expected_digest, new.expected_digest);
    assert_eq!(old.next_digest, new.next_digest);
    assert_ne!(old.challenge, new.challenge);
    assert_ne!(first, retry.envelope());
    assert_eq!(snapshot_entries(), original);
    drop(retry);
    let context = r.open().detach().unwrap();
    let a = prepare(&mut r, context, false, 9);
    let l = {
        let ns = r.ns.clone();
        let root = r.root();
        let inv = read_inventory(&root, &ns).unwrap();
        load(&root, &inv).unwrap()
    };
    let b = receipt(
        &a,
        l.latest.seq() + 1,
        *l.latest.candidate_digest(),
        WitnessStatus::Current,
    );
    let c = a.accept(r.root(), 200, &b).unwrap();
    for (k, v) in original
        .iter()
        .filter(|(k, _)| k == "anchor" || k.starts_with('m'))
    {
        assert_eq!(blob(&c.inventory, k), Some(v.as_slice()));
    }
    drop(c);
    clean();
}

#[test]
fn response_key_challenge_subject_status_position_and_http_are_not_authority() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..11 {
        let mut r = Rig::new(&[1, 2], 1);
        let before = snapshot_entries();
        let context = r.open().detach().unwrap();
        let a = prepare(&mut r, context, false, 5);
        let (seq, digest) = load_for_attempt(&mut r, &a);
        let mut b = receipt(&a, seq, digest, WitnessStatus::Current);
        let mut status = 200;
        match case {
            0 => b[74] ^= 1,
            1 => b[106] ^= 1,
            2 => b[2] ^= 1,
            3 => b[42] ^= 1,
            4 => b = receipt(&a, seq + 2, digest, WitnessStatus::Current),
            5 => b = receipt(&a, seq + 1, digest, WitnessStatus::Current),
            6 => b = receipt(&a, seq, digest, WitnessStatus::Conflict),
            7 => b = receipt(&a, seq, digest, WitnessStatus::Retired),
            8 => status = 403,
            9 => status = 409,
            _ => {
                let mut x = WitnessReceipt::parse(&b).unwrap();
                x.signature = SigningKey::from_bytes(&[8; 32])
                    .sign(&x.digest_to_sign())
                    .to_bytes();
                b = x.encode().to_vec();
            }
        }
        assert!(a.accept(r.root(), status, &b).is_err());
        assert_eq!(snapshot_entries(), before);
        clean();
    }
}

#[test]
fn detached_context_rejects_state_custody_change_expiry_and_duplicate_token() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..5 {
        let mut r = Rig::new(&[1], 0);
        let context = r.open().detach().unwrap();
        assert!(held_data_key::current().is_some());
        let a = prepare(&mut r, context, false, 5);
        let (seq, digest) = load_for_attempt(&mut r, &a);
        let b = receipt(&a, seq, digest, WitnessStatus::Current);
        match case {
            0 => hardware::expire(),
            1 => r.nvs.backend.seed("master_0_deriv", &[0]),
            2 => {
                let mut anchor = snapshot_entries()
                    .into_iter()
                    .find(|(k, _)| k == "anchor")
                    .unwrap()
                    .1;
                anchor[40] ^= 1;
                sys::alter("anchor", Some(anchor));
            }
            3 => {
                r.master.locked = true;
            }
            _ => {
                r.master.slot = 1;
            }
        }
        let root = HeldAllocationRoot::hold(&mut r.nvs, &mut r.master);
        if let Ok(root) = root {
            assert!(a.accept(root, 200, &b).is_err());
        } else {
            drop(a);
        }
        clean();
    }
    let mut r = Rig::new(&[1], 0);
    let context = r.open().detach().unwrap();
    let c = fresh(&mut r, context);
    let context = c.detach().unwrap();
    assert!(context.prepare(r.root(), [5; 32], false).is_err());
    clean();
}

#[test]
fn encrypted_writer_eligibility_external_pins_capacity_and_entropy_fail_closed() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..6 {
        let mut r = Rig::new(&[1], 0);
        let (mut p, mut capacity) = r.inputs();
        match case {
            0 => {
                r.nvs = stored(&r.master);
            }
            1 => p.descriptor[101] ^= 1,
            2 => p.genesis_receipt[74] ^= 1,
            3 => capacity.namespace = "elsewhere".into(),
            4 => capacity.partition = "other",
            _ => capacity.max_records = 33,
        }
        assert!(Controller::open(r.root(), p, capacity).is_err());
        sys::checked(|s| assert!(s.mutations.is_empty()));
        clean();
    }
    for value in [None, Some(0), Some(20)] {
        let mut r = Rig::new(&[1], 0);
        let context = r.open().detach().unwrap();
        if let Some(v) = value {
            hardware::repeat(v);
        } else {
            hardware::fail();
        }
        assert!(context.prepare(r.root(), [5; 32], false).is_err());
        clean();
    }
}

#[test]
fn duplicate_permanent_fields_expired_grant_and_capacity_do_not_write() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..7 {
        let mut r = Rig::new(&[2, 3], 1);
        let mut authorised = r.authorised(2);
        if case < 4 {
            let old = bytes(&r.v["manifests"][0]["plaintext"]);
            let at = [38, 70, 166, 198][case];
            authorised.data[at..at + 32].copy_from_slice(&old[at..at + 32]);
        }
        let context = r.open().detach().unwrap();
        let mut c = fresh(&mut r, context);
        if case == 4 {
            hardware::expire();
        }
        if case == 5 {
            c.bindings.capacity.max_records = 1;
        }
        if case == 6 {
            c.bindings.capacity.remaining_writes = 2;
        }
        assert!(c.append(authorised).is_err());
        sys::checked(|s| assert!(s.mutations.is_empty()));
        drop(c);
        clean();
    }
}

#[test]
fn set_commit_uncertainty_poison_controller_and_reopen_never_skips_bad_present_frame() {
    let _serial = SERIAL.lock().unwrap();
    for op in ["set", "commit"] {
        for nth in [1, 2] {
            for effect in [
                sys::WriteEffect::Old,
                sys::WriteEffect::New,
                sys::WriteEffect::Missing,
                sys::WriteEffect::Corrupt,
            ] {
                let mut r = Rig::new(&[1], 0);
                let authorised = r.authorised(1);
                let context = r.open().detach().unwrap();
                let mut c = fresh(&mut r, context);
                sys::inject_fault(Some(fault(op, nth)), effect);
                assert!(c.append(authorised).is_err());
                assert!(c.poisoned);
                let before = snapshot_entries();
                assert!(c.check().is_err());
                assert!(c.detach().is_err());
                assert_eq!(snapshot_entries(), before);
                clean();
                sys::inject_fault(None, sys::WriteEffect::Old);
                let (p, capacity) = r.inputs();
                let reopened = Controller::open(r.root(), p, capacity);
                if op == "set" && matches!(effect, sys::WriteEffect::Corrupt) {
                    assert!(reopened.is_err());
                } else {
                    assert!(reopened.is_ok());
                    drop(reopened);
                }
                clean();
            }
        }
    }
}

#[test]
fn raw_writer_all_boundary_failures_poison_and_never_erase() {
    let _serial = SERIAL.lock().unwrap();
    for op in [
        "open", "length", "read", "set", "commit", "find", "info", "next",
    ] {
        let mut r = Rig::new(&[1], 0);
        let root = r.root();
        let ns = namespace(&root.root);
        let original = snapshot_entries();
        sys::inject_fault(Some(fault(op, 1)), sys::WriteEffect::New);
        let opened = storage::WriteHandle::open(root.nvs, &ns);
        if op == "open" {
            assert!(opened.is_err());
            drop(opened);
        } else {
            let mut h = opened.unwrap();
            let result = if matches!(op, "find" | "info" | "next") {
                h.inventory(&ns).map(|_| ())
            } else {
                h.write(
                    storage::Target::Slot(0),
                    Some(&original[1].1),
                    &original[1].1,
                )
            };
            assert!(result.is_err());
            assert!(h.failed_for_test());
            assert!(h
                .write(storage::Target::Slot(1), None, &original[1].1)
                .is_err());
            drop(h);
        }
        drop(root);
        clean();
    }
}

#[test]
fn signed_candidate_conflict_keeps_pending_until_a_new_fresh_current_read() {
    let _serial = SERIAL.lock().unwrap();
    for http in [200, 409] {
        let mut r = Rig::new(&[1, 2], 1);
        let before = snapshot_entries();
        let context = r.open().detach().unwrap();
        let c = fresh(&mut r, context);
        let detached = c.detach().unwrap();
        let a = prepare(&mut r, detached, true, 6);
        let root = r.root();
        let inv = read_inventory(&root, &a.context.bindings.namespace).unwrap();
        let l = load(&root, &inv).unwrap();
        drop(root);
        let b = receipt(
            &a,
            l.latest.seq() + 1,
            *l.latest.candidate_digest(),
            WitnessStatus::Conflict,
        );
        assert!(a.accept(r.root(), http, &b).is_err());
        assert_eq!(snapshot_entries(), before);
        clean();
        let context = r.open().detach().unwrap();
        let a = prepare(&mut r, context, false, 7);
        let b = receipt(
            &a,
            l.latest.seq() + 1,
            *l.latest.candidate_digest(),
            WitnessStatus::Current,
        );
        let c = a.accept(r.root(), 200, &b).unwrap();
        assert_eq!(load(&c.root, &c.inventory).unwrap().latest.phase(), 0);
        drop(c);
        clean();
    }
}
#[test]
fn record_exact_retry_is_read_only_and_different_bytes_are_permanently_refused() {
    let _serial = SERIAL.lock().unwrap();
    let mut r = Rig::new(&[2, 3], 1);
    let ns = r.ns.clone();
    let root = r.root();
    let inv = read_inventory(&root, &ns).unwrap();
    let frame = blob(&inv, "m01").unwrap();
    let mut h = storage::WriteHandle::open(root.nvs, &ns).unwrap();
    h.write(storage::Target::Record(1), None, frame).unwrap();
    sys::checked(|s| assert!(s.mutations.is_empty()));
    let mut changed = frame.to_vec();
    changed[70] ^= 1;
    assert_eq!(
        h.write(storage::Target::Record(1), None, &changed),
        Err(InventoryHold::Records)
    );
    assert!(h.failed_for_test());
    drop(h);
    drop(root);
    clean();
}
#[test]
fn post_set_readback_fault_and_bad_success_length_keep_written_bytes_and_poison() {
    let _serial = SERIAL.lock().unwrap();
    for op in ["length", "read"] {
        for bad_length in [None, Some(1), Some(499)] {
            let mut r = Rig::new(&[1], 0);
            let ns = r.ns.clone();
            let root = r.root();
            let inv = read_inventory(&root, &ns).unwrap();
            let old = blob(&inv, "snap0").unwrap();
            let mut next = old.to_vec();
            next[70] ^= 1;
            sys::inject_fault(
                Some(sys::Fault {
                    op,
                    nth: 2,
                    err: if bad_length.is_some() {
                        sys::ESP_OK
                    } else {
                        sys::ESP_ERR_INVALID_ARG
                    },
                    null: false,
                    length: bad_length,
                }),
                sys::WriteEffect::Old,
            );
            let mut h = storage::WriteHandle::open(root.nvs, &ns).unwrap();
            assert!(h.write(storage::Target::Slot(0), Some(old), &next).is_err());
            assert!(h.failed_for_test());
            drop(h);
            sys::checked(|s| {
                assert_eq!(s.mutations, vec!["snap0"]);
                assert_eq!(s.passes[0][1].bytes, next);
            });
            drop(root);
            clean();
        }
    }
}
#[test]
fn signed_receipt_transpositions_and_nonce_reuse_have_no_write_authority() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..4 {
        let mut r = Rig::new(&[1], 0);
        let context = r.open().detach().unwrap();
        let a = prepare(&mut r, context, false, 5);
        let (seq, digest) = load_for_attempt(&mut r, &a);
        let b = receipt(&a, seq, digest, WitnessStatus::Current);
        let mut rcp = WitnessReceipt::parse(&b).unwrap();
        match case {
            0 => rcp.subject[0] ^= 1,
            1 => rcp.challenge[0] ^= 1,
            2 => rcp.digest[0] ^= 1,
            _ => rcp.seq += 1,
        }
        rcp.signature = SigningKey::from_bytes(&[9; 32])
            .sign(&rcp.digest_to_sign())
            .to_bytes();
        assert!(a.accept(r.root(), 200, &rcp.encode()).is_err());
        sys::checked(|s| assert!(s.mutations.is_empty()));
        clean();
    }
    let mut r = Rig::new(&[1], 0);
    let manifest = r.authorised(1);
    let context = r.open().detach().unwrap();
    let mut c = fresh(&mut r, context);
    let existing = blob(&c.inventory, "snap0").unwrap()[6];
    hardware::repeat(existing);
    assert_eq!(c.append(manifest).err(), Some(Error::Entropy));
    sys::checked(|s| assert!(s.mutations.is_empty()));
    drop(c);
    clean();
}

#[test]
fn exchange_history_is_bounded_before_entropy_or_signing() {
    let _serial = SERIAL.lock().unwrap();
    let mut r = Rig::new(&[1], 0);
    let mut context = r.open().detach().unwrap();
    for i in 0..MAX_EXCHANGES {
        let attempt = prepare(&mut r, context, false, i as u8 + 1);
        context = attempt.context;
    }
    hardware::fail();
    assert_eq!(
        context.prepare(r.root(), [255; 32], false).err().unwrap(),
        Error::Freshness
    );
    sys::checked(|s| assert!(s.mutations.is_empty()));
    clean();
}

#[test]
fn detached_guard_excludes_second_writer_without_holding_root_custody() {
    let _serial = SERIAL.lock().unwrap();
    let mut r = Rig::new(&[1], 0);
    let context = r.open().detach().unwrap();
    assert!(held_data_key::current().is_some());
    let (p, capacity) = r.inputs();
    assert_eq!(
        Controller::open(r.root(), p, capacity).err().unwrap(),
        Error::Busy
    );
    let a = prepare(&mut r, context, false, 5);
    drop(a);
    let c = r.open();
    drop(c);
    clean();
}

#[test]
fn promotion_uncertainty_never_returns_authority_and_present_corruption_holds() {
    let _serial = SERIAL.lock().unwrap();
    for orphan in [false, true] {
        for op in ["set", "commit"] {
            for nth in 1..=if orphan { 2 } else { 1 } {
                for effect in [
                    sys::WriteEffect::Old,
                    sys::WriteEffect::New,
                    sys::WriteEffect::Missing,
                    sys::WriteEffect::Corrupt,
                ] {
                    let mut r = Rig::new(if orphan { &[1] } else { &[1, 2] }, 1);
                    let context = r.open().detach().unwrap();
                    let a = prepare(&mut r, context, false, 5);
                    let root = r.root();
                    let inventory = read_inventory(&root, &a.context.bindings.namespace).unwrap();
                    let l = load(&root, &inventory).unwrap();
                    let digest = if orphan {
                        state_digest(&l.anchor.pins(), &candidate(&l, 1, 1).unwrap())
                    } else {
                        *l.latest.candidate_digest()
                    };
                    let seq = l.latest.seq() + 1;
                    drop(root);
                    let b = receipt(&a, seq, digest, WitnessStatus::Current);
                    sys::inject_fault(Some(fault(op, nth)), effect);
                    assert!(a.accept(r.root(), 200, &b).is_err());
                    clean();
                    sys::inject_fault(None, sys::WriteEffect::Old);
                    let (p, capacity) = r.inputs();
                    let reopened = Controller::open(r.root(), p, capacity);
                    if op == "set" && matches!(effect, sys::WriteEffect::Corrupt) {
                        assert!(reopened.is_err());
                    } else {
                        assert!(reopened.is_ok());
                        let c = reopened.unwrap();
                        assert!(c.grant.is_none());
                        drop(c);
                    }
                    clean();
                }
            }
        }
    }
}
