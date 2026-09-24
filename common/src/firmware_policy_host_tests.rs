//! Host-only fault-injection harness for the *actual* firmware `policy.rs`.
//!
//! The crate root (host unit-test build) provides:
//!   `extern crate self as esp_idf_svc;`
//!   `pub use firmware_policy_host_tests::nvs;`
//!   `#[path = "../../firmware/src/policy.rs"] pub mod engine;`
//!
//! Thus the firmware module's `use esp_idf_svc::nvs::{EspNvs, NvsDefault};`
//! resolves to the mock below, and its `use heartwood_common::...` resolves to
//! the real library. Only NVS I/O is faked; authority logic is the real code.
//!
//! No real credentials or secrets: every key here is a byte-repeat, and the
//! legacy fixture uses a canonical fabricated 64-hex secret.

#![cfg(all(test, feature = "nip46", feature = "nip44"))]

use std::cell::RefCell;
use std::collections::BTreeMap;

use heartwood_common::policy::CONNECT_SAFE_METHODS;

// ---------------------------------------------------------------------------
// Mock NVS
// ---------------------------------------------------------------------------

/// Fault-injection mock NVS backend, keyed by `String -> Vec<u8>`.
///
/// Mutable state sits behind `RefCell` so read paths taking `&self` can still
/// consume a scripted fault queue and record access, matching the real
/// `EspNvs` read-only API surface as used by `policy.rs`.
#[derive(Default)]
pub struct MockNvsState {
    store: BTreeMap<String, Vec<u8>>,
    /// Ordered scripted faults. Each entry fires when its (optional) key match
    /// and op match hold, decrementing `remaining_calls` until exhausted.
    faults: Vec<Fault>,
    /// Keys touched since the last `take_log`.
    log: Vec<(String, NvsOp)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvsOp {
    BlobLen,
    GetBlob,
    SetBlob,
    Remove,
}

#[derive(Debug, Clone)]
pub struct Fault {
    pub op: NvsOp,
    /// `None` matches any key.
    pub key: Option<String>,
    /// Number of matching calls still to poison.
    pub remaining_calls: usize,
    pub kind: FaultKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// `blob_len` reports an oversized/absurd length.
    OversizeLen(usize),
    /// `blob_len` (or `get_blob`) returns `Err`.
    ReadError,
    /// `set_blob` fails *and* the write is not committed.
    WriteFailBeforeCommit,
    /// `set_blob` returns an error but the bytes *are* committed.
    WriteCommitsWithError,
    /// The next `get_blob` returns corrupt (flipped) bytes once.
    CorruptReadBackOnce,
    /// `remove` returns `Err`, store unchanged.
    RemoveFail,
}

#[derive(Default)]
pub struct NvsDefault {
    inner: RefCell<MockNvsState>,
}

impl NvsDefault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate a key with raw bytes (no fault consumed).
    pub fn seed(&self, key: &str, bytes: &[u8]) {
        self.inner
            .borrow_mut()
            .store
            .insert(key.to_string(), bytes.to_vec());
    }

    /// Queue a fault. `usize::MAX` fires indefinitely; zero is inactive.
    pub fn push_fault(&self, fault: Fault) {
        self.inner.borrow_mut().faults.push(fault);
    }

    /// Convenience: one-shot fault on an exact key/op.
    pub fn fail_once(&self, op: NvsOp, key: &str, kind: FaultKind) {
        self.push_fault(Fault {
            op,
            key: Some(key.to_string()),
            remaining_calls: 1,
            kind,
        });
    }

    /// Drain the ordered `(key, op)` access log (no values).
    pub fn take_log(&self) -> Vec<(String, NvsOp)> {
        std::mem::take(&mut self.inner.borrow_mut().log)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.inner.borrow().store.contains_key(key)
    }
}

impl MockNvsState {
    fn record(&mut self, key: &str, op: NvsOp) {
        self.log.push((key.to_string(), op));
    }

    /// Pop a matching fault, decrementing its remaining count; return the kind.
    fn take_fault(&mut self, key: &str, op: NvsOp) -> Option<FaultKind> {
        let idx = self.faults.iter().position(|f| {
            f.op == op && (f.key.as_deref().map(|k| k == key).unwrap_or(true)) && f.remaining_calls != 0
        })?;
        let kind = self.faults[idx].kind;
        if self.faults[idx].remaining_calls == usize::MAX {
            // forever
            return Some(kind);
        }
        self.faults[idx].remaining_calls -= 1;
        if self.faults[idx].remaining_calls == 0 {
            self.faults.remove(idx);
        } else {
            // leave queued for further calls
        }
        Some(kind)
    }
}

/// The generic `EspNvs<T>` the firmware imports. `T` is `NvsDefault` at every
/// use site; the type parameter exists so the imported symbol matches exactly.
pub struct EspNvs<T = NvsDefault> {
    pub backend: T,
}

impl EspNvs<NvsDefault> {
    pub fn new() -> Self {
        Self { backend: NvsDefault::new() }
    }

    pub fn blob_len(&self, key: &str) -> Result<Option<usize>, &'static str> {
        let mut state = self.backend.inner.borrow_mut();
        state.record(key, NvsOp::BlobLen);
        if let Some(kind) = state.take_fault(key, NvsOp::BlobLen) {
            return match kind {
                FaultKind::OversizeLen(n) => Ok(Some(n)),
                FaultKind::ReadError => Err("injected blob_len error"),
                other => panic!("blob_len fault kind not supported: {other:?}"),
            };
        }
        Ok(state.store.get(key).map(|v| v.len()))
    }

    pub fn get_blob<'a>(
        &self,
        key: &str,
        out: &'a mut [u8],
    ) -> Result<Option<&'a [u8]>, &'static str> {
        let mut state = self.backend.inner.borrow_mut();
        state.record(key, NvsOp::GetBlob);
        if let Some(kind) = state.take_fault(key, NvsOp::GetBlob) {
            match kind {
                FaultKind::ReadError => return Err("injected get_blob error"),
                FaultKind::CorruptReadBackOnce => {
                    if let Some(bytes) = state.store.get(key).cloned() {
                        let n = bytes.len().min(out.len());
                        out[..n].copy_from_slice(&bytes[..n]);
                        if n > 0 {
                            out[0] ^= 0xFF; // flip bits: mismatch
                        }
                        return Ok(Some(&out[..n]));
                    }
                    return Ok(None);
                }
                other => panic!("get_blob fault kind not supported: {other:?}"),
            }
        }
        match state.store.get(key).cloned() {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() > out.len() {
                    // The real API would not fit; report as error.
                    return Err("read buffer too small");
                }
                let n = bytes.len();
                out[..n].copy_from_slice(&bytes);
                Ok(Some(&out[..n]))
            }
        }
    }

    pub fn set_blob(&mut self, key: &str, data: &[u8]) -> Result<(), &'static str> {
        let mut state = self.backend.inner.borrow_mut();
        state.record(key, NvsOp::SetBlob);
        if let Some(kind) = state.take_fault(key, NvsOp::SetBlob) {
            match kind {
                FaultKind::WriteFailBeforeCommit => return Err("injected write failure"),
                FaultKind::WriteCommitsWithError => {
                    state.store.insert(key.to_string(), data.to_vec());
                    return Err("injected write error (committed)");
                }
                other => panic!("set_blob fault kind not supported: {other:?}"),
            }
        }
        state.store.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> Result<bool, &'static str> {
        let mut state = self.backend.inner.borrow_mut();
        state.record(key, NvsOp::Remove);
        if let Some(kind) = state.take_fault(key, NvsOp::Remove) {
            match kind {
                FaultKind::RemoveFail => return Err("injected remove failure"),
                other => panic!("remove fault kind not supported: {other:?}"),
            }
        }
        Ok(state.store.remove(key).is_some())
    }
}

// ---------------------------------------------------------------------------
// Real firmware engine + helpers
// ---------------------------------------------------------------------------

pub mod nvs { pub use super::{EspNvs, NvsDefault}; }

#[path = "../../firmware/src/policy.rs"]
pub mod engine;
use engine::PolicyEngine;

// ---------------------------------------------------------------------------
// Fixtures / helpers
// ---------------------------------------------------------------------------

/// 64-hex fabricated secret (byte-repeat canonical form).
fn secret_hex(byte: u8) -> String {
    heartwood_common::hex::hex_encode(&[byte; 32])
}

/// 64-hex fabricated client pubkey (byte-repeat canonical form).
fn pubkey_hex(byte: u8) -> String {
    heartwood_common::hex::hex_encode(&[byte; 32])
}

fn client_id(s: &str) -> String {
    s.to_string()
}

const CONNSLOTS_0: &str = "connslots_0";
const MASTER_0_CONN: &str = "master_0_conn";
const POLICY_0: &str = "policy_0";

/// Build a *valid* legacy-format `Vec<ConnectSlot>` JSON for slot 0 with a
/// 64-hex secret and no bound identity, suitable for the migration test.
fn legacy_slot_json(secret_byte: u8) -> String {
    let secret = secret_hex(secret_byte);
    let methods = CONNECT_SAFE_METHODS
        .iter()
        .map(|m| format!("\"{m}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "[{{\
          \"slot_index\":0,\
          \"label\":\"default\",\
          \"secret\":\"{secret}\",\
          \"current_pubkey\":null,\
          \"allowed_methods\":[{methods}],\
          \"allowed_kinds\":[],\
          \"auto_approve\":true,\
          \"signing_approved\":false,\
          \"strict_permissions\":false,\
          \"authorized_pubkeys\":[],\
          \"escalate\":false,\
          \"petition_on_deny\":false,\
          \"audit_child_wrap\":false,\
          \"guardian_notice_wrap\":false,\
          \"bound_identity\":null,\
          \"approved_identities\":\"\",\
          \"was_bound\":false\
        }}]"
    )
}

/// Raw legacy secret bytes (32 bytes, byte-repeat).
fn legacy_secret_bytes(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn healthy_roundtrip_retains_grants_for_a_but_not_c() {
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();

    let slot = engine.create_slot(0, "shared".into(), secret_hex(0xA1)).expect("slot created");
    let client_a = pubkey_hex(0x11);
    let client_b = pubkey_hex(0x22);
    assert!(engine.assign_pubkey_to_slot(0, slot, client_a.clone()));
    assert!(engine.assign_pubkey_to_slot(0, slot, client_b.clone()));

    let ident_a = [0xAAu8; 32];
    let ident_b = [0xBBu8; 32];
    assert!(engine.record_identity(0, Ok(&client_a), &ident_a), "record A persona");
    assert!(engine.record_identity(0, Ok(&client_b), &ident_b), "record B persona");

    assert!(engine.persist_slots(&mut nvs, 0));
    let mut engine2 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(engine2.storage_ready(0));

    let slot_ref = engine2.list_slots(0).into_iter().find(|s| s.slot_index == slot).expect("slot survived");
    use heartwood_common::policy::client_identity_approved;
    assert!(client_identity_approved(&slot_ref, Some(&client_a), &ident_a));
    assert!(client_identity_approved(&slot_ref, Some(&client_b), &ident_b));

    let client_c = pubkey_hex(0x33);
    assert!(engine2.assign_pubkey_to_slot(0, slot, client_c.clone()));
    let ident_c = [0xCCu8; 32];
    let shared = &engine2.list_slots(0)[0];
    for id in [&ident_a, &ident_b, &ident_c] {
        assert!(!client_identity_approved(shared, Some(&client_c), id));
    }
    assert!(client_identity_approved(shared, Some(&client_a), &ident_a));
    assert!(client_identity_approved(shared, Some(&client_b), &ident_b));
    assert!(engine2.record_identity(0, Ok(&client_c), &ident_c), "record C persona");
    assert!(engine2.persist_slots(&mut nvs, 0));

    let engine3 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    let slot_ref = engine3.list_slots(0).into_iter().find(|s| s.slot_index == slot).expect("slot survived reboot");
    assert!(client_identity_approved(&slot_ref, Some(&client_a), &ident_a), "A grant persists");
    assert!(client_identity_approved(&slot_ref, Some(&client_b), &ident_b), "B grant persists");
    assert!(client_identity_approved(&slot_ref, Some(&client_c), &ident_c), "C grant persists");
    assert!(!client_identity_approved(&slot_ref, Some(&client_a), &ident_c), "A not approved for C persona");
    assert!(!client_identity_approved(&slot_ref, Some(&client_b), &ident_c), "B not approved for C persona");
}

#[test]
fn current_switch_a_to_b_preserves_both_grants() {
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();

    let slot = engine.create_slot(0, "shared".into(), secret_hex(0xA1)).expect("slot created");
    let client_a = pubkey_hex(0x11);
    let client_b = pubkey_hex(0x22);
    assert!(engine.assign_pubkey_to_slot(0, slot, client_a.clone()));
    assert!(engine.assign_pubkey_to_slot(0, slot, client_b.clone()));

    let ident_a = [0xAAu8; 32];
    let ident_b = [0xBBu8; 32];
    assert!(engine.record_identity(0, Ok(&client_a), &ident_a));
    assert!(engine.record_identity(0, Ok(&client_b), &ident_b));

    assert!(engine.persist_slots(&mut nvs, 0));
    let mut engine2 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(engine2.storage_ready(0));

    let before = engine2.list_slots(0)[0].client_grants.clone();
    for client in [&client_a, &client_b, &client_a] {
        assert!(engine2.assign_pubkey_to_slot(0, slot, client.clone()));
        assert_eq!(engine2.list_slots(0)[0].current_pubkey.as_ref(), Some(client));
        assert_eq!(engine2.list_slots(0)[0].client_grants, before);
    }
    assert!(engine2.persist_slots(&mut nvs, 0));

    let engine3 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(engine3.storage_ready(0));
    let slot_ref = engine3.list_slots(0).into_iter().find(|s| s.slot_index == slot).expect("slot survived");
    use heartwood_common::policy::client_identity_approved;
    assert!(client_identity_approved(&slot_ref, Some(&client_a), &ident_a), "A grant preserved across switch");
    assert!(client_identity_approved(&slot_ref, Some(&client_b), &ident_b), "B grant preserved across switch");
    assert!(!client_identity_approved(&slot_ref, Some(&client_a), &ident_b), "A not approved for B persona");
    assert!(!client_identity_approved(&slot_ref, Some(&client_b), &ident_a), "B not approved for A persona");
}

#[test]
fn full_eight_clients_rejects_ninth_without_eviction() {
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "many".into(), secret_hex(0x99)).unwrap();

    // Pair 8 distinct clients; 9th must be rejected (no eviction).
    for i in 0u8..8 {
        engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x40 + i));
    }
    assert!(engine.persist_slots(&mut nvs, 0));

    let mut engine2 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    let authorized_count = engine2
        .list_slots(0)
        .iter()
        .find(|s| s.slot_index == slot)
        .map(|s| s.authorized_pubkeys.len())
        .unwrap_or(0);
    assert_eq!(authorized_count, 8, "exactly 8 authorized clients");

    // 9th client: must not evict; either rejected or capped.
    let ninth = pubkey_hex(0xFF);
    engine2.assign_pubkey_to_slot(0, slot, ninth.clone());
    let after = engine2
        .list_slots(0)
        .iter()
        .find(|s| s.slot_index == slot)
        .map(|s| s.authorized_pubkeys.clone())
        .unwrap_or_default();
    assert!(
        after.len() <= 8,
        "capacity must not exceed MAX_AUTHORIZED_PUBKEYS; got {}",
        after.len()
    );
    // No eviction: the first client granted must still be authorized.
    assert!(
        after.contains(&pubkey_hex(0x40)),
        "the earliest authorized client must not be silently evicted"
    );
}

#[test]
fn malformed_present_table_does_not_fall_back_to_legacy_master_key() {
    // A present `connslots_0` that is malformed must *not* fall back to the
    // legacy `master_0_conn` key: the master is quarantined, list_slots is empty,
    // and the legacy secret was never read.
    let mut nvs = EspNvs::new();
    nvs.backend.seed(CONNSLOTS_0, b"this is not json");
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(0x77));

    let engine = PolicyEngine::load_from_nvs(&mut nvs, 1);

    assert!(
        !engine.storage_ready(0),
        "malformed present table must quarantine master 0"
    );
    assert!(
        engine.list_slots(0).is_empty(),
        "quarantined master exposes no slots"
    );

    let log = nvs.backend.take_log();
    let legacy_reads = log
        .iter()
        .filter(|(k, op)| k == MASTER_0_CONN && *op == NvsOp::GetBlob)
        .count();
    assert_eq!(
        legacy_reads, 0,
        "no fallback read of legacy {MASTER_0_CONN} when present table is malformed"
    );
}

#[test]
fn oversized_reported_length_quarantines_and_skips_legacy_fallback() {
    // `blob_len` reports an oversize length: load must quarantine and must not
    // attempt the legacy read.
    let mut nvs = EspNvs::new();
    let engine = PolicyEngine::new();
    let _ = engine; // engine not used; load is what matters

    nvs.backend.push_fault(Fault {
        op: NvsOp::BlobLen,
        key: Some(CONNSLOTS_0.to_string()),
        remaining_calls: 1,
        kind: FaultKind::OversizeLen(usize::MAX),
    });
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(0x88));

    let loaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(
        !loaded.storage_ready(0),
        "oversize blob_len must quarantine master 0"
    );
    assert!(loaded.list_slots(0).is_empty());

    let log = nvs.backend.take_log();
    let legacy_reads = log
        .iter()
        .filter(|(k, op)| k == MASTER_0_CONN && *op == NvsOp::GetBlob)
        .count();
    assert_eq!(
        legacy_reads, 0,
        "oversize length is not proof of absence — no legacy read"
    );
}

#[test]
fn blob_len_error_quarantines_master() {
    // `blob_len` returns Err: quarantine, no legacy fallback.
    let mut nvs = EspNvs::new();
    nvs.backend.push_fault(Fault {
        op: NvsOp::BlobLen,
        key: Some(CONNSLOTS_0.to_string()),
        remaining_calls: 1,
        kind: FaultKind::ReadError,
    });
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(0x99));

    let loaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(
        !loaded.storage_ready(0),
        "blob_len error must quarantine master 0"
    );
    assert!(loaded.list_slots(0).is_empty());
}

#[test]
fn missing_new_table_allows_genuine_legacy_migration() {
    // Genuine absent new key with legacy key present: migrate. The synthesized
    // slot has a 64-hex secret and empty consent grants.
    let mut nvs = EspNvs::new();
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(0x5A));

    let mut engine = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(
        engine.storage_ready(0),
        "genuine legacy migration must not quarantine"
    );
    let slots = engine.list_slots(0);
    assert_eq!(slots.len(), 1, "exactly one migrated slot");
    let migrated = &slots[0];
    assert_eq!(migrated.slot_index, 0);
    assert_eq!(migrated.secret.len(), 64, "migrated secret must be 64 hex chars");
    assert_eq!(
        migrated.secret,
        secret_hex(0x5A),
        "migrated secret must be the hex encoding of the legacy raw bytes"
    );
    // Empty consent: no bound identity and no approved identities yet.
    assert!(
        migrated.bound_identity.is_none(),
        "freshly migrated slot must not claim a bound identity"
    );
    assert!(
        migrated.approved_identities.is_empty(),
        "freshly migrated slot must start with empty approved identities"
    );

    // Persisted form must be durable.
    assert!(engine.persist_slots(&mut nvs, 0));
    assert!(nvs.backend.contains(CONNSLOTS_0));
    // Legacy secret key is retained (Task 5 cleanup), old policy key removed.
    assert!(!nvs.backend.contains(POLICY_0), "old policy key removed");
}

#[test]
fn initial_migration_write_failure_quarantines_master() {
    // Migration discovered, but the durable write to the new key fails:
    // the master is quarantined, subsequent persist refuses, and the old
    // master blob is not removed.
    let mut nvs = EspNvs::new();
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(0x5B));
    nvs.backend.seed(POLICY_0, b"stale-policy-blob");
    nvs.backend.push_fault(Fault {
        op: NvsOp::SetBlob,
        key: Some(CONNSLOTS_0.to_string()),
        remaining_calls: 1,
        kind: FaultKind::WriteFailBeforeCommit,
    });

    let mut engine = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(
        !engine.storage_ready(0),
        "failed migration persist must quarantine master 0"
    );
    assert!(!engine.persist_slots(&mut nvs, 0), "persist must refuse");
    assert!(
        nvs.backend.contains(MASTER_0_CONN),
        "old master blob must not be removed after failed migration"
    );
    assert!(
        nvs.backend.contains(POLICY_0),
        "old policy blob must not be removed after failed migration"
    );
}

#[test]
fn readback_mismatch_returns_false_and_leaves_dirty() {
    // set_blob succeeds, but the read-back bytes differ: persist_slots must
    // return false (readback is the authority boundary), even though the write
    // technically "succeeded".
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    engine.create_slot(0, "x".into(), secret_hex(0x01)).unwrap();

    nvs.backend.fail_once(
        NvsOp::GetBlob,
        CONNSLOTS_0,
        FaultKind::CorruptReadBackOnce,
    );

    assert!(
        !engine.persist_slots(&mut nvs, 0),
        "readback mismatch must not be reported durable"
    );
}

#[test]
fn committed_but_write_error_with_matching_readback_is_durable() {
    // set_blob returns Err but the bytes *are* committed, and the readback
    // matches: the current contract treats this as durable.
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    engine.create_slot(0, "y".into(), secret_hex(0x02)).unwrap();

    nvs.backend.fail_once(
        NvsOp::SetBlob,
        CONNSLOTS_0,
        FaultKind::WriteCommitsWithError,
    );

    assert!(
        engine.persist_slots(&mut nvs, 0),
        "committed-with-error plus matching readback counts durable"
    );
    // Reload must see the slot.
    let engine2 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert_eq!(engine2.list_slots(0).len(), 1);
    assert!(engine2.storage_ready(0));
}

#[test]
fn durable_rollback_restores_prior_authority_after_failed_write() {
    // After a failed persist, `restore_slot_state_durably` must restore the
    // prior authority (RAM) and make that compensation durable.
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();

    let slot = engine.create_slot(0, "z".into(), secret_hex(0x03)).unwrap();
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x55));
    assert!(engine.persist_slots(&mut nvs, 0));

    let snapshot = engine.snapshot_slot_state(0);

    // Mutate: add another client, then fail the persist.
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x66));
    nvs.backend.fail_once(
        NvsOp::SetBlob,
        CONNSLOTS_0,
        FaultKind::WriteFailBeforeCommit,
    );
    assert!(!engine.persist_slots(&mut nvs, 0));

    // Rollback restores prior authority durably.
    assert!(
        engine.restore_slot_state_durably(&mut nvs, snapshot),
        "rollback must succeed when NVS allows the compensation write"
    );

    // Prior grant state is back: only 0x55 is authorized again.
    let after = engine
        .list_slots(0)
        .iter()
        .find(|s| s.slot_index == slot)
        .map(|s| s.authorized_pubkeys.clone())
        .unwrap_or_default();
    assert!(
        after.contains(&pubkey_hex(0x55)),
        "prior authority 0x55 must be restored"
    );
    assert!(
        !after.contains(&pubkey_hex(0x66)),
        "new authority 0x66 must not survive rollback"
    );

    // And a fresh reload sees the restored state.
    let engine2 = PolicyEngine::load_from_nvs(&mut nvs, 1);
    let restored = engine2
        .list_slots(0)
        .iter()
        .find(|s| s.slot_index == slot)
        .map(|s| s.authorized_pubkeys.clone())
        .unwrap_or_default();
    assert!(restored.contains(&pubkey_hex(0x55)));
    assert!(!restored.contains(&pubkey_hex(0x66)));
}

#[test]
fn full_storage_drops_the_avatar_cache_before_refusing_pairings() {
    // A pairing write that fails is retried once after the cached avatars go:
    // they can be sent again, the pairings cannot. Names stay.
    let mut nvs = EspNvs::new();
    nvs.backend.seed("imav0", &[1, 1, 0, 0]);
    nvs.backend.seed("imav2", &[1, 1, 0, 0]);
    nvs.backend.seed("iman0", b"TheCryptoDonkey");
    let mut engine = PolicyEngine::new();
    engine.create_slot(0, "app".into(), secret_hex(0x06)).unwrap();
    nvs.backend.fail_once(NvsOp::SetBlob, CONNSLOTS_0, FaultKind::WriteFailBeforeCommit);
    assert!(engine.persist_slots(&mut nvs, 0), "the retry after eviction lands");
    assert!(!nvs.backend.contains("imav0") && !nvs.backend.contains("imav2"));
    assert!(nvs.backend.contains("iman0"), "the name is not a cache");

    // Nothing left to drop: the failure is reported, not retried.
    engine.create_slot(0, "second".into(), secret_hex(0x07)).unwrap();
    nvs.backend.fail_once(NvsOp::SetBlob, CONNSLOTS_0, FaultKind::WriteFailBeforeCommit);
    assert!(!engine.persist_slots(&mut nvs, 0));
}

#[test]
fn rollback_failure_quarantines_master_and_denies_lookup() {
    // Compensation write also fails: master is quarantined, list_slots empty,
    // and find_slot_by_pubkey denies lookups.
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "q".into(), secret_hex(0x04)).unwrap();
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x77));
    assert!(engine.persist_slots(&mut nvs, 0));
    let snapshot = engine.snapshot_slot_state(0);

    // The new value lands but cannot be verified. Compensation must overwrite
    // those bytes; a failed overwrite cannot pass by reading the old value.
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x88));
    nvs.backend.fail_once(NvsOp::GetBlob, CONNSLOTS_0, FaultKind::ReadError);
    assert!(!engine.persist_slots(&mut nvs, 0));
    nvs.backend.fail_once(NvsOp::SetBlob, CONNSLOTS_0, FaultKind::WriteFailBeforeCommit);

    assert!(
        !engine.restore_slot_state_durably(&mut nvs, snapshot),
        "rollback must fail when compensation write fails"
    );
    assert!(
        !engine.storage_ready(0),
        "failed rollback must quarantine master 0"
    );
    assert!(
        engine.find_slot_by_pubkey(0, &pubkey_hex(0x77)).is_none(),
        "quarantined master denies pubkey lookup"
    );
}

#[test]
fn signing_upgrade_invalidates_pending_approval_only_when_authority_changes() {
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "epoch".into(), secret_hex(0x05)).unwrap();
    let before = engine.approval_epoch();
    assert!(!engine.upgrade_to_signing(0, 255));
    assert!(engine.approval_is_current(before));

    assert!(engine.upgrade_to_signing(0, slot));
    assert!(!engine.approval_is_current(before));
    let granted = engine.approval_epoch();
    assert!(engine.upgrade_to_signing(0, slot));
    assert!(engine.approval_is_current(granted));

    engine.slots_mut(0)[0].strict_permissions = true;
    let strict = engine.approval_epoch();
    assert!(!engine.upgrade_to_signing(0, slot));
    assert!(engine.approval_is_current(strict));
}

#[test]
fn a_retained_client_reconnecting_keeps_pending_approvals() {
    // Two apps sharing one pairing take turns to connect. The rebind moves
    // only which key is current, so the other app's waiting card must stand.
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "default".into(), secret_hex(0x05)).unwrap();
    assert!(engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x0a)));
    assert!(engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x0b)));

    let pending = engine.approval_epoch();
    assert!(engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x0a)));
    assert!(engine.approval_is_current(pending), "a known key's rebind withdrew the card");
    engine.with_slots_keeping_approvals(0, |slots| slots[0].label = "Signet".into());
    assert!(engine.approval_is_current(pending), "naming the pairing withdrew the card");

    // A key the pairing has never held is still a change of authority.
    assert!(engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0x0c)));
    assert!(!engine.approval_is_current(pending));
}

#[test]
fn approval_epoch_invalidated_by_revoke_and_readd() {
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "e".into(), secret_hex(0x05)).unwrap();
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0xAA));

    let stamp_before = engine.approval_epoch();
    assert!(
        engine.approval_is_current(stamp_before),
        "engine's own epoch must be current"
    );

    // Revoke invalidates the stamp.
    assert!(engine.revoke_slot(0, slot));
    let after_revoke = engine.approval_epoch();
    assert!(
        !engine.approval_is_current(stamp_before),
        "revoke must invalidate prior approval stamp"
    );

    // Re-add a client: still a *different* stamp than the pre-revoke one.
    let slot2 = engine.create_slot(0, "e2".into(), secret_hex(0x06)).unwrap();
    engine.assign_pubkey_to_slot(0, slot2, pubkey_hex(0xBB));
    let after_readd = engine.approval_epoch();
    assert!(
        !engine.approval_is_current(stamp_before),
        "readd must not restore the pre-revoke stamp"
    );
    assert!(
        engine.approval_is_current(after_readd),
        "current engine epoch must be current"
    );
    assert_ne!(
        after_revoke, after_readd,
        "each authority move yields a fresh stamp"
    );
}

#[test]
fn rollback_does_not_restore_approval_epoch() {
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "r".into(), secret_hex(0x07)).unwrap();
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0xCC));
    assert!(engine.persist_slots(&mut nvs, 0));

    let snapshot = engine.snapshot_slot_state(0);
    let stamp_before = engine.approval_epoch();
    assert!(engine.approval_is_current(stamp_before));

    // Mutate + fail write + roll back.
    engine.assign_pubkey_to_slot(0, slot, pubkey_hex(0xDD));
    nvs.backend.fail_once(
        NvsOp::SetBlob,
        CONNSLOTS_0,
        FaultKind::WriteFailBeforeCommit,
    );
    assert!(!engine.persist_slots(&mut nvs, 0));
    assert!(engine.restore_slot_state_durably(&mut nvs, snapshot));

    assert!(
        !engine.approval_is_current(stamp_before),
        "rollback must not restore a prior approval stamp (revoked requests stay revoked)"
    );
}

#[test]
fn distinct_engines_have_distinct_epochs() {
    let e1 = PolicyEngine::new();
    let e2 = PolicyEngine::new();
    let s1 = e1.approval_epoch();
    let s2 = e2.approval_epoch();
    assert!(s1.is_some() && s2.is_some());
    assert_ne!(
        s1, s2,
        "distinct PolicyEngine instances must yield distinct approval epochs"
    );
    assert!(
        !e1.approval_is_current(s2),
        "an engine must not accept another engine's stamp"
    );
    assert!(
        !e2.approval_is_current(s1),
        "an engine must not accept another engine's stamp"
    );
}

#[test]
fn remove_failure_keeps_old_blob_and_reports_not_durable() {
    // When the slot table is empty, persist_slots must remove the key; if the
    // removal fails the operation must not be reported durable, and the old
    // bytes must remain.
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let empty_snapshot = engine.snapshot_slot_state(0);
    engine.create_slot(0, "m".into(), secret_hex(0x08)).unwrap();
    assert!(engine.persist_slots(&mut nvs, 0));
    assert!(nvs.backend.contains(CONNSLOTS_0));

    // Restore the state from before this master had any table. Revoking the
    // last slot alone writes [] and intentionally suppresses legacy fallback.
    nvs.backend.fail_once(NvsOp::Remove, CONNSLOTS_0, FaultKind::RemoveFail);

    assert!(
        !engine.restore_slot_state_durably(&mut nvs, empty_snapshot),
        "remove failure must not be reported durable"
    );
    assert!(
        nvs.backend.contains(CONNSLOTS_0),
        "old blob must remain when remove fails"
    );
}

// Compile-time assertions: the mock exposes exactly the API shape used by
// `firmware/src/policy.rs`.
#[allow(dead_code)]
fn _api_shape_check(engine: &mut EspNvs<NvsDefault>) {
    let _: Result<Option<usize>, &'static str> = engine.blob_len("k");
    let mut buf = [0u8; 8];
    let _: Result<Option<&[u8]>, &'static str> = engine.get_blob("k", &mut buf);
    let _: Result<(), &'static str> = engine.set_blob("k", b"v");
    let _: Result<bool, &'static str> = engine.remove("k");
}

#[test]
fn shared_client_revocation_invalidates_pending_but_keeps_other_clients() {
    use crate::policy::{CardKind, Gate};
    use crate::nip46::Nip46Method;
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "shared".into(), secret_hex(1)).unwrap();
    engine.set_exact_slot_policy(0, slot, vec!["sign_event".into()], vec![30078], true).unwrap();
    let clients: Vec<String> = [1, 2, 3].iter().map(|b| pubkey_hex(*b)).collect();
    let identity = [9; 32];
    for client in &clients {
        assert!(engine.assign_pubkey_to_slot(0, slot, client.clone()));
        assert!(engine.record_identity(0, Ok(client), &identity));
    }
    assert!(engine.persist_slots(&mut nvs, 0));
    let pending_stamp = engine.approval_epoch();
    let gate = |engine: &PolicyEngine, client: &str| engine.gate(0, client, true,
        &Nip46Method::SignEvent, "sign_event", Some(30078),
        engine.check(0, client, &Nip46Method::SignEvent, Some(30078)), false, false, Some(&identity));
    for client in &clients { assert_eq!(gate(&engine, client), Gate::Allow); }
    assert!(engine.revoke_identity(0, slot, &pubkey_hex(9), Some(&clients[2])).unwrap().unwrap().1);
    assert!(!engine.approval_is_current(pending_stamp));
    assert!(engine.persist_slots(&mut nvs, 0));
    let mut engine = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert_eq!(gate(&engine, &clients[0]), Gate::Allow);
    assert_eq!(gate(&engine, &clients[1]), Gate::Allow);
    assert_eq!(gate(&engine, &clients[2]), Gate::Card(CardKind::AllowAs { record: true }));
    assert_eq!(gate(&engine, &pubkey_hex(4)), Gate::Deny);
    assert!(engine.clear_identities(0, slot, None).unwrap());
    for client in &clients {
        assert_eq!(gate(&engine, client), Gate::Card(CardKind::AllowAs { record: true }));
    }
}

#[test]
fn full_consent_capacity_offers_once_without_evicting_existing_grants() {
    use crate::policy::{CardKind, Gate};
    use crate::nip46::Nip46Method;
    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "capacity".into(), secret_hex(1)).unwrap();
    let client = pubkey_hex(1);
    assert!(engine.assign_pubkey_to_slot(0, slot, client.clone()));
    for i in 1..=16 { assert!(engine.record_identity(0, Ok(&client), &[i; 32])); }
    let before = engine.list_slots(0)[0].client_grants.clone();
    assert!(!engine.record_identity(0, Ok(&client), &[17; 32]));
    assert_eq!(engine.list_slots(0)[0].client_grants, before);
    assert_eq!(engine.gate(0, &client, true, &Nip46Method::SignEvent, "sign_event",
        Some(30078), crate::policy::ApprovalTier::AutoApprove, false, false, Some(&[17; 32])),
        Gate::Card(CardKind::AllowAs { record: false }));
    assert!(crate::policy::client_identity_approved(&engine.list_slots(0)[0], Some(&client), &[1; 32]));

    assert!(engine.persist_slots(&mut nvs, 0));
    let reloaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
    let retained = &reloaded.list_slots(0)[0];
    assert!(!crate::policy::client_identity_approved(retained, Some(&client), &[17; 32]));
    assert!(crate::policy::client_identity_approved(retained, Some(&client), &[1; 32]));
    assert_eq!(reloaded.gate(0, &client, true, &Nip46Method::SignEvent, "sign_event",
        Some(30078), crate::policy::ApprovalTier::AutoApprove, false, false, Some(&[17; 32])),
        Gate::Card(CardKind::AllowAs { record: false }));
}

#[test]
fn full_client_capacity_rejects_ninth_and_retains_existing_consent() {
    use heartwood_common::policy::client_identity_approved;

    let mut nvs = EspNvs::new();
    let mut engine = PolicyEngine::new();
    let slot = engine.create_slot(0, "full".into(), secret_hex(2)).unwrap();
    let identity = [0x42; 32];
    let clients: Vec<String> = (1..=8).map(pubkey_hex).collect();
    for client in &clients {
        assert!(engine.assign_pubkey_to_slot(0, slot, client.clone()));
        assert!(engine.record_identity(0, Ok(client), &identity));
    }
    assert!(engine.persist_slots(&mut nvs, 0));
    let before = engine.list_slots(0)[0].client_grants.clone();
    let ninth = pubkey_hex(9);
    assert!(!engine.assign_pubkey_to_slot(0, slot, ninth.clone()));
    assert_eq!(engine.list_slots(0)[0].client_grants, before);

    let reloaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
    let retained = &reloaded.list_slots(0)[0];
    for client in &clients {
        assert!(client_identity_approved(retained, Some(client), &identity));
    }
    assert!(!client_identity_approved(retained, Some(&ninth), &identity));
}

#[test]
fn physically_approved_backup_recovery_requires_verified_empty_baseline() {
    let mut nvs = EspNvs::new();
    nvs.backend.seed(CONNSLOTS_0, b"corrupt");
    nvs.backend.seed(MASTER_0_CONN, &legacy_secret_bytes(9));
    let mut engine = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(!engine.storage_ready(0));
    nvs.backend.fail_once(NvsOp::SetBlob, CONNSLOTS_0, FaultKind::WriteFailBeforeCommit);
    assert!(!engine.recover_pairings_for_backup_restore(&mut nvs, 0));
    assert!(!engine.storage_ready(0));
    nvs.backend.fail_once(NvsOp::GetBlob, CONNSLOTS_0, FaultKind::ReadError);
    assert!(!engine.recover_pairings_for_backup_restore(&mut nvs, 0));
    assert!(!engine.storage_ready(0));
    assert!(engine.recover_pairings_for_backup_restore(&mut nvs, 0));
    assert!(engine.storage_ready(0));
    assert!(engine.list_slots(0).is_empty());
    let baseline = engine.snapshot_slot_state(0);
    engine.create_slot(0, "restore candidate".into(), secret_hex(4)).unwrap();
    assert!(engine.persist_slots(&mut nvs, 0));
    assert!(engine.restore_slot_state_durably(&mut nvs, baseline));
    let reloaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
    assert!(reloaded.storage_ready(0));
    assert!(reloaded.list_slots(0).is_empty(), "empty table must suppress old-secret migration");
}
