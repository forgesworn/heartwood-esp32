// firmware/src/policy.rs
//
// Client approval policy engine. Connection slots are persisted to NVS.
// The slot -- not the ephemeral client pubkey -- is the stable identity.

use std::time::Instant;
use core::sync::atomic::{AtomicU32, Ordering};

// Per-process stamps also distinguish replaced PolicyEngine instances. Pending
// requests never survive a device reboot. Exhaustion disables deferred approval.
static NEXT_APPROVAL_EPOCH: AtomicU32 = AtomicU32::new(1);
fn next_approval_epoch() -> Option<u32> {
    NEXT_APPROVAL_EPOCH.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).ok()
}

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use crate::nvs::ReplaceBlob;
use heartwood_common::nip46::Nip46Method;
use heartwood_common::policy::{
    authorize_pubkey_on_unique_slot, clear_approved_identities, evaluate_slot_policy,
    find_slot_by_pubkey,
    find_slot_by_pubkey_mut, find_slot_by_secret, gate_request, grant_slot_method,
    grant_slot_signing, next_slot_index, record_client_identity, remove_ambiguous_pubkeys,
    remove_authorized_pubkey, set_slot_bound_identity, strict_slot_denies_method,
    verdict_covers_identity, verdict_withdrawn, IdentityRef,
    validate_exact_slot_policy, ApprovalTier, ConnectSlot, ExactSlotPolicy, Gate, GateRequest,
    RemoveAuthorizedPubkey, CONNECT_SAFE_METHODS,
};

/// Parser/allocation cap, also enforced on writes. Actual storage capacity is
/// bounded by the board's NVS partition and other records; this is no promise
/// that every logically permitted combination fits physically.
const MAX_SLOT_BLOB_BYTES: usize = 64 * 1024;

/// Drop every cached avatar (`imav<slot>`, written by identity_meta.rs) and
/// keep the names. Returns how many went.
///
/// An avatar is a display nicety Sapwood can send again; the pairing table it
/// competes with for NVS cannot be re-created. On a 24 KiB partition an
/// 8 KiB avatar left no room for an 11-pairing table, so a restore the owner
/// had approved failed with "Storage error" (T-Display, 2026-09-24). Called
/// only when a pairing write fails. Spelt out here rather than in
/// identity_meta.rs because this file is also host-tested on its own.
fn evict_avatar_cache(nvs: &mut EspNvs<NvsDefault>) -> usize {
    // masters::MAX_MASTERS
    (0..8u8)
        .filter(|slot| matches!(nvs.remove(&format!("imav{slot}")), Ok(true)))
        .count()
}

/// How a slot-table write is judged against the NVS budget.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotWrite {
    /// A change someone asked for: growth is gated.
    Change,
    /// Authority removed: never gated.
    Revoke,
    /// Restoring or re-encoding what was already durable (rollback
    /// compensation, boot-time migrations): never gated.
    Repair,
}

/// What a restart finds after [`PolicyEngine::persist_revocation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationSave {
    /// The narrower table is on flash.
    Saved,
    /// The old table is still on flash: the revocation holds until the next
    /// restart only.
    OnlyUntilRestart,
    /// The table was erased to make room and could not be rewritten: the
    /// revoked party is gone, and so is every other pairing of this master
    /// unless a later save succeeds.
    TableLost,
}

impl RevocationSave {
    /// The outcome as a caller reports it: `Ok` only when it is on flash,
    /// otherwise what a restart would find, in words. `what` names the change
    /// ("pairing revocation").
    pub fn describe(self, what: &str) -> Result<(), String> {
        match self {
            RevocationSave::Saved => Ok(()),
            RevocationSave::OnlyUntilRestart => Err(format!(
                "storage_unavailable: {what} holds until the next restart only; it could not be saved, try again"
            )),
            RevocationSave::TableLost => Err(format!(
                "storage_full: {what} is saved, but this identity's other pairings could not be rewritten and are lost at the next restart unless a later change saves them"
            )),
        }
    }
}

/// Remove master `slot`'s pre-migration `master_N_conn` credential while its
/// `connslots_N` table is present, since boot synthesises a default pairing
/// from it whenever the table is absent, and a rewrite with no room erases
/// the table first. True when the credential is proven gone.
fn clear_legacy_connection(nvs: &mut EspNvs<NvsDefault>, slot: u8) -> bool {
    let legacy = format!("master_{slot}_conn");
    matches!(nvs.blob_len(&legacy), Ok(None))
        || (nvs.remove(&legacy).is_ok() && matches!(nvs.blob_len(&legacy), Ok(None)))
}

/// Maximum concurrent client sessions.
pub const MAX_SESSIONS: usize = 32;

/// Rate limit: requests per window.
const RATE_LIMIT_MAX: u32 = 60;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Per-master connection slot store.
pub struct MasterSlots {
    pub master_slot: u8,
    pub slots: Vec<ConnectSlot>,
}

/// In-memory rollback point around a request that may change slot authority.
/// Callers persist after dispatch; if that write fails, restoring this snapshot
/// prevents a success response from leaving volatile authority active in RAM.
#[derive(Clone)]
pub struct SlotStateSnapshot {
    master_slot: u8,
    slots: Option<Vec<ConnectSlot>>,
    slots_dirty: bool,
}

/// Per-client session state (rate limiting + active identity).
pub struct ClientSession {
    pub client_pubkey: [u8; 32],
    pub master_slot: u8,
    pub active_identity: Option<usize>,
    pub request_count: u32,
    pub window_start: Instant,
    /// Monotonic recency stamp from `PolicyEngine::session_seq` — drives
    /// least-recently-used eviction when the table is full.
    pub last_seen: u64,
}

impl ClientSession {
    pub fn new(client_pubkey: [u8; 32], master_slot: u8) -> Self {
        Self {
            client_pubkey,
            master_slot,
            active_identity: None,
            request_count: 0,
            window_start: Instant::now(),
            last_seen: 0,
        }
    }

    /// Check and update rate limit. Returns true if within limit.
    pub fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs();

        if elapsed >= RATE_LIMIT_WINDOW_SECS {
            self.request_count = 1;
            self.window_start = now;
            return true;
        }

        self.request_count += 1;
        self.request_count <= RATE_LIMIT_MAX
    }
}

/// C4 approve-once transient allow (schema doc §1.4): a guardian verdict
/// installs a short-lived silent approval for one (master, client,
/// method-or-kind) so the child's retry sails through. RAM-only by design —
/// it never touches NVS, and a reboot clears it.
pub struct TransientAllow {
    pub master_slot: u8,
    pub client_pubkey: String,
    /// `nip59::method_or_kind_key` of the approved request.
    pub key: String,
    /// The identity (x-only pubkey) the approved request acted as, when it
    /// was identity-scoped. The verdict covers that identity only: a retry as
    /// any other identity still meets the per-identity gate.
    pub identity: Option<[u8; 32]>,
    pub until: Instant,
}

/// Concurrent transient allows are capped (schema doc §1.4 suggests 8);
/// beyond the cap the oldest is dropped.
pub const MAX_TRANSIENT_ALLOWS: usize = 8;

/// The full policy state for the device.
pub struct PolicyEngine {
    /// Per-master connection slot stores.
    pub master_slots: Vec<MasterSlots>,
    /// Active client sessions.
    pub sessions: Vec<ClientSession>,
    /// Whether a bridge session is authenticated.
    pub bridge_authenticated: bool,
    /// Dirty flag: slots changed since last NVS write.
    pub slots_dirty: bool,
    /// A pairing was added since the last write: the one change the NVS
    /// growth gate applies to (`persist_slots`).
    slot_added: bool,
    approval_epoch: Option<u32>,
    quarantined_masters: Vec<u8>,
    /// Monotonic counter stamped onto sessions on every access — recency
    /// order for LRU eviction without depending on clock resolution.
    session_seq: u64,
    /// Live C4 approve-once windows. Consulted by `check`; installed only
    /// by a guardian `resolve_approval` verdict.
    transient_allows: Vec<TransientAllow>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            master_slots: Vec::new(),
            sessions: Vec::new(),
            bridge_authenticated: false,
            slots_dirty: false,
            slot_added: false,
            approval_epoch: next_approval_epoch(),
            quarantined_masters: Vec::new(),
            session_seq: 0,
            transient_allows: Vec::new(),
        }
    }

    pub fn storage_ready(&self, master: u8) -> bool {
        !self.quarantined_masters.contains(&master)
    }

    fn quarantine(&mut self, master: u8) {
        if !self.quarantined_masters.contains(&master) { self.quarantined_masters.push(master); }
        self.invalidate_approvals();
    }

    pub fn approval_epoch(&self) -> Option<u32> {
        self.approval_epoch
    }

    pub fn approval_is_current(&self, epoch: Option<u32>) -> bool {
        epoch.is_some() && epoch == self.approval_epoch
    }

    /// Withdraw pending device/guardian approvals before authority can move.
    /// Rollback never restores a stamp: a revoked request cannot be revived.
    pub fn invalidate_approvals(&mut self) {
        self.approval_epoch = next_approval_epoch();
        self.transient_allows.clear();
    }

    /// Install a C4 approve-once window for `(master, client, key)`. A fresh
    /// verdict for the same tuple replaces the old window; beyond the cap the
    /// oldest entry is dropped.
    pub fn install_transient_allow(
        &mut self,
        master_slot: u8,
        client_pubkey: String,
        key: String,
        identity: Option<[u8; 32]>,
        window_secs: u64,
    ) {
        let now = Instant::now();
        self.transient_allows.retain(|allow| {
            allow.until > now
                && !(allow.master_slot == master_slot
                    && allow.client_pubkey == client_pubkey
                    && allow.key == key)
        });
        if self.transient_allows.len() >= MAX_TRANSIENT_ALLOWS {
            self.transient_allows.remove(0);
        }
        self.transient_allows.push(TransientAllow {
            master_slot,
            client_pubkey,
            key,
            identity,
            until: now + std::time::Duration::from_secs(window_secs),
        });
    }

    /// True while a live approve-once window covers this request tuple.
    /// With `identity`, the window must also have been granted for exactly
    /// that identity.
    fn transient_allowed(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        key: &str,
        identity: Option<&[u8; 32]>,
    ) -> bool {
        let now = Instant::now();
        self.transient_allows.iter().any(|allow| {
            allow.master_slot == master_slot
                && allow.client_pubkey == client_pubkey
                && allow.key == key
                && allow.until > now
                && verdict_covers_identity(allow.identity.as_ref(), identity)
        })
    }

    /// Determine the approval tier for a request.
    pub fn check(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        method: &Nip46Method,
        event_kind: Option<u64>,
    ) -> ApprovalTier {
        // Protocol plumbing remains global even for an exact v2 slot.
        if matches!(
            method,
            Nip46Method::Connect
                | Nip46Method::Ping
                | Nip46Method::GetPublicKey
                | Nip46Method::SwitchRelays
        ) {
            return ApprovalTier::AutoApprove;
        }

        // Look up slot for this client pubkey.
        // Slots are consulted regardless of bridge authentication mode --
        // slots created after physical button approval are valid in
        // both legacy and passthrough modes.
        let slots = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot);

        let slot = slots.and_then(|ms| find_slot_by_pubkey(&ms.slots, client_pubkey));

        // Exact v2 policy is a hard method ceiling, including Heartwood
        // extensions that legacy clients may button-approve or auto-run. Check
        // it before those legacy invariants so an omitted extension is denied,
        // not merely downgraded to a physical prompt.
        if let Some(slot) = slot {
            if strict_slot_denies_method(slot, method.as_str()) {
                return ApprovalTier::Denied;
            }
        }

        // A rendezvous-child hand-off is not a reusable privilege. In
        // particular, an older broad slot must not turn a one-device physical
        // approval into a silent scalar-delivery capability. Exact slots are
        // still subject to the method ceiling above; a named exact slot gets a
        // button for every fresh request as well.
        if method.requires_fresh_physical_approval() {
            return ApprovalTier::ButtonRequired;
        }

        // C4 approve-once: a live transient allow lifts this exact
        // (client, method-or-kind) to silent approval — the guardian just
        // said yes to precisely this ask. Checked after the strict method
        // ceiling (a verdict never resurrects an unlisted method) and only
        // for slot-bound clients.
        if slot.is_some() {
            let key = heartwood_common::nip59::method_or_kind_key(method.as_str(), event_kind);
            if self.transient_allowed(master_slot, client_pubkey, &key, None) {
                return ApprovalTier::AutoApprove;
            }
        }

        // Heartwood extension invariants: a physical press per request —
        // UNLESS this client's slot policy explicitly lists the method. That
        // ceiling was itself physically confirmed (CONNSLOT_UPDATE's button)
        // or operator-authorised (set_exact_slot_policy), so consent moved to
        // pairing time; the Sapwood manager pairing and the family-bunker
        // enrolment/D4 flows depend on exactly this delegation. An unlisted
        // extension keeps the per-request button, and no pre-existing slot
        // lists one (they were never settable before persona management).
        if method.always_requires_button() {
            if let Some(slot) = slot {
                if slot
                    .allowed_methods
                    .iter()
                    .any(|allowed| allowed == method.as_str())
                {
                    return evaluate_slot_policy(slot, method.as_str(), event_kind);
                }
            }
            return ApprovalTier::ButtonRequired;
        }
        if method.is_oled_notify() {
            return ApprovalTier::OledNotify;
        }
        if method.always_auto_approve() {
            return ApprovalTier::AutoApprove;
        }

        let slot = match slot {
            Some(s) => s,
            None => return ApprovalTier::ButtonRequired,
        };

        evaluate_slot_policy(slot, method.as_str(), event_kind)
    }

    /// The identity and list-identities gate for one request: the same pure
    /// decision (`heartwood_common::policy::gate_request`) whether the relay
    /// is planning escalation before dispatch or the handler is dispatching.
    /// `tier` is this request's policy tier; `identity` the x-only pubkey of
    /// the key it will use, when it uses one. A live approve-once verdict
    /// counts only for this exact request, and for an identity-scoped request
    /// only for the identity the guardian was shown.
    #[allow(clippy::too_many_arguments)]
    pub fn gate(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        has_client: bool,
        method: &Nip46Method,
        method_name: &str,
        event_kind: Option<u64>,
        tier: ApprovalTier,
        explicit_context: bool,
        has_context: bool,
        identity: Option<&[u8; 32]>,
    ) -> Gate {
        let slot = self.find_slot_by_pubkey(master_slot, client_pubkey);
        let key = heartwood_common::nip59::method_or_kind_key(method.as_str(), event_kind);
        gate_request(&GateRequest {
            client_pubkey: Some(client_pubkey),
            has_client,
            slot,
            method: method_name,
            tier,
            explicit_context,
            has_context,
            identity,
            verdict: slot.is_some()
                && self.transient_allowed(master_slot, client_pubkey, &key, identity),
        })
    }

    /// Record a physically approved identity on a slot, found by client key
    /// (`Ok`) or by index (`Err`). True when the slot table changed (the caller
    /// makes it durable); a full list records nothing and the identity keeps
    /// prompting.
    pub fn record_identity(
        &mut self,
        master_slot: u8,
        slot: Result<&str, u8>,
        identity: &[u8; 32],
    ) -> bool {
        let changed = self
            .master_slots
            .iter_mut()
            .find(|ms| ms.master_slot == master_slot)
            .and_then(|ms| match slot {
                Ok(client_pubkey) => find_slot_by_pubkey_mut(&mut ms.slots, client_pubkey),
                Err(index) => ms.slots.iter_mut().find(|s| s.slot_index == index),
            })
            .is_some_and(|target| {
                let client = match slot { Ok(key) => Some(key.to_string()), Err(_) => target.current_pubkey.clone() };
                client.is_some_and(|key| record_client_identity(target, &key, identity))
            });
        self.slots_dirty |= changed;
        changed
    }

    /// Add `heartwood_list_identities` to a legacy client's slot after its
    /// card was physically approved. Strict slots are never widened here.
    pub fn grant_list_identities(&mut self, master_slot: u8, client_pubkey: &str) -> bool {
        let changed = self
            .master_slots
            .iter_mut()
            .find(|ms| ms.master_slot == master_slot)
            .and_then(|ms| find_slot_by_pubkey_mut(&mut ms.slots, client_pubkey))
            .filter(|slot| !slot.strict_permissions)
            .is_some_and(|slot| grant_slot_method(slot, "heartwood_list_identities"));
        self.slots_dirty |= changed;
        changed
    }

    /// Find or create a client session. Returns mutable reference.
    pub fn get_or_create_session(
        &mut self,
        client_pubkey: [u8; 32],
        master_slot: u8,
    ) -> Option<&mut ClientSession> {
        self.session_seq += 1;
        let seq = self.session_seq;

        let existing = self
            .sessions
            .iter()
            .position(|s| s.client_pubkey == client_pubkey && s.master_slot == master_slot);

        if let Some(idx) = existing {
            let session = &mut self.sessions[idx];
            session.last_seen = seq;
            return Some(session);
        }

        if self.sessions.len() >= MAX_SESSIONS {
            // Evict the least-recently-used session instead of rejecting the
            // new client. Sessions are per-boot request state (rate window,
            // active identity) that rebuilds transparently on the evicted
            // client's next request; rejecting here left a full table
            // silently ignoring every new client until reboot.
            if let Some(idx) = self
                .sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(idx, _)| idx)
            {
                let evicted = self.sessions.swap_remove(idx);
                log::info!(
                    "Session table full -- evicted least-recent client {}…",
                    &heartwood_common::hex::hex_encode(&evicted.client_pubkey)[..8]
                );
            }
        }

        let mut session = ClientSession::new(client_pubkey, master_slot);
        session.last_seen = seq;
        self.sessions.push(session);
        self.sessions.last_mut()
    }

    /// Clear all state (bridge disconnected).
    pub fn clear(&mut self) {
        self.invalidate_approvals();
        self.master_slots.clear();
        self.sessions.clear();
        self.bridge_authenticated = false;
        self.session_seq = 0;
    }

    // -------------------------------------------------------------------------
    // Slot CRUD
    // -------------------------------------------------------------------------

    /// List all slots for a master slot.
    pub fn list_slots(&self, master_slot: u8) -> &[ConnectSlot] {
        if !self.storage_ready(master_slot) { return &[]; }
        self.master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot)
            .map(|ms| ms.slots.as_slice())
            .unwrap_or(&[])
    }

    /// Mutable access to the slot vec for a master slot, creating the entry if absent.
    pub(crate) fn slots_mut(&mut self, master_slot: u8) -> &mut Vec<ConnectSlot> {
        self.invalidate_approvals();
        self.slot_vec(master_slot)
    }

    /// Change the slot table for a write that usually changes no authority (a
    /// retained client reconnecting, an app naming its pairing), withdrawing
    /// waiting approvals only if it turns out to have changed some after all.
    pub(crate) fn with_slots_keeping_approvals<R>(
        &mut self,
        master_slot: u8,
        change: impl FnOnce(&mut Vec<ConnectSlot>) -> R,
    ) -> R {
        let before = self.slot_vec(master_slot).clone();
        let result = change(self.slot_vec(master_slot));
        if heartwood_common::policy::slot_authority_changed(&before, self.slot_vec(master_slot)) {
            self.invalidate_approvals();
        }
        result
    }

    fn slot_vec(&mut self, master_slot: u8) -> &mut Vec<ConnectSlot> {
        if !self
            .master_slots
            .iter()
            .any(|ms| ms.master_slot == master_slot)
        {
            self.master_slots.push(MasterSlots {
                master_slot,
                slots: Vec::new(),
            });
        }
        // Safe: we just ensured the entry exists.
        self.master_slots
            .iter_mut()
            .find(|ms| ms.master_slot == master_slot)
            .map(|ms| &mut ms.slots)
            .unwrap()
    }

    /// Capture the complete slot state for one master before request dispatch.
    pub fn snapshot_slot_state(&self, master_slot: u8) -> SlotStateSnapshot {
        SlotStateSnapshot {
            master_slot,
            slots: self
                .master_slots
                .iter()
                .find(|entry| entry.master_slot == master_slot)
                .map(|entry| entry.slots.clone()),
            slots_dirty: self.slots_dirty,
        }
    }

    /// Restore a request's slot state after its durable write failed.
    pub fn restore_slot_state(&mut self, snapshot: SlotStateSnapshot) {
        self.invalidate_approvals();
        self.slot_added = false;
        match snapshot.slots {
            Some(slots) => match self
                .master_slots
                .iter_mut()
                .find(|entry| entry.master_slot == snapshot.master_slot)
            {
                Some(entry) => entry.slots = slots,
                None => self.master_slots.push(MasterSlots {
                    master_slot: snapshot.master_slot,
                    slots,
                }),
            },
            None => self
                .master_slots
                .retain(|entry| entry.master_slot != snapshot.master_slot),
        }
        self.slots_dirty = snapshot.slots_dirty;
    }

    /// Restore the prior in-memory authority and make that compensation
    /// durable. A failed write/read-back is ambiguous: the new blob may have
    /// landed even though it could not be verified, so RAM-only rollback is
    /// insufficient. RAM is restored first (fail closed for this boot), then
    /// the old snapshot is written and read back through the same authority
    /// boundary. A failed compensation leaves `slots_dirty` set for recovery.
    pub fn restore_slot_state_durably(
        &mut self,
        nvs: &mut EspNvs<NvsDefault>,
        snapshot: SlotStateSnapshot,
    ) -> bool {
        let master_slot = snapshot.master_slot;
        let prior_dirty = snapshot.slots_dirty;
        self.restore_slot_state(snapshot);
        self.slots_dirty = true;
        let restored = self.persist_slots_as(nvs, master_slot, SlotWrite::Repair);
        self.slots_dirty = if restored { prior_dirty } else { true };
        if !restored { self.quarantine(master_slot); }
        restored
    }

    /// Create a new connection slot with the given label and secret.
    /// Returns the new slot index, or None if all 16 slots are occupied.
    /// New slots are granted CONNECT_SAFE_METHODS with auto_approve=true,
    /// signing_approved=false.
    pub fn create_slot(&mut self, master_slot: u8, label: String, secret: String) -> Option<u8> {
        let slot_index = {
            let slots = self.list_slots(master_slot);
            next_slot_index(slots)?
        };
        let new_slot = ConnectSlot {
            slot_index,
            label,
            secret,
            current_pubkey: None,
            allowed_methods: CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: false,
            strict_permissions: false,
            authorized_pubkeys: vec![],
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: None,
            approved_identities: String::new(),
            was_bound: false,
            client_grants: Some(heartwood_common::client_grants::GrantSnapshot::empty()),
        };
        self.slots_mut(master_slot).push(new_slot);
        self.slots_dirty = true;
        self.slot_added = true;
        Some(slot_index)
    }

    /// Create a slot with an exact policy supplied by the authenticated remote
    /// operator. Validation happens before mutation, and signing authority is
    /// derived from the explicit `sign_event` method instead of a second flag.
    pub fn create_slot_with_exact_policy(
        &mut self,
        master_slot: u8,
        label: String,
        secret: String,
        policy: ExactSlotPolicy,
    ) -> Option<u8> {
        let slot_index = {
            let slots = self.list_slots(master_slot);
            next_slot_index(slots)?
        };
        self.slots_mut(master_slot).push(ConnectSlot {
            slot_index,
            label,
            secret,
            current_pubkey: None,
            allowed_methods: policy.allowed_methods,
            allowed_kinds: policy.allowed_kinds,
            auto_approve: policy.auto_approve,
            signing_approved: policy.signing_approved,
            strict_permissions: true,
            authorized_pubkeys: vec![],
            escalate: policy.escalate,
            petition_on_deny: policy.petition_on_deny,
            audit_child_wrap: policy.audit_child_wrap,
            guardian_notice_wrap: policy.guardian_notice_wrap,
            bound_identity: policy.bound_identity,
            approved_identities: String::new(),
            was_bound: false,
            client_grants: Some(heartwood_common::client_grants::GrantSnapshot::empty()),
        });
        self.slots_dirty = true;
        self.slot_added = true;
        Some(slot_index)
    }

    /// Replace a slot's automatic authority as one validated unit. This is used
    /// only by the authenticated v2 management protocol; legacy USB/button
    /// flows retain their existing physical-approval rules.
    pub fn set_exact_slot_policy(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        allowed_methods: Vec<String>,
        allowed_kinds: Vec<u64>,
        auto_approve: bool,
    ) -> Result<(), String> {
        let policy = validate_exact_slot_policy(allowed_methods, allowed_kinds, auto_approve)
            .map_err(str::to_string)?;
        let slot = self
            .slots_mut(master_slot)
            .iter_mut()
            .find(|slot| slot.slot_index == slot_index)
            .ok_or_else(|| "slot not found".to_string())?;
        slot.allowed_methods = policy.allowed_methods;
        slot.allowed_kinds = policy.allowed_kinds;
        slot.auto_approve = policy.auto_approve;
        slot.signing_approved = policy.signing_approved;
        slot.strict_permissions = true;
        self.slots_dirty = true;
        Ok(())
    }

    /// Apply the family-bunker C3 additive flags (escalate, petition,
    /// child-wrap, guardian-notice-wrap + identity binding) to an existing
    /// slot. Separate from
    /// `set_exact_slot_policy` so the exact-policy path and its tests stay
    /// untouched; callers that parsed the flags from the operator envelope
    /// apply them here. Returns true when the slot exists.
    pub fn set_slot_family_flags(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        escalate: bool,
        petition_on_deny: bool,
        audit_child_wrap: bool,
        guardian_notice_wrap: bool,
        bound_identity: Option<String>,
    ) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            slot.escalate = escalate;
            slot.petition_on_deny = petition_on_deny;
            slot.audit_child_wrap = audit_child_wrap;
            slot.guardian_notice_wrap = guardian_notice_wrap;
            // A changed binding clears the approved identities, and the new
            // binding is itself approved.
            set_slot_bound_identity(slot, bound_identity);
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    /// Update fields on an existing slot. Returns true if the slot was found.
    pub fn update_slot(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        label: Option<String>,
        allowed_methods: Option<Vec<String>>,
        allowed_kinds: Option<Vec<u64>>,
        auto_approve: Option<bool>,
    ) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            if let Some(l) = label {
                slot.label = l;
            }
            if let Some(methods) = allowed_methods {
                // Security: the management API cannot grant sign_event.
                // Only the physical button can do that (via upgrade_to_signing).
                // Filter out sign_event if the slot hasn't been button-approved.
                if !slot.signing_approved {
                    let filtered: Vec<String> =
                        methods.into_iter().filter(|m| m != "sign_event").collect();
                    slot.allowed_methods = filtered;
                } else {
                    slot.allowed_methods = methods;
                }
            }
            if let Some(kinds) = allowed_kinds {
                // Kind restrictions are stored regardless of signing_approved.
                // They take effect once the user physically approves the first
                // sign_event (which upgrades the slot and adds sign_event to
                // allowed_methods). Pre-configuring kinds before approval is
                // fine -- it just means the second sign onwards uses these rules.
                slot.allowed_kinds = kinds;
            }
            if let Some(approve) = auto_approve {
                slot.auto_approve = approve;
            }
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    /// Remove a slot by index. Returns true if found and removed.
    pub fn revoke_slot(&mut self, master_slot: u8, slot_index: u8) -> bool {
        let slots = self.slots_mut(master_slot);
        let before = slots.len();
        slots.retain(|s| s.slot_index != slot_index);
        let removed = slots.len() < before;
        if removed {
            self.slots_dirty = true;
        }
        removed
    }

    /// Prune a stale non-current client key from one slot.
    pub fn remove_authorized_pubkey(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        pubkey: &str,
    ) -> Option<RemoveAuthorizedPubkey> {
        let slot = self
            .slots_mut(master_slot)
            .iter_mut()
            .find(|slot| slot.slot_index == slot_index)?;
        let outcome = remove_authorized_pubkey(slot, pubkey);
        if outcome == RemoveAuthorizedPubkey::Removed {
            self.slots_dirty = true;
        }
        Some(outcome)
    }

    /// `revoke_client_identity`: withdraw one identity's approval from a slot
    /// (`heartwood_common::mgmt::revoke_client_identity`). Returns the parsed
    /// identity and whether the approved list changed, or `None` for no such
    /// slot. Live verdicts are dropped separately, by
    /// [`Self::drop_withdrawn_verdicts`], once the change is durable.
    pub fn revoke_identity(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        identity: &str,
        client: Option<&str>,
    ) -> Option<Result<(IdentityRef, bool), &'static str>> {
        let slot = self
            .slots_mut(master_slot)
            .iter_mut()
            .find(|slot| slot.slot_index == slot_index)?;
        let outcome = if let Some(client) = client {
            heartwood_common::policy::parse_identity_ref(identity).map(|id| {
                let result = heartwood_common::policy::revoke_client_identity_ref(slot, Some(client), &id);
                (id, result == heartwood_common::policy::RevokeIdentity::Removed)
            })
        } else { heartwood_common::mgmt::revoke_client_identity(slot, identity) };
        if matches!(outcome, Ok((_, true))) {
            self.slots_dirty = true;
        }
        Some(outcome)
    }

    /// `clear_client_identities`: withdraw every recorded identity approval
    /// from a slot, keeping its binding. `None` for no such slot.
    pub fn clear_identities(&mut self, master_slot: u8, slot_index: u8, client: Option<&str>) -> Option<bool> {
        let slot = self
            .slots_mut(master_slot)
            .iter_mut()
            .find(|slot| slot.slot_index == slot_index)?;
        let changed = match client {
            None => clear_approved_identities(slot),
            Some(client) => {
                let key = heartwood_common::policy::decode_client_key(client)?;
                slot.client_grants.as_mut()?.clear_client(&key).ok()?
            }
        };
        self.slots_dirty |= changed;
        Some(changed)
    }

    /// Drop the live approve-once verdicts an identity revocation withdraws:
    /// those given to any of the slot's client keys for `revoked`, or with
    /// `None` (clearing) for any identity but the slot's binding. Returns how
    /// many were dropped.
    pub fn drop_withdrawn_verdicts(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        revoked: Option<&IdentityRef>,
    ) -> usize {
        let Some(slot) = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot)
            .and_then(|ms| ms.slots.iter().find(|slot| slot.slot_index == slot_index))
        else {
            return 0;
        };
        let before = self.transient_allows.len();
        self.transient_allows.retain(|allow| {
            !(allow.master_slot == master_slot
                && verdict_withdrawn(slot, &allow.client_pubkey, allow.identity.as_ref(), revoked))
        });
        before - self.transient_allows.len()
    }

    /// Find a slot by the current client pubkey (immutable).
    pub fn find_slot_by_pubkey(&self, master_slot: u8, pubkey: &str) -> Option<&ConnectSlot> {
        find_slot_by_pubkey(self.list_slots(master_slot), pubkey)
    }

    /// Find a slot by its secret (constant-time comparison).
    pub fn find_slot_by_secret(&self, master_slot: u8, secret: &str) -> Option<&ConnectSlot> {
        find_slot_by_secret(self.list_slots(master_slot), secret)
    }

    /// Authorise a client pubkey on a slot (called on connect with valid secret).
    /// Adds it to the slot's authorised set and makes it the current binding,
    /// preserving any previously-bound client on that same shared-secret slot.
    /// The pubkey is removed from every other slot for this master first, so one
    /// client can never inherit an older slot's policy by vector ordering.
    /// Returns true if the target slot was found.
    pub fn assign_pubkey_to_slot(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        pubkey: String,
    ) -> bool {
        let assigned = self.with_slots_keeping_approvals(master_slot, |slots| {
            authorize_pubkey_on_unique_slot(slots, slot_index, &pubkey)
        });
        if assigned {
            self.slots_dirty = true;
        }
        assigned
    }

    /// Upgrade a slot to signing tier after first physical button approval.
    /// Adds only sign_event, preserving any method/kind ceiling the operator
    /// configured before the first signature. A default connect slot already
    /// contains every CONNECT_SAFE_METHOD, so its historical result is still
    /// the complete TOFU set.
    /// Returns true for a non-strict slot, including an already granted slot.
    pub fn upgrade_to_signing(&mut self, master_slot: u8, slot_index: u8) -> bool {
        // A no-op must not invalidate sibling requests awaiting approval.
        // Only mutable access advances the authority epoch.
        let Some(slot) = self.list_slots(master_slot).iter().find(|s| s.slot_index == slot_index) else {
            return false;
        };
        if slot.strict_permissions {
            return false;
        }
        if slot.signing_approved && slot.allowed_methods.iter().any(|m| m == "sign_event") {
            return true;
        }
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            // Exact v2 authority is installed only as one validated unit. A
            // later legacy "approve" must never insert sign_event (with empty
            // kinds meaning all kinds) into a crypto-only strict slot.
            if slot.strict_permissions {
                return false;
            }
            grant_slot_signing(slot);
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    // -------------------------------------------------------------------------
    // NVS persistence
    // -------------------------------------------------------------------------

    /// Persist all slots for a master slot to NVS if changed since last write.
    /// Transaction recovery relies on a single-key replace being wholly old or
    /// wholly new after a cut, never torn and never absent (`nvs::ReplaceBlob`).
    /// Exact immediate read-back proves which desired value is present;
    /// callers compensate with their prior snapshot when it does not.
    ///
    /// A new pairing must leave room to rewrite the largest pairing table in
    /// place afterwards (`nvs::growth_allowed`, headroom hygiene);
    /// cached avatars are dropped first if that makes the room. Otherwise
    /// nothing is written and this returns false, so the caller rolls back.
    /// A table with no room for a second copy is erased before its rewrite
    /// (`nvs::ReplaceBlob`), so a cut there leaves this master with no
    /// pairings, as every rewrite did before this firmware.
    pub fn persist_slots(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) -> bool {
        self.persist_slots_as(nvs, master_slot, SlotWrite::Change)
    }

    /// Save a table that only lost authority (a revoked pairing, client key
    /// or identity grant, or permissions narrowed). Never gated, and on
    /// failure the prior table is NOT restored, in RAM or on flash: that
    /// would re-authorise what was just revoked. RAM keeps the narrower table
    /// and stays dirty, so the next save of this master writes it again. The
    /// outcome says what a restart would find.
    pub fn persist_revocation(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) -> RevocationSave {
        if self.persist_slots_as(nvs, master_slot, SlotWrite::Revoke) {
            return RevocationSave::Saved;
        }
        self.slots_dirty = true;
        match nvs.blob_len(&format!("connslots_{master_slot}")) {
            Ok(None) => RevocationSave::TableLost,
            _ => RevocationSave::OnlyUntilRestart,
        }
    }

    fn persist_slots_as(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8, mode: SlotWrite) -> bool {
        if !self.storage_ready(master_slot) { return false; }
        if !self.slots_dirty {
            return true;
        }
        let key = format!("connslots_{master_slot}");
        let ms = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot);
        if ms.is_some_and(|m| heartwood_common::policy::validate_slot_table(&m.slots).is_err()) {
            log::error!("Invalid slot table for master {master_slot}; not written");
            return false;
        }
        let persisted = match ms {
            Some(ms) => match serde_json::to_string(&ms.slots) {
                // A table the boot loader could not read back is refused, not
                // written: persisting fails closed and the caller rolls back.
                Ok(json) if json.len() > MAX_SLOT_BLOB_BYTES => {
                    log::error!("Slot table for slot {master_slot} exceeds the load cap; not written");
                    false
                }
                Ok(json) => {
                    let stored_len = nvs.blob_len(&key);
                    let growing = !matches!(stored_len, Ok(Some(len)) if json.len() <= len);
                    let adding = core::mem::take(&mut self.slot_added);
                    if mode == SlotWrite::Change
                        && adding
                        && growing
                        && !crate::nvs::growth_allowed(nvs, &key, json.len())
                        && (evict_avatar_cache(nvs) == 0 || !crate::nvs::growth_allowed(nvs, &key, json.len()))
                    {
                        log::error!(
                            "Slot table for slot {master_slot} would leave too little room to rewrite it in place; not written"
                        );
                        return false;
                    }
                    // A present table may be erased before its rewrite, and
                    // boot rebuilds a default pairing from a pre-migration
                    // `master_N_conn` whenever the table is absent. So that
                    // credential goes first; if it cannot, write in place only.
                    let table_present = !matches!(stored_len, Ok(None));
                    let may_erase = !table_present || clear_legacy_connection(nvs, master_slot);
                    let write = |nvs: &mut EspNvs<NvsDefault>| {
                        if may_erase {
                            nvs.replace_blob(&key, json.as_bytes())
                        } else {
                            nvs.replace_blob_in_place(&key, json.as_bytes())
                        }
                    };
                    let mut written = write(nvs);
                    // Pairings outrank the avatar cache: if the write fails
                    // (in practice, NVS full), drop the avatars and try once
                    // more before refusing.
                    if written.is_err() && evict_avatar_cache(nvs) > 0 {
                        log::warn!(
                            "Slot table for slot {master_slot} did not fit: dropped cached avatars, retrying"
                        );
                        written = write(nvs);
                    }
                    if let Err(e) = written {
                        log::error!("Failed to persist slots for slot {master_slot}: {e:?}");
                    }
                    // A success return from replace_blob is not the authority
                    // boundary. Read the exact bytes back before a caller may
                    // ACK a new client or signing grant.
                    match nvs.blob_len(&key) {
                        Ok(Some(len)) if len == json.len() => {
                            let mut verify = vec![0u8; len];
                            matches!(
                                nvs.get_blob(&key, &mut verify),
                                Ok(Some(stored)) if stored == json.as_bytes()
                            )
                        }
                        Ok(Some(len)) => {
                            log::error!(
                                "Slot persistence read-back length mismatch for slot {master_slot}: {len} != {}",
                                json.len()
                            );
                            false
                        }
                        Ok(None) => {
                            log::error!(
                                "Slot persistence read-back missing for slot {master_slot}"
                            );
                            false
                        }
                        Err(e) => {
                            log::error!(
                                "Slot persistence read-back failed for slot {master_slot}: {e:?}"
                            );
                            false
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to serialise slots: {e}");
                    false
                }
            },
            None => {
                if let Err(e) = nvs.remove(&key) {
                    log::error!("Failed to remove persisted slots for slot {master_slot}: {e:?}");
                }
                match nvs.blob_len(&key) {
                    Ok(None) => true,
                    Ok(Some(_)) => {
                        log::error!(
                            "Persisted slots still present after remove for slot {master_slot}"
                        );
                        false
                    }
                    Err(e) => {
                        log::error!(
                            "Could not verify persisted slot removal for slot {master_slot}: {e:?}"
                        );
                        false
                    }
                }
            }
        };
        if persisted {
            self.slots_dirty = false;
        }
        persisted
    }

    /// Start a physically approved backup recovery from a quarantined table.
    /// Install and verify an empty table before lifting quarantine; never delete
    /// its key (absence could resurrect a pre-migration connection secret).
    /// If later backup replacement fails, this empty baseline remains safe.
    /// Only the USB backup path, after its physical hold, may call this method.
    pub fn recover_pairings_for_backup_restore(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) -> bool {
        if self.storage_ready(master_slot) { return true; }
        let key = format!("connslots_{master_slot}");
        let _ = nvs.replace_blob(&key, b"[]");
        let mut verify = [0u8; 2];
        let verified = matches!(nvs.blob_len(&key), Ok(Some(2)))
            && matches!(nvs.get_blob(&key, &mut verify), Ok(Some(bytes)) if bytes == b"[]");
        if !verified { return false; }
        self.invalidate_approvals();
        self.master_slots.retain(|entry| entry.master_slot != master_slot);
        self.master_slots.push(MasterSlots { master_slot, slots: Vec::new() });
        self.quarantined_masters.retain(|slot| *slot != master_slot);
        true
    }

    /// Load persisted slots from NVS for all master slots.
    ///
    /// Migration: if the new `connslots_{slot}` key is absent but the old
    /// `policy_{slot}` key exists alongside `master_{slot}_conn`, a single
    /// default slot (index 0, label "default") is synthesised from the old
    /// secret. The old `policy_{slot}` key is deleted; `master_{slot}_conn`
    /// is left for Task 5 to clean up.
    pub fn load_from_nvs(nvs: &mut EspNvs<NvsDefault>, master_count: u8) -> Self {
        let mut engine = Self::new();
        let mut persist_migrations: Vec<u8> = Vec::new();

        for slot in 0..master_count {
            let new_key = format!("connslots_{slot}");
            // Size the read from the stored blob: per-slot approved identity
            // lists can take the table past a fixed buffer, and a blob that
            // does not fit must not read back as "no slots" (every pairing
            // silently lost). Bounded so a corrupt length cannot exhaust heap.
            match nvs.blob_len(&new_key) {
                Ok(Some(len)) if len <= MAX_SLOT_BLOB_BYTES => {
                    let mut buf = vec![0u8; len];
                    let parsed = match nvs.get_blob(&new_key, &mut buf) {
                        Ok(Some(data)) => serde_json::from_slice::<Vec<ConnectSlot>>(data).ok(),
                        _ => None,
                    };
                    if let Some(mut slots) = parsed {
                        if remove_ambiguous_pubkeys(&mut slots) {
                            log::warn!(
                                "Removed ambiguous client ownership for master slot {slot}"
                            );
                            persist_migrations.push(slot);
                        }
                        match heartwood_common::policy::migrate_client_grants(&mut slots) {
                            Ok(true) => { if !persist_migrations.contains(&slot) { persist_migrations.push(slot); } }
                            Ok(false) => {}
                            Err(reason) => {
                                log::error!("Invalid client authority for master {slot}: {reason}; pairings disabled");
                                engine.quarantine(slot);
                                continue;
                            }
                        }
                        engine.master_slots.push(MasterSlots {
                            master_slot: slot,
                            slots,
                        });
                    } else {
                        log::error!("Unreadable slot table for master {slot}; pairings disabled");
                        engine.quarantine(slot);
                    }
                    // A present but unreadable table is not evidence of an
                    // unmigrated master. Never resurrect its old credential.
                    continue;
                }
                Ok(Some(_)) | Err(_) => {
                    log::error!("Invalid slot table length for master {slot}; pairings disabled");
                    engine.quarantine(slot);
                    continue;
                }
                Ok(None) => {} // Only proven absence permits the legacy migration.
            }

            // --- Migration: check old format ---
            let old_secret_key = format!("master_{slot}_conn");
            let mut secret_buf = [0u8; 32];
            let secret_hex = match nvs.get_blob(&old_secret_key, &mut secret_buf) {
                Ok(Some(bytes)) if bytes.len() == 32 => heartwood_common::hex::hex_encode(bytes),
                Ok(None) => continue,
                _ => {
                    engine.quarantine(slot);
                    continue;
                }
            };
            {
                let migrated_slot = ConnectSlot {
                    slot_index: 0,
                    label: "default".to_string(),
                    secret: secret_hex,
                    current_pubkey: None,
                    allowed_methods: CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
                    allowed_kinds: vec![],
                    auto_approve: true,
                    signing_approved: false,
                    strict_permissions: false,
                    authorized_pubkeys: vec![],
                    escalate: false,
                    petition_on_deny: false,
                    audit_child_wrap: false,
                    guardian_notice_wrap: false,
                    bound_identity: None,
                    approved_identities: String::new(),
                    was_bound: false,
                    client_grants: Some(heartwood_common::client_grants::GrantSnapshot::empty()),
                };

                log::info!("Migrated legacy policy for master slot {slot} to connslots format");

                engine.master_slots.push(MasterSlots {
                    master_slot: slot,
                    slots: vec![migrated_slot],
                });
                persist_migrations.push(slot);
            }
        }

        // Make each repaired master durable before normal request handling. If
        // NVS is unavailable, RAM remains fail-closed for this boot and the
        // dirty flag asks a later request to retry persistence.
        let mut persist_failed = false;
        for master_slot in persist_migrations {
            engine.slots_dirty = true;
            if !engine.persist_slots_as(nvs, master_slot, SlotWrite::Repair) {
                // Migration is not active until its exact durable form verifies.
                // Retain the old disk value for recovery but serve no volatile grants.
                engine.quarantine(master_slot);
                log::error!("Client consent migration could not persist for master {master_slot}; pairings disabled");
                persist_failed = true;
            } else {
                // Retire old metadata only after the replacement is verified.
                // Failure leaves redundant data; the present new table always wins.
                let _ = nvs.remove(&format!("policy_{master_slot}"));
            }
        }
        engine.slots_dirty = persist_failed;
        engine
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyEngine;
    use heartwood_common::policy::validate_exact_slot_policy;

    #[test]
    fn slot_snapshot_restores_authority_and_prior_dirty_state() {
        let mut engine = PolicyEngine::new();
        let first = engine
            .create_slot(0, "first".into(), "11".repeat(32))
            .unwrap();
        let second = engine
            .create_slot(0, "second".into(), "22".repeat(32))
            .unwrap();
        assert!(engine.assign_pubkey_to_slot(0, first, "aa".repeat(32)));
        engine.slots_dirty = false;

        let snapshot = engine.snapshot_slot_state(0);
        assert!(engine.assign_pubkey_to_slot(0, second, "aa".repeat(32)));
        assert_eq!(
            engine.find_slot_by_pubkey(0, &"aa".repeat(32)).map(|slot| slot.slot_index),
            Some(second),
        );

        engine.restore_slot_state(snapshot);
        assert_eq!(
            engine.find_slot_by_pubkey(0, &"aa".repeat(32)).map(|slot| slot.slot_index),
            Some(first),
        );
        assert!(!engine.slots_dirty);
    }

    #[test]
    fn slot_snapshot_removes_entry_created_by_failed_request() {
        let mut engine = PolicyEngine::new();
        let snapshot = engine.snapshot_slot_state(3);
        assert!(engine
            .create_slot(3, "volatile".into(), "33".repeat(32))
            .is_some());
        engine.restore_slot_state(snapshot);
        assert!(engine.list_slots(3).is_empty());
        assert!(!engine.slots_dirty);
    }

    #[test]
    fn session_table_evicts_least_recent_when_full() {
        let mut engine = PolicyEngine::new();
        for i in 0..super::MAX_SESSIONS {
            let mut pk = [0u8; 32];
            pk[0] = i as u8;
            assert!(engine.get_or_create_session(pk, 0).is_some());
        }

        // Touch the first client so it becomes the most recently used.
        let first = [0u8; 32];
        assert!(engine.get_or_create_session(first, 0).is_some());

        // A new client is admitted by evicting the least-recent (client 1),
        // never by rejection.
        let new_client = [0xFF; 32];
        assert!(engine.get_or_create_session(new_client, 0).is_some());
        assert_eq!(engine.sessions.len(), super::MAX_SESSIONS);
        assert!(engine.sessions.iter().any(|s| s.client_pubkey == new_client));
        assert!(engine.sessions.iter().any(|s| s.client_pubkey == first));
        let mut evicted = [0u8; 32];
        evicted[0] = 1;
        assert!(!engine.sessions.iter().any(|s| s.client_pubkey == evicted));
    }

    #[test]
    fn legacy_signing_upgrade_cannot_broaden_a_strict_crypto_slot() {
        let mut engine = PolicyEngine::new();
        let exact = validate_exact_slot_policy(vec!["nip44_encrypt".into()], vec![], true)
            .unwrap();
        let index = engine
            .create_slot_with_exact_policy(0, "crypto only".into(), "44".repeat(32), exact)
            .unwrap();
        engine.slots_dirty = false;

        assert!(!engine.upgrade_to_signing(0, index));
        let slot = &engine.list_slots(0)[0];
        assert!(slot.strict_permissions);
        assert!(!slot.signing_approved);
        assert!(!slot.allowed_methods.iter().any(|method| method == "sign_event"));
        assert!(!engine.slots_dirty);
    }
}
