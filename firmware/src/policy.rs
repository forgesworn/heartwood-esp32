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
use heartwood_common::nip46::Nip46Method;
use heartwood_common::owner_pairing::VaultContext;
use heartwood_common::policy::{
    authorize_pubkey_on_unique_slot, clear_approved_identities, evaluate_slot_policy_for_event,
    find_slot_by_pubkey,
    find_slot_by_pubkey_mut, find_slot_by_secret, gate_request_with_vault, grant_slot_method,
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

/// NVS entries [`evict_avatar_cache`] can be counted on to free: what a
/// slot write that does not fit reclaims before its second try, so the
/// setup hold's save-room check counts it as room. Each avatar at its
/// fewest entries (`heartwood_common::nvs_room::min_blob_entries`).
pub(crate) fn avatar_cache_entries(nvs: &EspNvs<NvsDefault>) -> usize {
    // masters::MAX_MASTERS
    (0..8u8)
        .filter_map(|slot| nvs.blob_len(&format!("imav{slot}")).ok().flatten())
        .map(heartwood_common::nvs_room::min_blob_entries)
        .sum()
}

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

    /// Test-only: the tier for a request that is not a login challenge.
    /// Production callers hold the event and use [`Self::check_for_event`].
    #[cfg(test)]
    pub fn check(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        method: &Nip46Method,
        event_kind: Option<u64>,
    ) -> ApprovalTier {
        self.check_for_event(master_slot, client_pubkey, method, event_kind, false)
    }

    /// Determine the approval tier for a request. `login_challenge` is
    /// `heartwood_common::policy::is_login_challenge` of the event being
    /// signed (kind 22242 with a `code` tag): such a request is never lifted
    /// above a button press, by slot policy or by a guardian's window.
    pub fn check_for_event(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        method: &Nip46Method,
        event_kind: Option<u64>,
        login_challenge: bool,
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

        // One-hold pairing (spec 4.5): the setup hold always shows its own
        // FULL ACCESS card and always waits for its 5 s hold, whatever the
        // slot lists and whatever a guardian verdict says. Pinned before the
        // transient allow and before the `allowed_methods` lift below, like
        // `requires_fresh_physical_approval` without its rendezvous checks.
        // A strict slot was refused above (the bundle is never an exact
        // method), so it still answers "unauthorised".
        if method.always_shows_own_card() {
            return ApprovalTier::ButtonRequired;
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
        // A login challenge is never lifted this way: it owes a press at the
        // device, so a guardian's remote yes cannot answer it.
        let is_login = method.as_str() == "sign_event" && login_challenge;
        if slot.is_some() && !is_login {
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
                    return evaluate_slot_policy_for_event(slot, method.as_str(), event_kind, login_challenge);
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

        evaluate_slot_policy_for_event(slot, method.as_str(), event_kind, login_challenge)
    }

    /// The identity and list-identities gate for one request: the same pure
    /// decision (`heartwood_common::policy::gate_request`) whether the relay
    /// is planning escalation before dispatch or the handler is dispatching.
    /// `tier` is this request's policy tier; `identity` the x-only pubkey of
    /// the key it will use, when it uses one. A live approve-once verdict
    /// counts only for this exact request, and for an identity-scoped request
    /// only for the identity the guardian was shown.
    #[cfg(test)]
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
        self.gate_with_vault(
            master_slot,
            client_pubkey,
            has_client,
            method,
            method_name,
            event_kind,
            tier,
            explicit_context,
            has_context,
            identity,
            VaultContext::NONE,
        )
    }

    /// [`Self::gate`] with Rule V (one-hold pairing spec 6): `vault` says
    /// whether the CALLER supplied a vault context
    /// (`VaultContext::from_explicit`, never a session's active identity).
    /// The handler's `plan_gate` is the only production caller, and both the
    /// handler and the relay's pre-dispatch planner go through it, so the two
    /// build `vault` the same way and reach the same decision.
    #[allow(clippy::too_many_arguments)]
    pub fn gate_with_vault(
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
        vault: VaultContext,
    ) -> Gate {
        let slot = self.find_slot_by_pubkey(master_slot, client_pubkey);
        let key = heartwood_common::nip59::method_or_kind_key(method.as_str(), event_kind);
        gate_request_with_vault(&GateRequest {
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
        }, vault)
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

    /// The setup hold's slot step (one-hold pairing spec 4.3, steps 2 to 5),
    /// after step 1 resolved or registered every name: grants for `act_as`
    /// (their x-only keys), the owner mark, LIST IDS, NIP-44 both ways,
    /// signing, and `style`'s kinds list. Adds and never removes (bar
    /// Everyday emptying Extra careful's list, a widening the hold consents
    /// to). Every other waiting card is withdrawn: the slot's authority is
    /// changing. Run inside a snapshot; on `Err` (a grant could not be
    /// recorded) the caller restores it. True when the slot changed.
    pub fn apply_bundle_press(
        &mut self,
        master_slot: u8,
        client_pubkey: &str,
        act_as: &[[u8; 32]],
        style: heartwood_common::owner_pairing::Style,
    ) -> Result<bool, heartwood_common::owner_pairing::BundleError> {
        let slot = find_slot_by_pubkey_mut(self.slots_mut(master_slot), client_pubkey)
            .filter(|slot| !slot.strict_permissions)
            .ok_or(heartwood_common::owner_pairing::BundleError::Unauthorised)?;
        let changed =
            heartwood_common::owner_pairing::apply_bundle_press(slot, client_pubkey, act_as, style)?;
        self.slots_dirty |= changed;
        Ok(changed)
    }

    /// `heartwood_owner_narrow` (spec 4.6) on the caller's own slot: sets
    /// Extra careful's list when the kinds list is empty, otherwise nothing.
    /// Never widens: a custom list (an operator narrowed it) stays as it is.
    /// `Unauthorised` without the owner mark. Waiting cards are withdrawn
    /// only when the slot actually changed. Whether it did, and the style now
    /// in force.
    pub fn owner_narrow(
        &mut self,
        master_slot: u8,
        client_pubkey: &str,
    ) -> Result<(bool, heartwood_common::owner_pairing::SlotStyle), heartwood_common::owner_pairing::BundleError> {
        let (changed, style) = self.with_slots_keeping_approvals(master_slot, |slots| {
            heartwood_common::owner_pairing::owner_narrow(find_slot_by_pubkey_mut(slots, client_pubkey))
        })?;
        self.slots_dirty |= changed;
        Ok((changed, style))
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
        let restored = self.persist_slots(nvs, master_slot);
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
        // A write that leaves the slot's authority as it was (an operator's
        // policy push re-sending the same policy) withdraws no waiting card
        // (review m4): only a real change does (`slot_authority_changed`).
        self.with_slots_keeping_approvals(master_slot, |slots| {
            let slot = slots
                .iter_mut()
                .find(|slot| slot.slot_index == slot_index)
                .ok_or_else(|| "slot not found".to_string())?;
            slot.allowed_methods = policy.allowed_methods;
            slot.allowed_kinds = policy.allowed_kinds;
            slot.auto_approve = policy.auto_approve;
            slot.signing_approved = policy.signing_approved;
            slot.strict_permissions = true;
            Ok::<(), String>(())
        })?;
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
        // Withdraws waiting cards only on a real authority change (review m4).
        let found = self.with_slots_keeping_approvals(master_slot, |slots| {
            let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) else {
                return false;
            };
            slot.escalate = escalate;
            slot.petition_on_deny = petition_on_deny;
            slot.audit_child_wrap = audit_child_wrap;
            slot.guardian_notice_wrap = guardian_notice_wrap;
            // A changed binding clears the approved identities, and the new
            // binding is itself approved.
            set_slot_bound_identity(slot, bound_identity);
            true
        });
        if found {
            self.slots_dirty = true;
        }
        found
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
        // A no-op write (an operator's policy push re-sending what the slot
        // already holds) withdraws no waiting card, a FULL ACCESS card
        // included: only a real authority change does (review m4,
        // `slot_authority_changed`). Lists compare in order, so a reordered
        // list counts as a change and still withdraws (fails closed).
        let found = self.with_slots_keeping_approvals(master_slot, |slots| {
            let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) else {
                return false;
            };
            // One-hold pairing (spec 4.6, 5.2): both lists are judged against
            // the slot as it was BEFORE this update. The owner mark may be
            // kept or dropped, never added; heartwood_approve_bundle is never
            // listed; and while the slot carried the mark its kinds list may
            // be kept or narrowed, never emptied or extended, even when this
            // same call drops the mark (methods are set first below).
            let allowed_methods = allowed_methods
                .map(|methods| heartwood_common::owner_pairing::update_slot_methods(slot, methods));
            let allowed_kinds = allowed_kinds
                .map(|kinds| heartwood_common::owner_pairing::update_slot_kinds(slot, kinds));
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
            true
        });
        if found {
            self.slots_dirty = true;
        }
        found
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
        // "Forget approvals" also forgets the setup hold (spec 5.2), with or
        // without a client. Dropped only once the clear itself succeeded, so
        // a refused clear changes nothing at all.
        let changed = heartwood_common::owner_pairing::drop_owner_mark(slot) | changed;
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

    /// The master's slots as a backup EXPORT writes them: unredacted, but
    /// without the owner mark or the bundle method (spec 5.2), so a new
    /// backup still imports on firmware that does not know the mark. The
    /// import strips them too (`sanitise_imported_slot`); the setup hold is
    /// the only way back to an owner pairing.
    pub fn exported_slots(&self, master_slot: u8) -> Vec<ConnectSlot> {
        let mut slots = self.list_slots(master_slot).to_vec();
        for slot in &mut slots {
            heartwood_common::owner_pairing::strip_owner_names(&mut slot.allowed_methods);
        }
        slots
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
    /// Transaction recovery relies on ESP-IDF NVS's single-key atomicity: a
    /// `connslots_N` blob is assumed to be wholly old or wholly new, never a
    /// torn mixture. Exact immediate read-back proves which desired value is
    /// present; callers compensate with their prior snapshot when it does not.
    pub fn persist_slots(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) -> bool {
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
                    let mut written = nvs.set_blob(&key, json.as_bytes());
                    // Pairings outrank the avatar cache: if the write fails
                    // (in practice, NVS full), drop the avatars and try once
                    // more before refusing.
                    if written.is_err() && evict_avatar_cache(nvs) > 0 {
                        log::warn!(
                            "Slot table for slot {master_slot} did not fit: dropped cached avatars, retrying"
                        );
                        written = nvs.set_blob(&key, json.as_bytes());
                    }
                    if let Err(e) = written {
                        log::error!("Failed to persist slots for slot {master_slot}: {e:?}");
                    }
                    // A success return from set_blob is not the authority
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
        let _ = nvs.set_blob(&key, b"[]");
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
            if !engine.persist_slots(nvs, master_slot) {
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
    use heartwood_common::nip46::Nip46Method;
    use heartwood_common::policy::{validate_exact_slot_policy, ApprovalTier};

    const CLIENT: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// A bound, non-strict pairing for `CLIENT` on master 0.
    fn paired_engine() -> (PolicyEngine, u8) {
        let mut engine = PolicyEngine::new();
        let index = engine.create_slot(0, "My Signet".into(), "55".repeat(32)).unwrap();
        assert!(engine.assign_pubkey_to_slot(0, index, CLIENT.into()));
        (engine, index)
    }

    use heartwood_common::owner_pairing::{
        self, is_owner_pairing, slot_has_owner_mark, Style, CAREFUL_KINDS, OWNER_MARK,
    };

    /// Put the setup hold's grants on the pairing (common's press, steps 2-5).
    fn press(engine: &mut PolicyEngine, index: u8, style: Style) {
        let slot = engine.slots_mut(0).iter_mut().find(|s| s.slot_index == index).unwrap();
        owner_pairing::apply_bundle_press(slot, CLIENT, &[[0x11; 32]], style).unwrap();
        assert!(is_owner_pairing(slot));
    }

    fn slot(engine: &PolicyEngine, index: u8) -> &heartwood_common::policy::ConnectSlot {
        engine.list_slots(0).iter().find(|s| s.slot_index == index).unwrap()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|m| m.to_string()).collect()
    }

    #[test]
    fn an_operator_create_then_update_naming_the_mark_leaves_no_mark() {
        // The stolen-operator-key case (spec 12): create_client then
        // update_client listing the mark (and the bundle) never makes an
        // owner pairing.
        let (mut engine, index) = paired_engine();
        let mut methods = names(heartwood_common::policy::CONNECT_SAFE_METHODS);
        methods.push(OWNER_MARK.into());
        methods.push("heartwood_approve_bundle".into());
        assert!(engine.update_slot(0, index, None, Some(methods), Some(vec![]), Some(true)));
        let after = slot(&engine, index);
        assert!(!slot_has_owner_mark(after));
        assert!(!after.allowed_methods.iter().any(|m| m == "heartwood_approve_bundle"));
        // And a slot the update tried to list the bundle on still cards it.
        assert_eq!(
            engine.check(0, CLIENT, &Nip46Method::HeartwoodApproveBundle, None),
            ApprovalTier::ButtonRequired
        );
    }

    #[test]
    fn update_slot_keeps_or_drops_the_mark_and_never_lists_the_bundle() {
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Everyday);
        // Keeping it in the list keeps it; the bundle is filtered even here.
        let mut kept = slot(&engine, index).allowed_methods.clone();
        kept.push("heartwood_approve_bundle".into());
        assert!(engine.update_slot(0, index, None, Some(kept), None, None));
        assert!(slot_has_owner_mark(slot(&engine, index)));
        assert!(!slot(&engine, index).allowed_methods.iter().any(|m| m == "heartwood_approve_bundle"));
        // Omitting it drops it (Sapwood's Edit).
        let dropped: Vec<String> = slot(&engine, index)
            .allowed_methods
            .iter()
            .filter(|m| *m != OWNER_MARK)
            .cloned()
            .collect();
        assert!(engine.update_slot(0, index, None, Some(dropped.clone()), None, None));
        assert!(!slot_has_owner_mark(slot(&engine, index)));
        // And naming it again cannot bring it back.
        let mut again = dropped;
        again.push(OWNER_MARK.into());
        assert!(engine.update_slot(0, index, None, Some(again), None, None));
        assert!(!slot_has_owner_mark(slot(&engine, index)));
    }

    #[test]
    fn a_no_op_slot_write_keeps_waiting_cards_and_a_real_change_withdraws_them() {
        // Review m4: an operator's policy push that re-sends what the owner
        // pairing already holds must not void a waiting FULL ACCESS card.
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Everyday);
        let current = slot(&engine, index).clone();
        let epoch = engine.approval_epoch();
        assert!(engine.update_slot(
            0,
            index,
            Some("Renamed".into()),
            Some(current.allowed_methods.clone()),
            Some(current.allowed_kinds.clone()),
            Some(current.auto_approve),
        ));
        assert!(engine.approval_is_current(epoch), "same lists and a new label");
        let mut with_bundle = current.allowed_methods.clone();
        with_bundle.push("heartwood_approve_bundle".into());
        assert!(engine.update_slot(0, index, None, Some(with_bundle), None, None));
        assert!(engine.approval_is_current(epoch), "the bundle is filtered, so nothing changed");
        assert!(engine.set_slot_family_flags(
            0,
            index,
            current.escalate,
            current.petition_on_deny,
            current.audit_child_wrap,
            current.guardian_notice_wrap,
            current.bound_identity.clone(),
        ));
        assert!(engine.approval_is_current(epoch), "the same family flags");
        assert!(!engine.update_slot(0, 99, None, Some(vec![]), None, None));
        assert!(engine.approval_is_current(epoch), "no such slot");

        // A real change withdraws them.
        assert!(engine.update_slot(0, index, None, None, Some(vec![1]), None));
        assert!(!engine.approval_is_current(epoch), "a kinds change");
        let epoch = engine.approval_epoch();
        assert!(engine.set_slot_family_flags(0, index, true, false, false, false, current.bound_identity.clone()));
        assert!(!engine.approval_is_current(epoch), "escalate set");

        // The strict path: the same exact policy twice withdraws only once.
        let (mut engine, index) = paired_engine();
        let methods = names(&["get_public_key", "nip44_encrypt"]);
        let epoch = engine.approval_epoch();
        engine.set_exact_slot_policy(0, index, methods.clone(), vec![], true).unwrap();
        assert!(!engine.approval_is_current(epoch), "the slot became strict");
        let epoch = engine.approval_epoch();
        engine.set_exact_slot_policy(0, index, methods, vec![], true).unwrap();
        assert!(engine.approval_is_current(epoch), "the same exact policy again");
    }

    #[test]
    fn a_marked_slot_kinds_list_may_narrow_but_never_widen() {
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Careful);
        assert_eq!(slot(&engine, index).allowed_kinds, CAREFUL_KINDS.to_vec());
        // Emptying (all kinds) and extending are applied with the old list.
        assert!(engine.update_slot(0, index, None, None, Some(vec![]), None));
        assert_eq!(slot(&engine, index).allowed_kinds, CAREFUL_KINDS.to_vec());
        assert!(engine.update_slot(0, index, None, None, Some(vec![30078, 22242, 1]), None));
        assert_eq!(slot(&engine, index).allowed_kinds, CAREFUL_KINDS.to_vec());
        // Narrowing is kept.
        assert!(engine.update_slot(0, index, None, None, Some(vec![30078]), None));
        assert_eq!(slot(&engine, index).allowed_kinds, vec![30078]);

        // One call that drops the mark AND empties the list keeps the list:
        // the rule reads the slot as it was before the update.
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Careful);
        let unmarked: Vec<String> = slot(&engine, index)
            .allowed_methods
            .iter()
            .filter(|m| *m != OWNER_MARK)
            .cloned()
            .collect();
        assert!(engine.update_slot(0, index, None, Some(unmarked), Some(vec![]), None));
        assert!(!slot_has_owner_mark(slot(&engine, index)));
        assert_eq!(slot(&engine, index).allowed_kinds, CAREFUL_KINDS.to_vec());
        // Once the mark is gone an operator may widen it, as today.
        assert!(engine.update_slot(0, index, None, None, Some(vec![]), None));
        assert!(slot(&engine, index).allowed_kinds.is_empty());

        // An unmarked slot takes any list, as today.
        let (mut engine, index) = paired_engine();
        assert!(engine.update_slot(0, index, None, None, Some(vec![1, 7]), None));
        assert!(engine.update_slot(0, index, None, None, Some(vec![]), None));
        assert!(slot(&engine, index).allowed_kinds.is_empty());
    }

    #[test]
    fn forget_approvals_drops_the_mark_and_revoke_leaves_it() {
        for client in [None, Some(CLIENT)] {
            let (mut engine, index) = paired_engine();
            press(&mut engine, index, Style::Everyday);
            engine.slots_dirty = false;
            assert_eq!(engine.clear_identities(0, index, client), Some(true), "{client:?}");
            assert!(!slot_has_owner_mark(slot(&engine, index)), "{client:?}");
            assert!(engine.slots_dirty);
        }
        // An unmarked slot with nothing to forget is unchanged.
        let (mut engine, index) = paired_engine();
        assert_eq!(engine.clear_identities(0, index, None), Some(false));

        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Everyday);
        let identity = heartwood_common::hex::hex_encode(&[0x11; 32]);
        assert!(matches!(engine.revoke_identity(0, index, &identity, Some(CLIENT)), Some(Ok((_, true)))));
        assert!(slot_has_owner_mark(slot(&engine, index)));
    }

    #[test]
    fn binding_a_second_client_key_drops_the_mark() {
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Everyday);
        // The same key reconnecting keeps it.
        assert!(engine.assign_pubkey_to_slot(0, index, CLIENT.into()));
        assert!(slot_has_owner_mark(slot(&engine, index)));
        assert!(engine.assign_pubkey_to_slot(0, index, "bb".repeat(32)));
        assert!(!slot_has_owner_mark(slot(&engine, index)));
    }

    #[test]
    fn a_backup_export_omits_the_mark_and_still_imports() {
        let (mut engine, index) = paired_engine();
        press(&mut engine, index, Style::Careful);
        engine.slots_mut(0)[0].allowed_methods.push("heartwood_approve_bundle".into());
        let exported = engine.exported_slots(0);
        let out = exported.iter().find(|s| s.slot_index == index).unwrap();
        assert!(!slot_has_owner_mark(out));
        assert!(!out.allowed_methods.iter().any(|m| m == "heartwood_approve_bundle"));
        // The engine itself still has it; only the export leaves it out.
        assert!(slot_has_owner_mark(slot(&engine, index)));
        // The export imports (older firmware's sanitiser rejects any unknown
        // name; this one accepts what it exported).
        let mut imported = out.clone();
        assert!(heartwood_common::policy::sanitise_imported_slot(&mut imported).is_ok());
        assert!(!slot_has_owner_mark(&imported));
    }

    #[test]
    fn set_exact_slot_policy_rejects_the_mark_and_the_bundle() {
        let (mut engine, index) = paired_engine();
        for name in [OWNER_MARK, "heartwood_approve_bundle", "heartwood_owner_status", "heartwood_owner_narrow"] {
            let result = engine.set_exact_slot_policy(0, index, vec!["sign_event".into(), name.into()], vec![], true);
            assert!(result.is_err(), "{name}");
        }
        assert!(!slot(&engine, index).strict_permissions);
    }

    #[test]
    fn rule_v_skips_the_identity_card_only_for_an_explicit_vault_context_on_an_owner_pairing() {
        use heartwood_common::owner_pairing::VaultContext;
        use heartwood_common::policy::{CardKind, Gate};
        let vault_key = [0x77; 32];
        let gate = |engine: &PolicyEngine, method: &Nip46Method, name: &str, kind: Option<u64>, explicit: bool, vault: VaultContext| {
            let tier = engine.check(0, CLIENT, method, kind);
            engine.gate_with_vault(0, CLIENT, true, method, name, kind, tier, explicit, true, Some(&vault_key), vault)
        };
        let vault = |kind| VaultContext::from_explicit(Some("signet:vault:contacts"), kind);

        let (mut engine, index) = paired_engine();
        // Before the setup hold: today's path, an identity card.
        assert!(matches!(
            gate(&engine, &Nip46Method::Nip44Encrypt, "nip44_encrypt", None, true, vault(None)),
            Gate::Card(CardKind::AllowAs { .. }) | Gate::Deny
        ));
        press(&mut engine, index, Style::Everyday);
        for (method, name, kind) in [
            (Nip46Method::GetPublicKey, "get_public_key", None),
            (Nip46Method::Nip44Encrypt, "nip44_encrypt", None),
            (Nip46Method::Nip44Decrypt, "nip44_decrypt", None),
            (Nip46Method::SignEvent, "sign_event", Some(30078)),
            (Nip46Method::SignEvent, "sign_event_compact", Some(30078)),
        ] {
            assert_eq!(gate(&engine, &method, name, kind, true, vault(kind)), Gate::Allow, "{name}");
            // The tier still governs, and is automatic after the hold.
            assert_eq!(engine.check(0, CLIENT, &method, kind), ApprovalTier::AutoApprove, "{name}");
            // A context the caller did not supply never counts.
            assert_ne!(gate(&engine, &method, name, kind, false, VaultContext::from_explicit(None, kind)), Gate::Allow, "{name}");
        }
        // Another kind under a vault context takes today's path.
        assert_ne!(
            gate(&engine, &Nip46Method::SignEvent, "sign_event", Some(1), true, vault(Some(1))),
            Gate::Allow
        );
        // A context that is not a vault purpose takes today's path.
        assert_ne!(
            gate(&engine, &Nip46Method::Nip44Encrypt, "nip44_encrypt", None, true,
                 VaultContext::from_explicit(Some("nostr:persona:persona"), None)),
            Gate::Allow
        );
    }

    #[test]
    fn the_press_grants_withdraws_waiting_cards_and_runs_again_adding_only() {
        let (mut engine, index) = paired_engine();
        let epoch = engine.approval_epoch();
        let persona = [0x22; 32];
        assert_eq!(engine.apply_bundle_press(0, CLIENT, &[persona], Style::Careful), Ok(true));
        assert!(!engine.approval_is_current(epoch), "waiting cards are withdrawn");
        assert!(engine.slots_dirty);
        let after = slot(&engine, index).clone();
        assert!(is_owner_pairing(&after));
        for name in owner_pairing::BUNDLE_GRANTED_METHODS {
            assert!(after.allowed_methods.iter().any(|m| m == name), "{name}");
        }
        assert!(after.signing_approved);
        assert_eq!(after.allowed_kinds, CAREFUL_KINDS.to_vec());
        assert!(heartwood_common::policy::client_identity_approved(&after, Some(CLIENT), &persona));
        // Again, Everyday: adds nothing, removes nothing, widens kinds.
        assert_eq!(engine.apply_bundle_press(0, CLIENT, &[persona], Style::Everyday), Ok(true));
        let again = slot(&engine, index);
        assert!(again.allowed_kinds.is_empty());
        assert!(heartwood_common::policy::client_identity_approved(again, Some(CLIENT), &persona));
        assert_eq!(engine.apply_bundle_press(0, CLIENT, &[persona], Style::Everyday), Ok(false));
        // A stranger's key or a strict slot gets nothing.
        assert!(engine.apply_bundle_press(0, &"cc".repeat(32), &[], Style::Everyday).is_err());
    }

    // Host harness only: the fault-injecting NVS exists in common's test
    // crate, not on the device target.
    #[cfg(not(target_os = "espidf"))]
    #[test]
    fn a_press_that_cannot_persist_is_rolled_back_durably() {
        // Spec 12: rollback on a failed persist, the handler's
        // persist-or-rollback sequence over common's fault-injecting NVS
        // (this module only compiles in that host harness).
        use crate::firmware_policy_host_tests::{FaultKind, NvsOp};
        let mut nvs = esp_idf_svc::nvs::EspNvs::new();
        let (mut engine, index) = paired_engine();
        assert!(engine.persist_slots(&mut nvs, 0));
        let before = slot(&engine, index).clone();
        let snapshot = engine.snapshot_slot_state(0);
        assert_eq!(engine.apply_bundle_press(0, CLIENT, &[[0x33; 32]], Style::Everyday), Ok(true));
        nvs.backend.fail_once(NvsOp::SetBlob, "connslots_0", FaultKind::WriteFailBeforeCommit);
        assert!(!engine.persist_slots(&mut nvs, 0));
        assert!(engine.restore_slot_state_durably(&mut nvs, snapshot));
        let after = slot(&engine, index);
        assert_eq!(after.allowed_methods, before.allowed_methods);
        assert!(!slot_has_owner_mark(after));
        // What is on flash is the old table too.
        let reloaded = PolicyEngine::load_from_nvs(&mut nvs, 1);
        assert!(!slot_has_owner_mark(&reloaded.list_slots(0)[0]));
    }

    #[test]
    fn narrow_never_widens_and_needs_the_mark() {
        use heartwood_common::owner_pairing::{BundleError, SlotStyle};
        let (mut engine, index) = paired_engine();
        assert_eq!(engine.owner_narrow(0, CLIENT), Err(BundleError::Unauthorised));
        press(&mut engine, index, Style::Everyday);
        let epoch = engine.approval_epoch();
        assert_eq!(engine.owner_narrow(0, CLIENT), Ok((true, SlotStyle::Careful)));
        assert_eq!(slot(&engine, index).allowed_kinds, CAREFUL_KINDS.to_vec());
        let epoch2 = engine.approval_epoch();
        assert_ne!(epoch, epoch2);
        // Already careful: nothing changes, nothing withdrawn.
        assert_eq!(engine.owner_narrow(0, CLIENT), Ok((false, SlotStyle::Careful)));
        assert!(engine.approval_is_current(epoch2));
        // An operator narrowed it: custom, and narrow leaves it as it is.
        assert!(engine.update_slot(0, index, None, None, Some(vec![30078]), None));
        assert_eq!(engine.owner_narrow(0, CLIENT), Ok((false, SlotStyle::Custom)));
        assert_eq!(slot(&engine, index).allowed_kinds, vec![30078]);
        assert_eq!(engine.owner_narrow(0, &"dd".repeat(32)), Err(BundleError::Unauthorised));
    }

    #[test]
    fn a_bundle_replaces_the_list_an_operator_narrowed_on_an_owner_pairing() {
        // Review round W5: the hold is the consent, so a marked slot's
        // narrowed list is replaced by the chosen style's list, either way.
        for (style, expected) in [(Style::Everyday, vec![]), (Style::Careful, CAREFUL_KINDS.to_vec())] {
            let (mut engine, index) = paired_engine();
            press(&mut engine, index, Style::Careful);
            assert!(engine.update_slot(0, index, None, None, Some(vec![30078]), None));
            assert!(heartwood_common::owner_pairing::check_bundle_slot(Some(slot(&engine, index)), CLIENT).is_ok());
            assert_eq!(engine.apply_bundle_press(0, CLIENT, &[[0x22; 32]], style), Ok(true), "{style:?}");
            assert_eq!(slot(&engine, index).allowed_kinds, expected, "{style:?}");
            assert!(slot_has_owner_mark(slot(&engine, index)));
        }
    }

    #[test]
    fn the_bundle_always_raises_its_own_card_whatever_the_slot_lists() {
        // Spec 4.5 / 12: a slot listing heartwood_approve_bundle (however it
        // got there) still gets the FULL ACCESS card, and a guardian's
        // approve-once window does not lift it either.
        let (mut engine, index) = paired_engine();
        let bundle = Nip46Method::HeartwoodApproveBundle;
        assert_eq!(engine.check(0, CLIENT, &bundle, None), ApprovalTier::ButtonRequired);
        engine.slots_mut(0)[index as usize]
            .allowed_methods
            .push("heartwood_approve_bundle".into());
        assert_eq!(engine.check(0, CLIENT, &bundle, None), ApprovalTier::ButtonRequired);
        engine.install_transient_allow(0, CLIENT.into(), "heartwood_approve_bundle".into(), None, 60);
        assert_eq!(engine.check(0, CLIENT, &bundle, None), ApprovalTier::ButtonRequired);

        // A strict slot refuses it before the pin (never an exact method).
        let exact = validate_exact_slot_policy(vec!["sign_event".into()], vec![], true).unwrap();
        let strict = engine
            .create_slot_with_exact_policy(0, "strict".into(), "66".repeat(32), exact)
            .unwrap();
        let other = "aa".repeat(32);
        assert!(engine.assign_pubkey_to_slot(0, strict, other.clone()));
        assert_eq!(engine.check(0, &other, &bundle, None), ApprovalTier::Denied);
    }

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
