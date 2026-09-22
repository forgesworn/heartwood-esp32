// common/src/client_grants.rs

//! Isolated G4 per-client persona consent state machine.
//!
//! The firmware stores `GrantSnapshot` alongside each pairing, through the
//! restrictive downgrade codec. This pure `no_std + alloc` module covers
//! persona consent only. Callers must still enforce NIP-46 methods,
//! event kinds, sensitive rules, guardian escalation, and all persistence.
//!
//! `GrantSet::from_legacy` snapshots existing firmware authority. The caller
//! must ensure the source `ConnectSlot` has already had cross-slot ambiguous
//! client keys removed; that prerequisite is not re-checked here.
//!
//! The caller must supply a fresh, unpredictable `lifetime` for every new or
//! reconstructed `GrantSet` (including on reboot or replacement) and must
//! discard pending approval requests on reboot. Reusing a lifetime is caller
//! error. No persistent anti-replay claim is made. No secret material is
//! stored here.
//!
//! `GrantSnapshot` persists consent without tickets or generation counters.
//! Restoring a `GrantSet` requires a new caller-supplied lifetime. The firmware
//! additionally invalidates deferred requests whenever authority changes.
//!
//! Limits (8 clients, 16 explicit grants, 16 legacy tags) are provisional;
//! the final storage schema and caps are not promised.

use alloc::vec::Vec;

mod snapshot;
pub use snapshot::GrantSnapshot;

const MAX_CLIENTS: usize = 8;
const MAX_EXPLICIT_GRANTS: usize = 16;
const MAX_LEGACY_TAGS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GrantContext {
    pub master_pubkey: [u8; 32],
    pub slot_fingerprint: [u8; 32],
    pub lifetime: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Member {
    key: [u8; 32],
    incarnation: u64,
    revision: u64,
    legacy_eligible: bool,
    legacy_revoked_tags: Vec<[u8; 8]>,
    legacy_bound_approved: bool,
}

/// Pure in-memory grant state machine. Fields are private so that only
/// `issue_ticket` can produce a ticket and only `GrantSet` can mutate state.
///
/// Production snapshot/restore is unsupported; see the module contract.
#[cfg_attr(test, derive(Clone))]
#[derive(PartialEq, Eq, Debug)]
pub struct GrantSet {
    context: GrantContext,
    set_revision: u64,
    next_incarnation: u64,
    members: Vec<Member>,
    legacy_tags: Vec<[u8; 8]>,
    legacy_bound: Option<[u8; 32]>,
    explicit_grants: Vec<([u8; 32], [u8; 32])>,
}

/// Binds pending state and detects invalidation under the unique-lifetime
/// contract. A ticket is not evidence that consent occurred: the caller must
/// verify physical, operator or guardian approval separately.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ApprovalTicket {
    context: GrantContext,
    set_revision: u64,
    client: [u8; 32],
    incarnation: u64,
    client_revision: u64,
    identity: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantError {
    InvalidLegacySnapshot,
    ClientCapacity,
    IdentityCapacity,
    UnknownClient,
    StaleTicket,
    CounterExhausted,
}

// --- internal hex helpers (do not allocate) ---------------------------------

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn all_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !all_lower_hex(s) {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for i in 0..N {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn decode_32_lower(s: &str) -> Option<[u8; 32]> {
    decode_fixed::<32>(s)
}

// --- GrantSet ---------------------------------------------------------------

impl GrantSet {
    pub fn new(context: GrantContext) -> Self {
        Self {
            context,
            set_revision: 0,
            next_incarnation: 0,
            members: Vec::new(),
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit_grants: Vec::new(),
        }
    }

    /// Snapshot legacy authority from a firmware `ConnectSlot`.
    ///
    /// Only existing members gain `legacy_eligible = true` and (if a bound
    /// identity is present) `legacy_bound_approved = true`. Future added
    /// clients never inherit legacy or binding authority. Full identities are
    /// never derived from 8-byte tags.
    pub fn from_legacy(
        context: GrantContext,
        slot: &crate::policy::ConnectSlot,
    ) -> Result<Self, GrantError> {
        // Snapshot clients (distinct-key cap enforced before accumulating).
        let mut keys: Vec<[u8; 32]> = Vec::new();
        if let Some(ref current) = slot.current_pubkey {
            let k = decode_32_lower(current).ok_or(GrantError::InvalidLegacySnapshot)?;
            keys.push(k);
        }
        for auth in &slot.authorized_pubkeys {
            let k = decode_32_lower(auth).ok_or(GrantError::InvalidLegacySnapshot)?;
            if keys.contains(&k) {
                continue;
            }
            if keys.len() >= MAX_CLIENTS {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            keys.push(k);
        }

        let legacy_bound = match slot.bound_identity {
            Some(ref b) => Some(decode_32_lower(b).ok_or(GrantError::InvalidLegacySnapshot)?),
            None => None,
        };

        // Snapshot legacy tags (8-byte prefixes).
        let ids = slot.approved_identities.as_str();
        let mut legacy_tags: Vec<[u8; 8]> = Vec::new();
        if !ids.is_empty() {
            if ids.len() % 16 != 0 {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            let tag_count = ids.len() / 16;
            if tag_count > MAX_LEGACY_TAGS {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            let bytes = ids.as_bytes();
            for i in 0..tag_count {
                let start = i * 16;
                let end = start + 16;
                let chunk = &bytes[start..end];
                if !chunk.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                    return Err(GrantError::InvalidLegacySnapshot);
                }
                let tag = decode_fixed::<8>(
                    core::str::from_utf8(chunk).map_err(|_| GrantError::InvalidLegacySnapshot)?,
                )
                .ok_or(GrantError::InvalidLegacySnapshot)?;
                legacy_tags.push(tag);
            }
        }

        let mut set = Self::new(context);
        let bound_present = legacy_bound.is_some();
        for key in keys {
            let incarnation = set.next_incarnation;
            set.next_incarnation = set
                .next_incarnation
                .checked_add(1)
                .ok_or(GrantError::CounterExhausted)?;
            set.members.push(Member {
                key,
                incarnation,
                revision: 0,
                legacy_eligible: true,
                legacy_revoked_tags: Vec::new(),
                legacy_bound_approved: bound_present,
            });
        }
        set.legacy_tags = legacy_tags;
        set.legacy_bound = legacy_bound;
        Ok(set)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn grant_count(&self) -> usize {
        self.explicit_grants.len()
    }

    fn find_member(&self, key: &[u8; 32]) -> Option<usize> {
        self.members.iter().position(|m| &m.key == key)
    }

    fn tag_of(identity: &[u8; 32]) -> [u8; 8] {
        let mut t = [0u8; 8];
        t.copy_from_slice(&identity[..8]);
        t
    }

    /// Add a new client key. Returns `true` if added, `false` if it already
    /// existed. Ninth distinct key returns `ClientCapacity` with no mutation.
    pub fn add_client(&mut self, key: [u8; 32]) -> Result<bool, GrantError> {
        if self.find_member(&key).is_some() {
            return Ok(false);
        }
        if self.members.len() >= MAX_CLIENTS {
            return Err(GrantError::ClientCapacity);
        }
        let incarnation = self.next_incarnation;
        let next = self
            .next_incarnation
            .checked_add(1)
            .ok_or(GrantError::CounterExhausted)?;
        self.next_incarnation = next;
        self.members.push(Member {
            key,
            incarnation,
            revision: 0,
            legacy_eligible: false,
            legacy_revoked_tags: Vec::new(),
            legacy_bound_approved: false,
        });
        Ok(true)
    }

    /// Remove a client. Returns `true` if it existed. Removes all grants and
    /// legacy eligibility. A re-added identical key gets a new incarnation
    /// and no authority. `next_incarnation` is preserved.
    pub fn remove_client(&mut self, key: &[u8; 32]) -> Result<bool, GrantError> {
        let Some(idx) = self.find_member(key) else {
            return Ok(false);
        };
        self.members.remove(idx);
        self.explicit_grants.retain(|(c, _)| c != key);
        Ok(true)
    }

    /// Exact membership + identity authority check.
    pub fn allows(&self, client: &[u8; 32], identity: &[u8; 32]) -> bool {
        let Some(idx) = self.find_member(client) else {
            return false;
        };
        let m = &self.members[idx];

        // Grandfathered legacy path.
        if m.legacy_eligible {
            let tag = Self::tag_of(identity);

            // Tag-based legacy approval, withdrawn if this exact tag was revoked.
            if self.legacy_tags.iter().any(|t| t == &tag) {
                let tag_revoked = m.legacy_revoked_tags.iter().any(|t| t == &tag);
                if !tag_revoked {
                    return true;
                }
            }

            // Exact bound-identity approval, independent of tag revocation.
            // Only the bound identity itself matches; unrelated identities
            // sharing a tag prefix are not covered by this path.
            if m.legacy_bound_approved {
                if let Some(ref b) = self.legacy_bound {
                    if b == identity {
                        return true;
                    }
                }
            }
        }

        // New explicit grants: exact full-key match.
        self.explicit_grants
            .iter()
            .any(|(c, i)| c == client && i == identity)
    }

    /// Issue a ticket for a pending approval. Does not require the identity to
    /// be currently allowed. Returns `UnknownClient` if the client is not a
    /// member.
    pub fn issue_ticket(
        &self,
        client: &[u8; 32],
        identity: [u8; 32],
    ) -> Result<ApprovalTicket, GrantError> {
        let Some(idx) = self.find_member(client) else {
            return Err(GrantError::UnknownClient);
        };
        let m = &self.members[idx];
        Ok(ApprovalTicket {
            context: self.context,
            set_revision: self.set_revision,
            client: *client,
            incarnation: m.incarnation,
            client_revision: m.revision,
            identity,
        })
    }

    /// Validate that a ticket still refers to the current context, set
    /// revision, membership, and client revision.
    pub fn validate_ticket(&self, ticket: &ApprovalTicket) -> Result<(), GrantError> {
        if ticket.context != self.context {
            return Err(GrantError::StaleTicket);
        }
        if ticket.set_revision != self.set_revision {
            return Err(GrantError::StaleTicket);
        }
        let Some(idx) = self.find_member(&ticket.client) else {
            return Err(GrantError::UnknownClient);
        };
        let m = &self.members[idx];
        if m.incarnation != ticket.incarnation || m.revision != ticket.client_revision {
            return Err(GrantError::StaleTicket);
        }
        Ok(())
    }

    /// Apply a validated ticket. Returns `true` if a new explicit grant was
    /// inserted, `false` if the identity was already allowed. Capacity error
    /// leaves the set unchanged (ticket still valid).
    pub fn approve(&mut self, ticket: &ApprovalTicket) -> Result<bool, GrantError> {
        self.validate_ticket(ticket)?;
        if self.allows(&ticket.client, &ticket.identity) {
            return Ok(false);
        }
        if self.explicit_grants.len() >= MAX_EXPLICIT_GRANTS {
            return Err(GrantError::IdentityCapacity);
        }
        self.explicit_grants.push((ticket.client, ticket.identity));
        Ok(true)
    }

    /// Revoke authority for `(client, identity)`. Bumps the client's
    /// revision (invalidating pending tickets) even if nothing matches.
    /// Returns whether effective authority changed.
    ///
    /// Semantics:
    /// - Removes any exact explicit grant for `(client, identity)`.
    /// - If `(client, identity)` is currently covered by a legacy tag, that
    ///   tag is revoked for this member (conservative; withdraws all
    ///   identities sharing the tag).
    /// - If `identity` equals the bound identity and this member has bound
    ///   approval, the bound flag is cleared for this member. This is
    ///   independent of tag revocation: revoking an unrelated identity whose
    ///   tag collides with the bound prefix does not erase the exact bound
    ///   approval. Revoking the bound identity itself removes both its legacy
    ///   tag coverage (if any) and its bound flag.
    ///
    /// All possible errors are preflighted before any mutation.
    pub fn revoke_identity(
        &mut self,
        client: &[u8; 32],
        identity: &[u8; 32],
    ) -> Result<bool, GrantError> {
        let Some(idx) = self.find_member(client) else {
            return Err(GrantError::UnknownClient);
        };

        // --- Preflight (no mutation) ---

        // Revision bump must not overflow.
        let new_rev = self.members[idx]
            .revision
            .checked_add(1)
            .ok_or(GrantError::CounterExhausted)?;

        let tag = Self::tag_of(identity);
        let m = &self.members[idx];

        let already_tag_revoked = m.legacy_revoked_tags.iter().any(|t| t == &tag);
        let tag_approved_by_legacy = self.legacy_tags.iter().any(|t| t == &tag);
        let bound_matches = m.legacy_bound_approved
            && self
                .legacy_bound
                .as_ref()
                .map(|b| b == identity)
                .unwrap_or(false);

        // Whether we will need to push a revoked tag, and whether that push
        // would exceed MAX_LEGACY_TAGS (defensive; snapshot cap should
        // prevent this, but we honor the bound atomically).
        let will_push_tag = m.legacy_eligible && tag_approved_by_legacy && !already_tag_revoked;
        if will_push_tag && m.legacy_revoked_tags.len() >= MAX_LEGACY_TAGS {
            return Err(GrantError::InvalidLegacySnapshot);
        }

        let exact_grant_present = self
            .explicit_grants
            .iter()
            .any(|(c, i)| c == client && i == identity);

        // --- Mutations (once, after all preflight) ---

        let mut changed = false;

        if exact_grant_present {
            self.explicit_grants
                .retain(|(c, i)| !(c == client && i == identity));
            changed = true;
        }

        if will_push_tag {
            // Tag-based legacy withdrawal.
            changed = true;
        }

        if bound_matches {
            changed = true;
        }

        {
            let m = &mut self.members[idx];
            if will_push_tag {
                m.legacy_revoked_tags.push(tag);
            }
            if bound_matches {
                m.legacy_bound_approved = false;
            }
            m.revision = new_rev;
        }

        Ok(changed)
    }

    /// Clear a client's authority but keep membership. Always bumps the
    /// client revision (invalidating tickets), even if nothing else changed.
    pub fn clear_client(&mut self, client: &[u8; 32]) -> Result<bool, GrantError> {
        let Some(idx) = self.find_member(client) else {
            return Err(GrantError::UnknownClient);
        };
        let new_rev = self.members[idx]
            .revision
            .checked_add(1)
            .ok_or(GrantError::CounterExhausted)?;

        let mut changed = false;

        let before_len = self.explicit_grants.len();
        self.explicit_grants.retain(|(c, _)| c != client);
        if self.explicit_grants.len() != before_len {
            changed = true;
        }

        {
            let m = &mut self.members[idx];
            if m.legacy_eligible {
                m.legacy_eligible = false;
                changed = true;
            }
            if m.legacy_bound_approved {
                m.legacy_bound_approved = false;
                changed = true;
            }
            if !m.legacy_revoked_tags.is_empty() {
                m.legacy_revoked_tags.clear();
                changed = true;
            }
        }

        self.members[idx].revision = new_rev;
        Ok(changed)
    }

    /// Bump the set revision without changing any grants. Callers must use
    /// this on relevant external policy changes.
    pub fn invalidate_all(&mut self) -> Result<(), GrantError> {
        self.set_revision = self
            .set_revision
            .checked_add(1)
            .ok_or(GrantError::CounterExhausted)?;
        Ok(())
    }

    /// Clear all membership, grants, and legacy data. Bumps the set revision
    /// so any pending ticket against the prior revision is stale rather than
    /// merely unknown-client. Preserves `next_incarnation`. No pending ticket
    /// can restore authority.
    pub fn clear_all(&mut self) -> Result<(), GrantError> {
        let new_rev = self
            .set_revision
            .checked_add(1)
            .ok_or(GrantError::CounterExhausted)?;
        self.set_revision = new_rev;
        self.members.clear();
        self.legacy_tags.clear();
        self.legacy_bound = None;
        self.explicit_grants.clear();
        Ok(())
    }
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ConnectSlot;
    use alloc::string::String;

    fn ctx(lifetime_byte: u8) -> GrantContext {
        GrantContext {
            master_pubkey: [0x11; 32],
            slot_fingerprint: [0x22; 32],
            lifetime: [lifetime_byte; 32],
        }
    }

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn hex32(b: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            s.push('0');
            s.push(char::from_digit(b as u32, 16).unwrap());
        }
        s
    }

    /// Produce a 16-char lowercase hex string representing the full 8 bytes
    /// all equal to `b`: e.g. `hex8(0x07) == "0707070707070707"`.
    fn hex8(b: u8) -> String {
        let mut s = String::with_capacity(16);
        for _ in 0..8 {
            s.push(char::from_digit(((b >> 4) & 0xf) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }

    /// Build a 32-byte identity whose first 8 bytes equal `prefix` and whose
    /// remaining 24 bytes are all `tail`.
    fn id_with_prefix(prefix: [u8; 8], tail: u8) -> [u8; 32] {
        let mut id = [tail; 32];
        id[..8].copy_from_slice(&prefix);
        id
    }

    fn empty_slot() -> ConnectSlot {
        ConnectSlot {
            slot_index: 0,
            label: String::new(),
            secret: String::new(),
            current_pubkey: None,
            allowed_methods: Vec::new(),
            allowed_kinds: Vec::new(),
            auto_approve: false,
            signing_approved: false,
            strict_permissions: false,
            authorized_pubkeys: Vec::new(),
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: None,
            approved_identities: String::new(),
            was_bound: false,
            client_grants: None,
        }
    }

    #[test]
    fn test_new_set_is_empty() {
        let s = GrantSet::new(ctx(1));
        assert_eq!(s.member_count(), 0);
        assert_eq!(s.grant_count(), 0);
        assert!(!s.allows(&key(1), &key(2)));
    }

    #[test]
    fn test_add_client_and_idempotent() {
        let mut s = GrantSet::new(ctx(1));
        assert!(s.add_client(key(1)).unwrap());
        assert!(!s.add_client(key(1)).unwrap());
        assert_eq!(s.member_count(), 1);
    }

    #[test]
    fn test_client_capacity_8_9_and_unchanged() {
        let mut s = GrantSet::new(ctx(1));
        for i in 0..8u8 {
            assert!(s.add_client(key(i)).unwrap());
        }
        let before = s.clone();
        assert_eq!(
            s.add_client(key(9)).unwrap_err(),
            GrantError::ClientCapacity
        );
        assert_eq!(s, before);
    }

    #[test]
    fn test_explicit_capacity_16_and_dup_idempotent() {
        let mut s = GrantSet::new(ctx(1));
        assert!(s.add_client(key(1)).unwrap());
        for i in 0..16u8 {
            let t = s.issue_ticket(&key(1), key(i)).unwrap();
            assert!(s.approve(&t).unwrap());
        }
        assert_eq!(s.grant_count(), 16);
        // 17th distinct
        let t = s.issue_ticket(&key(1), key(17)).unwrap();
        let before = s.clone();
        assert_eq!(s.approve(&t).unwrap_err(), GrantError::IdentityCapacity);
        assert_eq!(s, before);
        // duplicate of one already present is idempotent false
        let t2 = s.issue_ticket(&key(1), key(0)).unwrap();
        assert!(!s.approve(&t2).unwrap());
    }

    #[test]
    fn test_from_legacy_preserves_members_and_bound_only() {
        let mut slot = empty_slot();
        slot.current_pubkey = Some(hex32(0xa));
        slot.authorized_pubkeys.push(hex32(0xa)); // dedup with current
        slot.authorized_pubkeys.push(hex32(0xb));
        slot.bound_identity = Some(hex32(0xc));
        let s = GrantSet::from_legacy(ctx(2), &slot).unwrap();
        assert_eq!(s.member_count(), 2);
        // Bound-only legacy path for identity 0xc
        assert!(s.allows(&key(0xa), &key(0xc)));
        assert!(s.allows(&key(0xb), &key(0xc)));
        // An unrelated identity does not match.
        assert!(!s.allows(&key(0xa), &key(0xd)));
        // Unknown client C does not match.
        assert!(!s.allows(&key(0xc), &key(0xc)));
    }

    #[test]
    fn test_from_legacy_tagged_approval_and_prefix_collision() {
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0x1));
        // Legacy tags are full 8-byte prefixes (16 hex chars each).
        slot.approved_identities = format!("{}{}", hex8(0x07), hex8(0x09));
        let s = GrantSet::from_legacy(ctx(3), &slot).unwrap();

        // Identity whose first 8 bytes are exactly 0x0707070707070707.
        let id_a = id_with_prefix([0x07; 8], 0x00);
        // A colliding identity with same 8-byte prefix but different tail.
        let id_b = id_with_prefix([0x07; 8], 0xff);

        assert!(s.allows(&key(0x1), &id_a));
        // Documented: prefix collision matches grandfathered legacy path.
        assert!(s.allows(&key(0x1), &id_b));
    }

    #[test]
    fn test_from_legacy_member_with_zero_grants_then_add_client_empty() {
        // Migrated snapshot: bound + legacy tags, but zero existing clients.
        let mut slot = empty_slot();
        slot.approved_identities = hex8(0x07);
        slot.bound_identity = Some(hex32(0xc));

        let mut s = GrantSet::from_legacy(ctx(3), &slot).unwrap();
        assert_eq!(s.member_count(), 0);
        assert_eq!(s.grant_count(), 0);

        // Add a client to the SAME set (not a fresh set). It must not inherit
        // legacy tag or bound authority.
        assert!(s.add_client(key(1)).unwrap());
        let tag_id = id_with_prefix([0x07; 8], 0x00);
        assert!(!s.allows(&key(1), &tag_id));
        assert!(!s.allows(&key(1), &key(0xc)));
        assert!(!s.allows(&key(1), &key(0xd)));
    }

    #[test]
    fn test_from_legacy_malformed_inputs_rejected() {
        // short current pubkey
        let mut slot = empty_slot();
        slot.current_pubkey = Some("abc".into());
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // uppercase not allowed (contract: lowercase only)
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push("AB".repeat(32));
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // bad approved_identities length (not multiple of 16)
        let mut slot = empty_slot();
        slot.approved_identities = "abcd".into();
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // non-hex tag
        let mut slot = empty_slot();
        slot.approved_identities = "zz00000000000000".into();
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // overcap approved_identities (17 tags)
        let mut slot = empty_slot();
        let mut ids = String::new();
        for _ in 0..17 {
            ids.push_str(&hex8(0x01));
        }
        slot.approved_identities = ids;
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // overcap authorized keys (9 distinct)
        let mut slot = empty_slot();
        for i in 0..9u8 {
            slot.authorized_pubkeys.push(hex32(i + 1));
        }
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // bound_identity malformed / non-ASCII
        let mut slot = empty_slot();
        slot.bound_identity = Some("not-hex-not-32-bytes".into());
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );

        // current_pubkey non-ASCII
        let mut slot = empty_slot();
        slot.current_pubkey = Some("é".repeat(32));
        assert_eq!(
            GrantSet::from_legacy(ctx(1), &slot).unwrap_err(),
            GrantError::InvalidLegacySnapshot
        );
    }

    #[test]
    fn test_remove_client_readd_new_incarnation_and_no_authority() {
        let mut s = GrantSet::new(ctx(4));
        assert!(s.add_client(key(1)).unwrap());
        let t = s.issue_ticket(&key(1), key(2)).unwrap();
        assert!(s.approve(&t).unwrap());
        assert!(s.allows(&key(1), &key(2)));

        assert!(s.remove_client(&key(1)).unwrap());
        assert!(!s.allows(&key(1), &key(2)));

        // Re-add: fresh incarnation, no grants.
        assert!(s.add_client(key(1)).unwrap());
        assert!(!s.allows(&key(1), &key(2)));

        // Old ticket must be stale (incarnation differs).
        assert_eq!(s.validate_ticket(&t).unwrap_err(), GrantError::StaleTicket);
    }

    #[test]
    fn test_revoke_identity_absent_still_stales_pending_ticket() {
        let mut s = GrantSet::new(ctx(5));
        assert!(s.add_client(key(1)).unwrap());
        let t = s.issue_ticket(&key(1), key(99)).unwrap();
        // Identity never allowed; revoke must still bump revision.
        assert!(!s.revoke_identity(&key(1), &key(99)).unwrap());
        // Ticket is now stale.
        assert_eq!(s.validate_ticket(&t).unwrap_err(), GrantError::StaleTicket);
        assert_eq!(s.approve(&t).unwrap_err(), GrantError::StaleTicket);
    }

    #[test]
    fn test_revoke_identity_legacy_tag_and_bound() {
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0x1));
        slot.approved_identities = hex8(0x07);
        slot.bound_identity = Some(hex32(0xc));
        let mut s = GrantSet::from_legacy(ctx(6), &slot).unwrap();

        let id_a = id_with_prefix([0x07; 8], 0x00);
        let id_b = id_with_prefix([0x07; 8], 0xee);

        // Both prefix-matching identities currently allowed via tag.
        assert!(s.allows(&key(0x1), &id_a));
        assert!(s.allows(&key(0x1), &id_b));

        // Revoking id_a conservatively withdraws the whole tag.
        assert!(s.revoke_identity(&key(0x1), &id_a).unwrap());
        assert!(!s.allows(&key(0x1), &id_a));
        assert!(!s.allows(&key(0x1), &id_b));

        // Bound identity path can be withdrawn.
        assert!(s.allows(&key(0x1), &key(0xc)));
        assert!(s.revoke_identity(&key(0x1), &key(0xc)).unwrap());
        assert!(!s.allows(&key(0x1), &key(0xc)));
    }

    #[test]
    fn test_revoke_unrelated_legacy_prefix_does_not_erase_exact_bound() {
        // Exact bound identity is approved. An unrelated identity whose
        // 8-byte prefix equals the bound identity's prefix is revoked. That
        // must not erase the exact bound approval.
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0x1));
        slot.bound_identity = Some(hex32(0xc));
        let mut s = GrantSet::from_legacy(ctx(6), &slot).unwrap();

        // Bound identity itself is allowed.
        assert!(s.allows(&key(0x1), &key(0xc)));

        // Unrelated identity whose 8-byte prefix collides with 0xc's.
        let collide = id_with_prefix([0x0c; 8], 0xff);
        assert_ne!(collide, key(0xc));

        // Revoke the unrelated identity. Legacy path does not tag-cover it
        // (no legacy tags), and it is not the bound identity, so no change to
        // bound approval.
        assert!(!s.revoke_identity(&key(0x1), &collide).unwrap());

        // Exact bound identity is STILL allowed.
        assert!(s.allows(&key(0x1), &key(0xc)));

        // Now revoke the bound identity itself: removes bound flag.
        assert!(s.revoke_identity(&key(0x1), &key(0xc)).unwrap());
        assert!(!s.allows(&key(0x1), &key(0xc)));
    }

    #[test]
    fn test_clear_client_keeps_membership_and_isolates_others() {
        let mut s = GrantSet::new(ctx(7));
        assert!(s.add_client(key(1)).unwrap());
        assert!(s.add_client(key(2)).unwrap());
        let t2 = s.issue_ticket(&key(2), key(9)).unwrap();
        assert!(s.approve(&t2).unwrap());

        let t1 = s.issue_ticket(&key(1), key(9)).unwrap();
        assert!(s.approve(&t1).unwrap());

        assert!(s.clear_client(&key(1)).unwrap());
        assert_eq!(s.member_count(), 2); // both still members
        assert!(!s.allows(&key(1), &key(9)));
        // Other member unaffected.
        assert!(s.allows(&key(2), &key(9)));
        // Ticket for cleared client is stale.
        assert_eq!(s.validate_ticket(&t1).unwrap_err(), GrantError::StaleTicket);
        // Ticket for the other client still valid.
        assert!(s.validate_ticket(&t2).is_ok());
    }

    #[test]
    fn test_ticket_context_and_set_revision_validation() {
        let mut s = GrantSet::new(ctx(8));
        assert!(s.add_client(key(1)).unwrap());
        let t = s.issue_ticket(&key(1), key(2)).unwrap();

        // Same client membership in both sets, but differing master/slot/
        // lifetime: failure reason must be context mismatch, not membership.
        let mut other_ctx = ctx(8);
        other_ctx.master_pubkey = [0x33; 32];
        other_ctx.slot_fingerprint = [0x44; 32];
        other_ctx.lifetime = [0x55; 32];
        let mut s_other = GrantSet::new(other_ctx);
        assert!(s_other.add_client(key(1)).unwrap());
        assert_eq!(
            s_other.validate_ticket(&t).unwrap_err(),
            GrantError::StaleTicket
        );

        // Differing master only.
        let mut ctx_master = ctx(8);
        ctx_master.master_pubkey = [0x77; 32];
        let mut s_master = GrantSet::new(ctx_master);
        assert!(s_master.add_client(key(1)).unwrap());
        assert_eq!(
            s_master.validate_ticket(&t).unwrap_err(),
            GrantError::StaleTicket
        );

        // Differing slot only.
        let mut ctx_slot = ctx(8);
        ctx_slot.slot_fingerprint = [0x88; 32];
        let mut s_slot = GrantSet::new(ctx_slot);
        assert!(s_slot.add_client(key(1)).unwrap());
        assert_eq!(
            s_slot.validate_ticket(&t).unwrap_err(),
            GrantError::StaleTicket
        );

        // Same context, differing set_revision -> stale.
        let mut s2 = GrantSet::new(ctx(8));
        assert!(s2.add_client(key(1)).unwrap());
        s2.invalidate_all().unwrap();
        assert_eq!(s2.validate_ticket(&t).unwrap_err(), GrantError::StaleTicket);

        // Same context, same set_revision, but unknown client -> UnknownClient.
        let s3 = GrantSet::new(ctx(8));
        assert_eq!(
            s3.validate_ticket(&t).unwrap_err(),
            GrantError::UnknownClient
        );

        // invalidate_all invalidates existing tickets.
        s.invalidate_all().unwrap();
        assert_eq!(s.validate_ticket(&t).unwrap_err(), GrantError::StaleTicket);
    }

    #[test]
    fn test_clear_all_bumps_revision_so_ticket_is_stale_not_unknown() {
        let mut s = GrantSet::new(ctx(10));
        assert!(s.add_client(key(1)).unwrap());
        let t = s.issue_ticket(&key(1), key(2)).unwrap();
        let incarnation_used_before = s.next_incarnation_observed_for_test();

        s.clear_all().unwrap();
        assert_eq!(s.member_count(), 0);
        assert_eq!(s.grant_count(), 0);
        // Set revision was bumped, so the pending ticket is StaleTicket (not
        // UnknownClient — the revision mismatch is detected first).
        assert_eq!(s.validate_ticket(&t).unwrap_err(), GrantError::StaleTicket);

        // Re-add: incarnation must be >= prior counter (monotonic).
        assert!(s.add_client(key(1)).unwrap());
        assert!(s.next_incarnation_observed_for_test() > incarnation_used_before);
    }

    #[test]
    fn test_incarnation_overflow_fails_unchanged() {
        let mut s = GrantSet::new(ctx(11));
        s.force_next_incarnation_for_test(u64::MAX);
        let before = s.clone();
        assert_eq!(
            s.add_client(key(1)).unwrap_err(),
            GrantError::CounterExhausted
        );
        assert_eq!(s, before);
    }

    #[test]
    fn test_set_revision_overflow_fails_unchanged() {
        let mut s = GrantSet::new(ctx(12));
        assert!(s.add_client(key(1)).unwrap());
        s.force_set_revision_for_test(u64::MAX);
        let before = s.clone();
        assert_eq!(s.clear_all().unwrap_err(), GrantError::CounterExhausted);
        assert_eq!(s, before);
        assert_eq!(
            s.invalidate_all().unwrap_err(),
            GrantError::CounterExhausted
        );
        assert_eq!(s, before);
    }

    #[test]
    fn test_client_revision_overflow_fails_unchanged() {
        let mut s = GrantSet::new(ctx(13));
        assert!(s.add_client(key(1)).unwrap());
        s.force_client_revision_for_test(&key(1), u64::MAX);
        let before = s.clone();
        assert_eq!(
            s.revoke_identity(&key(1), &key(2)).unwrap_err(),
            GrantError::CounterExhausted
        );
        assert_eq!(s, before);
        assert_eq!(
            s.clear_client(&key(1)).unwrap_err(),
            GrantError::CounterExhausted
        );
        assert_eq!(s, before);
    }

    #[test]
    fn test_new_full_identity_distinguishes_after_collision() {
        // Legacy grants tag 0x07 (via prefix). A new explicit grant for a full
        // identity sharing that tag must only allow the exact full identity.
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0x1));
        slot.approved_identities = hex8(0x07);
        let mut s = GrantSet::from_legacy(ctx(14), &slot).unwrap();

        let id_a = id_with_prefix([0x07; 8], 0x00);
        let id_b = id_with_prefix([0x07; 8], 0xaa);

        // Clear legacy first so we test explicit-only path.
        s.clear_client(&key(0x1)).unwrap();
        assert!(!s.allows(&key(0x1), &id_a));
        assert!(!s.allows(&key(0x1), &id_b));

        let t = s.issue_ticket(&key(0x1), id_a).unwrap();
        assert!(s.approve(&t).unwrap());
        assert!(s.allows(&key(0x1), &id_a));
        // Same tag, different full identity: not allowed.
        assert!(!s.allows(&key(0x1), &id_b));
    }

    #[test]
    fn test_migrate_ab_legacy_tag_bound_then_add_c_no_inheritance() {
        // Legacy snapshot: two members A and B, with a legacy tag and a bound
        // identity. Neither A nor B must inherit anything beyond legacy paths.
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0xa));
        slot.authorized_pubkeys.push(hex32(0xb));
        slot.approved_identities = hex8(0x07);
        slot.bound_identity = Some(hex32(0xc));
        let mut s = GrantSet::from_legacy(ctx(20), &slot).unwrap();
        assert_eq!(s.member_count(), 2);

        let tag_id = id_with_prefix([0x07; 8], 0x00);
        // A and B are covered by tag and by bound identity.
        assert!(s.allows(&key(0xa), &tag_id));
        assert!(s.allows(&key(0xb), &tag_id));
        assert!(s.allows(&key(0xa), &key(0xc)));
        assert!(s.allows(&key(0xb), &key(0xc)));

        // Ticket for A before adding C. Adding C must not invalidate it.
        let t_a = s.issue_ticket(&key(0xa), key(0xd)).unwrap();

        // Add new client C.
        assert!(s.add_client(key(0xc)).unwrap());
        assert_eq!(s.member_count(), 3);

        // A and B unchanged: still allowed via legacy paths.
        assert!(s.allows(&key(0xa), &tag_id));
        assert!(s.allows(&key(0xb), &tag_id));
        assert!(s.allows(&key(0xa), &key(0xc)));
        assert!(s.allows(&key(0xb), &key(0xc)));

        // C does not inherit legacy tag or bound authority.
        assert!(!s.allows(&key(0xc), &tag_id));
        assert!(!s.allows(&key(0xc), &key(0xc)));
        assert!(!s.allows(&key(0xc), &key(0xd)));

        // Adding C must not invalidate pending ticket for A.
        assert!(s.validate_ticket(&t_a).is_ok());

        // Approve a full identity for C. Must not broaden A or B.
        let t_c = s.issue_ticket(&key(0xc), key(0xd)).unwrap();
        assert!(s.approve(&t_c).unwrap());
        assert!(s.allows(&key(0xc), &key(0xd)));
        // A and B do not gain key(0xd).
        assert!(!s.allows(&key(0xa), &key(0xd)));
        assert!(!s.allows(&key(0xb), &key(0xd)));

        // Ticket for A still valid after C's approval.
        assert!(s.validate_ticket(&t_a).is_ok());
    }

    #[test]
    fn test_per_client_legacy_revocation_and_readd_no_resurrection() {
        // Two members, both legacy-eligible with the same legacy tag. Revoke
        // the tag for member A. Remove and re-add A. A must not resurrect
        // legacy authority. Member B must remain unaffected throughout.
        let mut slot = empty_slot();
        slot.authorized_pubkeys.push(hex32(0xa));
        slot.authorized_pubkeys.push(hex32(0xb));
        slot.approved_identities = hex8(0x07);
        let mut s = GrantSet::from_legacy(ctx(21), &slot).unwrap();

        let tag_id = id_with_prefix([0x07; 8], 0x00);
        assert!(s.allows(&key(0xa), &tag_id));
        assert!(s.allows(&key(0xb), &tag_id));

        // Revoke tag for A only.
        assert!(s.revoke_identity(&key(0xa), &tag_id).unwrap());
        assert!(!s.allows(&key(0xa), &tag_id));
        // B unchanged.
        assert!(s.allows(&key(0xb), &tag_id));

        // Remove and re-add A.
        assert!(s.remove_client(&key(0xa)).unwrap());
        assert!(s.add_client(key(0xa)).unwrap());
        // A has no legacy authority after re-add.
        assert!(!s.allows(&key(0xa), &tag_id));
        // B still unaffected.
        assert!(s.allows(&key(0xb), &tag_id));
    }

    #[test]
    fn test_capacity_released_by_revoke() {
        let mut s = GrantSet::new(ctx(22));
        assert!(s.add_client(key(1)).unwrap());

        // Fill explicit grants to capacity.
        for i in 0..16u8 {
            let t = s.issue_ticket(&key(1), key(i)).unwrap();
            assert!(s.approve(&t).unwrap());
        }
        assert_eq!(s.grant_count(), 16);

        // At capacity: a new identity fails.
        let t_new = s.issue_ticket(&key(1), key(0xfe)).unwrap();
        assert_eq!(s.approve(&t_new).unwrap_err(), GrantError::IdentityCapacity);

        // Revoke one grant -> capacity is released.
        assert!(s.revoke_identity(&key(1), &key(0)).unwrap());
        assert_eq!(s.grant_count(), 15);

        // The previously pending ticket was issued before the revoke, so its
        // client_revision is now stale. Re-issue and approve.
        let t_retry = s.issue_ticket(&key(1), key(0xfe)).unwrap();
        assert!(s.approve(&t_retry).unwrap());
        assert_eq!(s.grant_count(), 16);
        assert!(s.allows(&key(1), &key(0xfe)));
    }

    #[test]
    fn test_unknown_client_operations_are_error_and_unchanged() {
        let mut s = GrantSet::new(ctx(23));
        assert!(s.add_client(key(1)).unwrap());
        let before = s.clone();

        assert_eq!(
            s.revoke_identity(&key(2), &key(3)).unwrap_err(),
            GrantError::UnknownClient
        );
        assert_eq!(s, before);

        assert_eq!(
            s.clear_client(&key(2)).unwrap_err(),
            GrantError::UnknownClient
        );
        assert_eq!(s, before);

        assert_eq!(
            s.issue_ticket(&key(2), key(3)).unwrap_err(),
            GrantError::UnknownClient
        );
        assert_eq!(s, before);
    }

    #[test]
    fn revoking_an_uninherited_legacy_tag_only_invalidates_tickets() {
        for previously_grandfathered in [false, true] {
            let mut slot = empty_slot();
            slot.authorized_pubkeys.push(hex32(1));
            slot.approved_identities = hex8(7);
            let mut set = GrantSet::from_legacy(ctx(24), &slot).unwrap();
            let client = if previously_grandfathered {
                set.clear_client(&key(1)).unwrap();
                key(1)
            } else {
                set.add_client(key(2)).unwrap();
                key(2)
            };
            let identity = id_with_prefix([7; 8], 0xaa);
            let ticket = set.issue_ticket(&client, identity).unwrap();
            assert!(!set.allows(&client, &identity));
            assert_eq!(set.revoke_identity(&client, &identity), Ok(false));
            assert!(!set.allows(&client, &identity));
            assert_eq!(set.approve(&ticket), Err(GrantError::StaleTicket));
        }
    }

    // --- test-only accessors / mutators (never affect production semantics) ---

    impl GrantSet {
        fn next_incarnation_observed_for_test(&self) -> u64 {
            self.next_incarnation
        }
        fn force_next_incarnation_for_test(&mut self, v: u64) {
            self.next_incarnation = v;
        }
        fn force_set_revision_for_test(&mut self, v: u64) {
            self.set_revision = v;
        }
        fn force_client_revision_for_test(&mut self, key: &[u8; 32], v: u64) {
            if let Some(idx) = self.find_member(key) {
                self.members[idx].revision = v;
            }
        }
    }
}
