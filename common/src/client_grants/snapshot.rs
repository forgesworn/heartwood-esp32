// common/src/client_grants/snapshot.rs
//!
//! Compact durable snapshot adapter for `GrantSet`.
//!
//! **Durable authority only.** A `GrantSnapshot` captures membership, legacy
//! eligibility/revocations, the bound identity, and explicit grants. It never
//! captures the live `GrantContext`, lifetime, tickets, revisions, or
//! incarnations. Restoring always requires a caller-supplied fresh
//! `GrantContext` (fresh `lifetime`) and reconstructs counters from scratch.
//!
//! Snapshot clone is a plain data clone, not a live `GrantSet` clone; a cloned
//! snapshot contains no live tickets.
//!
//! The adapter reuses `GrantSet` mutation logic for its public `add_client`,
//! `remove_client`, `approve`, `revoke_identity` and `clear_client` methods by
//! operating on a private, in-memory `GrantSet` constructed from an internal
//! constant context. That `GrantSet` is private to the adapter and its tickets
//! are never returned, stored, or reachable to any caller — so no ticket from
//! this adapter can be observed or replayed. The firmware's actual pending
//! approval requests are guarded separately by runtime authority epochs, not by
//! this adapter.

use alloc::string::String;
use alloc::vec::Vec;

use super::{GrantContext, GrantError, GrantSet};

/// Firmware's `ConnectSlot` (re-export via the parent module or `crate::policy`).
use crate::policy::ConnectSlot;

// --- caps -------------------------------------------------------------------

use super::{MAX_CLIENTS as MAX_MEMBERS, MAX_LEGACY_TAGS, MAX_EXPLICIT_GRANTS as MAX_EXPLICIT};

/// Byte size of a fully populated snapshot before hex encoding.
const MAX_BINARY: usize = 973;
/// Hex-encoded length of a fully populated snapshot.
const MAX_HEX: usize = MAX_BINARY * 2;

const VERSION: u8 = 1;

// --- bit flags --------------------------------------------------------------

const FLAG_LEGACY_ELIGIBLE: u8 = 0b0000_0001;
const FLAG_LEGACY_BOUND_APPROVED: u8 = 0b0000_0010;
const FLAG_KNOWN: u8 = FLAG_LEGACY_ELIGIBLE | FLAG_LEGACY_BOUND_APPROVED;

// --- internal constant context ----------------------------------------------

/// Internal-only context used to drive a private `GrantSet` for mutation
/// preflight/replay. Never exposed; tickets issued under this context remain
/// inside `SnapshotState` and are discarded. Restored snapshots always use the
/// caller's fresh context.
const INTERNAL_CTX: GrantContext = GrantContext {
    master_pubkey: [0u8; 32],
    slot_fingerprint: [0u8; 32],
    lifetime: [0u8; 32],
};

// --- hex helpers ------------------------------------------------------------

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// --- snapshot struct --------------------------------------------------------

/// Durable, cloneable, comparable authority snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantSnapshot {
    // Members in insertion order; order is stable in encoding.
    members: Vec<SnapMember>,
    legacy_tags: Vec<[u8; 8]>,
    legacy_bound: Option<[u8; 32]>,
    // (member index, identity) pairs. Index is into `members`.
    explicit: Vec<(u8, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapMember {
    key: [u8; 32],
    flags: u8,
    // Bitmask indexed by `legacy_tags` position for legacy-revoked tags.
    revoked_mask: u16,
}

// --- GrantSnapshot impl -----------------------------------------------------

impl GrantSnapshot {
    /// Empty snapshot.
    pub fn empty() -> Self {
        GrantSnapshot {
            members: Vec::new(),
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: Vec::new(),
        }
    }

    /// Snapshot legacy authority from a firmware `ConnectSlot`.
    ///
    /// Only existing members receive legacy eligibility. `legacy_bound_approved`
    /// is set only when the slot's bound identity is present.
    pub fn from_legacy(slot: &ConnectSlot) -> Result<Self, GrantError> {
        // Reuse core legacy capture; then adapt flags to include the bound bit.
        // `GrantSet::from_legacy` uses `InvalidLegacySnapshot` for decode
        // failures and capacity overflow.
        let set = GrantSet::from_legacy(INTERNAL_CTX, slot)?;

        let mut members: Vec<SnapMember> = Vec::with_capacity(set.members.len());
        for m in &set.members {
            let mut flags = 0u8;
            if m.legacy_eligible {
                flags |= FLAG_LEGACY_ELIGIBLE;
            }
            if m.legacy_bound_approved {
                flags |= FLAG_LEGACY_BOUND_APPROVED;
            }
            members.push(SnapMember {
                key: m.key,
                flags,
                revoked_mask: 0,
            });
        }

        Ok(GrantSnapshot {
            members,
            legacy_tags: set.legacy_tags,
            legacy_bound: set.legacy_bound,
            explicit: Vec::new(),
        })
    }

    /// Number of members in the snapshot.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Number of explicit grants in the snapshot.
    pub fn grant_count(&self) -> usize {
        self.explicit.len()
    }

    /// Keys of all members, in encoding order.
    pub fn client_keys(&self) -> Vec<[u8; 32]> {
        self.members.iter().map(|m| m.key).collect()
    }

    /// Read effective consent without allocating a reconstructed grant set.
    pub fn allows(&self, client: &[u8; 32], identity: &[u8; 32]) -> bool {
        let Some(index) = self.members.iter().position(|m| &m.key == client) else { return false; };
        let member = &self.members[index];
        if member.flags & FLAG_LEGACY_ELIGIBLE != 0 {
            if member.flags & FLAG_LEGACY_BOUND_APPROVED != 0 && self.legacy_bound.as_ref() == Some(identity) {
                return true;
            }
            if self.legacy_tags.iter().enumerate().any(|(bit, tag)| tag[..] == identity[..8] && member.revoked_mask & (1 << bit) == 0) {
                return true;
            }
        }
        self.explicit.iter().any(|(i, key)| *i as usize == index && key == identity)
    }

    // Reuse the reviewed core. The temporary set and any ticket it issues
    // cannot escape this immediate transaction; pending firmware requests use
    // a separate authority epoch that is never restored from a snapshot.
    fn update(&mut self, apply: impl FnOnce(&mut GrantSet) -> Result<bool, GrantError>) -> Result<bool, GrantError> {
        let mut set = self.restore(INTERNAL_CTX);
        let changed = apply(&mut set)?;
        *self = set.snapshot();
        Ok(changed)
    }

    pub fn add_client(&mut self, key: [u8; 32]) -> Result<bool, GrantError> {
        self.update(|set| set.add_client(key))
    }

    pub fn remove_client(&mut self, key: &[u8; 32]) -> Result<bool, GrantError> {
        self.update(|set| set.remove_client(key))
    }

    pub fn approve(&mut self, client: &[u8; 32], identity: &[u8; 32]) -> Result<bool, GrantError> {
        self.update(|set| {
            let ticket = set.issue_ticket(client, *identity)?;
            set.approve(&ticket)
        })
    }

    pub fn revoke_identity(&mut self, client: &[u8; 32], identity: &[u8; 32]) -> Result<bool, GrantError> {
        self.update(|set| set.revoke_identity(client, identity))
    }

    pub fn clear_client(&mut self, client: &[u8; 32]) -> Result<bool, GrantError> {
        self.update(|set| set.clear_client(client))
    }

    /// Withdraw all identity consent while retaining the paired client keys.
    pub fn clear_identities(&mut self) -> bool {
        let changed = self.members.iter().any(|m| m.flags != 0) || !self.explicit.is_empty();
        for member in &mut self.members { member.flags = 0; member.revoked_mask = 0; }
        self.explicit.clear();
        self.legacy_tags.clear();
        self.legacy_bound = None;
        changed
    }

    pub fn approved_keys(&self, client: &[u8; 32]) -> Vec<[u8; 32]> {
        let Some(index) = self.members.iter().position(|m| &m.key == client) else { return Vec::new(); };
        let mut keys: Vec<_> = self.explicit.iter().filter(|(i, _)| *i as usize == index).map(|(_, key)| *key).collect();
        if let Some(bound) = self.legacy_bound {
            if self.members[index].flags & FLAG_LEGACY_BOUND_APPROVED != 0 && !keys.contains(&bound) { keys.push(bound); }
        }
        keys
    }

    pub fn approved_tags(&self, client: &[u8; 32]) -> Vec<[u8; 8]> {
        let Some(member) = self.members.iter().find(|m| &m.key == client) else { return Vec::new(); };
        if member.flags & FLAG_LEGACY_ELIGIBLE == 0 { return Vec::new(); }
        self.legacy_tags.iter().enumerate().filter(|(bit, _)| member.revoked_mask & (1 << bit) == 0).map(|(_, tag)| *tag).collect()
    }

    // --- encoding --------------------------------------------------------

    /// Canonical lowercase hex encoding. See module docs for the layout.
    pub fn encode(&self) -> String {
        let mut bytes: Vec<u8> = Vec::with_capacity(MAX_BINARY);

        bytes.push(VERSION);
        bytes.push(self.members.len() as u8);
        bytes.push(self.legacy_tags.len() as u8);
        bytes.push(if self.legacy_bound.is_some() { 1 } else { 0 });
        bytes.push(self.explicit.len() as u8);

        for tag in &self.legacy_tags {
            bytes.extend_from_slice(tag);
        }
        if let Some(b) = &self.legacy_bound {
            bytes.extend_from_slice(b);
        }

        for m in &self.members {
            bytes.extend_from_slice(&m.key);
            bytes.push(m.flags);
            bytes.push((m.revoked_mask & 0xff) as u8);
            bytes.push(((m.revoked_mask >> 8) & 0xff) as u8);
        }

        for (idx, id) in &self.explicit {
            bytes.push(*idx);
            bytes.extend_from_slice(id);
        }

        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX_LOWER[(b >> 4) as usize] as char);
            out.push(HEX_LOWER[(b & 0xf) as usize] as char);
        }
        out
    }

    /// Decode a canonical lowercase-hex snapshot, rejecting malformed,
    /// non-canonical, oversized, or ambiguous input.
    pub fn decode(s: &str) -> Result<Self, GrantError> {
        // Reject before allocating if too long. Also rejects empty input.
        if s.is_empty() || s.len() > MAX_HEX || s.len() % 2 != 0 {
            return Err(GrantError::InvalidLegacySnapshot);
        }

        // All characters must be lowercase hex. Reject uppercase.
        let sb = s.as_bytes();
        for &b in sb {
            if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                return Err(GrantError::InvalidLegacySnapshot);
            }
        }

        // Decode into a byte buffer sized to the input.
        let n = s.len() / 2;
        let mut buf: Vec<u8> = Vec::with_capacity(n);
        let mut i = 0;
        while i < sb.len() {
            let hi = hex_val(sb[i]).ok_or(GrantError::InvalidLegacySnapshot)?;
            let lo = hex_val(sb[i + 1]).ok_or(GrantError::InvalidLegacySnapshot)?;
            buf.push((hi << 4) | lo);
            i += 2;
        }

        // Header.
        if buf.len() < 5 {
            return Err(GrantError::InvalidLegacySnapshot);
        }
        let version = buf[0];
        if version != VERSION {
            return Err(GrantError::InvalidLegacySnapshot);
        }
        let member_count = buf[1] as usize;
        let tag_count = buf[2] as usize;
        let bound_present = buf[3];
        if bound_present > 1 {
            return Err(GrantError::InvalidLegacySnapshot);
        }
        let explicit_count = buf[4] as usize;

        if member_count > MAX_MEMBERS
            || tag_count > MAX_LEGACY_TAGS
            || explicit_count > MAX_EXPLICIT
        {
            return Err(GrantError::InvalidLegacySnapshot);
        }

        // Compute expected total before reading the rest.
        let expected = 5
            + tag_count * 8
            + if bound_present == 1 { 32 } else { 0 }
            + member_count * 35
            + explicit_count * 33;
        if buf.len() != expected {
            return Err(GrantError::InvalidLegacySnapshot);
        }

        let mut cursor = 5usize;

        let mut legacy_tags: Vec<[u8; 8]> = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            let mut t = [0u8; 8];
            t.copy_from_slice(&buf[cursor..cursor + 8]);
            if legacy_tags.contains(&t) {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            legacy_tags.push(t);
            cursor += 8;
        }

        let legacy_bound = if bound_present == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&buf[cursor..cursor + 32]);
            cursor += 32;
            Some(b)
        } else {
            None
        };

        let mut members: Vec<SnapMember> = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf[cursor..cursor + 32]);
            cursor += 32;
            let flags = buf[cursor];
            cursor += 1;
            if flags & !FLAG_KNOWN != 0 {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            // Bound flag requires bound + legacy eligibility.
            if (flags & FLAG_LEGACY_BOUND_APPROVED) != 0 && (flags & FLAG_LEGACY_ELIGIBLE) == 0 {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            if (flags & FLAG_LEGACY_BOUND_APPROVED) != 0 && legacy_bound.is_none() {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            let lo = buf[cursor];
            let hi = buf[cursor + 1];
            cursor += 2;
            let revoked_mask = (lo as u16) | ((hi as u16) << 8);

            // Duplicate member keys rejected.
            if members.iter().any(|m| m.key == key) {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            // Revoked bits require legacy eligibility; no bits beyond tag_count.
            if revoked_mask != 0 {
                if (flags & FLAG_LEGACY_ELIGIBLE) == 0 {
                    return Err(GrantError::InvalidLegacySnapshot);
                }
                let allowed_mask: u16 = if tag_count == 16 {
                    0xffff
                } else {
                    ((1u32 << tag_count) - 1) as u16
                };
                if (revoked_mask & !allowed_mask) != 0 {
                    return Err(GrantError::InvalidLegacySnapshot);
                }
            }

            members.push(SnapMember {
                key,
                flags,
                revoked_mask,
            });
        }

        let mut explicit: Vec<(u8, [u8; 32])> = Vec::with_capacity(explicit_count);
        for _ in 0..explicit_count {
            let idx = buf[cursor];
            cursor += 1;
            if (idx as usize) >= member_count {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&buf[cursor..cursor + 32]);
            cursor += 32;

            // Duplicate (member, identity) pairs rejected.
            if explicit
                .iter()
                .any(|(i, existing)| *i == idx && existing == &id)
            {
                return Err(GrantError::InvalidLegacySnapshot);
            }
            explicit.push((idx, id));
        }

        if cursor != buf.len() {
            return Err(GrantError::InvalidLegacySnapshot);
        }

        Ok(GrantSnapshot {
            members,
            legacy_tags,
            legacy_bound,
            explicit,
        })
    }

    /// Restore into a fresh `GrantSet` under `context`.
    ///
    /// Counters are reset: `set_revision = 0`, `next_incarnation = N`
    /// (member count), with member incarnations `0..N`. The caller must supply
    /// a fresh, unpredictable `lifetime` — old tickets are invalid because
    /// their recorded context will not match.
    pub fn restore(&self, context: GrantContext) -> GrantSet {
        let mut set = GrantSet::new(context);
        set.set_revision = 0;
        set.next_incarnation = 0;

        for m in &self.members {
            let incarnation = set.next_incarnation;
            set.next_incarnation = set.next_incarnation.saturating_add(1);
            let mut revoked: Vec<[u8; 8]> = Vec::new();
            for (bit, tag) in self.legacy_tags.iter().enumerate() {
                if m.revoked_mask & (1u16 << bit) != 0 {
                    revoked.push(*tag);
                }
            }
            set.members.push(super::Member {
                key: m.key,
                incarnation,
                revision: 0,
                legacy_eligible: (m.flags & FLAG_LEGACY_ELIGIBLE) != 0,
                legacy_revoked_tags: revoked,
                legacy_bound_approved: (m.flags & FLAG_LEGACY_BOUND_APPROVED) != 0,
            });
        }

        set.legacy_tags = self.legacy_tags.clone();
        set.legacy_bound = self.legacy_bound;

        for (idx, id) in &self.explicit {
            let key = self.members[*idx as usize].key;
            set.explicit_grants.push((key, *id));
        }

        set
    }
}

// Expose a snapshot-creation hook on `GrantSet` via this shim, so callers can
// do `set.snapshot()` rather than reaching into private fields from outside the
// module. Because this file is a child module of `client_grants`, it can read
// parent-private fields.
impl GrantSet {
    /// Produce a durable `GrantSnapshot` of the current authority.
    pub fn snapshot(&self) -> GrantSnapshot {
        let members: Vec<SnapMember> = self
            .members
            .iter()
            .map(|m| {
                let mut flags = 0u8;
                if m.legacy_eligible {
                    flags |= FLAG_LEGACY_ELIGIBLE;
                }
                if m.legacy_bound_approved {
                    flags |= FLAG_LEGACY_BOUND_APPROVED;
                }
                let mut mask = 0u16;
                for (bit, tag) in self.legacy_tags.iter().enumerate() {
                    if m.legacy_revoked_tags.iter().any(|t| t == tag) {
                        mask |= 1u16 << bit;
                    }
                }
                SnapMember {
                    key: m.key,
                    flags,
                    revoked_mask: mask,
                }
            })
            .collect();

        // Map explicit grants to member indices.
        let mut explicit: Vec<(u8, [u8; 32])> = Vec::with_capacity(self.explicit_grants.len());
        for (ck, id) in &self.explicit_grants {
            if let Some(idx) = self.members.iter().position(|m| &m.key == ck) {
                explicit.push((idx as u8, *id));
            }
        }

        GrantSnapshot {
            members,
            legacy_tags: self.legacy_tags.clone(),
            legacy_bound: self.legacy_bound,
            explicit,
        }
    }
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_grants::{GrantContext, GrantError, GrantSet};
    use crate::policy::ConnectSlot;
    use alloc::string::String;
    use alloc::vec::Vec;

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

    fn identity(prefix: u8, tail: u8) -> [u8; 32] {
        let mut id = [tail; 32];
        id[..8].copy_from_slice(&[prefix; 8]);
        id
    }

    fn hex8(b: u8) -> String {
        let mut s = String::with_capacity(16);
        for _ in 0..8 {
            s.push(HEX_LOWER[((b >> 4) & 0xf) as usize] as char);
            s.push(HEX_LOWER[(b & 0xf) as usize] as char);
        }
        s
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

    fn hex32_byte(b: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            s.push(HEX_LOWER[(b >> 4) as usize] as char);
            s.push(HEX_LOWER[(b & 0xf) as usize] as char);
        }
        s
    }

    #[test]
    fn empty_snapshot_roundtrip() {
        let s = GrantSnapshot::empty();
        let enc = s.encode();
        let dec = GrantSnapshot::decode(&enc).expect("decode");
        assert_eq!(s, dec);
    }

    #[test]
    fn snapshot_roundtrip_with_membership_and_grants() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        set.add_client(key(2)).unwrap();
        {
            let ticket = set.issue_ticket(&key(1), identity(0xaa, 0xbb)).unwrap();
            set.approve(&ticket).unwrap();
        }
        let snap = set.snapshot();
        let enc = snap.encode();
        let dec = GrantSnapshot::decode(&enc).expect("decode");
        assert_eq!(snap, dec);

        let restored = dec.restore(ctx(9));
        assert!(restored.allows(&key(1), &identity(0xaa, 0xbb)));
        assert!(!restored.allows(&key(2), &identity(0xaa, 0xbb)));
    }

    #[test]
    fn legacy_ab_retained_c_empty() {
        let mut slot = empty_slot();
        slot.current_pubkey = Some(hex32_byte(0x01));
        slot.authorized_pubkeys = alloc::vec![hex32_byte(0x02)];
        slot.bound_identity = Some(hex32_byte(0x0a));
        slot.approved_identities = hex8(0xaa);

        let snap = GrantSnapshot::from_legacy(&slot).expect("snapshot");
        assert_eq!(snap.member_count(), 2);
        assert_eq!(snap.client_keys(), alloc::vec![key(0x01), key(0x02)]);

        // A and B inherit; C added later does not.
        let mut snap = snap;
        snap.add_client(key(0x03)).unwrap();
        let restored = snap.restore(ctx(5));
        let id_legacy = identity(0xaa, 0x00);
        assert!(restored.allows(&key(0x01), &id_legacy));
        assert!(restored.allows(&key(0x02), &id_legacy));
        assert!(!restored.allows(&key(0x03), &id_legacy));
    }

    #[test]
    fn revoked_c_never_resurrects_and_bounds_independent() {
        let mut slot = empty_slot();
        slot.current_pubkey = Some(hex32_byte(0x01));
        slot.bound_identity = Some(hex32_byte(0x0a));
        slot.approved_identities = hex8(0xaa);

        let mut snap = GrantSnapshot::from_legacy(&slot).expect("snapshot");
        let id_c = {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&[0xaa; 8]);
            id[8..].copy_from_slice(&[0xcc; 24]);
            id
        };
        snap.revoke_identity(&key(0x01), &id_c).unwrap();

        // Tag-based coverage is withdrawn.
        let restored = snap.restore(ctx(7));
        assert!(!restored.allows(&key(0x01), &id_c));

        // But bound identity still works.
        let bound = key(0x0a); // not relevant, use literal
        let _ = bound;
        let mut b = [0u8; 32];
        b.copy_from_slice(&[0x0a; 32]);
        assert!(restored.allows(&key(0x01), &b));
    }

    #[test]
    fn old_ticket_rejected_after_restore_with_fresh_lifetime() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        let ticket = set.issue_ticket(&key(1), identity(0xaa, 0xbb)).unwrap();

        let snap = set.snapshot();
        let restored = snap.restore(ctx(2));
        // Ticket carries ctx(1); restored has ctx(2).
        assert!(matches!(
            restored.validate_ticket(&ticket),
            Err(GrantError::StaleTicket)
        ));
    }

    #[test]
    fn readd_starts_empty() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        {
            let ticket = set.issue_ticket(&key(1), identity(0xaa, 0xbb)).unwrap();
            set.approve(&ticket).unwrap();
        }
        let snap1 = set.snapshot();
        let mut restored = snap1.restore(ctx(3));
        assert!(restored.allows(&key(1), &identity(0xaa, 0xbb)));

        restored.remove_client(&key(1)).unwrap();
        restored.add_client(key(1)).unwrap();
        assert!(!restored.allows(&key(1), &identity(0xaa, 0xbb)));
    }

    #[test]
    fn malformed_decode_rejected() {
        // Empty.
        assert!(GrantSnapshot::decode("").is_err());
        // Odd length.
        assert!(GrantSnapshot::decode("0").is_err());
        // Uppercase.
        let mut fixture = GrantSnapshot::empty();
        fixture.add_client([0xab; 32]).unwrap();
        let mut s = fixture.encode();
        s.make_ascii_uppercase();
        assert!(GrantSnapshot::decode(&s).is_err());
        // Non-hex.
        assert!(GrantSnapshot::decode("zz").is_err());
        // Bad version.
        let mut bytes = alloc::vec![VERSION; 5];
        bytes[0] = 0x02;
        let bad = encode_bytes(&bytes);
        assert!(GrantSnapshot::decode(&bad).is_err());
        // Truncated header.
        assert!(GrantSnapshot::decode("0001").is_err());
        // Trailing garbage.
        let good = GrantSnapshot::empty().encode();
        let mut with_tail = good.clone();
        with_tail.push('0');
        with_tail.push('0');
        assert!(GrantSnapshot::decode(&with_tail).is_err());
    }

    #[test]
    fn overcap_decode_rejected_before_allocating() {
        // Header claiming 200 members.
        let bytes = alloc::vec![VERSION, 200, 0, 0, 0];
        let s = encode_bytes(&bytes);
        assert!(GrantSnapshot::decode(&s).is_err());
    }

    #[test]
    fn flags_validation() {
        // Build a snapshot with a bogus flag byte.
        let snap = GrantSnapshot {
            members: alloc::vec![SnapMember {
                key: key(1),
                flags: 0b1000_0000,
                revoked_mask: 0,
            }],
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: Vec::new(),
        };
        let enc = snap.encode();
        assert!(GrantSnapshot::decode(&enc).is_err());

        // Bound flag without bound must fail.
        let snap2 = GrantSnapshot {
            members: alloc::vec![SnapMember {
                key: key(1),
                flags: FLAG_LEGACY_ELIGIBLE | FLAG_LEGACY_BOUND_APPROVED,
                revoked_mask: 0,
            }],
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: Vec::new(),
        };
        assert!(GrantSnapshot::decode(&snap2.encode()).is_err());
    }

    #[test]
    fn duplicate_members_rejected() {
        let snap = GrantSnapshot {
            members: alloc::vec![
                SnapMember {
                    key: key(1),
                    flags: 0,
                    revoked_mask: 0,
                },
                SnapMember {
                    key: key(1),
                    flags: 0,
                    revoked_mask: 0,
                },
            ],
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: Vec::new(),
        };
        assert!(GrantSnapshot::decode(&snap.encode()).is_err());
    }

    #[test]
    fn duplicate_tags_rejected() {
        let snap = GrantSnapshot {
            members: Vec::new(),
            legacy_tags: alloc::vec![[0xaa; 8], [0xaa; 8]],
            legacy_bound: None,
            explicit: Vec::new(),
        };
        assert!(GrantSnapshot::decode(&snap.encode()).is_err());
    }

    #[test]
    fn unknown_grant_member_rejected() {
        let snap = GrantSnapshot {
            members: alloc::vec![SnapMember {
                key: key(1),
                flags: 0,
                revoked_mask: 0,
            }],
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: alloc::vec![(5u8, identity(0xaa, 0xbb))],
        };
        assert!(GrantSnapshot::decode(&snap.encode()).is_err());
    }

    #[test]
    fn revoked_mask_requires_legacy_eligibility() {
        let snap = GrantSnapshot {
            members: alloc::vec![SnapMember {
                key: key(1),
                flags: 0,
                revoked_mask: 0b1,
            }],
            legacy_tags: alloc::vec![[0xaa; 8]],
            legacy_bound: None,
            explicit: Vec::new(),
        };
        assert!(GrantSnapshot::decode(&snap.encode()).is_err());
    }

    #[test]
    fn revoked_mask_out_of_range_bits_rejected() {
        let snap = GrantSnapshot {
            members: alloc::vec![SnapMember {
                key: key(1),
                flags: FLAG_LEGACY_ELIGIBLE,
                revoked_mask: 0b10,
            }],
            legacy_tags: alloc::vec![[0xaa; 8]], // only bit 0 valid
            legacy_bound: None,
            explicit: Vec::new(),
        };
        assert!(GrantSnapshot::decode(&snap.encode()).is_err());
    }

    #[test]
    fn full_key_grants_persist_and_revoke() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        let id = identity(0x77, 0x66);
        {
            let ticket = set.issue_ticket(&key(1), id).unwrap();
            set.approve(&ticket).unwrap();
        }
        let mut snap = set.snapshot();
        assert!(snap.allows(&key(1), &id));
        snap.revoke_identity(&key(1), &id).unwrap();
        let restored = snap.restore(ctx(4));
        assert!(!restored.allows(&key(1), &id));
    }

    #[test]
    fn clear_client_and_identities() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        {
            let ticket = set.issue_ticket(&key(1), identity(0xaa, 0xbb)).unwrap();
            set.approve(&ticket).unwrap();
        }
        let mut snap = set.snapshot();
        assert!(snap.clear_client(&key(1)).unwrap());
        // Membership retained, authority gone.
        assert_eq!(snap.client_keys(), alloc::vec![key(1)]);
        assert!(!snap.allows(&key(1), &identity(0xaa, 0xbb)));

        // clear_identities retains membership and clears grants.
        {
            let ticket = set.issue_ticket(&key(1), identity(0xcc, 0xdd)).unwrap();
            set.approve(&ticket).unwrap();
        }
        let mut snap2 = set.snapshot();
        assert!(snap2.clear_identities());
        assert_eq!(snap2.client_keys(), alloc::vec![key(1)]);
        assert_eq!(snap2.grant_count(), 0);
    }

    #[test]
    fn no_eviction_on_caps() {
        let mut snap = GrantSnapshot::empty();
        for i in 0..MAX_MEMBERS {
            assert!(snap.add_client(key(i as u8)).unwrap());
        }
        // Ninth member rejected, snapshot unchanged.
        let before = snap.clone();
        assert_eq!(snap.add_client(key(0xff)), Err(GrantError::ClientCapacity));
        assert_eq!(snap, before);
    }

    #[test]
    fn maximal_encoding_size_and_roundtrip() {
        let mut snap = GrantSnapshot {
            members: Vec::new(),
            legacy_tags: Vec::new(),
            legacy_bound: None,
            explicit: Vec::new(),
        };
        for i in 0..MAX_MEMBERS {
            snap.members.push(SnapMember {
                key: {
                    let mut k = [0u8; 32];
                    k[0] = i as u8;
                    k
                },
                flags: FLAG_LEGACY_ELIGIBLE,
                revoked_mask: 0,
            });
        }
        for i in 0..MAX_LEGACY_TAGS {
            let mut t = [0u8; 8];
            t[0] = i as u8;
            snap.legacy_tags.push(t);
        }
        snap.legacy_bound = Some([0xaa; 32]);
        for m in snap.members.iter_mut() {
            m.flags = FLAG_LEGACY_ELIGIBLE | FLAG_LEGACY_BOUND_APPROVED;
            m.revoked_mask = 0xffff;
        }
        for i in 0..MAX_EXPLICIT {
            snap.explicit.push((0u8, {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                id
            }));
        }

        let enc = snap.encode();
        assert!(enc.len() <= MAX_HEX);
        let dec = GrantSnapshot::decode(&enc).expect("decode");

        // Compare semantically: order of legacy revoked tags is normalized by
        // mask so structs should be equal.
        assert_eq!(dec.members.len(), MAX_MEMBERS);
        assert_eq!(dec.legacy_tags.len(), MAX_LEGACY_TAGS);
        assert_eq!(dec.explicit.len(), MAX_EXPLICIT);
        assert_eq!(dec.members[0].revoked_mask, 0xffff);
    }

    #[test]
    fn snapshot_clone_is_plain_data() {
        let mut set = GrantSet::new(ctx(1));
        set.add_client(key(1)).unwrap();
        let snap = set.snapshot();
        let cloned = snap.clone();
        assert_eq!(snap, cloned);
        // Mutating the clone doesn't affect the original.
        let mut cloned = cloned;
        cloned.add_client(key(2)).unwrap();
        assert_ne!(snap, cloned);
    }

    fn encode_bytes(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX_LOWER[(b >> 4) as usize] as char);
            out.push(HEX_LOWER[(b & 0xf) as usize] as char);
        }
        out
    }
    #[test]
    fn host_clear_withdraws_legacy_bound_and_previously_revoked_identity() {
        let mut slot = empty_slot();
        slot.current_pubkey = Some(hex32_byte(1));
        slot.approved_identities = hex8(2);
        slot.bound_identity = Some(hex32_byte(3));
        let mut snapshot = GrantSnapshot::from_legacy(&slot).unwrap();
        snapshot.revoke_identity(&key(1), &key(2)).unwrap();
        assert!(snapshot.clear_identities());
        let saved = GrantSnapshot::decode(&snapshot.encode()).unwrap();
        assert_eq!(saved.client_keys(), vec![key(1)]);
        assert!(!saved.allows(&key(1), &key(2)), "clear must not remove a revocation and resurrect its tag");
        assert!(!saved.allows(&key(1), &key(3)), "clear withdraws bound consent too");
    }

    #[test]
    fn host_full_legacy_tag_table_remains_revocable() {
        let mut slot = empty_slot();
        slot.current_pubkey = Some(hex32_byte(1));
        slot.approved_identities = (0u8..16).map(hex8).collect();
        let mut snapshot = GrantSnapshot::from_legacy(&slot).unwrap();
        assert_eq!(snapshot.revoke_identity(&key(1), &key(9)), Ok(true));
        assert!(!snapshot.allows(&key(1), &key(9)));
        assert!(snapshot.allows(&key(1), &key(10)));
    }

}
