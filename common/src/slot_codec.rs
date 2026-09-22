//! Downgrade-safe persistence codec for [`crate::policy::ConnectSlot`].
//!
//! An old firmware reader must never gain signing/crypto/persona authority from
//! a slot blob written by a newer firmware. Two wire shapes exist:
//!
//! * legacy: every `ConnectSlot` runtime field except `client_grants`. Written
//!   unchanged when `client_grants` is `None`.
//! * extended: a restrictive legacy projection (no authority-bearing values)
//!   flattened together with a `g4` extension carrying the real policy tuple
//!   and an encoded grant snapshot.
//!
//! `g4` is authoritative: when present, the projection's policy/identity fields
//! are ignored and the runtime slot is rebuilt from `g4`. Hash binding detects an
//! old/raw writer that edited membership or secret while leaving a stale `g4`.
//! It is *not* an authenticity claim.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::client_grants::GrantSnapshot;
use crate::policy::ConnectSlot;

// Flags used in the compact `g4.p.2` policy word.
const F_AUTO: u8 = 1;
const F_SIGNING: u8 = 2;
const F_STRICT: u8 = 4;
const F_ESCALATE: u8 = 8;
const F_PETITION: u8 = 16;
const F_AUDIT_CHILD: u8 = 32;
const F_GUARDIAN: u8 = 64;
const F_WAS_BOUND: u8 = 128;

const MAX_METHODS: usize = 32;
const MAX_METHOD_LEN: usize = 64;
const MAX_KINDS: usize = 64;
const MAX_MEMBERS: usize = 8;
const MAX_SLOT_INDEX: u8 = 16;
const MAX_G4_LEN: usize = 1946;

/// Historical legacy wire shape: current `ConnectSlot` fields except
/// `client_grants`, with the original serde defaults/renames.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacySlot {
    slot_index: u8,
    label: String,
    secret: String,
    #[serde(default)]
    current_pubkey: Option<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_kinds: Vec<u64>,
    #[serde(default)]
    auto_approve: bool,
    #[serde(default)]
    signing_approved: bool,
    #[serde(default)]
    strict_permissions: bool,
    #[serde(default)]
    authorized_pubkeys: Vec<String>,
    #[serde(default)]
    escalate: bool,
    #[serde(default)]
    petition_on_deny: bool,
    #[serde(default)]
    audit_child_wrap: bool,
    #[serde(default)]
    guardian_notice_wrap: bool,
    #[serde(default)]
    bound_identity: Option<String>,
    #[serde(default, rename = "ids", skip_serializing_if = "String::is_empty")]
    approved_identities: String,
    #[serde(default, rename = "wb", skip_serializing_if = "is_false")]
    was_bound: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_present_g4")]
    g4: Option<G4>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Versioned `g4` extension.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct G4 {
    v: u8,
    /// `(methods, kinds, flags, bound_identity)`
    p: (Vec<String>, Vec<u64>, u8, Option<String>),
    g: String,
    h: String,
}

/// Distinguishes an *absent* `g4` key (legacy semantics, `None`) from a
/// *present* `g4` key whose value is `null` (malformed, must fail closed).
/// Deserialises the inner `G4` directly so `null` is rejected by the derived
/// visitor rather than silently collapsing to `Option::None`.
fn deserialize_present_g4<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<G4>, D::Error> {
    let g4: G4 = G4::deserialize(deserializer)?;
    Ok(Some(g4))
}

impl LegacySlot {
    fn from_connect(slot: &ConnectSlot) -> Self {
        LegacySlot {
            slot_index: slot.slot_index,
            label: slot.label.clone(),
            secret: slot.secret.clone(),
            current_pubkey: slot.current_pubkey.clone(),
            // authority-bearing policy is suppressed in the projection path; here
            // we always copy, callers build the restrictive projection explicitly.
            allowed_methods: slot.allowed_methods.clone(),
            allowed_kinds: slot.allowed_kinds.clone(),
            auto_approve: slot.auto_approve,
            signing_approved: slot.signing_approved,
            strict_permissions: slot.strict_permissions,
            authorized_pubkeys: slot.authorized_pubkeys.clone(),
            escalate: slot.escalate,
            petition_on_deny: slot.petition_on_deny,
            audit_child_wrap: slot.audit_child_wrap,
            guardian_notice_wrap: slot.guardian_notice_wrap,
            bound_identity: slot.bound_identity.clone(),
            approved_identities: slot.approved_identities.clone(),
            was_bound: slot.was_bound,
            g4: None,
        }
    }

    /// Restrictive projection for the extended wire shape. No authority leaks.
    fn projection(slot: &ConnectSlot) -> Self {
        LegacySlot {
            slot_index: slot.slot_index,
            label: slot.label.clone(),
            secret: slot.secret.clone(),
            current_pubkey: slot.current_pubkey.clone(),
            allowed_methods: Vec::new(),
            allowed_kinds: Vec::new(),
            auto_approve: false,
            signing_approved: false,
            strict_permissions: true,
            authorized_pubkeys: slot.authorized_pubkeys.clone(),
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: None,
            approved_identities: String::new(),
            was_bound: true,
            g4: None,
        }
    }
}

// --- validation helpers ------------------------------------------------------

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn canonicalize_lower_hex64(s: &str) -> Option<String> {
    if !is_lower_hex64(s) {
        return None;
    }
    Some(String::from(s))
}

fn validate_methods(methods: &[String]) -> Result<(), &'static str> {
    if methods.len() > MAX_METHODS {
        return Err("too many methods");
    }
    let mut seen: Vec<&str> = Vec::with_capacity(methods.len());
    for m in methods {
        if m.is_empty() || m.len() > MAX_METHOD_LEN {
            return Err("bad method length");
        }
        if seen.contains(&m.as_str()) {
            return Err("duplicate method");
        }
        seen.push(m.as_str());
    }
    Ok(())
}

fn validate_kinds(kinds: &[u64]) -> Result<(), &'static str> {
    if kinds.len() > MAX_KINDS {
        return Err("too many kinds");
    }
    let mut seen: Vec<u64> = Vec::with_capacity(kinds.len());
    for k in kinds {
        if seen.contains(k) {
            return Err("duplicate kind");
        }
        seen.push(*k);
    }
    Ok(())
}

/// Distinct union of `current_pubkey` and `authorized_pubkeys`, canonical
/// lowercase 64-hex, capped at [`MAX_MEMBERS`].
fn member_union(slot: &ConnectSlot) -> Result<Vec<String>, &'static str> {
    let mut out: Vec<String> = Vec::new();
    if let Some(cur) = slot.current_pubkey.as_deref() {
        let c = canonicalize_lower_hex64(cur).ok_or("bad current_pubkey")?;
        if !out.contains(&c) {
            out.push(c);
        }
    }
    for k in &slot.authorized_pubkeys {
        let c = canonicalize_lower_hex64(k).ok_or("bad authorized_pubkey")?;
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.len() > MAX_MEMBERS {
        return Err("too many members");
    }
    out.sort();
    Ok(out)
}

fn snapshot_members(snapshot: &GrantSnapshot) -> Result<Vec<String>, &'static str> {
    let keys = snapshot.client_keys();
    if keys.len() > MAX_MEMBERS {
        return Err("snapshot too many members");
    }
    let mut out: Vec<String> = Vec::with_capacity(keys.len());
    for k in keys {
        let hex = encode_lower_hex(&k);
        if !out.contains(&hex) {
            out.push(hex);
        }
    }
    out.sort();
    Ok(out)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn project_hash(proj: &LegacySlot) -> String {
    // Canonical serde_json of the projection. Field order is fixed by struct
    // declaration, so this is stable across our own writers.
    let bytes = serde_json::to_vec(proj).expect("projection serialises");
    let digest = Sha256::digest(&bytes);
    encode_lower_hex(&digest)
}

fn flags_from_slot(slot: &ConnectSlot) -> u8 {
    let mut f = 0u8;
    if slot.auto_approve {
        f |= F_AUTO;
    }
    if slot.signing_approved {
        f |= F_SIGNING;
    }
    if slot.strict_permissions {
        f |= F_STRICT;
    }
    if slot.escalate {
        f |= F_ESCALATE;
    }
    if slot.petition_on_deny {
        f |= F_PETITION;
    }
    if slot.audit_child_wrap {
        f |= F_AUDIT_CHILD;
    }
    if slot.guardian_notice_wrap {
        f |= F_GUARDIAN;
    }
    if slot.was_bound {
        f |= F_WAS_BOUND;
    }
    f
}

fn flags_apply(slot: &mut ConnectSlot, f: u8) {
    slot.auto_approve = f & F_AUTO != 0;
    slot.signing_approved = f & F_SIGNING != 0;
    slot.strict_permissions = f & F_STRICT != 0;
    slot.escalate = f & F_ESCALATE != 0;
    slot.petition_on_deny = f & F_PETITION != 0;
    slot.audit_child_wrap = f & F_AUDIT_CHILD != 0;
    slot.guardian_notice_wrap = f & F_GUARDIAN != 0;
    slot.was_bound = f & F_WAS_BOUND != 0;
}

/// The strict projection invariants we require of any decoded extended blob.
fn check_strict_projection(proj: &LegacySlot) -> Result<(), &'static str> {
    if !proj.allowed_methods.is_empty() {
        return Err("projection methods not empty");
    }
    if !proj.allowed_kinds.is_empty() {
        return Err("projection kinds not empty");
    }
    if proj.auto_approve || proj.signing_approved {
        return Err("projection auto/signing not false");
    }
    if !proj.strict_permissions {
        return Err("projection strict not true");
    }
    if proj.escalate
        || proj.petition_on_deny
        || proj.audit_child_wrap
        || proj.guardian_notice_wrap
    {
        return Err("projection escalation flags not false");
    }
    if proj.bound_identity.is_some() {
        return Err("projection bound_identity set");
    }
    if !proj.approved_identities.is_empty() {
        return Err("projection ids not empty");
    }
    if !proj.was_bound {
        return Err("projection was_bound not true");
    }
    Ok(())
}

// --- SlotCodec ---------------------------------------------------------------

/// Serialisation/deserialisation adapter for `ConnectSlot`.
///
/// Host removes `Serialize`/`Deserialize` from `ConnectSlot` and routes
/// persistence through this type.
struct SlotCodec;

impl SlotCodec {
    /// Serialise with the legacy or extended wire shape as appropriate.
    pub fn serialize<S: Serializer>(
        slot: &ConnectSlot,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // Legacy path: keep historical behaviour (including historically-invalid
        // fixtures) untouched whenever there is no snapshot.
        let Some(snapshot) = slot.client_grants.as_ref() else {
            let legacy = LegacySlot::from_connect(slot);
            return legacy.serialize(serializer);
        };

        // --- extended validation ---------------------------------------------
        validate_slot(slot).map_err(S::Error::custom)?;

        let union = member_union(slot).map_err(S::Error::custom)?;
        let snap_members = snapshot_members(snapshot).map_err(S::Error::custom)?;
        if union != snap_members {
            return Err(S::Error::custom(
                "snapshot membership != distinct union of client keys",
            ));
        }

        let mut proj = LegacySlot::projection(slot);
        check_strict_projection(&proj).map_err(S::Error::custom)?;
        let h = project_hash(&proj);

        let g = snapshot.encode();
        if g.is_empty() || g.len() > MAX_G4_LEN {
            return Err(S::Error::custom("empty snapshot encoding"));
        }

        let g4 = G4 {
            v: 1,
            p: (
                slot.allowed_methods.clone(),
                slot.allowed_kinds.clone(),
                flags_from_slot(slot),
                slot.bound_identity.clone(),
            ),
            g,
            h,
        };

        proj.g4 = Some(g4);
        proj.serialize(serializer)
    }

    /// Deserialise, returning a runtime `ConnectSlot`.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ConnectSlot, D::Error> {
        // One derived struct rejects duplicate known fields without serde's
        // generic flatten/content machinery on this memory-constrained target.
        let mut stored = LegacySlot::deserialize(deserializer)?;
        let Some(g4) = stored.g4.take() else {
            // Genuinely absent extension -> legacy semantics.
            let legacy = stored;
            return Ok(ConnectSlot {
                slot_index: legacy.slot_index,
                label: legacy.label,
                secret: legacy.secret,
                current_pubkey: legacy.current_pubkey,
                allowed_methods: legacy.allowed_methods,
                allowed_kinds: legacy.allowed_kinds,
                auto_approve: legacy.auto_approve,
                signing_approved: legacy.signing_approved,
                strict_permissions: legacy.strict_permissions,
                authorized_pubkeys: legacy.authorized_pubkeys,
                escalate: legacy.escalate,
                petition_on_deny: legacy.petition_on_deny,
                audit_child_wrap: legacy.audit_child_wrap,
                guardian_notice_wrap: legacy.guardian_notice_wrap,
                bound_identity: legacy.bound_identity,
                approved_identities: legacy.approved_identities,
                was_bound: legacy.was_bound,
                client_grants: None,
            });
        };

        // --- extended path: fail closed, never fall back ---------------------
        if g4.v != 1 {
            return Err(D::Error::custom("unknown g4 version"));
        }
        if g4.g.len() > MAX_G4_LEN {
            return Err(D::Error::custom("g4 snapshot too large"));
        }

        // The projection must obey the strict, authority-free invariants.
        check_strict_projection(&stored).map_err(D::Error::custom)?;

        // Hash must match the projection we actually received.
        let expect_h = project_hash(&stored);
        if expect_h != g4.h {
            return Err(D::Error::custom("g4 projection hash mismatch"));
        }

        // Policy tuple validation.
        let (methods, kinds, flags, bound) = g4.p;
        validate_methods(&methods).map_err(D::Error::custom)?;
        validate_kinds(&kinds).map_err(D::Error::custom)?;
        if let Some(b) = bound.as_deref() {
            if !is_lower_hex64(b) {
                return Err(D::Error::custom("g4 bound_identity not lowercase 64-hex"));
            }
        }

        // Slot index / secret sanity for the extended shape.
        if stored.slot_index >= MAX_SLOT_INDEX {
            return Err(D::Error::custom("slot_index out of range"));
        }
        if !is_lower_hex64(&stored.secret) {
            return Err(D::Error::custom("secret not lowercase 64-hex"));
        }

        let snapshot = GrantSnapshot::decode(&g4.g).map_err(|_| D::Error::custom("invalid grant snapshot"))?;

        // Membership re-check: snapshot must equal distinct union of retained
        // client keys in the projection, otherwise an old writer may have
        // tampered with membership.
        let mut union: Vec<String> = Vec::new();
        if let Some(cur) = stored.current_pubkey.as_deref() {
            let c = canonicalize_lower_hex64(cur)
                .ok_or_else(|| D::Error::custom("bad current_pubkey"))?;
            if !union.contains(&c) {
                union.push(c);
            }
        }
        for k in &stored.authorized_pubkeys {
            let c = canonicalize_lower_hex64(k)
                .ok_or_else(|| D::Error::custom("bad authorized_pubkey"))?;
            if !union.contains(&c) {
                union.push(c);
            }
        }
        if union.len() > MAX_MEMBERS {
            return Err(D::Error::custom("too many members"));
        }
        union.sort();

        let snap_members = snapshot_members(&snapshot).map_err(D::Error::custom)?;
        if union != snap_members {
            return Err(D::Error::custom(
                "g4 snapshot membership != distinct union of client keys",
            ));
        }

        // Rebuild runtime authority from `g4`. Snapshot is now the sole consent
        // authority, so the approved identity list is emptied.
        let mut slot = ConnectSlot {
            slot_index: stored.slot_index,
            label: stored.label,
            secret: stored.secret,
            current_pubkey: stored.current_pubkey,
            allowed_methods: methods,
            allowed_kinds: kinds,
            auto_approve: false,
            signing_approved: false,
            strict_permissions: false,
            authorized_pubkeys: stored.authorized_pubkeys,
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: bound,
            approved_identities: String::new(),
            was_bound: false,
            client_grants: Some(snapshot),
        };
        flags_apply(&mut slot, flags);
        Ok(slot)
    }
}

impl fmt::Debug for SlotCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlotCodec")
    }
}

// --- public entry points -----------------------------------------------------

/// Serialise a `ConnectSlot` through the downgrade-safe codec.
pub fn serialize<S: Serializer>(
    slot: &ConnectSlot,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    SlotCodec::serialize(slot, serializer)
}

/// Deserialise a `ConnectSlot` through the downgrade-safe codec.
pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ConnectSlot, D::Error> {
    SlotCodec::deserialize(deserializer)
}

/// Full-table validation hook for the loader. Verifies every slot's shape and
/// membership invariants, and enforces that any existing `g4` slot has an empty
/// `approved_identities` (the snapshot is the sole consent authority).
pub fn validate_slot(slot: &ConnectSlot) -> Result<(), &'static str> {
    if slot.slot_index >= MAX_SLOT_INDEX {
        return Err("slot_index out of range");
    }
    if !is_lower_hex64(&slot.secret) {
        return Err("secret not lowercase 64-hex");
    }
    validate_methods(&slot.allowed_methods)?;
    validate_kinds(&slot.allowed_kinds)?;
    if let Some(b) = slot.bound_identity.as_deref() {
        if !is_lower_hex64(b) {
            return Err("bound_identity not lowercase 64-hex");
        }
    }

    let union = member_union(slot)?;
    if union.len() > MAX_MEMBERS {
        return Err("too many members");
    }

    match slot.client_grants.as_ref() {
        None => Ok(()),
        Some(snapshot) => {
            if !slot.approved_identities.is_empty() {
                return Err("extended slot retains approved_identities");
            }
            let snap_members = snapshot_members(snapshot)?;
            if union != snap_members {
                return Err("snapshot membership != distinct union of client keys");
            }
            Ok(())
        }
    }
}

impl Serialize for ConnectSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(self, serializer)
    }
}
impl<'de> Deserialize<'de> for ConnectSlot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize(deserializer)
    }
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_grants::GrantSnapshot;
    use crate::policy::ConnectSlot;

    // Frozen pre-G4 typed reader/writer: deliberately knows no extension.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OldSlot {
    slot_index: u8,
    label: String,
    secret: String,
    #[serde(default)]
    current_pubkey: Option<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_kinds: Vec<u64>,
    #[serde(default)]
    auto_approve: bool,
    #[serde(default)]
    signing_approved: bool,
    #[serde(default)]
    strict_permissions: bool,
    #[serde(default)]
    authorized_pubkeys: Vec<String>,
    #[serde(default)]
    escalate: bool,
    #[serde(default)]
    petition_on_deny: bool,
    #[serde(default)]
    audit_child_wrap: bool,
    #[serde(default)]
    guardian_notice_wrap: bool,
    #[serde(default)]
    bound_identity: Option<String>,
    #[serde(default, rename = "ids", skip_serializing_if = "String::is_empty")]
    approved_identities: String,
    #[serde(default, rename = "wb", skip_serializing_if = "is_false")]
    was_bound: bool,
}

    fn base_slot() -> ConnectSlot {
        ConnectSlot {
            slot_index: 0,
            label: "test".into(),
            secret: "aa".repeat(32),
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

    fn hex64(byte: u8) -> String {
        encode_lower_hex(&[byte; 32])
    }

    fn roundtrip(slot: &ConnectSlot) -> ConnectSlot {
        let json = serde_json::to_string(slot).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    // Helper: serialise a slot through the codec without requiring the host to
    // have derived Serialize on ConnectSlot. We build the JSON manually by
    // constructing the StoredSlot shape.
    fn to_json(slot: &ConnectSlot) -> serde_json::Value {
        use serde_json::json;
        // Mirror what our serializer would produce, for fixtures only.
        match slot.client_grants.as_ref() {
            None => {
                let legacy = LegacySlot::from_connect(slot);
                serde_json::to_value(&legacy).unwrap()
            }
            Some(_) => {
                // Use a serializer shim: serde_json::to_value on a value built
                // through our codec. Reuse the same G4 logic by serialising the
                // projection + g4 manually.
                let proj = LegacySlot::projection(slot);
                let h = project_hash(&proj);
                let g = slot.client_grants.as_ref().unwrap().encode();
                let mut obj = serde_json::to_value(&proj).unwrap();
                let map = obj.as_object_mut().unwrap();
                map.insert(
                    "g4".into(),
                    json!({
                        "v": 1,
                        "p": [
                            slot.allowed_methods.clone(),
                            slot.allowed_kinds.clone(),
                            flags_from_slot(slot),
                            slot.bound_identity.clone(),
                        ],
                        "g": g,
                        "h": h,
                    }),
                );
                obj
            }
        }
    }

    #[test]
    fn legacy_serial_roundtrip() {
        let mut s = base_slot();
        s.label = "legacy".into();
        s.auto_approve = true;
        s.was_bound = true;
        s.bound_identity = Some(hex64(0x11));
        s.approved_identities = "0011223344556677".into();

        let v = to_json(&s);
        let json = serde_json::to_string(&v).unwrap();
        // Old/legacy reader path.
        let legacy: OldSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(legacy.label, "legacy");
        assert!(legacy.auto_approve);
        assert_eq!(legacy.bound_identity, Some(hex64(0x11)));
        assert_eq!(legacy.approved_identities, "0011223344556677");

        // Codec decode path returns grants=None.
        let decoded: ConnectSlot = serde_json::from_str(&json).unwrap();
        assert!(decoded.client_grants.is_none());
        assert_eq!(decoded.label, "legacy");
    }

    #[test]
    fn new_roundtrip_actual_policy_with_snapshot_grant() {
        let mut s = base_slot();
        s.slot_index = 3;
        s.label = "ext".into();
        s.current_pubkey = Some(hex64(0x22));
        s.authorized_pubkeys = vec![hex64(0x22), hex64(0x33)];
        s.allowed_methods = vec!["sign_event".into(), "ping".into()];
        s.allowed_kinds = vec![1, 4, 30023];
        s.auto_approve = true;
        s.signing_approved = true;
        s.strict_permissions = true;
        s.escalate = true;
        s.petition_on_deny = true;
        s.audit_child_wrap = true;
        s.guardian_notice_wrap = true;
        s.bound_identity = Some(hex64(0x44));
        s.was_bound = true;

        // Build a snapshot whose members equal the union {0x22, 0x33}.
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x22; 32]).unwrap();
        snap.add_client([0x33; 32]).unwrap();
        s.client_grants = Some(snap.clone());

        let v = to_json(&s);
        let json = serde_json::to_string(&v).unwrap();

        // Extended decode must resurrect actual policy and grants.
        let decoded: ConnectSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.slot_index, 3);
        assert_eq!(decoded.allowed_methods, s.allowed_methods);
        assert_eq!(decoded.allowed_kinds, s.allowed_kinds);
        assert!(decoded.auto_approve);
        assert!(decoded.signing_approved);
        assert!(decoded.strict_permissions);
        assert!(decoded.escalate);
        assert!(decoded.petition_on_deny);
        assert!(decoded.audit_child_wrap);
        assert!(decoded.guardian_notice_wrap);
        assert_eq!(decoded.bound_identity, s.bound_identity);
        assert!(decoded.was_bound);
        let g = decoded.client_grants.expect("grants present");
        let mut want = snap.client_keys();
        want.sort();
        let mut got = g.client_keys();
        got.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn old_projection_deserialised_into_legacy_strict_empty() {
        // Simulate: an extended blob, but read by an OLD reader that only knows
        // LegacySlot. It must see the strict, empty projection and ignore g4.
        let mut s = base_slot();
        s.allowed_methods = vec!["sign_event".into()];
        s.strict_permissions = false;
        s.authorized_pubkeys = vec![hex64(0x55)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x55; 32]).unwrap();
        s.client_grants = Some(snap);

        let v = to_json(&s);
        let json = serde_json::to_string(&v).unwrap();
        let legacy: OldSlot = serde_json::from_str(&json).unwrap();

        // Old reader sees no authority.
        assert!(legacy.allowed_methods.is_empty());
        assert!(legacy.allowed_kinds.is_empty());
        assert!(!legacy.auto_approve);
        assert!(!legacy.signing_approved);
        assert!(legacy.strict_permissions);
        assert!(!legacy.escalate);
        assert!(!legacy.petition_on_deny);
        assert!(!legacy.audit_child_wrap);
        assert!(!legacy.guardian_notice_wrap);
        assert!(legacy.bound_identity.is_none());
        assert!(legacy.approved_identities.is_empty());
        assert!(legacy.was_bound);
        // But retained client keys survive for display.
        assert_eq!(legacy.authorized_pubkeys, vec![hex64(0x55)]);
    }

    #[test]
    fn emulate_old_typed_writer_drops_g4_and_grants_have_no_authority() {
        // Old writer roundtrips a ConnectSlot typed value, dropping g4 and
        // any extension it doesn't understand. Because from_legacy captures
        // current membership as legacy eligibility, the resulting empty
        // snapshot has no authority until the user re-approves.
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x66)];
        s.bound_identity = Some(hex64(0x77));

        s.client_grants = Some(GrantSnapshot::from_legacy(&s).unwrap());
        let written = serde_json::to_string(&s).unwrap();
        let old: OldSlot = serde_json::from_str(&written).unwrap();
        let old_written = serde_json::to_string(&old).unwrap();
        assert!(!old_written.contains("g4"));
        let reloaded: ConnectSlot = serde_json::from_str(&old_written).unwrap();
        let snap = GrantSnapshot::from_legacy(&reloaded).unwrap();
        assert!(!snap.allows(&[0x66; 32], &[0x77; 32]));
    }

    #[test]
    fn outer_membership_tamper_rejected() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x88)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x88; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        // Tamper: add a member to authorized_pubkeys.
        let map = v.as_object_mut().unwrap();
        let arr = map
            .get_mut("authorized_pubkeys")
            .unwrap()
            .as_array_mut()
            .unwrap();
        arr.push(serde_json::Value::String(hex64(0x99)));
        // Hash still matches the projection we *did* receive, but membership
        // union no longer equals snapshot members -> reject.
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(err.to_string().contains("projection hash mismatch"), "{}", err);
    }

    #[test]
    fn secret_tamper_rejected() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8a)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8a; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        let map = v.as_object_mut().unwrap();
        map.insert(
            "secret".into(),
            serde_json::Value::String("bb".repeat(32)),
        );
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(err.to_string().contains("hash"), "{}", err);
    }

    #[test]
    fn flag_tamper_rejected() {
        // The projection's flags are hashed; editing them without updating h
        // must be detected.
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8b)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8b; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        let map = v.as_object_mut().unwrap();
        map.insert("strict_permissions".into(), serde_json::Value::Bool(false));
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(
            err.to_string().contains("strict") || err.to_string().contains("hash"),
            "{}",
            err
        );
    }

    #[test]
    fn duplicate_g4_rejected() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8c)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8c; 32]).unwrap();
        s.client_grants = Some(snap);

        let written = serde_json::to_string(&s).unwrap();
        assert!(serde_json::from_str::<ConnectSlot>(&written).is_ok());
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        let mut json = serde_json::to_string(&v).unwrap();
        // Inject a second g4 key by textual splice.
        let needle = "\"g4\":";
        let pos = json.find(needle).expect("g4 present");
        let dup = format!("\"g4\":{},", v.get("g4").unwrap());
        json.insert_str(pos, &dup);
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        // Duplicate struct key -> "duplicate field".
        assert!(
            err.to_string().contains("duplicate field `g4`"),
            "{}",
            err
        );
    }

    #[test]
    fn duplicate_known_outer_field_rejected() {
        let v = to_json(&base_slot());
        let mut json = serde_json::to_string(&v).unwrap();
        // Duplicate `label`.
        let needle = "\"label\":";
        let pos = json.find(needle).expect("label present");
        let end = json[pos..].find(',').unwrap() + pos;
        let label_src = json[pos..end].to_string();
        json.insert_str(end + 1, &format!("{},", label_src));
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(
            err.to_string().contains("duplicate") || err.to_string().contains("label"),
            "{}",
            err
        );
    }

    #[test]
    fn null_g4_fails() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8d)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8d; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        let map = v.as_object_mut().unwrap();
        map.insert("g4".into(), serde_json::Value::Null);
        let json = serde_json::to_string(&v).unwrap();
        // Exercise the actual deserialiser: null must not become legacy state.
        assert!(serde_json::from_str::<ConnectSlot>(&json).is_err(), "present null extension must be rejected");
    }

    #[test]
    fn unknown_version_fails() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8e)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8e; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        let map = v.as_object_mut().unwrap();
        let g4 = map.get_mut("g4").unwrap().as_object_mut().unwrap();
        g4.insert("v".into(), serde_json::Value::Number(2.into()));
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(err.to_string().contains("version"), "{}", err);
    }

    #[test]
    fn bad_truncated_hex_rejected() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x8f)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x8f; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        let map = v.as_object_mut().unwrap();
        let g4 = map.get_mut("g4").unwrap().as_object_mut().unwrap();
        g4.insert("g".into(), serde_json::Value::String("deadbeef".into()));
        // Update hash: not needed, decode fails before hash matters? It fails
        // at GrantSnapshot::decode anyway.
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn overcaps_methods_rejected() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x90)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x90; 32]).unwrap();
        s.client_grants = Some(snap);

        let mut v = to_json(&s);
        // Push 33 methods into the g4 policy tuple.
        let map = v.as_object_mut().unwrap();
        let g4 = map.get_mut("g4").unwrap().as_object_mut().unwrap();
        let p = g4.get_mut("p").unwrap().as_array_mut().unwrap();
        let methods: Vec<serde_json::Value> =
            (0..33).map(|i| serde_json::Value::String(format!("m{}", i))).collect();
        p[0] = serde_json::Value::Array(methods);
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(err.to_string().contains("method"), "{}", err);
    }

    #[test]
    fn duplicate_member_input_rejected() {
        // Two identical entries in authorized_pubkeys collapse to one union
        // member, which then mismatches the snapshot members count.
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x91), hex64(0x92)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x91; 32]).unwrap();
        snap.add_client([0x91; 32]).unwrap_or(false);
        // Force a two-member snapshot that matches; then tamper to duplicate.
        let mut s2 = s.clone();
        let mut snap2 = GrantSnapshot::empty();
        snap2.add_client([0x91; 32]).unwrap();
        snap2.add_client([0x92; 32]).unwrap();
        s2.client_grants = Some(snap2);

        let mut v = to_json(&s2);
        let map = v.as_object_mut().unwrap();
        let arr = map
            .get_mut("authorized_pubkeys")
            .unwrap()
            .as_array_mut()
            .unwrap();
        // Replace second with first -> union shrinks -> mismatch.
        arr[1] = serde_json::Value::String(hex64(0x91));
        let json = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<ConnectSlot>(&json).unwrap_err();
        assert!(err.to_string().contains("projection hash mismatch"), "{}", err);
    }

    #[test]
    fn no_accidental_bound_consent_after_roundtrip() {
        let mut s = base_slot();
        s.authorized_pubkeys = vec![hex64(0x93)];
        s.bound_identity = Some(hex64(0x94));
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0x93; 32]).unwrap();
        // Intentionally do NOT approve an identity.
        s.client_grants = Some(snap);

        let v = to_json(&s);
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ConnectSlot = serde_json::from_str(&json).unwrap();
        assert!(decoded.approved_identities.is_empty());
        let g = decoded.client_grants.as_ref().unwrap();
        assert!(!g.allows(&[0x93; 32], &[0x94; 32]));
    }

    #[test]
    fn grant_a_does_not_leak_to_b() {
        let mut a = base_slot();
        a.slot_index = 0;
        a.authorized_pubkeys = vec![hex64(0xa1)];
        let mut snap_a = GrantSnapshot::empty();
        snap_a.add_client([0xa1; 32]).unwrap();
        a.client_grants = Some(snap_a);

        let mut b = base_slot();
        b.slot_index = 1;
        b.authorized_pubkeys = vec![hex64(0xb1)];
        let mut snap_b = GrantSnapshot::empty();
        snap_b.add_client([0xb1; 32]).unwrap();
        b.client_grants = Some(snap_b);

        let ja = serde_json::to_string(&to_json(&a)).unwrap();
        let jb = serde_json::to_string(&to_json(&b)).unwrap();

        let da: ConnectSlot = serde_json::from_str(&ja).unwrap();
        let db: ConnectSlot = serde_json::from_str(&jb).unwrap();

        let ga = da.client_grants.as_ref().unwrap();
        let gb = db.client_grants.as_ref().unwrap();
        assert!(ga.client_keys().contains(&[0xa1; 32]));
        assert!(!ga.client_keys().contains(&[0xb1; 32]));
        assert!(gb.client_keys().contains(&[0xb1; 32]));
        assert!(!gb.client_keys().contains(&[0xa1; 32]));
    }

    #[test]
    fn validate_slot_accepts_legacy_and_extended() {
        let legacy = base_slot();
        assert!(validate_slot(&legacy).is_ok());

        let mut ext = base_slot();
        ext.authorized_pubkeys = vec![hex64(0xc1)];
        let mut snap = GrantSnapshot::empty();
        snap.add_client([0xc1; 32]).unwrap();
        ext.client_grants = Some(snap);
        assert!(validate_slot(&ext).is_ok());

        // Extended with retained ids must be rejected.
        let mut bad = ext.clone();
        bad.approved_identities = "0011223344556677".into();
        assert!(validate_slot(&bad).is_err());
    }

    #[test]
    fn validate_slot_rejects_bad_methods() {
        let mut s = base_slot();
        let m: Vec<String> = (0..33).map(|i| format!("m{}", i)).collect();
        s.allowed_methods = m;
        assert!(validate_slot(&s).is_err());
    }

    #[test]
    fn legacy_invalid_fixture_allowed_when_grants_none() {
        // Historical fixtures may carry bad slot_index/secret; we must not
        // break the no-grants path.
        let mut s = base_slot();
        s.slot_index = 200;
        s.secret = "NOTHEX".into();
        let v = to_json(&s);
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ConnectSlot = serde_json::from_str(&json).unwrap();
        assert!(decoded.client_grants.is_none());
        assert_eq!(decoded.slot_index, 200);
    }
    #[test]
    fn host_known_reconnect_changes_current_without_changing_snapshot_order() {
        let mut slot = base_slot();
        slot.current_pubkey = Some(hex64(1));
        slot.authorized_pubkeys = vec![hex64(1), hex64(2)];
        slot.approved_identities = "aa".repeat(8);
        slot.client_grants = Some(GrantSnapshot::from_legacy(&slot).unwrap());
        slot.approved_identities.clear();
        slot.current_pubkey = Some(hex64(2));
        let round = roundtrip(&slot);
        assert!(round.client_grants.as_ref().unwrap().allows(&[1;32], &[0xaa;32]));
        assert!(round.client_grants.as_ref().unwrap().allows(&[2;32], &[0xaa;32]));
    }

    #[test]
    fn host_serializer_refuses_noncanonical_and_shadowed_authority() {
        let mut slot = base_slot();
        slot.current_pubkey = Some(hex64(0xab));
        slot.client_grants = Some(GrantSnapshot::from_legacy(&slot).unwrap());
        slot.current_pubkey = Some(hex64(0xab).to_ascii_uppercase());
        assert!(serde_json::to_string(&slot).is_err());
        slot.current_pubkey = Some(hex64(0xab));
        slot.approved_identities = "aa".repeat(8);
        assert!(serde_json::to_string(&slot).is_err());
    }

}
