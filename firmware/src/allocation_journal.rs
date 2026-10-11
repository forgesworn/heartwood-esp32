//! Dormant read-only local inventory. It grants no writer/witness authority.
//! The exact format and unresolved runtime gates are in the journal-format doc.
#![allow(dead_code)]

use super::NormalizedMasterRootV1;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const MAX_RECORDS: usize = 32;
const MAX_SEQ: u64 = 9_007_199_254_740_991;
const ANCHOR_PLAIN: usize = 431;
const ANCHOR_FRAME: usize = 476;
const SNAP_PLAIN: usize = 452;
const SNAP_FRAME: usize = 498;
const MANIFEST_PLAIN: usize = 278;
const MANIFEST_FRAME: usize = 356;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InventoryHold {
    Storage,
    Changed,
    Custody,
    Missing,
    Format,
    Authentication,
    Binding,
    Chain,
    Records,
}

pub(super) fn expected_blob_width(key: &str) -> Option<usize> {
    match key {
        "anchor" => Some(ANCHOR_FRAME),
        "snap0" | "snap1" => Some(SNAP_FRAME),
        k if k.len() == 3
            && k.as_bytes()[0] == b'm'
            && k.as_bytes()[1..].iter().all(u8::is_ascii_digit) =>
        {
            let n = (k.as_bytes()[1] - b'0') * 10 + k.as_bytes()[2] - b'0';
            (1..=32).contains(&n).then_some(MANIFEST_FRAME)
        }
        _ => None,
    }
}

/// The future adapter must enumerate ALL keys, read exact blobs, propagate any
/// error, and open the namespace read-only. A partial list is not a storage proof.
pub(crate) struct StoredBlob<'a> {
    pub(crate) key: &'a str,
    pub(crate) bytes: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    PairedNeedsWitness,
    LoneNeedsWitness,
    OrphanNeedsWitness,
}

/// Describes local bytes only. Derived writer and witness signatures are always
/// UNVERIFIED. There is no valid/ready/authorised token or release API.
pub(crate) struct Report {
    pub(crate) layout: Layout,
    pub(crate) snapshots_present: u8,
    pub(crate) orphan_ordinal: Option<u8>,
    pub(crate) retained_records: u8,
    pub(crate) pending: bool,
}
impl core::fmt::Debug for Report {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalInventory")
            .field("layout", &self.layout)
            .field("derived_writer_verified", &false)
            .field("witness_signatures_verified", &false)
            .finish_non_exhaustive()
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn key(root: &NormalizedMasterRootV1, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(root.0.as_ref()).expect("HMAC key width");
    for part in parts {
        h.update(part);
    }
    Zeroizing::new(h.finalize().into_bytes().into())
}
fn nonzero(b: &[u8]) -> bool {
    b.iter().any(|&v| v != 0)
}
fn array<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    b[at..at + N].try_into().expect("fixed validated layout")
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(array(b, at))
}
fn schema() -> [u8; 32] {
    hash(&[b"HW allocation journal schema v1\0"])
}
fn aad(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(parts.concat())
}

// Only descendants of the private held-root module can obtain this borrow.
// The production entry below is only called by HeldAllocationRoot::inspect_journal.
struct Codec<'a> {
    root: &'a NormalizedMasterRootV1,
    subject: Zeroizing<[u8; 32]>,
    issuer: &'a [u8; 32],
}
impl<'a> Codec<'a> {
    fn new(root: &'a NormalizedMasterRootV1, issuer: &'a [u8; 32]) -> Result<Self, InventoryHold> {
        let subject = key(root, &[b"VMLS/1 allocation subject\0"]);
        if !nonzero(subject.as_ref()) || !nonzero(issuer) {
            return Err(InventoryHold::Binding);
        }
        Ok(Self {
            root,
            subject,
            issuer,
        })
    }
    fn open<const N: usize>(
        &self,
        k: &[u8; 32],
        nonce: &[u8],
        ct: &[u8],
        tag: &[u8],
        associated: &[u8],
    ) -> Result<Zeroizing<[u8; N]>, InventoryHold> {
        if nonce.len() != 24 || ct.len() != N || tag.len() != 16 || !nonzero(nonce) {
            return Err(InventoryHold::Format);
        }
        let mut out = Zeroizing::new([0; N]);
        out.copy_from_slice(ct);
        XChaCha20Poly1305::new(k.into())
            .decrypt_in_place_detached(
                &XNonce::from(array::<24>(nonce, 0)),
                associated,
                out.as_mut(),
                &Tag::from(array::<16>(tag, 0)),
            )
            .map_err(|_| InventoryHold::Authentication)?;
        Ok(out)
    }
    fn anchor(&self, frame: &[u8]) -> Result<Anchor, InventoryHold> {
        if frame.len() != ANCHOR_FRAME || &frame[..5] != b"HWAC\x01" {
            return Err(InventoryHold::Format);
        }
        let k = key(self.root, &[b"HW allocation anchor key v1\0"]);
        let data = self.open(
            &k,
            &frame[5..29],
            &frame[29..460],
            &frame[460..],
            &aad(&[
                b"HW allocation anchor aad v1\0",
                self.subject.as_ref(),
                self.issuer,
                &frame[..29],
            ]),
        )?;
        let a = Anchor(data);
        if &a.0[..5] != b"HWAD\x01"
            || a.subject() != self.subject.as_ref()
            || a.issuer() != self.issuer
        {
            return Err(InventoryHold::Binding);
        }
        for chunk in a.0[5..229].chunks_exact(32) {
            if !nonzero(chunk) {
                return Err(InventoryHold::Binding);
            }
        }
        if a.0[197..229] != schema()
            || a.0[165..197] != hash(&[b"HW allocation route v1\0", &[1], &a.0[133..165]])
        {
            return Err(InventoryHold::Binding);
        }
        let pins = a.pins();
        let empty = state(0, &[], &pins);
        let digest = state_digest(&pins, &empty);
        if *a.genesis_digest() != digest {
            return Err(InventoryHold::Binding);
        }
        receipt(a.genesis_receipt(), a.subject(), 0, &digest)?;
        Ok(a)
    }
    fn manifest(&self, frame: &[u8], ordinal: u8, a: &Anchor) -> Result<Manifest, InventoryHold> {
        if frame.len() != MANIFEST_FRAME
            || &frame[..5] != b"HWAE\x01"
            || frame[5] != ordinal
            || ordinal == 0
            || ordinal > 32
        {
            return Err(InventoryHold::Format);
        }
        let pins = a.pins();
        let k = key(self.root, &[b"HW allocation manifest key v1\0", &pins]);
        let data = self.open(
            &k,
            &frame[38..62],
            &frame[62..340],
            &frame[340..],
            &aad(&[b"HW allocation manifest aad v1\0", &pins, &frame[..62]]),
        )?;
        if &data[..5] != b"HWAM\x01"
            || data[5] != ordinal
            || data[6..38] != *a.issuer()
            || data[230..262] != schema()
            || number(data.as_ref(), 262) >= number(data.as_ref(), 270)
        {
            return Err(InventoryHold::Binding);
        }
        for chunk in data[6..262].chunks_exact(32) {
            if !nonzero(chunk) {
                return Err(InventoryHold::Binding);
            }
        }
        let id = hash(&[b"HW allocation manifest v1\0", &pins, data.as_ref()]);
        if frame[6..38] != id {
            return Err(InventoryHold::Binding);
        }
        Ok(Manifest { data, id })
    }
    fn snapshot(&self, frame: &[u8], slot: u8, a: &Anchor) -> Result<Snapshot, InventoryHold> {
        if slot > 1 || frame.len() != SNAP_FRAME || &frame[..5] != b"HWSC\x01" || frame[5] != slot {
            return Err(InventoryHold::Format);
        }
        let pins = a.pins();
        let k = key(self.root, &[b"HW allocation snapshot key v1\0", &pins]);
        let data = self.open(
            &k,
            &frame[6..30],
            &frame[30..482],
            &frame[482..],
            &aad(&[b"HW allocation snapshot aad v1\0", &pins, &frame[..30]]),
        )?;
        let s = Snapshot {
            data,
            frame_hash: hash(&[b"HW allocation snapshot v1\0", &[slot], frame]),
        };
        if &s.data[..5] != b"HWAS\x01"
            || s.data[46..78] != pins
            || s.generation() == 0
            || (s.generation() == 1) == nonzero(s.predecessor())
            || s.seq() > MAX_SEQ
        {
            return Err(InventoryHold::Binding);
        }
        check_state(s.active())?;
        if s.seq() < s.active()[0] as u64
            || (s.active()[0] == 0 && s.seq() != 0)
            || *s.active_digest() != state_digest(&pins, s.active())
        {
            return Err(InventoryHold::Binding);
        }
        receipt(s.receipt(), a.subject(), s.seq(), s.active_digest())?;
        match s.phase() {
            0 => {
                if nonzero(&s.data[353..]) {
                    return Err(InventoryHold::Binding);
                }
            }
            1 => {
                if s.seq() == MAX_SEQ {
                    return Err(InventoryHold::Binding);
                }
                check_state(s.candidate())?;
                if *s.candidate_digest() != state_digest(&pins, s.candidate()) {
                    return Err(InventoryHold::Binding);
                }
                candidate_transition(&s)?;
            }
            _ => return Err(InventoryHold::Format),
        }
        if s.generation() == 1
            && (s.phase() != 0
                || s.seq() != 0
                || s.active()[0] != 0
                || s.active_digest() != a.genesis_digest()
                || s.receipt() != a.genesis_receipt())
        {
            return Err(InventoryHold::Binding);
        }
        Ok(s)
    }
}

struct Anchor(Zeroizing<[u8; ANCHOR_PLAIN]>);
impl Anchor {
    fn subject(&self) -> &[u8; 32] {
        self.0[5..37].try_into().unwrap()
    }
    fn issuer(&self) -> &[u8; 32] {
        self.0[69..101].try_into().unwrap()
    }
    fn pins(&self) -> [u8; 32] {
        hash(&[b"HW allocation pins v1\0", &self.0[..229]])
    }
    fn genesis_digest(&self) -> &[u8; 32] {
        self.0[229..261].try_into().unwrap()
    }
    fn genesis_receipt(&self) -> &[u8] {
        &self.0[261..]
    }
}
struct Manifest {
    data: Zeroizing<[u8; MANIFEST_PLAIN]>,
    id: [u8; 32],
}
struct Snapshot {
    data: Zeroizing<[u8; SNAP_PLAIN]>,
    frame_hash: [u8; 32],
}
impl Snapshot {
    fn phase(&self) -> u8 {
        self.data[5]
    }
    fn generation(&self) -> u64 {
        number(self.data.as_ref(), 6)
    }
    fn predecessor(&self) -> &[u8] {
        &self.data[14..46]
    }
    fn seq(&self) -> u64 {
        number(self.data.as_ref(), 78)
    }
    fn active_digest(&self) -> &[u8; 32] {
        self.data[86..118].try_into().unwrap()
    }
    fn receipt(&self) -> &[u8] {
        &self.data[118..288]
    }
    fn active(&self) -> &[u8] {
        &self.data[288..353]
    }
    fn candidate(&self) -> &[u8] {
        &self.data[353..418]
    }
    fn kind(&self) -> u8 {
        self.data[418]
    }
    fn ordinal(&self) -> u8 {
        self.data[419]
    }
    fn candidate_digest(&self) -> &[u8; 32] {
        self.data[420..452].try_into().unwrap()
    }
}

fn receipt(b: &[u8], subject: &[u8; 32], seq: u64, digest: &[u8; 32]) -> Result<(), InventoryHold> {
    // These are structural comparisons ONLY, never an Ed25519 or fresh receipt gate.
    if b.len() != 170
        || b[..2] != [1, 0]
        || b[2..34] != *subject
        || number(b, 34) != seq
        || b[42..74] != *digest
        || !nonzero(&b[74..106])
        || !nonzero(&b[106..])
    {
        return Err(InventoryHold::Binding);
    }
    Ok(())
}
fn check_state(s: &[u8]) -> Result<(), InventoryHold> {
    if s.len() != 65 || s[0] > 32 || !nonzero(&s[1..33]) {
        return Err(InventoryHold::Records);
    }
    for (i, &v) in s[33..].iter().enumerate() {
        if (i < s[0] as usize && !(1..=3).contains(&v)) || (i >= s[0] as usize && v != 0) {
            return Err(InventoryHold::Records);
        }
    }
    Ok(())
}
fn set_hash(count: u8, ids: &[[u8; 32]], pins: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HW allocation record set v1\0");
    h.update(pins);
    h.update([count]);
    for (i, id) in ids.iter().take(count as usize).enumerate() {
        h.update([i as u8 + 1]);
        h.update(id);
    }
    h.finalize().into()
}
fn state(count: u8, ids: &[[u8; 32]], pins: &[u8; 32]) -> [u8; 65] {
    let mut out = [0; 65];
    out[0] = count;
    out[1..33].copy_from_slice(&set_hash(count, ids, pins));
    out[33..33 + count as usize].fill(1);
    out
}
fn state_digest(pins: &[u8; 32], s: &[u8]) -> [u8; 32] {
    hash(&[b"HW allocation state v1\0", pins, s])
}
fn candidate_transition(s: &Snapshot) -> Result<(), InventoryHold> {
    let a = s.active();
    let c = s.candidate();
    let n = s.ordinal() as usize;
    if n == 0 || n > 32 {
        return Err(InventoryHold::Records);
    }
    match s.kind() {
        1 => {
            if a[0] >= 32 || c[0] != a[0] + 1 || n != c[0] as usize || c[33 + n - 1] != 1 {
                return Err(InventoryHold::Records);
            }
            for i in 0..32 {
                if i != n - 1 && a[33 + i] != c[33 + i] {
                    return Err(InventoryHold::Records);
                }
            }
        }
        2 | 3 => {
            if n > a[0] as usize
                || a[..33] != c[..33]
                || a[33 + n - 1] != 1
                || c[33 + n - 1] != s.kind()
            {
                return Err(InventoryHold::Records);
            }
            for i in 0..32 {
                if i != n - 1 && a[33 + i] != c[33 + i] {
                    return Err(InventoryHold::Records);
                }
            }
        }
        _ => return Err(InventoryHold::Records),
    }
    Ok(())
}
fn chain(old: &Snapshot, new: &Snapshot) -> Result<(), InventoryHold> {
    if old.generation().checked_add(1) != Some(new.generation())
        || new.predecessor() != old.frame_hash
    {
        return Err(InventoryHold::Chain);
    }
    let matches = match (old.phase(), new.phase()) {
        (0, 1) => {
            old.seq() == new.seq()
                && old.active() == new.active()
                && old.active_digest() == new.active_digest()
                && old.receipt() == new.receipt()
        }
        (1, 0) => {
            old.seq().checked_add(1) == Some(new.seq())
                && old.candidate() == new.active()
                && old.candidate_digest() == new.active_digest()
        }
        _ => false,
    };
    if !matches {
        return Err(InventoryHold::Chain);
    }
    Ok(())
}

pub(super) fn namespace(root: &NormalizedMasterRootV1) -> String {
    let k = key(root, &[b"HW allocation local namespace v1\0"]);
    let mut out = String::from("a");
    const HEX: &[u8] = b"0123456789abcdef";
    for &v in &k[..7] {
        out.push(HEX[(v >> 4) as usize] as char);
        out.push(HEX[(v & 15) as usize] as char);
    }
    out
}

/// LOWER BOUND only: not a space preflight, reservation or authority check.
pub(super) fn minimum_entries(count: u8) -> Result<usize, InventoryHold> {
    if count > 32 {
        return Err(InventoryHold::Records);
    }
    Ok(54 + 14 * count as usize)
}

pub(super) fn inspect(
    root: &NormalizedMasterRootV1,
    issuer: &[u8; 32],
    blobs: &[StoredBlob<'_>],
) -> Result<Report, InventoryHold> {
    if blobs.len() > 35 {
        return Err(InventoryHold::Format);
    }
    let mut stored: [Option<&[u8]>; 35] = [None; 35];
    for blob in blobs {
        let p = match blob.key {
            "anchor" => 0,
            "snap0" => 1,
            "snap1" => 2,
            k if k.len() == 3
                && k.as_bytes()[0] == b'm'
                && k.as_bytes()[1..].iter().all(u8::is_ascii_digit) =>
            {
                let n = (k.as_bytes()[1] - b'0') * 10 + k.as_bytes()[2] - b'0';
                if n == 0 || n > 32 {
                    return Err(InventoryHold::Format);
                }
                2 + n as usize
            }
            _ => return Err(InventoryHold::Format),
        };
        if stored[p].replace(blob.bytes).is_some() {
            return Err(InventoryHold::Format);
        }
    }
    let codec = Codec::new(root, issuer)?;
    let a = codec.anchor(stored[0].ok_or(InventoryHold::Missing)?)?;
    // A present invalid slot must fail, even if the other is valid.
    let s0 = stored[1].map(|b| codec.snapshot(b, 0, &a)).transpose()?;
    let s1 = stored[2].map(|b| codec.snapshot(b, 1, &a)).transpose()?;
    let (latest, slots) = match (&s0, &s1) {
        (Some(x), Some(y)) => {
            let (old, new) = if x.generation() < y.generation() {
                (x, y)
            } else {
                (y, x)
            };
            chain(old, new)?;
            (new, 2)
        }
        (Some(x), None) | (None, Some(x)) => (x, 1),
        (None, None) => return Err(InventoryHold::Missing),
    };
    let mut manifests: Vec<Manifest> = Vec::new();
    let mut ids = Vec::new();
    let mut gap = false;
    for n in 1..=32 {
        match stored[2 + n] {
            None => gap = true,
            Some(_) if gap => return Err(InventoryHold::Records),
            Some(b) => {
                let m = codec.manifest(b, n as u8, &a)?;
                for old in &manifests {
                    // Salt, R, browser operation, challenge: all remain burned.
                    for at in [38, 70, 166, 198] {
                        if old.data[at..at + 32] == m.data[at..at + 32] {
                            return Err(InventoryHold::Records);
                        }
                    }
                }
                ids.push(m.id);
                manifests.push(m);
            }
        }
    }
    let pins = a.pins();
    // Validate both snapshots' sets, including the older frame, against every
    // immutable record rather than trusting the newest state hash alone.
    for snap in [&s0, &s1].into_iter().flatten() {
        for st in
            core::iter::once(snap.active()).chain((snap.phase() == 1).then(|| snap.candidate()))
        {
            if st[0] as usize > ids.len() || st[1..33] != set_hash(st[0], &ids, &pins) {
                return Err(InventoryHold::Records);
            }
        }
    }
    let referenced = if latest.phase() == 1 {
        latest.candidate()[0]
    } else {
        latest.active()[0]
    } as usize;
    let orphan = match ids.len().checked_sub(referenced) {
        Some(0) => None,
        Some(1) if latest.phase() == 0 && referenced < 32 => Some((referenced + 1) as u8),
        _ => return Err(InventoryHold::Records),
    };
    Ok(Report {
        layout: if orphan.is_some() {
            Layout::OrphanNeedsWitness
        } else if slots == 1 {
            Layout::LoneNeedsWitness
        } else {
            Layout::PairedNeedsWitness
        },
        snapshots_present: slots,
        orphan_ordinal: orphan,
        retained_records: ids.len() as u8,
        pending: latest.phase() == 1,
    })
}

#[cfg(test)]
#[path = "../../common/src/allocation_journal_host_tests.rs"]
mod tests;
