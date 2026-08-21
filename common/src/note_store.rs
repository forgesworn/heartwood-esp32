//! LNURLcash bearer-note ledger — the note-locker lifecycle model.
//!
//! Heartwood custodies LUD-25 bearer notes for a browser wallet that does all
//! the mint HTTP work (see docs/plans/2026-08-18-note-locker-goal.md). The
//! wire contract is lnurl-vault's command set, so the lnurl-wallet client
//! drives this store unmodified; this module is the state machine and byte
//! format behind those commands, kept platform-independent so host tests can
//! pin the two invariants money depends on:
//!
//!  - **Persist-before-disclose.** A freshly generated secret reaches storage
//!    before its hash is returned to the caller. The hash is what the wallet
//!    registers with the mint; once registered, the mint holds value that
//!    only the preimage can move, so a power cut between disclosure and
//!    persistence would burn that value permanently. The reverse order can
//!    only ever strand an unreferenced blob.
//!  - **A note is its secret.** Importing a secret the store already holds
//!    returns the existing note untouched — two entries backed by one secret
//!    would report double the value and leave one looking spendable after
//!    the other was melted. This is also what makes a lost import response
//!    safe to retry.
//!
//! Like lnurl-vault's `vault.c` (itself adapted from this repo's approval
//! logic — the designs trade both ways), this module enforces state rules
//! only. Physical button gating lives with the dispatcher; storage and
//! randomness are injected so the firmware wires NVS + `fill_random` and the
//! tests wire deterministic fakes. Sealing at rest wraps the encoded blob one
//! layer out (`seed_cipher`-style AEAD, phase 2) — the codec here is the
//! plaintext record format.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::hex::{hex_decode, hex_encode};

/// Raw secret length — a LUD-25 `k1` is 32 bytes, disclosed as 64 hex chars.
pub const SECRET_LEN: usize = 32;
/// Note id: 8 lowercase hex chars (4 random bytes), the vault-protocol shape.
pub const ID_LEN: usize = 8;
/// Cap on held notes. Steady state is one balance note plus split/merge
/// transients; 16 sealed records stay comfortably inside the existing 16 KB
/// NVS partition alongside masters, policies and personas.
pub const MAX_NOTES: usize = 16;
pub const MAX_LABEL_LEN: usize = 32;
pub const MAX_HOST_LEN: usize = 64;
/// LUD-25 offline-verification signature, hex. A recoverable signature is 65
/// bytes = 130 hex chars; allow a little slack for format drift upstream.
pub const MAX_SIG_LEN: usize = 132;
pub const MAX_PARENTS: usize = 16;
/// Cap on notes that arrived by Nostr gift wrap and have not yet been rotated
/// by a wallet. A letterbox, not a vault: the secret also sits encrypted on
/// every relay that carried the wrap, and the device cannot rotate it, so
/// these are held only until a wallet collects them. Low so a stranger
/// cannot fill the locker with dust.
pub const MAX_RECEIVED: usize = 4;

const NOTE_MAGIC: [u8; 4] = *b"HWNB";
/// v2 appends the Nostr peer. v1 blobs decode with `peer: None`.
const NOTE_VERSION: u8 = 2;

/// `pending` → `confirmed` → `spent`, exactly the vault lifecycle: a secret
/// exists and its hash may be registered mint-side (PENDING), the mint has
/// confirmed the note is real spendable value (CONFIRMED), the note was
/// melted or burned as a rotate/split/merge input (SPENT).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoteState {
    Pending,
    Confirmed,
    Spent,
}

impl NoteState {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoteState::Pending => "pending",
            NoteState::Confirmed => "confirmed",
            NoteState::Spent => "spent",
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            NoteState::Pending => 0,
            NoteState::Confirmed => 1,
            NoteState::Spent => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(NoteState::Pending),
            1 => Some(NoteState::Confirmed),
            2 => Some(NoteState::Spent),
            _ => None,
        }
    }
}

/// Nostr provenance. A note that arrived by gift wrap, or left by one. Not a
/// lifecycle state (the wire protocol's three states are fixed by the vault
/// client) but it changes what the note may do: a note with a peer can never
/// be sent again -- a received secret is already on the relays under someone
/// else's key and must be rotated first, and a sent one would be a double
/// spend waiting for the mint to settle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer {
    From([u8; 32]),
    To([u8; 32]),
}

/// A held note, secret included. Never serialise this onto a wire — that is
/// what [`NoteMeta`] exists for. The secret is zeroised on drop.
#[derive(Clone)]
pub struct Note {
    pub id: String,
    pub secret: [u8; SECRET_LEN],
    pub state: NoteState,
    pub amount_msat: u64,
    pub host: String,
    pub label: String,
    /// Optional LUD-25 mint signature over (note id, amount), hex. Stored
    /// opaquely for the wallet to verify — the device never interprets it.
    pub sig: String,
    pub parent_ids: Vec<String>,
    pub created_at: u32,
    pub updated_at: u32,
    pub peer: Option<Peer>,
}

impl Drop for Note {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Metadata view of a note — the only shape list/get paths may expose.
/// Deliberately has no secret field, so "accidentally serialised the money"
/// is a type error rather than a review finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteMeta {
    pub id: String,
    pub state: NoteState,
    pub amount_msat: u64,
    pub host: String,
    pub label: String,
    pub sig: String,
    pub parent_ids: Vec<String>,
    pub created_at: u32,
    pub updated_at: u32,
    pub peer: Option<Peer>,
}

impl Note {
    fn meta(&self) -> NoteMeta {
        NoteMeta {
            id: self.id.clone(),
            state: self.state,
            amount_msat: self.amount_msat,
            host: self.host.clone(),
            label: self.label.clone(),
            sig: self.sig.clone(),
            parent_ids: self.parent_ids.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            peer: self.peer,
        }
    }
}

/// Why an operation refused. Maps one-to-one onto the vault protocol's error
/// codes (`code()`), with storage write failure folded into `storage_full`
/// the way the vault reports it — the caller-visible truth is "the device
/// could not persist this", and the two causes are distinguished by
/// `get_info`'s storage field, not the per-command error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoteError {
    NotFound,
    InvalidState,
    /// At cap, index unknown this boot, or a storage write failed.
    StorageFull,
    BadRequest,
}

impl NoteError {
    pub fn code(&self) -> &'static str {
        match self {
            NoteError::NotFound => "not_found",
            NoteError::InvalidState => "invalid_state",
            NoteError::StorageFull => "storage_full",
            NoteError::BadRequest => "bad_request",
        }
    }
}

/// A storage backend failure. Deliberately carries nothing: the model reacts
/// identically whatever the cause, and the firmware layer owns logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageError;

/// Injected persistence, mirroring `vault_storage_t`: an index blob naming
/// the held ids, one encoded blob per note keyed by id. The firmware wires
/// NVS (with at-rest sealing around the blob); tests wire an in-memory fake
/// with power-cut fail points.
///
/// `load_index` distinguishes "no index yet" (`Ok(None)` — a fresh device,
/// the store starts empty and knows it) from "the read failed" (`Err` — the
/// store must fail closed, see [`NoteStore::index_known`]).
pub trait NoteStorage {
    fn load_index(&mut self) -> Result<Option<Vec<String>>, StorageError>;
    fn save_index(&mut self, ids: &[String]) -> Result<(), StorageError>;
    fn load_note(&mut self, id: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError>;
    fn delete_note(&mut self, id: &str) -> Result<(), StorageError>;
    /// The trusted-sender list (`trust::TrustList::encode`), beside the
    /// notes. A storage that cannot keep it refuses, and the command layer
    /// then refuses the trust: an unpersisted trust would vanish at reboot
    /// and mislead until then.
    fn save_trust(&mut self, _blob: &[u8]) -> Result<(), StorageError> {
        Err(StorageError)
    }
}

// ---- codec ----

/// Encode one note as the plaintext record blob (magic, version, fixed
/// fields, length-prefixed strings). Sealing at rest wraps this whole blob;
/// the format itself carries no key material beyond the secret it exists to
/// hold.
pub fn encode_note(note: &Note) -> Result<Vec<u8>, &'static str> {
    if note.id.len() != ID_LEN || !is_lower_hex(&note.id) {
        return Err("note id must be 8 lowercase hex chars");
    }
    if note.host.len() > MAX_HOST_LEN {
        return Err("host too long");
    }
    if note.label.len() > MAX_LABEL_LEN {
        return Err("label too long");
    }
    if note.sig.len() > MAX_SIG_LEN || !is_lower_hex_or_empty(&note.sig) {
        return Err("sig malformed");
    }
    if note.parent_ids.len() > MAX_PARENTS {
        return Err("too many parents");
    }
    let mut out = Vec::with_capacity(64 + SECRET_LEN + note.host.len() + note.label.len());
    out.extend_from_slice(&NOTE_MAGIC);
    out.push(NOTE_VERSION);
    out.extend_from_slice(note.id.as_bytes());
    out.push(note.state.to_byte());
    out.extend_from_slice(&note.amount_msat.to_be_bytes());
    out.extend_from_slice(&note.created_at.to_be_bytes());
    out.extend_from_slice(&note.updated_at.to_be_bytes());
    out.extend_from_slice(&note.secret);
    out.push(note.host.len() as u8);
    out.extend_from_slice(note.host.as_bytes());
    out.push(note.label.len() as u8);
    out.extend_from_slice(note.label.as_bytes());
    out.push(note.sig.len() as u8);
    out.extend_from_slice(note.sig.as_bytes());
    out.push(note.parent_ids.len() as u8);
    for p in &note.parent_ids {
        if p.len() != ID_LEN || !is_lower_hex(p) {
            return Err("parent id must be 8 lowercase hex chars");
        }
        out.extend_from_slice(p.as_bytes());
    }
    match note.peer {
        None => out.push(0),
        Some(Peer::From(pk)) => {
            out.push(1);
            out.extend_from_slice(&pk);
        }
        Some(Peer::To(pk)) => {
            out.push(2);
            out.extend_from_slice(&pk);
        }
    }
    Ok(out)
}

/// Decode a record blob. `None` for anything malformed — a partial note is
/// refused outright rather than guessed at, the same rule lnurl-vault's
/// `nvs_load_note` follows ("refusing a partial note").
pub fn decode_note(blob: &[u8]) -> Option<Note> {
    let mut r = Reader(blob);
    if r.take(4)? != NOTE_MAGIC {
        return None;
    }
    let version = r.u8()?;
    if version != 1 && version != NOTE_VERSION {
        return None;
    }
    let id = r.str_exact(ID_LEN)?;
    if !is_lower_hex(&id) {
        return None;
    }
    let state = NoteState::from_byte(r.u8()?)?;
    let amount_msat = r.u64()?;
    let created_at = r.u32()?;
    let updated_at = r.u32()?;
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(r.take(SECRET_LEN)?);
    let host = r.str_prefixed(MAX_HOST_LEN)?;
    let label = r.str_prefixed(MAX_LABEL_LEN)?;
    let sig = r.str_prefixed(MAX_SIG_LEN)?;
    if !is_lower_hex_or_empty(&sig) {
        return None;
    }
    let parent_count = r.u8()? as usize;
    if parent_count > MAX_PARENTS {
        return None;
    }
    let mut parent_ids = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        let p = r.str_exact(ID_LEN)?;
        if !is_lower_hex(&p) {
            return None;
        }
        parent_ids.push(p);
    }
    let peer = if version >= 2 {
        match r.u8()? {
            0 => None,
            1 => Some(Peer::From(r.take(32)?.try_into().ok()?)),
            2 => Some(Peer::To(r.take(32)?.try_into().ok()?)),
            _ => return None,
        }
    } else {
        None
    };
    if !r.0.is_empty() {
        // Trailing bytes mean the blob is not what it claims to be.
        return None;
    }
    Some(Note {
        id,
        secret,
        state,
        amount_msat,
        host,
        label,
        sig,
        parent_ids,
        created_at,
        updated_at,
        peer,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn str_exact(&mut self, n: usize) -> Option<String> {
        core::str::from_utf8(self.take(n)?).ok().map(|s| s.to_string())
    }
    fn str_prefixed(&mut self, max: usize) -> Option<String> {
        let len = self.u8()? as usize;
        if len > max {
            return None;
        }
        self.str_exact(len)
    }
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_lower_hex_or_empty(s: &str) -> bool {
    s.is_empty() || is_lower_hex(s)
}

/// `sha256(secret)` as lowercase hex — the `h` a wallet registers with the
/// mint, and (not coincidentally) exactly the mint's own ledger key for the
/// note (`_note_id` in lnurl-mint).
pub fn secret_hash_hex(secret: &[u8; SECRET_LEN]) -> String {
    let digest = Sha256::digest(secret);
    hex_encode(&digest)
}

// ---- the store ----

/// What `list_notes` hands back for one page.
pub struct NotePage {
    pub notes: Vec<NoteMeta>,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
}

/// The in-RAM ledger plus its persistence discipline. All mutating paths
/// write storage first and update RAM only on success, so a failed write
/// leaves RAM matching what is actually on flash and a retry converges.
pub struct NoteStore {
    notes: Vec<Note>,
    /// False when this boot could not read the persisted index. The store
    /// then refuses anything that would create a note or rewrite the index —
    /// either would risk overwriting a list it cannot see. Blob-only rewrites
    /// (confirm, mark_spent, rename) stay allowed, matching the vault.
    index_known: bool,
    cap: usize,
}

/// The outcome of loading: the store, plus any indexed ids whose blobs were
/// missing or undecodable. The store skips them (their flash bytes are left
/// alone for a firmware that understands them); the caller decides how loudly
/// to report — anything skipped means note counts are not statements about
/// how many notes exist.
pub struct LoadOutcome {
    pub store: NoteStore,
    pub skipped: Vec<String>,
}

impl NoteStore {
    /// Load every persisted note. An unreadable index fails closed: the store
    /// comes up empty with `index_known == false` and refuses creation, the
    /// analogue of `vault_init_storage_unavailable`. Recovery is a reboot,
    /// never a wipe.
    pub fn load(storage: &mut dyn NoteStorage, cap: usize) -> LoadOutcome {
        let ids = match storage.load_index() {
            Ok(Some(ids)) => ids,
            Ok(None) => Vec::new(),
            Err(_) => {
                return LoadOutcome {
                    store: NoteStore { notes: Vec::new(), index_known: false, cap },
                    skipped: Vec::new(),
                }
            }
        };
        let mut notes = Vec::new();
        let mut skipped = Vec::new();
        for id in ids {
            match storage.load_note(&id) {
                Ok(Some(mut blob)) => {
                    let decoded = decode_note(&blob);
                    blob.zeroize(); // the raw blob embeds the secret
                    match decoded {
                        Some(note) if note.id == id => notes.push(note),
                        _ => skipped.push(id),
                    }
                }
                _ => skipped.push(id),
            }
        }
        LoadOutcome { store: NoteStore { notes, index_known: true, cap }, skipped }
    }

    /// Fail-closed constructor for a boot whose storage never came up at all.
    pub fn storage_unavailable(cap: usize) -> NoteStore {
        NoteStore { notes: Vec::new(), index_known: false, cap }
    }

    pub fn index_known(&self) -> bool {
        self.index_known
    }

    pub fn counts(&self) -> (usize, usize) {
        let pending = self.notes.iter().filter(|n| n.state == NoteState::Pending).count();
        (self.notes.len(), pending)
    }

    /// Received notes a wallet has not yet rotated and marked spent.
    pub fn received_count(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| n.state == NoteState::Confirmed && matches!(n.peer, Some(Peer::From(_))))
            .count()
    }

    pub fn get_meta(&self, id: &str) -> Option<NoteMeta> {
        self.notes.iter().find(|n| n.id == id).map(|n| n.meta())
    }

    /// One page of metadata, vault-protocol paging semantics: `total` is how
    /// many notes exist, `next_offset` present only when more follow.
    pub fn list(&self, offset: usize, limit: usize) -> NotePage {
        let total = self.notes.len();
        let start = offset.min(total);
        let end = start.saturating_add(limit.max(1)).min(total);
        let notes = self.notes[start..end].iter().map(|n| n.meta()).collect();
        NotePage {
            notes,
            total,
            offset,
            next_offset: if end < total { Some(end) } else { None },
        }
    }

    /// Generate one fresh secret (rotate/merge replacement). Persists the
    /// PENDING note — blob first, then index — and only then returns
    /// `(id, h)`. The hash crossing this function's boundary is the
    /// disclosure the persist-before-disclose invariant is about.
    pub fn new_secret(
        &mut self,
        storage: &mut dyn NoteStorage,
        rng: &mut dyn FnMut(&mut [u8]),
        parent_ids: &[String],
        label: &str,
        now: u32,
    ) -> Result<(String, String), NoteError> {
        self.admit_creation(1)?;
        let note = self.build_pending(storage, rng, parent_ids, label, now)?;
        let (id, h) = (note.id.clone(), secret_hash_hex(&note.secret));
        self.persist_new(storage, alloc::vec![note])?;
        Ok((id, h))
    }

    /// Generate two fresh secrets sharing one parent lineage (split target +
    /// change). Both blobs are persisted before the single index write, so a
    /// cut anywhere leaves either both indexed or neither — and in neither
    /// case has a hash been disclosed.
    pub fn new_secret_pair(
        &mut self,
        storage: &mut dyn NoteStorage,
        rng: &mut dyn FnMut(&mut [u8]),
        parent_ids: &[String],
        label: &str,
        now: u32,
    ) -> Result<(String, String, String, String), NoteError> {
        self.admit_creation(2)?;
        let first = self.build_pending(storage, rng, parent_ids, label, now)?;
        // The second draw must not collide with the first, which is not yet
        // in `self.notes` — check explicitly.
        let mut second = self.build_pending(storage, rng, parent_ids, label, now)?;
        if second.id == first.id {
            second.id = self.fresh_id(rng, Some(&first.id)).ok_or(NoteError::StorageFull)?;
        }
        let out = (
            first.id.clone(),
            secret_hash_hex(&first.secret),
            second.id.clone(),
            secret_hash_hex(&second.secret),
        );
        self.persist_new(storage, alloc::vec![first, second])?;
        Ok(out)
    }

    /// PENDING → CONFIRMED once the mint answered OK. A blob-only rewrite:
    /// allowed even when the index is unknown, like the vault.
    pub fn confirm(
        &mut self,
        storage: &mut dyn NoteStorage,
        id: &str,
        amount_msat: u64,
        host: &str,
        sig: Option<&str>,
        now: u32,
    ) -> Result<(), NoteError> {
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(NoteError::BadRequest);
        }
        let sig = sig.unwrap_or("");
        if sig.len() > MAX_SIG_LEN || !is_lower_hex_or_empty(sig) {
            return Err(NoteError::BadRequest);
        }
        let idx = self.find(id)?;
        if self.notes[idx].state != NoteState::Pending {
            return Err(NoteError::InvalidState);
        }
        let mut updated = self.notes[idx].clone();
        updated.state = NoteState::Confirmed;
        updated.amount_msat = amount_msat;
        updated.host = host.to_string();
        updated.sig = sig.to_string();
        updated.updated_at = now;
        self.persist_rewrite(storage, idx, updated)
    }

    /// Drop a PENDING note the mint rejected. Index write first, then blob
    /// delete: a cut between the two strands an unreferenced blob, never an
    /// indexed ghost.
    pub fn discard(&mut self, storage: &mut dyn NoteStorage, id: &str) -> Result<(), NoteError> {
        let idx = self.find(id)?;
        if self.notes[idx].state != NoteState::Pending {
            return Err(NoteError::InvalidState);
        }
        self.persist_remove(storage, idx)
    }

    /// Whether `export_secret` would succeed — the dispatcher's pre-approval
    /// state check, side-effect free so no secret is materialised just to
    /// probe. Split out because the export path used to call export_secret
    /// twice, hex-encoding (and then dropping, un-zeroised) the secret once
    /// purely as a state probe.
    pub fn can_export(&self, id: &str) -> Result<(), NoteError> {
        let idx = self.find(id)?;
        if self.notes[idx].state != NoteState::Confirmed {
            return Err(NoteError::InvalidState);
        }
        Ok(())
    }

    /// Reveal a CONFIRMED note's secret as hex. State check only — the
    /// physical gate is the dispatcher's job, exactly the `vault.c` split.
    pub fn export_secret(&self, id: &str) -> Result<String, NoteError> {
        self.can_export(id)?;
        let idx = self.find(id)?;
        Ok(hex_encode(&self.notes[idx].secret))
    }

    /// Register an externally-known secret directly as CONFIRMED. Idempotent
    /// on the secret: re-importing returns the existing note's id, `false`,
    /// and modifies nothing — a second import cannot restate amount or host.
    pub fn import_secret(
        &mut self,
        storage: &mut dyn NoteStorage,
        rng: &mut dyn FnMut(&mut [u8]),
        k1_hex: &str,
        host: &str,
        amount_msat: u64,
        label: &str,
        now: u32,
    ) -> Result<(String, bool), NoteError> {
        if k1_hex.len() != SECRET_LEN * 2 {
            return Err(NoteError::BadRequest);
        }
        let mut secret_bytes = hex_decode(k1_hex).map_err(|_| NoteError::BadRequest)?;
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();
        if host.is_empty() || host.len() > MAX_HOST_LEN || label.len() > MAX_LABEL_LEN {
            return Err(NoteError::BadRequest);
        }
        if let Some(existing) = self.notes.iter().find(|n| n.secret == secret) {
            return Ok((existing.id.clone(), false));
        }
        self.admit_creation(1)?;
        let id = self.fresh_id(rng, None).ok_or(NoteError::StorageFull)?;
        let note = Note {
            id: id.clone(),
            secret,
            state: NoteState::Confirmed,
            amount_msat,
            host: host.to_string(),
            label: label.to_string(),
            sig: String::new(),
            parent_ids: Vec::new(),
            created_at: now,
            updated_at: now,
            peer: None,
        };
        self.persist_new(storage, alloc::vec![note])?;
        Ok((id, true))
    }

    /// Store a secret that arrived by gift wrap from `from`, CONFIRMED with
    /// provenance. Idempotent on the secret, like import: a relay replaying
    /// the same wrap yields the existing id and no second entry. Subject to
    /// [`MAX_RECEIVED`] as well as the overall cap.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &mut self,
        storage: &mut dyn NoteStorage,
        rng: &mut dyn FnMut(&mut [u8]),
        secret: &[u8; SECRET_LEN],
        host: &str,
        amount_msat: u64,
        from: &[u8; 32],
        now: u32,
    ) -> Result<(String, bool), NoteError> {
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(NoteError::BadRequest);
        }
        if let Some(existing) = self.notes.iter().find(|n| n.secret == *secret) {
            return Ok((existing.id.clone(), false));
        }
        if self.received_count() >= MAX_RECEIVED {
            return Err(NoteError::StorageFull);
        }
        self.admit_creation(1)?;
        let id = self.fresh_id(rng, None).ok_or(NoteError::StorageFull)?;
        let note = Note {
            id: id.clone(),
            secret: *secret,
            state: NoteState::Confirmed,
            amount_msat,
            host: host.to_string(),
            label: String::new(),
            sig: String::new(),
            parent_ids: Vec::new(),
            created_at: now,
            updated_at: now,
            peer: Some(Peer::From(*from)),
        };
        self.persist_new(storage, alloc::vec![note])?;
        Ok((id, true))
    }

    /// Whether `mark_sent` (and so a gift-wrapped send) may proceed:
    /// CONFIRMED and never given to or received from anyone.
    pub fn can_send(&self, id: &str) -> Result<(), NoteError> {
        let idx = self.find(id)?;
        let n = &self.notes[idx];
        if n.state != NoteState::Confirmed || n.peer.is_some() {
            return Err(NoteError::InvalidState);
        }
        Ok(())
    }

    /// Record that the secret was sealed to `to`. Persisted BEFORE the wrap
    /// leaves the device, so a cut between the two strands a wrap that was
    /// never published rather than a note that can be sent twice. The note
    /// stays CONFIRMED (the mint still honours it until someone rotates, which
    /// is what makes unsend possible) but can never be sent again.
    pub fn mark_sent(
        &mut self,
        storage: &mut dyn NoteStorage,
        id: &str,
        to: &[u8; 32],
        now: u32,
    ) -> Result<(), NoteError> {
        self.can_send(id)?;
        let idx = self.find(id)?;
        let mut updated = self.notes[idx].clone();
        updated.peer = Some(Peer::To(*to));
        updated.updated_at = now;
        self.persist_rewrite(storage, idx, updated)
    }

    /// The raw secret, for sealing inside a gift wrap on-device. State check
    /// only, as with `export_secret`; the caller zeroises its copy.
    pub fn secret_for_send(&self, id: &str) -> Result<[u8; SECRET_LEN], NoteError> {
        self.can_send(id)?;
        let idx = self.find(id)?;
        Ok(self.notes[idx].secret)
    }

    /// CONFIRMED → SPENT once the wallet confirms settlement (or the note was
    /// burned as a rotate/split/merge input). Blob-only rewrite.
    pub fn mark_spent(
        &mut self,
        storage: &mut dyn NoteStorage,
        id: &str,
        now: u32,
    ) -> Result<(), NoteError> {
        let idx = self.find(id)?;
        if self.notes[idx].state != NoteState::Confirmed {
            return Err(NoteError::InvalidState);
        }
        let mut updated = self.notes[idx].clone();
        updated.state = NoteState::Spent;
        updated.updated_at = now;
        self.persist_rewrite(storage, idx, updated)
    }

    /// Relabel a note in any state. Blob-only rewrite.
    pub fn rename(
        &mut self,
        storage: &mut dyn NoteStorage,
        id: &str,
        label: &str,
        now: u32,
    ) -> Result<(), NoteError> {
        if label.len() > MAX_LABEL_LEN {
            return Err(NoteError::BadRequest);
        }
        let idx = self.find(id)?;
        let mut updated = self.notes[idx].clone();
        updated.label = label.to_string();
        updated.updated_at = now;
        self.persist_rewrite(storage, idx, updated)
    }

    /// Housekeeping: only a SPENT note may be deleted — a PENDING note is
    /// dropped via `discard`, and a CONFIRMED one is live money.
    pub fn delete(&mut self, storage: &mut dyn NoteStorage, id: &str) -> Result<(), NoteError> {
        let idx = self.find(id)?;
        if self.notes[idx].state != NoteState::Spent {
            return Err(NoteError::InvalidState);
        }
        self.persist_remove(storage, idx)
    }

    /// Re-persist every held note's blob unchanged — the re-seal/unseal pass
    /// behind an at-rest enable or disable, where the storage layer's
    /// wrapping has changed but the records have not. Blob rewrites only,
    /// never the index. Stops at the first failure (RAM still matches what
    /// each successful write left on flash, because nothing in RAM changed);
    /// re-running after the storage recovers converges.
    pub fn rewrite_all(&mut self, storage: &mut dyn NoteStorage) -> Result<(), NoteError> {
        for note in &self.notes {
            let mut blob = encode_note(note).map_err(|_| NoteError::BadRequest)?;
            let saved = storage.save_note(&note.id, &blob);
            blob.zeroize(); // the encoded record embeds the raw secret
            saved.map_err(|_| NoteError::StorageFull)?;
        }
        Ok(())
    }

    // ---- internals ----

    fn find(&self, id: &str) -> Result<usize, NoteError> {
        self.notes.iter().position(|n| n.id == id).ok_or(NoteError::NotFound)
    }

    fn admit_creation(&self, adding: usize) -> Result<(), NoteError> {
        if !self.index_known {
            // Creating would rewrite an index this boot cannot see.
            return Err(NoteError::StorageFull);
        }
        if self.notes.len() + adding > self.cap {
            return Err(NoteError::StorageFull);
        }
        Ok(())
    }

    /// A fresh random id not colliding with any held note (nor `also_not`,
    /// for the second half of a pair). `None` only if the RNG hands back the
    /// same collision repeatedly, which means something far worse than an id
    /// clash is going on.
    fn fresh_id(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        also_not: Option<&str>,
    ) -> Option<String> {
        for _ in 0..100 {
            let mut raw = [0u8; ID_LEN / 2];
            rng(&mut raw);
            let id = hex_encode(&raw);
            let clashes = self.notes.iter().any(|n| n.id == id) || also_not == Some(id.as_str());
            if !clashes {
                return Some(id);
            }
        }
        None
    }

    fn build_pending(
        &self,
        _storage: &mut dyn NoteStorage,
        rng: &mut dyn FnMut(&mut [u8]),
        parent_ids: &[String],
        label: &str,
        now: u32,
    ) -> Result<Note, NoteError> {
        if label.len() > MAX_LABEL_LEN || parent_ids.len() > MAX_PARENTS {
            return Err(NoteError::BadRequest);
        }
        for p in parent_ids {
            if p.len() != ID_LEN || !is_lower_hex(p) {
                return Err(NoteError::BadRequest);
            }
        }
        let mut secret = [0u8; SECRET_LEN];
        rng(&mut secret);
        let id = self.fresh_id(rng, None).ok_or(NoteError::StorageFull)?;
        Ok(Note {
            id,
            secret,
            state: NoteState::Pending,
            amount_msat: 0,
            host: String::new(),
            label: label.to_string(),
            sig: String::new(),
            parent_ids: parent_ids.to_vec(),
            created_at: now,
            updated_at: now,
            peer: None,
        })
    }

    /// Persist freshly created notes: every blob first, then one index write,
    /// then RAM. A failure anywhere leaves RAM (and the index) without the
    /// new notes; stranded blobs are unreferenced and get overwritten by a
    /// later note reusing the id.
    fn persist_new(
        &mut self,
        storage: &mut dyn NoteStorage,
        new_notes: Vec<Note>,
    ) -> Result<(), NoteError> {
        for note in &new_notes {
            let mut blob = encode_note(note).map_err(|_| NoteError::BadRequest)?;
            let saved = storage.save_note(&note.id, &blob);
            blob.zeroize(); // the encoded record embeds the raw secret
            saved.map_err(|_| NoteError::StorageFull)?;
        }
        let mut ids: Vec<String> = self.notes.iter().map(|n| n.id.clone()).collect();
        ids.extend(new_notes.iter().map(|n| n.id.clone()));
        storage.save_index(&ids).map_err(|_| NoteError::StorageFull)?;
        self.notes.extend(new_notes);
        Ok(())
    }

    /// Persist an in-place rewrite (state/label change): blob write, then
    /// RAM. The index is untouched, which is what keeps these paths legal on
    /// an index-unknown boot.
    fn persist_rewrite(
        &mut self,
        storage: &mut dyn NoteStorage,
        idx: usize,
        updated: Note,
    ) -> Result<(), NoteError> {
        let mut blob = encode_note(&updated).map_err(|_| NoteError::BadRequest)?;
        let saved = storage.save_note(&updated.id, &blob);
        blob.zeroize(); // the encoded record embeds the raw secret
        saved.map_err(|_| NoteError::StorageFull)?;
        self.notes[idx] = updated;
        Ok(())
    }

    /// Persist a removal: index write first (so a cut never leaves an indexed
    /// ghost), then best-effort blob delete, then RAM.
    fn persist_remove(&mut self, storage: &mut dyn NoteStorage, idx: usize) -> Result<(), NoteError> {
        if !self.index_known {
            return Err(NoteError::StorageFull);
        }
        let removed_id = self.notes[idx].id.clone();
        let ids: Vec<String> = self
            .notes
            .iter()
            .filter(|n| n.id != removed_id)
            .map(|n| n.id.clone())
            .collect();
        storage.save_index(&ids).map_err(|_| NoteError::StorageFull)?;
        // The blob is unreferenced now; a failed delete strands bytes, not
        // state, and the id-reuse path overwrites them.
        let _ = storage.delete_note(&removed_id);
        self.notes.remove(idx); // Drop zeroises the secret.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;

    /// In-memory storage with a power-cut fail point: after `budget` runs
    /// out, every mutating call fails and applies nothing, which is what a
    /// cut mid-operation looks like to the caller — and what survives is
    /// exactly what was committed before it.
    struct FakeStorage {
        index: Option<Vec<String>>,
        notes: BTreeMap<String, Vec<u8>>,
        index_read_fails: bool,
        budget: Option<usize>,
        /// Successful mutations, so the torture test can count a flow's
        /// writes without abusing the budget.
        writes: usize,
    }

    impl FakeStorage {
        fn new() -> Self {
            FakeStorage {
                index: None,
                notes: BTreeMap::new(),
                index_read_fails: false,
                budget: None,
                writes: 0,
            }
        }

        fn spend(&mut self) -> Result<(), StorageError> {
            match &mut self.budget {
                Some(0) => Err(StorageError),
                Some(n) => {
                    *n -= 1;
                    self.writes += 1;
                    Ok(())
                }
                None => {
                    self.writes += 1;
                    Ok(())
                }
            }
        }
    }

    impl NoteStorage for FakeStorage {
        fn load_index(&mut self) -> Result<Option<Vec<String>>, StorageError> {
            if self.index_read_fails {
                return Err(StorageError);
            }
            Ok(self.index.clone())
        }
        fn save_index(&mut self, ids: &[String]) -> Result<(), StorageError> {
            self.spend()?;
            self.index = Some(ids.to_vec());
            Ok(())
        }
        fn load_note(&mut self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.notes.get(id).cloned())
        }
        fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError> {
            self.spend()?;
            self.notes.insert(id.to_string(), blob.to_vec());
            Ok(())
        }
        fn delete_note(&mut self, id: &str) -> Result<(), StorageError> {
            self.spend()?;
            self.notes.remove(id);
            Ok(())
        }
    }

    /// Deterministic RNG: an incrementing counter, so ids and secrets are
    /// unique and every run is reproducible.
    fn test_rng() -> impl FnMut(&mut [u8]) {
        let mut counter: u64 = 0;
        move |buf: &mut [u8]| {
            for chunk in buf.chunks_mut(8) {
                counter += 1;
                let bytes = counter.to_be_bytes();
                let n = chunk.len().min(8);
                // Low-order bytes, so short draws (note ids) actually vary.
                chunk[..n].copy_from_slice(&bytes[8 - n..]);
            }
        }
    }

    fn fresh_store(storage: &mut FakeStorage) -> NoteStore {
        NoteStore::load(storage, MAX_NOTES).store
    }

    fn sample_note() -> Note {
        Note {
            id: "a1b2c3d4".to_string(),
            secret: [7u8; SECRET_LEN],
            state: NoteState::Confirmed,
            amount_msat: 21_000,
            host: "mint.example".to_string(),
            label: "coffee float".to_string(),
            sig: "ab".repeat(65),
            parent_ids: vec!["deadbeef".to_string(), "cafef00d".to_string()],
            created_at: 100,
            updated_at: 200,
            peer: Some(Peer::From([0xab; 32])),
        }
    }

    #[test]
    fn codec_round_trip() {
        let note = sample_note();
        let blob = encode_note(&note).unwrap();
        let back = decode_note(&blob).unwrap();
        assert_eq!(back.id, note.id);
        assert_eq!(back.secret, note.secret);
        assert_eq!(back.state, note.state);
        assert_eq!(back.amount_msat, note.amount_msat);
        assert_eq!(back.host, note.host);
        assert_eq!(back.label, note.label);
        assert_eq!(back.sig, note.sig);
        assert_eq!(back.parent_ids, note.parent_ids);
        assert_eq!(back.created_at, note.created_at);
        assert_eq!(back.updated_at, note.updated_at);
        assert_eq!(back.peer, note.peer);
    }

    #[test]
    fn codec_reads_v1_blobs_without_a_peer() {
        let mut note = sample_note();
        note.peer = None;
        let v2 = encode_note(&note).unwrap();
        // A v1 record is the v2 record minus the trailing peer tag.
        let mut v1 = v2[..v2.len() - 1].to_vec();
        v1[4] = 1;
        let back = decode_note(&v1).unwrap();
        assert_eq!(back.peer, None);
        assert_eq!(back.secret, note.secret);
        // The peer tag is not optional in v2.
        assert!(decode_note(&v2[..v2.len() - 1]).is_none());
        // Unknown peer tag.
        let mut bad = v2.clone();
        *bad.last_mut().unwrap() = 9;
        assert!(decode_note(&bad).is_none());
    }

    #[test]
    fn receive_and_send_provenance() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let alice = [0xa1u8; 32];
        let bob = [0xb0u8; 32];

        let (rid, created) = store
            .receive(&mut storage, &mut rng, &[3u8; SECRET_LEN], "mint.example", 5_000, &alice, 10)
            .unwrap();
        assert!(created);
        let meta = store.get_meta(&rid).unwrap();
        assert_eq!(meta.state, NoteState::Confirmed);
        assert_eq!(meta.peer, Some(Peer::From(alice)));
        assert_eq!(store.received_count(), 1);
        // Replayed wrap: same secret, same id, nothing new.
        let (again, created) = store
            .receive(&mut storage, &mut rng, &[3u8; SECRET_LEN], "other.example", 1, &bob, 11)
            .unwrap();
        assert_eq!(again, rid);
        assert!(!created);
        assert_eq!(store.counts().0, 1);
        // A received note is exportable (the wallet collects it) but never
        // forwardable.
        assert!(store.can_export(&rid).is_ok());
        assert_eq!(store.can_send(&rid), Err(NoteError::InvalidState));
        assert_eq!(
            store.mark_sent(&mut storage, &rid, &bob, 12),
            Err(NoteError::InvalidState)
        );

        // A minted, confirmed note can be sent exactly once.
        let (sid, _) = store.new_secret(&mut storage, &mut rng, &[], "", 20).unwrap();
        assert_eq!(store.can_send(&sid), Err(NoteError::InvalidState));
        store.confirm(&mut storage, &sid, 7_000, "mint.example", None, 21).unwrap();
        assert!(store.can_send(&sid).is_ok());
        let secret = store.secret_for_send(&sid).unwrap();
        store.mark_sent(&mut storage, &sid, &bob, 22).unwrap();
        assert_eq!(store.get_meta(&sid).unwrap().peer, Some(Peer::To(bob)));
        assert_eq!(store.can_send(&sid), Err(NoteError::InvalidState));
        assert_eq!(store.secret_for_send(&sid), Err(NoteError::InvalidState));
        // Still exportable: unsend rotates it through the owner's wallet.
        assert_eq!(store.export_secret(&sid).unwrap(), hex_encode(&secret));
        store.mark_spent(&mut storage, &sid, 23).unwrap();
        assert_eq!(store.received_count(), 1);

        // Provenance survives a reload.
        let reloaded = fresh_store(&mut storage);
        assert_eq!(reloaded.get_meta(&rid).unwrap().peer, Some(Peer::From(alice)));
        assert_eq!(reloaded.get_meta(&sid).unwrap().peer, Some(Peer::To(bob)));
        assert_eq!(reloaded.can_send(&sid), Err(NoteError::InvalidState));
    }

    #[test]
    fn received_cap_is_separate_and_low() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let alice = [0xa1u8; 32];
        for i in 0..MAX_RECEIVED {
            store
                .receive(&mut storage, &mut rng, &[i as u8 + 1; SECRET_LEN], "m.example", 1, &alice, 1)
                .unwrap();
        }
        assert_eq!(
            store.receive(&mut storage, &mut rng, &[0x77; SECRET_LEN], "m.example", 1, &alice, 1),
            Err(NoteError::StorageFull)
        );
        // Minting is unaffected by the received cap.
        assert!(store.new_secret(&mut storage, &mut rng, &[], "", 2).is_ok());
        // Rotating one out (spent) frees a slot.
        let id = store.list(0, 1).notes[0].id.clone();
        store.mark_spent(&mut storage, &id, 3).unwrap();
        assert_eq!(store.received_count(), MAX_RECEIVED - 1);
        assert!(store
            .receive(&mut storage, &mut rng, &[0x77; SECRET_LEN], "m.example", 1, &alice, 4)
            .is_ok());
        // Nothing was written for the refused one.
        assert!(store.get_meta(&id).unwrap().state == NoteState::Spent);
    }

    #[test]
    fn codec_rejects_malformed() {
        let blob = encode_note(&sample_note()).unwrap();
        // Wrong magic.
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert!(decode_note(&bad).is_none());
        // Wrong version.
        let mut bad = blob.clone();
        bad[4] = 99;
        assert!(decode_note(&bad).is_none());
        // Truncated at every length.
        for cut in 0..blob.len() {
            assert!(decode_note(&blob[..cut]).is_none(), "cut at {cut} decoded");
        }
        // Trailing garbage.
        let mut bad = blob.clone();
        bad.push(0);
        assert!(decode_note(&bad).is_none());
        // Invalid state byte.
        let mut bad = blob;
        bad[13] = 7;
        assert!(decode_note(&bad).is_none());
    }

    #[test]
    fn lifecycle_happy_path() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);

        let (id, h) = store.new_secret(&mut storage, &mut rng, &[], "float", 10).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(store.counts(), (1, 1));

        store.confirm(&mut storage, &id, 21_000, "mint.example", None, 20).unwrap();
        let meta = store.get_meta(&id).unwrap();
        assert_eq!(meta.state, NoteState::Confirmed);
        assert_eq!(meta.amount_msat, 21_000);

        let k1 = store.export_secret(&id).unwrap();
        // The disclosed hash must be the hash of the disclosed secret.
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&hex_decode(&k1).unwrap());
        assert_eq!(secret_hash_hex(&secret), h);

        store.mark_spent(&mut storage, &id, 30).unwrap();
        assert_eq!(store.get_meta(&id).unwrap().state, NoteState::Spent);
        store.delete(&mut storage, &id).unwrap();
        assert_eq!(store.counts(), (0, 0));

        // Everything above survived on flash at each step; final state too.
        let reloaded = fresh_store(&mut storage);
        assert_eq!(reloaded.counts(), (0, 0));
    }

    #[test]
    fn state_guards() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let (id, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();

        // PENDING: no export, no spend, no delete.
        assert_eq!(store.export_secret(&id), Err(NoteError::InvalidState));
        assert_eq!(store.mark_spent(&mut storage, &id, 0), Err(NoteError::InvalidState));
        assert_eq!(store.delete(&mut storage, &id), Err(NoteError::InvalidState));

        store.confirm(&mut storage, &id, 1_000, "mint.example", None, 0).unwrap();
        // CONFIRMED: no re-confirm, no discard, no delete.
        assert_eq!(
            store.confirm(&mut storage, &id, 1_000, "mint.example", None, 0),
            Err(NoteError::InvalidState)
        );
        assert_eq!(store.discard(&mut storage, &id), Err(NoteError::InvalidState));
        assert_eq!(store.delete(&mut storage, &id), Err(NoteError::InvalidState));

        store.mark_spent(&mut storage, &id, 0).unwrap();
        // SPENT: no export, no re-spend, no discard.
        assert_eq!(store.export_secret(&id), Err(NoteError::InvalidState));
        assert_eq!(store.mark_spent(&mut storage, &id, 0), Err(NoteError::InvalidState));
        assert_eq!(store.discard(&mut storage, &id), Err(NoteError::InvalidState));

        assert_eq!(store.export_secret("00000000"), Err(NoteError::NotFound));
    }

    #[test]
    fn import_is_idempotent_on_secret() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let k1 = "ab".repeat(32);

        let (id, created) = store
            .import_secret(&mut storage, &mut rng, &k1, "mint.example", 5_000, "gift", 10)
            .unwrap();
        assert!(created);

        // Re-import returns the same note and restates nothing.
        let (id2, created2) = store
            .import_secret(&mut storage, &mut rng, &k1, "evil.example", 999_999, "lies", 20)
            .unwrap();
        assert_eq!(id2, id);
        assert!(!created2);
        let meta = store.get_meta(&id).unwrap();
        assert_eq!(meta.amount_msat, 5_000);
        assert_eq!(meta.host, "mint.example");
        assert_eq!(store.counts(), (1, 0));

        // Re-importing an already-spent secret returns it, still SPENT.
        store.mark_spent(&mut storage, &id, 30).unwrap();
        let (id3, created3) = store
            .import_secret(&mut storage, &mut rng, &k1, "mint.example", 5_000, "", 40)
            .unwrap();
        assert_eq!(id3, id);
        assert!(!created3);
        assert_eq!(store.get_meta(&id).unwrap().state, NoteState::Spent);
    }

    #[test]
    fn cap_refusal() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = NoteStore::load(&mut storage, 3).store;

        store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        // A pair would exceed the cap of 3 by one.
        assert_eq!(
            store
                .new_secret_pair(&mut storage, &mut rng, &[], "", 0)
                .err(),
            Some(NoteError::StorageFull)
        );
        store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        assert_eq!(
            store.new_secret(&mut storage, &mut rng, &[], "", 0).err(),
            Some(NoteError::StorageFull)
        );
        assert_eq!(
            store
                .import_secret(&mut storage, &mut rng, &"cd".repeat(32), "m.example", 1, "", 0)
                .err(),
            Some(NoteError::StorageFull)
        );
    }

    #[test]
    fn unknown_index_fails_closed() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        // Seed one confirmed note, then make the index unreadable.
        let mut store = fresh_store(&mut storage);
        let (id, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        store.confirm(&mut storage, &id, 1_000, "mint.example", None, 0).unwrap();

        storage.index_read_fails = true;
        let outcome = NoteStore::load(&mut storage, MAX_NOTES);
        let mut blind = outcome.store;
        assert!(!blind.index_known());
        assert_eq!(blind.counts(), (0, 0));

        // Creation and index rewrites refuse; the note on flash is safe.
        assert_eq!(
            blind.new_secret(&mut storage, &mut rng, &[], "", 0).err(),
            Some(NoteError::StorageFull)
        );
        assert_eq!(
            blind
                .import_secret(&mut storage, &mut rng, &"ef".repeat(32), "m.example", 1, "", 0)
                .err(),
            Some(NoteError::StorageFull)
        );

        // A reboot that can read the index recovers everything.
        storage.index_read_fails = false;
        let recovered = fresh_store(&mut storage);
        assert_eq!(recovered.counts(), (1, 0));
        assert!(recovered.export_secret(&id).is_ok());
    }

    #[test]
    fn load_skips_undecodable_blobs_without_dropping_them() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let (id_a, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        let (id_b, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();

        // Corrupt one blob on flash.
        storage.notes.insert(id_a.clone(), vec![1, 2, 3]);
        let outcome = NoteStore::load(&mut storage, MAX_NOTES);
        assert_eq!(outcome.skipped, vec![id_a.clone()]);
        assert_eq!(outcome.store.counts(), (1, 1));
        assert!(outcome.store.get_meta(&id_b).is_some());
        // The corrupt bytes were not erased — left for a firmware that
        // understands them.
        assert!(storage.notes.contains_key(&id_a));
    }

    #[test]
    fn persist_before_disclose_under_power_cut() {
        // Cut at every storage write inside new_secret_pair: whatever the cut
        // point, no hash is disclosed whose preimage is not on flash.
        for budget in 0..3 {
            let mut storage = FakeStorage::new();
            let mut rng = test_rng();
            let mut store = fresh_store(&mut storage);
            storage.budget = Some(budget);

            let result = store.new_secret_pair(&mut storage, &mut rng, &[], "", 0);
            storage.budget = None;

            match result {
                Ok((id, h, id2, h2)) => {
                    // Disclosure happened, so both preimages must be on flash
                    // and indexed.
                    let reloaded = fresh_store(&mut storage);
                    for (id, h) in [(&id, &h), (&id2, &h2)] {
                        let blob = storage.notes.get(id.as_str()).expect("disclosed but not on flash");
                        let note = decode_note(blob).expect("disclosed but undecodable");
                        assert_eq!(&secret_hash_hex(&note.secret), h);
                        assert!(reloaded.get_meta(id).is_some(), "disclosed but not indexed");
                    }
                }
                Err(NoteError::StorageFull) => {
                    // Nothing was disclosed; the index must not reference
                    // anything undecodable or half-created.
                    let outcome = NoteStore::load(&mut storage, MAX_NOTES);
                    assert!(outcome.skipped.is_empty());
                    assert_eq!(outcome.store.counts(), (0, 0));
                }
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
    }

    /// The full spend flow with a power cut at every possible storage write,
    /// asserting the burn-proof invariant at each cut and that re-running
    /// converges.
    #[test]
    fn spend_flow_power_cut_torture() {
        // Dry run to count storage writes in the whole scripted flow.
        let total_writes = {
            let mut storage = FakeStorage::new();
            let (_, completed) = run_spend_flow(&mut storage, None);
            assert!(completed, "dry run must succeed");
            storage.writes
        };
        assert!(total_writes >= 8, "flow unexpectedly cheap ({total_writes} writes)");

        for cut in 0..total_writes {
            let mut storage = FakeStorage::new();
            let (disclosed, _completed) = run_spend_flow(&mut storage, Some(cut));

            // Invariant: every hash the flow disclosed before the cut has its
            // preimage decodable on flash.
            for (id, h) in disclosed {
                let blob = storage
                    .notes
                    .get(&id)
                    .unwrap_or_else(|| panic!("cut {cut}: {id} disclosed, not on flash"));
                let note = decode_note(blob).expect("undecodable disclosed note");
                assert_eq!(secret_hash_hex(&note.secret), h, "cut {cut}: hash mismatch");
            }

            // The index never references an undecodable blob.
            let outcome = NoteStore::load(&mut storage, MAX_NOTES);
            assert!(outcome.skipped.is_empty(), "cut {cut}: index references garbage");

            // Convergence: rerunning the whole flow against the surviving
            // state succeeds outright.
            let (_, completed) = run_spend_flow(&mut storage, None);
            assert!(completed, "rerun after cut {cut} must converge");
        }
    }

    /// Scripted flow: mint-import a note, rotate it, then split-and-melt.
    /// Returns every (id, hash) pair disclosed along the way — on a cut, the
    /// pairs disclosed before it — plus whether the flow ran to completion.
    fn run_spend_flow(storage: &mut FakeStorage, cut_after: Option<usize>) -> (Vec<(String, String)>, bool) {
        let mut rng = test_rng();
        let outcome = NoteStore::load(storage, MAX_NOTES);
        let mut store = outcome.store;
        let mut disclosed: Vec<(String, String)> = Vec::new();
        if let Some(n) = cut_after {
            storage.budget = Some(n);
        }

        macro_rules! step {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(_) => {
                        storage.budget = None;
                        return (disclosed, false);
                    }
                }
            };
        }

        // The wallet retries with at-least-once semantics — the protocol's
        // own import doc spells this out ("treat id as the note for this
        // secret ... read its state if that matters"). So a rerun tolerates
        // already-done: mark_spent on an already-SPENT note and delete of an
        // already-gone one both count as converged, not failed.
        fn mark_spent_idem(
            store: &mut NoteStore,
            storage: &mut FakeStorage,
            id: &str,
            now: u32,
        ) -> Result<(), NoteError> {
            match store.mark_spent(storage, id, now) {
                Err(NoteError::InvalidState)
                    if store.get_meta(id).map(|m| m.state) == Some(NoteState::Spent) =>
                {
                    Ok(())
                }
                other => other,
            }
        }
        fn delete_idem(
            store: &mut NoteStore,
            storage: &mut FakeStorage,
            id: &str,
        ) -> Result<(), NoteError> {
            match store.delete(storage, id) {
                Err(NoteError::NotFound) => Ok(()),
                other => other,
            }
        }

        // Mint: preimage arrives from the browser, is imported, and per
        // LUD-25 immediately rotated (the mint was a prior holder).
        let preimage = "5a".repeat(32);
        let (minted, _) = step!(store.import_secret(storage, &mut rng, &preimage, "mint.example", 10_000, "mint", 1));
        let (rot_id, rot_h) = step!(store.new_secret(storage, &mut rng, &[minted.clone()], "", 2));
        disclosed.push((rot_id.clone(), rot_h));
        // Mint said OK to the rotate:
        step!(store.confirm(storage, &rot_id, 10_000, "mint.example", None, 3));
        step!(mark_spent_idem(&mut store, storage, &minted, 4));

        // Spend 3 000 of it: split into target + change, melt the target.
        let _k1 = step!(store.export_secret(&rot_id).map_err(|e| e));
        let (tgt, tgt_h, chg, chg_h) =
            step!(store.new_secret_pair(storage, &mut rng, &[rot_id.clone()], "", 5));
        disclosed.push((tgt.clone(), tgt_h));
        disclosed.push((chg.clone(), chg_h));
        step!(store.confirm(storage, &tgt, 3_000, "mint.example", None, 6));
        step!(store.confirm(storage, &chg, 7_000, "mint.example", None, 6));
        step!(mark_spent_idem(&mut store, storage, &rot_id, 7));
        // Melt of the target settled:
        step!(mark_spent_idem(&mut store, storage, &tgt, 8));
        // Housekeeping. A deleted SPENT note's secret is deliberately gone
        // from flash, so its disclosure no longer binds — retire it from the
        // invariant set.
        step!(delete_idem(&mut store, storage, &minted));
        step!(delete_idem(&mut store, storage, &rot_id));
        disclosed.retain(|(id, _)| id != &rot_id);
        step!(delete_idem(&mut store, storage, &tgt));
        disclosed.retain(|(id, _)| id != &tgt);

        storage.budget = None;
        (disclosed, true)
    }

    #[test]
    fn pair_shares_lineage_and_distinct_ids() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let parents = vec!["deadbeef".to_string()];
        let (id, h, id2, h2) = store
            .new_secret_pair(&mut storage, &mut rng, &parents, "split", 0)
            .unwrap();
        assert_ne!(id, id2);
        assert_ne!(h, h2);
        assert_eq!(store.get_meta(&id).unwrap().parent_ids, parents);
        assert_eq!(store.get_meta(&id2).unwrap().parent_ids, parents);
    }

    #[test]
    fn pair_second_id_collision_regenerates() {
        let mut storage = FakeStorage::new();
        let mut store = fresh_store(&mut storage);
        // An RNG whose first several 4-byte draws repeat, forcing the pair's
        // second id to collide with the first and take the regeneration path.
        let mut calls = 0usize;
        let mut rng = move |buf: &mut [u8]| {
            calls += 1;
            let fill = if calls <= 4 { 0x22 } else { calls as u8 };
            for b in buf.iter_mut() {
                *b = fill;
            }
        };
        let (id, _, id2, _) = store.new_secret_pair(&mut storage, &mut rng, &[], "", 0).unwrap();
        assert_ne!(id, id2);
        // Both persisted under their (distinct) ids and reloadable.
        let reloaded = fresh_store(&mut storage);
        assert!(reloaded.get_meta(&id).is_some());
        assert!(reloaded.get_meta(&id2).is_some());
    }

    #[test]
    fn import_idempotency_survives_reload() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let k1 = "ab".repeat(32);
        let id = {
            let mut store = fresh_store(&mut storage);
            let (id, created) = store
                .import_secret(&mut storage, &mut rng, &k1, "mint.example", 5_000, "", 0)
                .unwrap();
            assert!(created);
            id
        };
        // A fresh boot must still recognise the secret as already held.
        let mut store = fresh_store(&mut storage);
        let (id2, created2) = store
            .import_secret(&mut storage, &mut rng, &k1, "mint.example", 5_000, "", 1)
            .unwrap();
        assert_eq!(id2, id);
        assert!(!created2);
    }

    #[test]
    fn id_collision_regenerates() {
        let mut storage = FakeStorage::new();
        let mut store = fresh_store(&mut storage);
        // An RNG that repeats the same id bytes twice before diverging.
        let mut calls = 0usize;
        let mut rng = move |buf: &mut [u8]| {
            calls += 1;
            let fill = if calls <= 3 { 0x11 } else { calls as u8 };
            for b in buf.iter_mut() {
                *b = fill;
            }
        };
        let (id_a, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        let (id_b, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn list_pages_with_totals() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        for _ in 0..5 {
            store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        }
        let page = store.list(0, 2);
        assert_eq!((page.total, page.notes.len(), page.next_offset), (5, 2, Some(2)));
        let page = store.list(2, 2);
        assert_eq!((page.total, page.notes.len(), page.next_offset), (5, 2, Some(4)));
        let page = store.list(4, 2);
        assert_eq!((page.total, page.notes.len(), page.next_offset), (5, 1, None));
        let page = store.list(9, 2);
        assert_eq!((page.total, page.notes.len(), page.next_offset), (5, 0, None));
    }

    #[test]
    fn bad_requests_are_rejected_before_any_write() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        storage.budget = Some(0); // Any storage write would fail loudly.

        let long_label = "x".repeat(MAX_LABEL_LEN + 1);
        assert_eq!(
            store.new_secret(&mut storage, &mut rng, &[], &long_label, 0).err(),
            Some(NoteError::BadRequest)
        );
        assert_eq!(
            store
                .new_secret(&mut storage, &mut rng, &["nothex!!".to_string()], "", 0)
                .err(),
            Some(NoteError::BadRequest)
        );
        assert_eq!(
            store
                .import_secret(&mut storage, &mut rng, "zz", "mint.example", 1, "", 0)
                .err(),
            Some(NoteError::BadRequest)
        );
        assert_eq!(
            store
                .import_secret(&mut storage, &mut rng, &"ab".repeat(32), "", 1, "", 0)
                .err(),
            Some(NoteError::BadRequest)
        );
    }

    #[test]
    fn rewrite_all_repersists_every_note_and_converges_after_failure() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let (a, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        let (b, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();
        store.confirm(&mut storage, &a, 1_000, "mint.example", None, 1).unwrap();

        // Fail after the first of the two blob writes.
        storage.budget = Some(1);
        assert_eq!(store.rewrite_all(&mut storage), Err(NoteError::StorageFull));
        storage.budget = None;
        // Nothing in RAM changed and a rerun completes.
        store.rewrite_all(&mut storage).unwrap();
        let reloaded = fresh_store(&mut storage);
        assert_eq!(reloaded.get_meta(&a).unwrap().state, NoteState::Confirmed);
        assert!(reloaded.get_meta(&b).is_some());
    }

    #[test]
    fn failed_write_leaves_ram_matching_flash() {
        let mut storage = FakeStorage::new();
        let mut rng = test_rng();
        let mut store = fresh_store(&mut storage);
        let (id, _) = store.new_secret(&mut storage, &mut rng, &[], "", 0).unwrap();

        storage.budget = Some(0);
        assert_eq!(
            store.confirm(&mut storage, &id, 1_000, "mint.example", None, 1).err(),
            Some(NoteError::StorageFull)
        );
        storage.budget = None;

        // RAM still says PENDING, matching flash, and the retry converges.
        assert_eq!(store.get_meta(&id).unwrap().state, NoteState::Pending);
        store.confirm(&mut storage, &id, 1_000, "mint.example", None, 2).unwrap();
        let reloaded = fresh_store(&mut storage);
        assert_eq!(reloaded.get_meta(&id).unwrap().state, NoteState::Confirmed);
    }
}
