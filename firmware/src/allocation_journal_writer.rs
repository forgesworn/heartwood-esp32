//! Dormant, private durable controller. No runtime input producers or child API.
//! Root custody exists only during synchronous work; detached exchanges contain
//! public bindings and a nonsecret journal guard, never a root or manifest.
use super::super::{
    journal_nvs::{self, OwnedBlob, ReadHandle},
    HeldAllocationRoot,
};
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{Mutex, MutexGuard};
use vmls_core::{
    allocation_witness::{ForwardedRequest, Request},
    receipt::{WitnessReceipt, WitnessStatus},
    witness::{AdvanceRequest, ReadRequest},
};

#[path = "allocation_journal_write_nvs.rs"]
mod storage;
static WRITER: Mutex<()> = Mutex::new(());
const EXCHANGE_US: u64 = 30_000_000;
const MAX_EXCHANGES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Inventory(InventoryHold),
    Busy,
    Capacity,
    Freshness,
    Expired,
    Entropy,
    Response,
}
impl From<InventoryHold> for Error {
    fn from(e: InventoryHold) -> Self {
        Self::Inventory(e)
    }
}
type Result<T> = std::result::Result<T, Error>;

// These nominal authorities have NO production constructor. Local descriptors,
// arithmetic NVS estimates and browser assertions cannot create them. Their
// future physical producers require separate review before runtime activation.
struct EnrolmentPins {
    descriptor: [u8; 229],
    genesis_digest: [u8; 32],
    genesis_receipt: [u8; 170],
}
struct MeasuredCapacity {
    partition: &'static str,
    namespace: String,
    max_records: u8,
    remaining_writes: u32,
}
struct AuthorisedManifest {
    data: Zeroizing<[u8; MANIFEST_PLAIN]>,
}
struct AuthorisedLifecycle {
    ordinal: u8,
    kind: u8,
}

struct Bindings {
    pins: EnrolmentPins,
    capacity: MeasuredCapacity,
    namespace: String,
    issuer: [u8; 32],
    slot: u8,
    mode: u8,
    version: u8,
    fingerprint: [u8; 32],
}
struct Grant {
    deadline: u64,
    fingerprint: [u8; 32],
}
struct Controller<'a> {
    root: HeldAllocationRoot<'a>,
    guard: MutexGuard<'static, ()>,
    bindings: Bindings,
    inventory: Vec<OwnedBlob>,
    grant: Option<Grant>,
    challenges: Vec<[u8; 32]>,
    tokens: Vec<[u8; 32]>,
    poisoned: bool,
}
struct Context {
    guard: MutexGuard<'static, ()>,
    bindings: Bindings,
    grant: Option<Grant>,
    challenges: Vec<[u8; 32]>,
    tokens: Vec<[u8; 32]>,
}
struct Attempt {
    context: Context,
    envelope: Zeroizing<Vec<u8>>,
    challenge: [u8; 32],
    deadline: u64,
    advance: bool,
}
struct Loaded {
    anchor: Anchor,
    latest: Snapshot,
    slot: u8,
    manifests: Vec<Manifest>,
    orphan: Option<u8>,
}

fn refs(inventory: &[OwnedBlob]) -> Vec<StoredBlob<'_>> {
    inventory
        .iter()
        .map(|b| StoredBlob {
            key: &b.key,
            bytes: &b.bytes,
        })
        .collect()
}
fn fingerprint(inventory: &[OwnedBlob]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HW allocation held inventory v1\0");
    for b in inventory {
        h.update([b.key.len() as u8]);
        h.update(b.key.as_bytes());
        h.update((b.bytes.len() as u16).to_be_bytes());
        h.update(&b.bytes);
    }
    h.finalize().into()
}
fn blob<'a>(inventory: &'a [OwnedBlob], name: &str) -> Option<&'a [u8]> {
    inventory
        .iter()
        .find(|b| b.key == name)
        .map(|b| b.bytes.as_slice())
}
fn load(root: &HeldAllocationRoot<'_>, inventory: &[OwnedBlob]) -> Result<Loaded> {
    let report = inspect(&root.root, &root.issuer, &refs(inventory))?;
    let c = Codec::new(&root.root, &root.issuer)?;
    let a = c.anchor(blob(inventory, "anchor").ok_or(InventoryHold::Missing)?)?;
    let s0 = blob(inventory, "snap0")
        .map(|b| c.snapshot(b, 0, &a))
        .transpose()?;
    let s1 = blob(inventory, "snap1")
        .map(|b| c.snapshot(b, 1, &a))
        .transpose()?;
    let (latest, slot) = match (s0, s1) {
        (Some(x), Some(y)) if x.generation() > y.generation() => (x, 0),
        (Some(_), Some(y)) => (y, 1),
        (Some(x), None) => (x, 0),
        (None, Some(y)) => (y, 1),
        _ => return Err(InventoryHold::Missing.into()),
    };
    let mut manifests = Vec::new();
    for n in 1..=report.retained_records {
        manifests.push(c.manifest(
            blob(inventory, &format!("m{n:02}")).ok_or(InventoryHold::Missing)?,
            n,
            &a,
        )?);
    }
    Ok(Loaded {
        anchor: a,
        latest,
        slot,
        manifests,
        orphan: report.orphan_ordinal,
    })
}
fn read_inventory(root: &HeldAllocationRoot<'_>, namespace: &str) -> Result<Vec<OwnedBlob>> {
    root.recheck_for_write()
        .map_err(|_| InventoryHold::Custody)?;
    if !super::super::crypto::backend_ready() {
        return Err(InventoryHold::Crypto.into());
    }
    let handle = ReadHandle::open(root.nvs, namespace)?;
    let first = journal_nvs::collect(&handle, namespace)?;
    let second = journal_nvs::collect(&handle, namespace)?;
    if first != second {
        return Err(InventoryHold::Changed.into());
    }
    load(root, &first)?;
    root.recheck_for_write()
        .map_err(|_| InventoryHold::Custody)?;
    Ok(first)
}
fn check_bindings(
    root: &HeldAllocationRoot<'_>,
    b: &Bindings,
    inventory: &[OwnedBlob],
) -> Result<()> {
    root.recheck_for_write()
        .map_err(|_| InventoryHold::Custody)?;
    if root.issuer != b.issuer
        || root.slot != b.slot
        || root.mode as u8 != b.mode
        || root.version != b.version
        || namespace(&root.root) != b.namespace
        || fingerprint(inventory) != b.fingerprint
    {
        return Err(InventoryHold::Changed.into());
    }
    let l = load(root, inventory)?;
    if l.anchor.0[..229] != b.pins.descriptor
        || l.anchor.genesis_digest() != &b.pins.genesis_digest
        || l.anchor.genesis_receipt() != b.pins.genesis_receipt
    {
        return Err(InventoryHold::Binding.into());
    }
    if b.capacity.partition != "nvs"
        || b.capacity.namespace != b.namespace
        || b.capacity.max_records > 32
        || l.manifests.len() > b.capacity.max_records as usize
    {
        return Err(Error::Capacity);
    }
    root.recheck_for_write()
        .map_err(|_| InventoryHold::Custody)?;
    Ok(())
}
fn now() -> Result<u64> {
    #[cfg(test)]
    {
        return hardware::now();
    }
    #[cfg(not(test))]
    {
        let value = unsafe { esp_idf_svc::sys::esp_timer_get_time() };
        u64::try_from(value).map_err(|_| Error::Expired)
    }
}
fn live(deadline: u64) -> Result<()> {
    if now()? >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    #[cfg(test)]
    let ok = hardware::entropy(&mut out);
    #[cfg(not(test))]
    let ok = crate::entropy::stacked_entropy(None, &mut out);
    if !ok || !nonzero(&out) {
        return Err(Error::Entropy);
    }
    Ok(out)
}
fn nonce(inventory: &[OwnedBlob]) -> Result<[u8; 24]> {
    let n = random()?;
    for b in inventory {
        let at = if b.key == "anchor" {
            5
        } else if b.key.starts_with("snap") {
            6
        } else {
            38
        };
        if b.bytes[at..at + 24] == n {
            return Err(Error::Entropy);
        }
    }
    Ok(n)
}
fn seal(
    k: &[u8; 32],
    header: &[u8],
    nonce: &[u8; 24],
    plain: &[u8],
    associated: &[u8],
) -> Result<Vec<u8>> {
    let mut data = Zeroizing::new(plain.to_vec());
    let tag = XChaCha20Poly1305::new(k.into())
        .encrypt_in_place_detached(&XNonce::from(*nonce), associated, &mut data)
        .map_err(|_| InventoryHold::Crypto)?;
    Ok([header, data.as_slice(), &tag[..]].concat())
}
fn seal_snapshot(
    root: &HeldAllocationRoot<'_>,
    a: &Anchor,
    slot: u8,
    plain: &[u8],
    inventory: &[OwnedBlob],
) -> Result<Vec<u8>> {
    let n = nonce(inventory)?;
    let header = [b"HWSC\x01".as_slice(), &[slot], &n].concat();
    let pins = a.pins();
    let k = key(&root.root, &[b"HW allocation snapshot key v1\0", &pins]);
    let frame = seal(
        &k,
        &header,
        &n,
        plain,
        &aad(&[b"HW allocation snapshot aad v1\0", &pins, &header]),
    )?;
    Codec::new(&root.root, &root.issuer)?.snapshot(&frame, slot, a)?;
    Ok(frame)
}
fn candidate(l: &Loaded, kind: u8, ordinal: u8) -> Result<[u8; 65]> {
    if l.latest.phase() != 0 || l.latest.seq() >= MAX_SEQ || l.latest.generation() > u64::MAX - 2 {
        return Err(InventoryHold::Chain.into());
    }
    let mut out = array::<65>(l.latest.active(), 0);
    match kind {
        1 if ordinal == out[0] + 1 && ordinal <= 32 && l.manifests.len() == ordinal as usize => {
            out[0] = ordinal;
            let ids: Vec<_> = l.manifests.iter().map(|m| m.id).collect();
            out[1..33].copy_from_slice(&set_hash(ordinal, &ids, &l.anchor.pins()));
            out[32 + ordinal as usize] = 1;
        }
        2 | 3 if ordinal > 0 && ordinal <= out[0] && out[32 + ordinal as usize] == 1 => {
            out[32 + ordinal as usize] = kind;
        }
        _ => return Err(InventoryHold::Records.into()),
    }
    Ok(out)
}
impl<'a> Controller<'a> {
    fn open(
        root: HeldAllocationRoot<'a>,
        pins: EnrolmentPins,
        capacity: MeasuredCapacity,
    ) -> Result<Self> {
        let guard = WRITER.try_lock().map_err(|_| Error::Busy)?;
        let ns = namespace(&root.root);
        let inventory = read_inventory(&root, &ns)?;
        let bindings = Bindings {
            pins,
            capacity,
            namespace: ns,
            issuer: root.issuer,
            slot: root.slot,
            mode: root.mode as u8,
            version: root.version,
            fingerprint: fingerprint(&inventory),
        };
        check_bindings(&root, &bindings, &inventory)?;
        Ok(Self {
            root,
            guard,
            bindings,
            inventory,
            grant: None,
            challenges: vec![],
            tokens: vec![],
            poisoned: false,
        })
    }
    fn check(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(InventoryHold::Storage.into());
        }
        let result = (|| {
            let inventory = read_inventory(&self.root, &self.bindings.namespace)?;
            check_bindings(&self.root, &self.bindings, &inventory)?;
            if inventory != self.inventory {
                return Err(InventoryHold::Changed.into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            self.grant = None;
        }
        result
    }
    fn fresh(&mut self) -> Result<u64> {
        self.check()?;
        let g = self.grant.take().ok_or(Error::Freshness)?;
        live(g.deadline)?;
        if g.fingerprint != self.bindings.fingerprint {
            return Err(InventoryHold::Changed.into());
        }
        Ok(g.deadline)
    }
    fn detach(mut self) -> Result<Context> {
        self.check()?;
        let Self {
            root,
            guard,
            bindings,
            grant,
            challenges,
            tokens,
            ..
        } = self;
        drop(root);
        Ok(Context {
            guard,
            bindings,
            grant,
            challenges,
            tokens,
        })
    }
    // Every storage error, including a post-write scan error, poisons this
    // instance. Complete expected inventory is compared before and after set.
    fn write(
        &mut self,
        target: storage::Target,
        key_name: String,
        frame: Vec<u8>,
        budget: u32,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            if self.bindings.capacity.remaining_writes < budget {
                return Err(Error::Capacity);
            }
            let mut handle = storage::WriteHandle::open(self.root.nvs, &self.bindings.namespace)?;
            if handle.inventory(&self.bindings.namespace)? != self.inventory {
                return Err(InventoryHold::Changed.into());
            }
            let old = blob(&self.inventory, &key_name);
            let expected = if key_name.starts_with('m') { None } else { old };
            handle.write(target, expected, &frame)?;
            let mut next: Vec<_> = self
                .inventory
                .iter()
                .map(|b| OwnedBlob {
                    key: b.key.clone(),
                    bytes: b.bytes.clone(),
                })
                .collect();
            if let Some(b) = next.iter_mut().find(|b| b.key == key_name) {
                b.bytes = frame;
            } else {
                next.push(OwnedBlob {
                    key: key_name,
                    bytes: frame,
                });
            }
            next.sort_by(|a, b| a.key.cmp(&b.key));
            let actual = handle.inventory(&self.bindings.namespace)?;
            if actual != next {
                return Err(InventoryHold::Changed.into());
            }
            load(&self.root, &actual)?;
            self.root
                .recheck_for_write()
                .map_err(|_| InventoryHold::Custody)?;
            self.bindings.capacity.remaining_writes -= 1;
            self.bindings.fingerprint = fingerprint(&actual);
            self.inventory = actual;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            self.grant = None;
        }
        result
    }
    fn pending(&mut self, kind: u8, ordinal: u8) -> Result<()> {
        self.check()?;
        let l = load(&self.root, &self.inventory)?;
        let c = candidate(&l, kind, ordinal)?;
        let mut p = Zeroizing::new(*l.latest.data);
        p[5] = 1;
        p[6..14].copy_from_slice(&(l.latest.generation() + 1).to_be_bytes());
        p[14..46].copy_from_slice(&l.latest.frame_hash);
        p[353..418].copy_from_slice(&c);
        p[418] = kind;
        p[419] = ordinal;
        p[420..452].copy_from_slice(&state_digest(&l.anchor.pins(), &c));
        let slot = 1 - l.slot;
        let frame = seal_snapshot(&self.root, &l.anchor, slot, p.as_ref(), &self.inventory)?;
        // Validate the exact chain before invoking SDK.
        let s =
            Codec::new(&self.root.root, &self.root.issuer)?.snapshot(&frame, slot, &l.anchor)?;
        chain(&l.latest, &s)?;
        self.write(storage::Target::Slot(slot), format!("snap{slot}"), frame, 2)
    }
    fn append(&mut self, authorised: AuthorisedManifest) -> Result<()> {
        let deadline = self.fresh()?;
        let l = load(&self.root, &self.inventory)?;
        let ordinal = l.latest.active()[0]
            .checked_add(1)
            .ok_or(InventoryHold::Records)?;
        if l.latest.phase() != 0
            || l.orphan.is_some()
            || ordinal > self.bindings.capacity.max_records
            || self.bindings.capacity.remaining_writes < 3
        {
            return Err(Error::Capacity);
        }
        // Reject overflow BEFORE consuming storage entropy or writing a record.
        if l.latest.seq() >= MAX_SEQ || l.latest.generation() > u64::MAX - 2 {
            return Err(InventoryHold::Chain.into());
        }
        let pins = l.anchor.pins();
        let id = hash(&[
            b"HW allocation manifest v1\0",
            &pins,
            authorised.data.as_ref(),
        ]);
        for m in &l.manifests {
            for at in [38, 70, 166, 198] {
                if m.data[at..at + 32] == authorised.data[at..at + 32] {
                    return Err(InventoryHold::Records.into());
                }
            }
        }
        let n = nonce(&self.inventory)?;
        let header = [b"HWAE\x01".as_slice(), &[ordinal], &id, &n].concat();
        let k = key(
            &self.root.root,
            &[b"HW allocation manifest key v1\0", &pins],
        );
        let frame = seal(
            &k,
            &header,
            &n,
            authorised.data.as_ref(),
            &aad(&[b"HW allocation manifest aad v1\0", &pins, &header]),
        )?;
        Codec::new(&self.root.root, &self.root.issuer)?.manifest(&frame, ordinal, &l.anchor)?;
        live(deadline)?;
        self.write(
            storage::Target::Record(ordinal),
            format!("m{ordinal:02}"),
            frame,
            3,
        )?;
        live(deadline)?;
        self.pending(1, ordinal)?;
        self.grant = Some(Grant {
            deadline,
            fingerprint: self.bindings.fingerprint,
        });
        Ok(())
    }
    fn lifecycle(&mut self, action: AuthorisedLifecycle) -> Result<()> {
        let deadline = self.fresh()?;
        let l = load(&self.root, &self.inventory)?;
        if l.orphan.is_some() || !matches!(action.kind, 2 | 3) {
            return Err(InventoryHold::Records.into());
        }
        candidate(&l, action.kind, action.ordinal)?;
        live(deadline)?;
        self.pending(action.kind, action.ordinal)?;
        self.grant = Some(Grant {
            deadline,
            fingerprint: self.bindings.fingerprint,
        });
        Ok(())
    }
    fn promote(&mut self, receipt: &[u8]) -> Result<()> {
        self.check()?;
        let l = load(&self.root, &self.inventory)?;
        if l.latest.phase() != 1 || l.latest.generation() == u64::MAX {
            return Err(InventoryHold::Chain.into());
        }
        let mut p = Zeroizing::new(*l.latest.data);
        p[5] = 0;
        p[6..14].copy_from_slice(&(l.latest.generation() + 1).to_be_bytes());
        p[14..46].copy_from_slice(&l.latest.frame_hash);
        p[78..86].copy_from_slice(&(l.latest.seq() + 1).to_be_bytes());
        p[86..118].copy_from_slice(l.latest.candidate_digest());
        p[118..288].copy_from_slice(receipt);
        p[288..353].copy_from_slice(l.latest.candidate());
        p[353..].fill(0);
        let slot = 1 - l.slot;
        let frame = seal_snapshot(&self.root, &l.anchor, slot, p.as_ref(), &self.inventory)?;
        let s =
            Codec::new(&self.root.root, &self.root.issuer)?.snapshot(&frame, slot, &l.anchor)?;
        chain(&l.latest, &s)?;
        self.write(storage::Target::Slot(slot), format!("snap{slot}"), frame, 1)?;
        self.grant = None;
        Ok(())
    }
}
impl Context {
    fn attach<'a>(self, root: HeldAllocationRoot<'a>) -> Result<Controller<'a>> {
        let inventory = read_inventory(&root, &self.bindings.namespace)?;
        check_bindings(&root, &self.bindings, &inventory)?;
        Ok(Controller {
            root,
            guard: self.guard,
            bindings: self.bindings,
            inventory,
            grant: self.grant,
            challenges: self.challenges,
            tokens: self.tokens,
            poisoned: false,
        })
    }
    fn prepare(
        self,
        root: HeldAllocationRoot<'_>,
        courier_token: [u8; 32],
        advance: bool,
    ) -> Result<Attempt> {
        let mut c = self.attach(root)?;
        c.check()?;
        let start = now()?;
        let deadline = start.checked_add(EXCHANGE_US).ok_or(Error::Expired)?;
        let token_hash = hash(&[b"HW allocation observed courier token v1\0", &courier_token]);
        if c.challenges.len() >= MAX_EXCHANGES
            || c.tokens.len() >= MAX_EXCHANGES
            || !nonzero(&courier_token)
            || c.tokens.contains(&token_hash)
        {
            return Err(Error::Freshness);
        }
        let l = load(&c.root, &c.inventory)?;
        let deadline = if advance {
            let g = c.grant.take().ok_or(Error::Freshness)?;
            live(g.deadline)?;
            if g.fingerprint != c.bindings.fingerprint
                || l.latest.phase() != 1
                || l.orphan.is_some()
            {
                return Err(Error::Freshness);
            }
            deadline.min(g.deadline)
        } else {
            deadline
        };
        let challenge = random()?;
        if c.challenges.contains(&challenge) || l.anchor.genesis_receipt()[74..106] == challenge {
            return Err(Error::Entropy);
        }
        for b in &c.inventory {
            if b.key.starts_with("snap") {
                let s = Codec::new(&c.root.root, &c.root.issuer)?
                    .snapshot(&b.bytes, b.bytes[5], &l.anchor)?;
                if s.receipt()[74..106] == challenge {
                    return Err(Error::Entropy);
                }
            }
        }
        c.challenges.push(challenge);
        c.tokens.push(token_hash);
        let request = if advance {
            Request::Advance(AdvanceRequest {
                subject: *l.anchor.subject(),
                expected_seq: l.latest.seq(),
                expected_digest: *l.latest.active_digest(),
                next_digest: *l.latest.candidate_digest(),
                challenge,
            })
        } else {
            Request::Read(ReadRequest {
                subject: *l.anchor.subject(),
                challenge,
            })
        };
        let seed = key(&c.root.root, &[b"VMLS/1 allocation writer seed\0"]);
        if !super::super::crypto::writer_matches(&seed, l.anchor.writer()) {
            return Err(InventoryHold::Binding.into());
        }
        let unsigned =
            ForwardedRequest::new(*l.anchor.writer(), courier_token, request.clone(), [0; 64])
                .map_err(|_| Error::Response)?;
        let signature = SigningKey::from_bytes(&seed)
            .sign(&unsigned.digest_to_sign(l.anchor.witness()))
            .to_bytes();
        let envelope = ForwardedRequest::new(*l.anchor.writer(), courier_token, request, signature)
            .map_err(|_| Error::Response)?;
        envelope
            .clone()
            .verify(l.anchor.witness())
            .map_err(|_| InventoryHold::Signature)?;
        live(deadline)?;
        c.check()?;
        c.grant = None;
        let context = c.detach()?;
        Ok(Attempt {
            context,
            envelope: Zeroizing::new(envelope.encode()),
            challenge,
            deadline,
            advance,
        })
    }
}
impl Attempt {
    fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    fn accept<'a>(
        self,
        root: HeldAllocationRoot<'a>,
        http_status: u16,
        bytes: &[u8],
    ) -> Result<Controller<'a>> {
        live(self.deadline)?;
        let mut c = self.context.attach(root)?;
        c.check()?;
        let l = load(&c.root, &c.inventory)?;
        // Unsigned courier errors, witness refusal, retirement and conflict
        // yield no authority. No caller boolean can turn a response into Current.
        if http_status != 200 {
            return Err(Error::Response);
        }
        let r = WitnessReceipt::verified(bytes, l.anchor.witness(), &self.challenge)
            .map_err(|_| InventoryHold::Signature)?;
        if r.status != WitnessStatus::Current
            || r.subject != *l.anchor.subject()
            || !nonzero(&r.signature)
        {
            return Err(Error::Response);
        }
        live(self.deadline)?;
        let at_active = r.seq == l.latest.seq() && r.digest == *l.latest.active_digest();
        let target = if l.latest.phase() == 1 {
            Some(*l.latest.candidate_digest())
        } else if let Some(n) = l.orphan {
            Some(state_digest(&l.anchor.pins(), &candidate(&l, 1, n)?))
        } else {
            None
        };
        let at_candidate = l.latest.seq().checked_add(1) == Some(r.seq) && target == Some(r.digest);
        if self.advance && !at_candidate {
            return Err(Error::Freshness);
        }
        if at_candidate {
            if let Some(n) = l.orphan {
                c.pending(1, n)?;
            }
            live(self.deadline)?;
            c.promote(bytes)?;
        } else if at_active && !self.advance {
            if let Some(n) = l.orphan {
                c.pending(1, n)?;
            }
            c.grant = Some(Grant {
                deadline: self.deadline,
                fingerprint: c.bindings.fingerprint,
            });
        } else {
            return Err(Error::Freshness);
        }
        live(self.deadline)?;
        c.check()?;
        Ok(c)
    }
}

#[cfg(test)]
mod hardware {
    use super::*;
    use std::cell::RefCell;
    struct State {
        now: u64,
        counter: u8,
        fail: bool,
        repeated: Option<u8>,
    }
    thread_local! {static STATE:RefCell<State>=RefCell::new(State {now:1,counter:100,fail:false,repeated:None});}
    pub(super) fn reset() {
        STATE.with(|s| {
            *s.borrow_mut() = State {
                now: 1,
                counter: 100,
                fail: false,
                repeated: None,
            }
        });
    }
    pub(super) fn now() -> Result<u64> {
        STATE.with(|s| Ok(s.borrow().now))
    }
    pub(super) fn entropy(out: &mut [u8]) -> bool {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            if s.fail {
                return false;
            }
            s.counter = s.counter.wrapping_add(1);
            out.fill(s.repeated.unwrap_or(s.counter));
            true
        })
    }
    pub(super) fn expire() {
        STATE.with(|s| s.borrow_mut().now += EXCHANGE_US);
    }
    pub(super) fn fail() {
        STATE.with(|s| s.borrow_mut().fail = true);
    }
    pub(super) fn repeat(value: u8) {
        STATE.with(|s| s.borrow_mut().repeated = Some(value));
    }
}
#[cfg(test)]
#[path = "../../common/src/allocation_journal_writer_host_tests.rs"]
mod tests;
