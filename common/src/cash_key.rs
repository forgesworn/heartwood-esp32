//! LUD-25 key-path notes on this device: notes paid to its own keys.
//!
//! A key-path note is a BIP-341 output key `Q` that is the holder's own key,
//! used as is with no BIP-86 tweak. The mint only ever learns `cp1<Q>`, and
//! the note is spent with a `ck1`: `Q` and a BIP-340 key-path signature over
//! the sighash of one canonical, never-broadcast transaction whose prevout is
//! bound to the mint's domain. A mint that holds a watch-only `cx1` for a
//! lightning address mints each payment straight to the holder's next key, so
//! the gift wrap that tells the holder about it carries no secret at all, only
//! where to look and at which index.
//!
//! **Where this device's receiving keys come from.** A lightning address on a
//! Nostr-native mint belongs to an npub: the key that signed the registration
//! owns the name, and payments are wrapped to it. That key lives here and
//! never leaves, so it is the root. From LUD-26 (luds `92e430f`) on:
//!
//! ```text
//! seed     = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//! S        = m/139'/d1/d2/d3/d4 from that seed, d1..d4 from HMAC-SHA256(m/139'/0, domain)
//! share n  = S/0'/2/n'            exported as cx1 = bech32m("cx", chainCode || P compressed)
//! note i   = S/0'/2/n'/i          plain BIP-32, no tweak; Q = x(sk_i * G)
//! ck1      = Q || BIP-340(sk_i, key-path sighash of the canonical spend for the domain), aux_rand = 0
//! ```
//!
//! The first line is this device's own (lnurlcash-conformance's
//! `nostr-seed.json`), and the only one. Everything below it is LUD-26
//! exactly. It exists because this device never holds a BIP-32 master (see
//! [`crate::cash`]): what it holds is the identity key, which the owner's
//! recovery phrase already backs up. So these notes come back from the
//! heartwood's phrase, and nothing paired with the device can spend them
//! without it.
//!
//! `domain` is the mint's hostname, lowercase, without its port: the string
//! the canonical spend commits to ([`spend_domain`]). Only account 0 is used,
//! and only its share chain (`S/0'/2`): the wallet and change chains
//! (`S/0'/0`, `S/0'/1`) are a wallet's own notes, which this device neither
//! makes nor hands out, so nothing here derives them. Shares are numbered
//! below [`SHARE_LIMIT`]: a wrap names its note's index but not its share,
//! so a key paid to a share is found by trying every share this device could
//! have handed out.
//!
//! **The legacy whole branches.** Before LUD-26 a mint held one `cx1` for the
//! whole branch `m/139'/d1..d4` (the host hashed as stored, port included)
//! and derived each note with a tagged-hash tweak, first without a purpose
//! (luds `6e865b1`) and then with one (`50d740a`: purpose 2 is a Lightning
//! Address's). Before `50d740a` this device, following lnurl-wallet's
//! `cashSecrets.ts`, hung that branch off `m/139'/1'` instead (the
//! superseded branch). A mint keeps crediting whatever `cx1` a name was
//! registered with, so every one of those keys is still a place money lands:
//! a claim that names its key tries them all after the shares, and an address
//! proof can be signed by either branch to move a name off it. Nothing new is
//! ever handed out on them.
//!
//! HMAC keyed by the secret with a fixed label is the shape
//! [`crate::derive::nsec_to_tree_root`] already uses. The label is not an
//! nsec-tree message (those all start `nsec-tree`), so the seed is never a key
//! nsec-tree hands out as an identity.
//!
//! Graded in the tests below against lnurlcash-conformance 0.16.2's
//! `part2.json`, `nostr-seed.json` and `spec-vectors.json` (luds `92e430f`),
//! and, for the legacy branches, 0.15.0's `part2.json` and `nostr-seed.json`
//! and 0.16.2's `legacy` set.

use alloc::string::String;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cash::{derive_cash_child, derive_cash_domain_node, derive_cash_root, CashNode};
use crate::derive::backend;
use crate::encoding::{encode_ck1, encode_cx1, encode_share_cx1};

type HmacSha256 = Hmac<Sha256>;

/// What the seed step hashes, keyed by the identity's secret.
pub const NOSTR_SEED_LABEL: &[u8] = b"LNURLcash/nostr-seed";

const HARDENED: u32 = 0x8000_0000;

/// `S/0'`: account 0, the only one this device uses.
const ACCOUNT_ZERO: u32 = HARDENED;

/// `S/a'/2`: the chain of shares, the only keys that may be handed out.
const SHARE_CHAIN: u32 = 2;

/// Shares this device hands out, and searches for a wrapped key, at a mint:
/// 0 to 19. A wrap carries a note's index and not its share, so every share a
/// payment could be on is tried; a share above this would be one whose wraps
/// are refused as not ours. One share per name or counterparty, so twenty
/// names at one mint before this binds. LUD-26's own recovery stops after 5
/// consecutive empty shares, which a device handing out at most twenty never
/// reaches past.
pub const SHARE_LIMIT: u32 = 20;

/// The wallet's own notes on the legacy tweak (a split's `p1`, every rotate or
/// merge output). Never derived here except to grade the vectors and to keep
/// a claim that names it working.
pub const PURPOSE_WALLET: u32 = 0;
/// A split's change `p2`, on the legacy tweak.
pub const PURPOSE_CHANGE: u32 = 1;
/// Lightning Address auto-mint on the legacy tweak: what a mint still credits
/// a name registered with a whole branch on, so the purpose a legacy claim
/// assumes.
pub const PURPOSE_LIGHTNING_ADDRESS: u32 = 2;

/// `m/139'/1'`: where this device hung its whole branch before LUD-25
/// `50d740a`. Read only; see the module docs.
const SUPERSEDED_ADDRESS_BRANCH: u32 = 1 | HARDENED;

const NOTE_DERIVE_TAG: &[u8] = b"LNURLcash/derive";
const MINT_PREVOUT_TAG: &[u8] = b"LNURLcash/mint";
const TAP_SIGHASH_TAG: &[u8] = b"TapSighash";

/// secp256k1's group order, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The seed a Nostr identity's keys at every mint hang off.
pub fn nostr_cash_seed(identity_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(identity_secret).expect("HMAC accepts any key length");
    mac.update(NOSTR_SEED_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `m/139'` from an identity's seed.
fn identity_root(identity_secret: &[u8; 32]) -> Result<CashNode, &'static str> {
    let seed = nostr_cash_seed(identity_secret);
    derive_cash_root(seed.as_ref())
}

// ---- LUD-26: shares ----

/// `S` for one mint, from `m/139'`: the domain hashed without its port.
/// Bearer material for every key at that mint, so it stays on this device.
pub fn service_root_at(root: &CashNode, host: &str) -> Result<CashNode, &'static str> {
    derive_cash_domain_node(root, &spend_domain(host))
}

/// `S` for one mint and one Nostr identity.
pub fn service_root(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
    service_root_at(&identity_root(identity_secret)?, host)
}

/// `S/0'/2`, account 0's share chain, from `S`. Every share is a hardened
/// child of it.
pub fn share_chain_of(service_root: &CashNode) -> Result<CashNode, &'static str> {
    derive_cash_child(&derive_cash_child(service_root, ACCOUNT_ZERO)?, SHARE_CHAIN)
}

fn share_chain(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
    share_chain_of(&service_root(identity_secret, host)?)
}

/// Whether `share` is one this device hands out.
pub fn valid_share(share: u32) -> bool {
    share < SHARE_LIMIT
}

/// Share `share` of a share chain, `S/0'/2/share'`. Refused at or above
/// [`SHARE_LIMIT`], so nothing derived here is a share a wrap search misses.
pub fn share_at(chain: &CashNode, share: u32) -> Result<CashNode, &'static str> {
    if !valid_share(share) {
        return Err("a share is 0 to 19");
    }
    derive_cash_child(chain, share | HARDENED)
}

/// Share `share` of this identity at the mint `host`.
pub fn share_node(identity_secret: &[u8; 32], host: &str, share: u32) -> Result<CashNode, &'static str> {
    share_at(&share_chain(identity_secret, host)?, share)
}

/// A share as a watcher holds it: chain code and compressed point, the two
/// halves of its `cx1`. Enough to derive every note's public key and no
/// note's secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareKey {
    pub chain_code: [u8; 32],
    pub point: [u8; 33],
}

pub fn share_key_of(node: &CashNode) -> Result<ShareKey, &'static str> {
    Ok(ShareKey { chain_code: node.chain_code, point: backend::compressed_pubkey(&node.private_key)? })
}

/// A share's `cx1`: what a mint is told so it can mint to the share.
pub fn share_cx1_of(node: &CashNode) -> Result<String, &'static str> {
    let key = share_key_of(node)?;
    Ok(encode_share_cx1(&key.chain_code, &key.point))
}

/// The key of note `index` on a share: plain BIP-32 CKDpriv, unhardened, so a
/// watcher holding the `cx1` derives the same public key with CKDpub. An
/// index BIP-32 calls invalid (a ~2^-127 event) is refused, never swapped for
/// the next: the mint skips it, so nothing is ever minted to it.
pub fn share_note_key(share: &CashNode, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if index >= HARDENED {
        return Err("a note index on a share is below 2^31");
    }
    let child = derive_cash_child(share, index)?;
    Ok(Zeroizing::new(child.private_key))
}

// ---- the legacy whole branches ----

/// Which of this device's two legacy whole branches at a mint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchKind {
    /// `m/139'/d1..d4`, handed out from LUD-25 `50d740a` until LUD-26.
    Legacy,
    /// `m/139'/1'/...`, from before `50d740a`.
    Superseded,
}

impl BranchKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Superseded => "superseded",
        }
    }
}

/// One of the legacy whole branches at a mint, from `m/139'`. `host` is the
/// mint as a wallet spelt it then (see [`crate::cash`]): lowercase, port
/// included, no scheme and no path.
pub fn legacy_branch_at(root: &CashNode, host: &str, kind: BranchKind) -> Result<CashNode, &'static str> {
    match kind {
        BranchKind::Legacy => derive_cash_domain_node(root, host),
        BranchKind::Superseded => derive_cash_domain_node(&derive_cash_child(root, SUPERSEDED_ADDRESS_BRANCH)?, host),
    }
}

/// One of this identity's legacy whole branches at `host`.
pub fn legacy_branch(identity_secret: &[u8; 32], host: &str, kind: BranchKind) -> Result<CashNode, &'static str> {
    legacy_branch_at(&identity_root(identity_secret)?, host, kind)
}

/// A whole branch as a watcher holds it: its x coordinate, which names the
/// even-y point, and its chain code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Branch {
    pub pubkey: [u8; 32],
    pub chain_code: [u8; 32],
}

/// The watch-only half of a branch, and whether its own point has odd y.
fn watch(node: &CashNode) -> Result<(Branch, bool), &'static str> {
    let point = backend::compressed_pubkey(&node.private_key)?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&point[1..]);
    Ok((Branch { pubkey, chain_code: node.chain_code }, point[0] == 0x03))
}

pub fn branch_of(node: &CashNode) -> Result<Branch, &'static str> {
    Ok(watch(node)?.0)
}

/// A legacy branch's 64-byte `cx1`. Never handed out any more; it is how a
/// host names the branch a name is still on file with.
pub fn cx1_of(node: &CashNode) -> Result<String, &'static str> {
    let branch = branch_of(node)?;
    Ok(encode_cx1(&branch.pubkey, &branch.chain_code))
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag = Sha256::digest(tag);
    let mut hasher = Sha256::new().chain_update(tag).chain_update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `value mod n` for a 32-byte big-endian value. One subtraction is enough:
/// any 256-bit value is below 2n.
fn reduce_mod_n(value: [u8; 32]) -> [u8; 32] {
    if value < CURVE_ORDER {
        return value;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = value[i] as i16 - CURVE_ORDER[i] as i16 - borrow;
        borrow = 0;
        if digit < 0 {
            digit += 256;
            borrow = 1;
        }
        out[i] = digit as u8;
    }
    out
}

/// The legacy tweak: with a purpose from `50d740a`, without one before it.
fn note_tweak(branch: &Branch, purpose: Option<u32>, index: u32) -> [u8; 32] {
    let digest = match purpose {
        Some(purpose) => tagged_hash(
            NOTE_DERIVE_TAG,
            &[&branch.pubkey, &branch.chain_code, &purpose.to_be_bytes(), &index.to_be_bytes()],
        ),
        None => tagged_hash(NOTE_DERIVE_TAG, &[&branch.pubkey, &branch.chain_code, &index.to_be_bytes()]),
    };
    reduce_mod_n(digest)
}

/// The branch key is negated first when its point has odd y, because the
/// legacy `cx1` carries only x and x names the even-y point. Skipping that
/// would give a key whose public key is not the one the mint minted to.
fn tweaked_note_key(node: &CashNode, purpose: Option<u32>, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let (branch, odd) = watch(node)?;
    let tweak = note_tweak(&branch, purpose, index);
    let base = if odd {
        Zeroizing::new(backend::negate(&node.private_key)?)
    } else {
        Zeroizing::new(node.private_key)
    };
    // The tweak is already reduced mod n, so the only refusal left is a zero
    // sum: a ~2^-256 event, and a wrong key is a note nobody finds.
    backend::tweak_add(&base, &tweak)
        .map(Zeroizing::new)
        .map_err(|_| "this note index is unusable on this branch")
}

/// The key of note `index` on one `purpose` of a legacy branch, under the
/// `50d740a` tweak. Both are any uint32 and never hardened.
pub fn note_secret_key(node: &CashNode, purpose: u32, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    tweaked_note_key(node, Some(purpose), index)
}

/// The key of note `index` on a legacy branch under the `6e865b1` tweak,
/// which had no purpose.
pub fn pre_purpose_note_secret_key(node: &CashNode, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    tweaked_note_key(node, None, index)
}

// ---- spends ----

/// `x(sk * G)`: the note's output key Q, what it is filed under, and what its
/// `cp1` encodes.
pub fn note_pubkey(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    backend::pubkey_from_secret(secret)
}

/// The mint a note's withdraw endpoint belongs to: `moneyer.dev/w` is at
/// `moneyer.dev`. The locker stores the endpoint; keys are per mint.
pub fn branch_host(note_host: &str) -> &str {
    note_host.split('/').next().unwrap_or(note_host)
}

/// The domain a spend, a share's `S` and an address proof are bound to: the
/// mint's hostname, lowercase, never its scheme, path or port. Only the
/// legacy branches hash the host as stored, port included.
pub fn spend_domain(note_host: &str) -> String {
    let host = branch_host(note_host);
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
}

/// The BIP-341 key-path sighash (SIGHASH_DEFAULT, no annex) of input 0 of
/// LUD-25's canonical spend for `domain`: version 2, one input spending
/// `(tagged_hash("LNURLcash/mint", domain), 0)` with an empty scriptSig and
/// sequence 0xffffffff, one zero-value output with an empty script, lock time
/// 0, and the spent output `(OP_1 <Q>, 0)`. Never broadcast; it exists so a
/// `ck1` is a standard Taproot signature that is worth nothing at any other
/// mint.
pub fn key_path_sighash(domain: &str, output_key: &[u8; 32]) -> [u8; 32] {
    let txid = tagged_hash(MINT_PREVOUT_TAG, &[domain.as_bytes()]);
    let sha_prevouts: [u8; 32] = Sha256::new()
        .chain_update(txid)
        .chain_update(0u32.to_le_bytes())
        .finalize()
        .into();
    let sha_amounts: [u8; 32] = Sha256::digest(0u64.to_le_bytes()).into();
    // compact-size 34, then OP_1 and a 32-byte push of Q
    let sha_script_pubkeys: [u8; 32] = Sha256::new()
        .chain_update([0x22, 0x51, 0x20])
        .chain_update(output_key)
        .finalize()
        .into();
    let sha_sequences: [u8; 32] = Sha256::digest(0xffff_ffffu32.to_le_bytes()).into();
    // value 0, then an empty script (compact-size 0)
    let sha_outputs: [u8; 32] = Sha256::new()
        .chain_update(0u64.to_le_bytes())
        .chain_update([0x00])
        .finalize()
        .into();
    tagged_hash(
        TAP_SIGHASH_TAG,
        &[
            &[0x00],                 // sighash epoch
            &[0x00],                 // hash_type: SIGHASH_DEFAULT
            &2u32.to_le_bytes(),     // nVersion
            &0u32.to_le_bytes(),     // nLockTime
            &sha_prevouts,
            &sha_amounts,
            &sha_script_pubkeys,
            &sha_sequences,
            &sha_outputs,
            &[0x00],                 // spend_type: key path, no annex
            &0u32.to_le_bytes(),     // input_index
        ],
    )
}

/// The note's key-path spend, `Q || signature`: what a `ck1` carries.
pub fn key_path_spend(secret: &[u8; 32], domain: &str) -> Result<[u8; 96], &'static str> {
    let output_key = note_pubkey(secret)?;
    let signature = backend::sign_bip340_zero_aux(secret, &key_path_sighash(domain, &output_key))?;
    let mut spend = [0u8; 96];
    spend[..32].copy_from_slice(&output_key);
    spend[32..].copy_from_slice(&signature);
    Ok(spend)
}

/// The note's bearer credential at the mint whose endpoint is `note_host`:
/// what a wallet presents as `k1` to spend it. Disclosing it is disclosing the
/// note, exactly as a bearer note's preimage is, but only at that mint.
pub fn ck1_of(secret: &[u8; 32], note_host: &str) -> Result<String, &'static str> {
    let mut spend = key_path_spend(secret, &spend_domain(note_host))?;
    let ck1 = encode_ck1(&spend);
    zeroize::Zeroize::zeroize(&mut spend);
    Ok(ck1)
}

// ---- claims: which key a note was paid to ----

/// Where a claimed key was found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyOrigin {
    /// Note `index` of this share.
    Share(u32),
    /// A legacy whole branch, on the purposed or the pre-purpose tweak.
    Branch(BranchKind),
}

/// A note key this device derived for a claim. Zeroised on drop.
pub struct ClaimedKey {
    pub secret: Zeroizing<[u8; 32]>,
    pub pubkey: [u8; 32],
    pub origin: KeyOrigin,
}

const NOT_OURS: &str = "that note is paid to a key this device does not hold";

/// The key a note paid to `identity` at `host` with `index` answers to.
///
/// With `expected`, the public key the note is said to be minted to, every
/// key the note could be on is tried and the one that matches is returned:
/// `share` first if named, then every share this device hands out, then the
/// legacy branches (each on `legacy_purpose` and on the pre-purpose tweak),
/// where names registered before LUD-26 are still paid. A key matching none
/// is refused: a wrap naming a key this device does not hold is either for
/// another device or not a note at all, and either way it is not money this
/// locker can keep. Without `expected` there is nothing to check a guess
/// against, so the share must be named and only that key is derived.
///
/// `host` is the mint as stored, port included (the legacy branches hash it;
/// the shares hash its [`spend_domain`]).
pub fn claim_note_key(
    identity_secret: &[u8; 32],
    host: &str,
    index: u32,
    expected: Option<&[u8; 32]>,
    share: Option<u32>,
    legacy_purpose: u32,
) -> Result<ClaimedKey, &'static str> {
    if let Some(share) = share {
        if !valid_share(share) {
            return Err("a share is 0 to 19");
        }
    }
    let root = identity_root(identity_secret)?;
    let chain = share_chain_of(&service_root_at(&root, host)?)?;
    let on_share = |n: u32| -> Result<ClaimedKey, &'static str> {
        let secret = share_note_key(&share_at(&chain, n)?, index)?;
        let pubkey = note_pubkey(&secret)?;
        Ok(ClaimedKey { secret, pubkey, origin: KeyOrigin::Share(n) })
    };
    let Some(want) = expected else {
        return on_share(share.ok_or("name the key the note is paid to (p), or its share")?);
    };
    // Shares hold only indices below 2^31; a legacy branch holds any uint32.
    if index < HARDENED {
        let named = share.into_iter();
        let rest = (0..SHARE_LIMIT).filter(|n| Some(*n) != share);
        for n in named.chain(rest) {
            // An index BIP-32 refuses on one share is simply not this one.
            if let Ok(found) = on_share(n) {
                if found.pubkey == *want {
                    return Ok(found);
                }
            }
        }
    }
    for kind in [BranchKind::Legacy, BranchKind::Superseded] {
        let node = legacy_branch_at(&root, host, kind)?;
        for purpose in [Some(legacy_purpose), None] {
            let Ok(secret) = tweaked_note_key(&node, purpose, index) else { continue };
            let pubkey = note_pubkey(&secret)?;
            if pubkey == *want {
                return Ok(ClaimedKey { secret, pubkey, origin: KeyOrigin::Branch(kind) });
            }
        }
    }
    Err(NOT_OURS)
}

// ---- address proofs: the key on file agrees to a change of name ----
//
// A `cx1` is public, so a mint will not point a name at one, move it to
// another, or clear it, on anyone's say-so but the key's (LUD-26
// "Registration"). Agreement is a BIP-340 signature, aux_rand zero, over the
// sha256 of one of three messages: a POST's register, by the share being
// registered; a PUT's update, by the key ON FILE, binding the new `cx1`, sent
// with the new share's register proof as `newsig`; and a DELETE's unregister,
// by the key on file. A share signs with its own key `p`; a legacy branch
// (a name registered before LUD-26) with its branch key, whose x(P) is the
// key its 64-byte `cx1` carries. That is what dni's reference mint reads for
// a legacy row, and moneyer accepts it as well as its older index-0 key.

/// What an address proof agrees to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressAction {
    /// Point a free name at a share (POST).
    Register,
    /// Move a registered name to another share (PUT).
    Update,
    /// Clear the name's `cx1` (DELETE).
    Unregister,
}

impl AddressAction {
    pub fn parse(action: &str) -> Option<Self> {
        match action {
            "register" => Some(Self::Register),
            "update" => Some(Self::Update),
            "unregister" => Some(Self::Unregister),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Update => "update",
            Self::Unregister => "unregister",
        }
    }

    /// Whether the message names the `cx1` the name is bound to.
    pub fn binds_cx1(&self) -> bool {
        !matches!(self, Self::Unregister)
    }
}

/// A lightning-address username as a Nostr-native mint registers one:
/// `^[a-z0-9][a-z0-9._-]{2,31}$`, the rule moneyer's `NAME_RULE` applies.
/// Exact, never folded: LUD-26 signs the name in lowercase, and refusing an
/// uppercase one keeps the card showing exactly what is signed. It also
/// keeps `:` and `+` out of the message.
pub fn valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=32).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// `LNURLcash:<action>:<domain>:<username>[:<cx1>]`, the `cx1` exactly when
/// the action binds one. `None` when it does not fit the action.
pub fn address_proof_message(
    action: AddressAction,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> Option<String> {
    if action.binds_cx1() != cx1.is_some() {
        return None;
    }
    let mut message = alloc::format!("LNURLcash:{}:{domain}:{username}", action.as_str());
    if let Some(cx1) = cx1 {
        message.push(':');
        message.push_str(cx1);
    }
    Some(message)
}

/// The plain sha256 of [`address_proof_message`], what a proof signs.
pub fn address_proof_digest(
    action: AddressAction,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> Option<[u8; 32]> {
    address_proof_message(action, domain, username, cx1).map(|m| Sha256::digest(m.as_bytes()).into())
}

/// A key this device can sign an address proof with at a mint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofKey {
    Share(u32),
    Branch(BranchKind),
}

impl ProofKey {
    /// `share`, `legacy` or `superseded`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Share(_) => "share",
            Self::Branch(kind) => kind.as_str(),
        }
    }
}

/// One address proof and the x-only key it verifies under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressProof {
    pub signature: [u8; 64],
    pub pubkey: [u8; 32],
}

/// Sign `digest` with a share's or a legacy branch's own key, aux_rand zero
/// as LUD-25 has a wallet sign everything, so the same request always gets
/// the same proof. BIP-340 signs for x(P) whatever P's parity.
pub fn sign_address_proof(node: &CashNode, digest: &[u8; 32]) -> Result<AddressProof, &'static str> {
    Ok(AddressProof {
        signature: backend::sign_bip340_zero_aux(&node.private_key, digest)?,
        pubkey: backend::pubkey_from_secret(&node.private_key)?,
    })
}

/// The key `key` names, derived.
fn proof_node(identity_secret: &[u8; 32], host: &str, key: ProofKey) -> Result<CashNode, &'static str> {
    match key {
        ProofKey::Share(n) => share_node(identity_secret, host, n),
        ProofKey::Branch(kind) => legacy_branch(identity_secret, host, kind),
    }
}

/// Which of this identity's keys at `host` a `cx1` is, as its type and the
/// `cx1` spelt as this device spells it (lowercase). Compared as decoded
/// bytes, so an all-uppercase `cx1` (valid bech32m) names the same key.
/// A 65-byte share `cx1` is looked for on `share` if named, else on every
/// share this device hands out; a 64-byte one on the two legacy branches.
/// Anything else is refused: this device proves only for keys it holds.
pub fn proof_key_of(
    identity_secret: &[u8; 32],
    host: &str,
    cx1: &str,
    share: Option<u32>,
) -> Result<(ProofKey, String), &'static str> {
    if let Some((chain_code, point)) = crate::encoding::decode_share_cx1(cx1) {
        let named = ShareKey { chain_code, point };
        let chain = share_chain(identity_secret, host)?;
        let candidates = match share {
            Some(n) if !valid_share(n) => return Err("a share is 0 to 19"),
            Some(n) => n..n + 1,
            None => 0..SHARE_LIMIT,
        };
        for n in candidates {
            let node = share_at(&chain, n)?;
            if share_key_of(&node)? == named {
                return Ok((ProofKey::Share(n), encode_share_cx1(&chain_code, &point)));
            }
        }
        return Err(match share {
            Some(_) => "that cx1 is not that share of this identity at that mint",
            None => "that cx1 is not one of this identity's shares at that mint",
        });
    }
    let (pubkey, chain_code) = crate::encoding::decode_cx1(cx1).ok_or("that is not a cx1")?;
    if share.is_some() {
        return Err("a 64-byte cx1 is a whole branch, not a share");
    }
    let named = Branch { pubkey, chain_code };
    let root = identity_root(identity_secret)?;
    for kind in [BranchKind::Legacy, BranchKind::Superseded] {
        if branch_of(&legacy_branch_at(&root, host, kind)?)? == named {
            return Ok((ProofKey::Branch(kind), encode_cx1(&pubkey, &chain_code)));
        }
    }
    Err("that cx1 is not one of this device's branches at that mint")
}

/// What a request for an address proof asks for, once checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofRequest<'a> {
    pub action: AddressAction,
    /// The mint as stored, port included (a legacy branch hashes it).
    pub host: &'a str,
    pub username: &'a str,
    /// The share the name is bound to: register and update only.
    pub share: Option<u32>,
    /// The key that signs `sig`: for register the share itself, for update
    /// and unregister the one on file.
    pub signer: ProofKey,
}

/// The proofs a request is answered with: `sig`, and for an update the new
/// share's register proof as `newsig`, and the `cx1` they bind.
pub struct Proofs {
    pub sig: AddressProof,
    pub newsig: Option<AddressProof>,
    pub cx1: Option<String>,
}

/// Sign what `request` asks for, bound to the mint's [`spend_domain`]. Never
/// returns a key.
///
/// The request is checked again here (a register signed by anything but its
/// own share, an update to the share already on file, a share where the
/// action binds none), so nothing can sign a message the card did not name
/// by building a request by hand.
pub fn address_proofs(identity_secret: &[u8; 32], request: &ProofRequest<'_>) -> Result<Proofs, &'static str> {
    if !valid_username(request.username) {
        return Err("a name is 3 to 32 of a-z, 0-9, dot, dash or underscore, starting with a letter or digit");
    }
    if request.action.binds_cx1() != request.share.is_some() {
        return Err("register and update bind a share; unregister binds none");
    }
    match (request.action, request.share, request.signer) {
        (AddressAction::Register, Some(n), ProofKey::Share(m)) if n == m => {}
        (AddressAction::Register, _, _) => return Err("a register is signed by the share it registers"),
        (AddressAction::Update, Some(n), ProofKey::Share(m)) if n == m => {
            return Err("that share is the one on file already")
        }
        _ => {}
    }
    let domain = spend_domain(request.host);
    let bound = match request.share {
        Some(n) => Some(share_node(identity_secret, request.host, n)?),
        None => None,
    };
    let cx1 = match &bound {
        Some(node) => Some(share_cx1_of(node)?),
        None => None,
    };
    let digest = |action| {
        address_proof_digest(action, &domain, request.username, cx1.as_deref()).ok_or("no such proof")
    };
    let signer = match (request.signer, &bound) {
        (ProofKey::Share(m), Some(node)) if request.share == Some(m) => node.clone(),
        (key, _) => proof_node(identity_secret, request.host, key)?,
    };
    let sig = sign_address_proof(&signer, &digest(request.action)?)?;
    let newsig = match (request.action, &bound) {
        (AddressAction::Update, Some(node)) => Some(sign_address_proof(node, &digest(AddressAction::Register)?)?),
        _ => None,
    };
    Ok(Proofs { sig, newsig, cx1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::{cash_domain_indices, cash_node_to_bytes};
    use crate::encoding::encode_cp1;
    use crate::hex::{hex_decode, hex_encode};
    use serde_json::Value;

    const IDENTITY: [u8; 32] = [7u8; 32];

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex_decode(text).expect("hex").try_into().expect("length")
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    fn fixture(name: &str) -> Value {
        let raw = match name {
            "lud26-part2" => include_str!("../tests/fixtures/lud26-part2.json"),
            "lud26-nostr-seed" => include_str!("../tests/fixtures/lud26-nostr-seed.json"),
            "lud26-spec" => include_str!("../tests/fixtures/lud26-spec-vectors.json"),
            "lud25-part2" => include_str!("../tests/fixtures/lud25-part2.json"),
            "lud25-nostr-seed" => include_str!("../tests/fixtures/lud25-nostr-seed.json"),
            _ => unreachable!(),
        };
        serde_json::from_str(raw).unwrap()
    }

    /// One share note against a vector: key, both public key forms, `cp1`,
    /// and, where the vector has them, the spend.
    fn check_share_note(share: &CashNode, domain: &str, note: &Value, at: &str) -> bool {
        let index = note["index"].as_u64().expect("index") as u32;
        let secret = share_note_key(share, index).unwrap();
        assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{at} sk");
        assert_eq!(
            hex_encode(&backend::compressed_pubkey(&secret).unwrap()),
            text(note, "notePubkeyCompressed"),
            "{at} point"
        );
        let pubkey = note_pubkey(&secret).unwrap();
        assert_eq!(hex_encode(&pubkey), text(note, "notePubkey"), "{at} Q");
        assert_eq!(encode_cp1(&pubkey), text(note, "cp1"), "{at} cp1");
        assert_eq!(hex_encode(&key_path_sighash(domain, &pubkey)), text(note, "sighash"), "{at} sighash");
        let spend = key_path_spend(&secret, domain).unwrap();
        assert_eq!(hex_encode(&spend[32..]), text(note, "keyPathSignature"), "{at} signature");
        assert_eq!(encode_ck1(&spend), text(note, "ck1"), "{at} ck1");
        index == HARDENED - 1
    }

    /// Account 0's shares of one vector service root, and their notes.
    /// Returns (odd share seen, even share seen, top index seen).
    fn check_shares(service: &CashNode, domain: &str, account: &Value, label: &str) -> (bool, bool, bool) {
        assert_eq!(account["account"], 0);
        let chain = share_chain_of(service).unwrap();
        let mut seen = (false, false, false);
        for share in account["shares"].as_array().expect("shares") {
            let n = share["share"].as_u64().unwrap() as u32;
            let at = format!("{label} share {n}");
            let node = share_at(&chain, n).unwrap();
            assert_eq!(hex_encode(&node.private_key), text(share, "sharePrivateKey"), "{at}");
            let key = share_key_of(&node).unwrap();
            assert_eq!(hex_encode(&key.point), text(share, "sharePubkey"), "{at}");
            assert_eq!(hex_encode(&key.chain_code), text(share, "chainCode"), "{at}");
            assert_eq!(share_cx1_of(&node).unwrap(), text(share, "cx1"), "{at}");
            seen.0 |= key.point[0] == 0x03;
            seen.1 |= key.point[0] == 0x02;
            for note in share["notes"].as_array().expect("notes") {
                seen.2 |= check_share_note(&node, domain, note, &at);
            }
        }
        seen
    }

    #[test]
    fn matches_the_lud26_part2_vectors() {
        // Eight BIP-39 seeds at four hosts, one with a port, two shares on
        // account 0, and note indices up to 2^31 - 1.
        let vectors = fixture("lud26-part2");
        let branches = vectors["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 8);
        let mut seen = (false, false, false);
        let mut port_seen = false;
        for branch in branches {
            let host = text(branch, "host");
            let domain = text(branch, "domain");
            assert_eq!(spend_domain(host), domain, "{host}");
            port_seen |= host != domain;
            let root = derive_cash_root(&hex_decode(text(branch, "seedHex")).unwrap()).unwrap();
            let hashing = derive_cash_child(&root, 0).unwrap();
            assert_eq!(hex_encode(&hashing.private_key), text(branch, "cashHashingKey"), "{host}");
            // the domain is hashed, never the host with its port
            let indices: Vec<u64> = cash_domain_indices(&root, domain).unwrap().iter().map(|&d| d as u64).collect();
            let want: Vec<u64> = branch["domainIndices"].as_array().unwrap().iter().map(|d| d.as_u64().unwrap()).collect();
            assert_eq!(indices, want, "{host}");
            let service = service_root_at(&root, host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&service).as_ref()), text(branch, "serviceRoot"), "{host}");
            let found = check_shares(&service, domain, &branch["accounts"][0], host);
            seen = (seen.0 | found.0, seen.1 | found.1, seen.2 | found.2);
        }
        // Parity matters to the cx1's prefix byte and to nothing else here,
        // so both must be in the set; likewise a port and the top index.
        assert_eq!(seen, (true, true, true));
        assert!(port_seen);
    }

    #[test]
    fn matches_the_lud26_nostr_seed_vectors() {
        let vectors = fixture("lud26-nostr-seed");
        let mut port_seen = false;
        for case in vectors["cases"].as_array().expect("cases") {
            let identity = unhex::<32>(text(case, "identity"));
            let host = text(case, "host");
            let domain = text(case, "domain");
            assert_eq!(spend_domain(host), domain, "{host}");
            port_seen |= host != domain;
            assert_eq!(hex_encode(nostr_cash_seed(&identity).as_ref()), text(case, "seed"), "{host}");
            let service = service_root(&identity, host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&service).as_ref()), text(case, "serviceRoot"), "{host}");
            check_shares(&service, domain, &case["accounts"][0], host);
            // and what the wire hands out is the same share
            let share0 = &case["accounts"][0]["shares"][0];
            assert_eq!(share_cx1_of(&share_node(&identity, host, 0).unwrap()).unwrap(), text(share0, "cx1"));
        }
        assert!(port_seen);
    }

    /// The spec's own vectors, under their own field names.
    fn spec_share(derivation: &Value, n: usize) -> &Value {
        &derivation["accounts"][0]["shareable"][n]
    }

    #[test]
    fn matches_the_lud26_spec_derivation() {
        let lud26 = &fixture("lud26-spec")["lud26"];
        assert_eq!(fixture("lud26-spec")["luds"], "92e430f");
        for derivation in lud26["derivation"].as_array().expect("derivation") {
            let domain = text(derivation, "domain");
            let root = derive_cash_root(&hex_decode(text(derivation, "seed")).unwrap()).unwrap();
            assert_eq!(hex_encode(&derive_cash_child(&root, 0).unwrap().private_key), text(derivation, "cashHashingKey"));
            let d: Vec<u64> = derivation["d"].as_array().unwrap().iter().map(|d| d.as_u64().unwrap()).collect();
            let ours: Vec<u64> = cash_domain_indices(&root, domain).unwrap().iter().map(|&v| v as u64).collect();
            assert_eq!(ours, d, "{domain}");
            let chain = share_chain_of(&service_root_at(&root, domain).unwrap()).unwrap();
            let account = &derivation["accounts"][0];
            assert_eq!(account["account"], 0);
            for share in account["shareable"].as_array().unwrap() {
                let n = share["share"].as_u64().unwrap() as u32;
                let node = share_at(&chain, n).unwrap();
                assert_eq!(hex_encode(&node.private_key), text(share, "p"), "{domain} {n}");
                assert_eq!(hex_encode(&share_key_of(&node).unwrap().point), text(share, "P"), "{domain} {n}");
                assert_eq!(hex_encode(&node.chain_code), text(share, "chaincode"), "{domain} {n}");
                assert_eq!(share_cx1_of(&node).unwrap(), text(share, "cx1"), "{domain} {n}");
                for note in share["notes"].as_array().unwrap() {
                    let i = note["i"].as_u64().unwrap() as u32;
                    let sk = share_note_key(&node, i).unwrap();
                    assert_eq!(hex_encode(sk.as_ref()), text(note, "sk"), "{domain} {n}/{i}");
                    assert_eq!(hex_encode(&backend::compressed_pubkey(&sk).unwrap()), text(note, "pk"));
                    assert_eq!(hex_encode(&note_pubkey(&sk).unwrap()), text(note, "Q"));
                    assert_eq!(encode_cp1(&note_pubkey(&sk).unwrap()), text(note, "cp1"));
                }
            }
        }
    }

    #[test]
    fn matches_the_lud26_registration_vectors_byte_for_byte() {
        // register share 0's cx1 for alice, update to share 1 (sig by the key
        // on file, newsig by the new share), then unregister with share 1.
        let lud26 = &fixture("lud26-spec")["lud26"];
        let reg = &lud26["registration"];
        let derivation = &lud26["derivation"][1];
        let domain = text(reg, "domain");
        assert_eq!(text(derivation, "domain"), domain);
        let username = text(reg, "username");
        let root = derive_cash_root(&hex_decode(text(derivation, "seed")).unwrap()).unwrap();
        let chain = share_chain_of(&service_root_at(&root, domain).unwrap()).unwrap();
        let (first, second) = (share_at(&chain, 0).unwrap(), share_at(&chain, 1).unwrap());
        let (cx1, new_cx1) = (share_cx1_of(&first).unwrap(), share_cx1_of(&second).unwrap());
        assert_eq!(cx1, text(reg, "cx1"));
        assert_eq!(new_cx1, text(reg, "new_cx1"));
        assert_eq!(cx1, text(spec_share(derivation, 0), "cx1"));
        // the first share has odd y, so its proof is the parity case
        assert_eq!(share_key_of(&first).unwrap().point[0], 0x03);

        let check = |vector: &Value, action: AddressAction, bound: Option<&str>, node: &CashNode| {
            let message = address_proof_message(action, domain, username, bound).unwrap();
            assert_eq!(message, text(vector, "message"));
            let digest = address_proof_digest(action, domain, username, bound).unwrap();
            assert_eq!(hex_encode(&digest), text(vector, "digest"), "{message}");
            let proof = sign_address_proof(node, &digest).unwrap();
            assert_eq!(hex_encode(&proof.signature), text(vector, "sig"), "{message}");
            assert_eq!(proof.pubkey, note_pubkey(&node.private_key).unwrap());
        };
        check(&reg["register"], AddressAction::Register, Some(&cx1), &first);
        check(&reg["update"]["sig"], AddressAction::Update, Some(&new_cx1), &first);
        check(&reg["update"]["newsig"], AddressAction::Register, Some(&new_cx1), &second);
        check(&reg["unregister"], AddressAction::Unregister, None, &second);
    }

    #[test]
    fn matches_the_lud26_part2_address_proofs() {
        // Seven proofs by account 0's shares of the first part2 seed: one
        // register, a PUT's two, an unregister, another name, another mint,
        // and an uppercase name, which this device refuses rather than folds.
        let vectors = fixture("lud26-part2");
        let branch = &vectors["branches"][0];
        let root = derive_cash_root(&hex_decode(text(branch, "seedHex")).unwrap()).unwrap();
        let chain = share_chain_of(&service_root_at(&root, text(branch, "domain")).unwrap()).unwrap();
        let proofs = vectors["addressProofs"].as_array().expect("addressProofs");
        assert_eq!(proofs.len(), 7);
        let mut actions = [false; 3];
        let mut folded = 0;
        for proof in proofs {
            let action = AddressAction::parse(text(proof, "action")).expect("action");
            let domain = text(proof, "domain");
            let username = text(proof, "username");
            if !valid_username(username) {
                assert_eq!(username, "Alice");
                folded += 1;
                continue;
            }
            let bound = proof["cx1"].as_str();
            // the signer is whichever of the seed's shares at its own mint its
            // cx1 is (the "another mint" proof is by a mint.example share)
            let signer = (0..SHARE_LIMIT)
                .map(|n| share_at(&chain, n).unwrap())
                .find(|node| share_cx1_of(node).unwrap() == text(proof, "signerCx1"))
                .expect("signer is a share of the first seed");
            let at = format!("{} {domain} {username}", action.as_str());
            assert_eq!(address_proof_message(action, domain, username, bound).unwrap(), text(proof, "message"), "{at}");
            let digest = address_proof_digest(action, domain, username, bound).unwrap();
            assert_eq!(hex_encode(&digest), text(proof, "digest"), "{at}");
            let signed = sign_address_proof(&signer, &digest).unwrap();
            assert_eq!(hex_encode(&signed.pubkey), text(proof, "signerPubkey"), "{at}");
            assert_eq!(hex_encode(&signed.signature), text(proof, "signature"), "{at}");
            actions[action as usize] = true;
        }
        assert_eq!(actions, [true; 3]);
        assert_eq!(folded, 1);
    }

    #[test]
    fn the_message_has_a_cx1_exactly_when_the_action_binds_one() {
        let cx1 = Some("cx1abc");
        assert!(address_proof_message(AddressAction::Register, "d", "alice", None).is_none());
        assert!(address_proof_message(AddressAction::Update, "d", "alice", None).is_none());
        assert!(address_proof_message(AddressAction::Unregister, "d", "alice", cx1).is_none());
        assert_eq!(
            address_proof_message(AddressAction::Update, "d", "alice", cx1).unwrap(),
            "LNURLcash:update:d:alice:cx1abc"
        );
    }

    // ---- legacy branches ----

    #[test]
    fn matches_the_lud25_part2_vectors_on_the_legacy_branch() {
        // 0.15.0's set: eight whole branches, both parities, a host with a
        // port (hashed as stored), indices up to u32::MAX on purpose 0, then
        // purposes 1 and 2, with spends.
        let vectors = fixture("lud25-part2");
        let branches = vectors["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 8);
        let (mut odd_seen, mut port_seen) = (false, false);
        for branch in branches {
            let host = text(branch, "host");
            let domain = text(branch, "domain");
            port_seen |= host != domain;
            let root = derive_cash_root(&hex_decode(text(branch, "seedHex")).unwrap()).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&root).as_ref()), text(branch, "cashRoot"), "{host}");
            let node = legacy_branch_at(&root, host, BranchKind::Legacy).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(branch, "addressNode"), "{host}");
            let (watched, odd) = watch(&node).unwrap();
            assert_eq!(hex_encode(&watched.pubkey), text(branch, "branchPubkey"), "{host}");
            assert_eq!(odd, text(branch, "branchParity") == "odd", "{host}");
            odd_seen |= odd;
            assert_eq!(cx1_of(&node).unwrap(), text(branch, "cx1"), "{host}");
            let mut purposes = [false; 3];
            for note in branch["notes"].as_array().expect("notes") {
                let purpose = note["purpose"].as_u64().unwrap() as u32;
                let index = note["index"].as_u64().unwrap() as u32;
                purposes[purpose as usize] = true;
                let secret = note_secret_key(&node, purpose, index).unwrap();
                assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{host} {purpose}/{index}");
                let pubkey = note_pubkey(&secret).unwrap();
                assert_eq!(hex_encode(&pubkey), text(note, "notePubkey"));
                let spend = key_path_spend(&secret, domain).unwrap();
                assert_eq!(encode_ck1(&spend), text(note, "ck1"), "{host} {purpose}/{index}");
            }
            assert_eq!(purposes, [true; 3], "{host}");
        }
        assert!(odd_seen && port_seen);
    }

    #[test]
    fn matches_the_lud25_nostr_seed_vectors_on_the_legacy_branch() {
        let vectors = fixture("lud25-nostr-seed");
        for case in vectors["cases"].as_array().expect("cases") {
            let identity = unhex::<32>(text(case, "identity"));
            let host = text(case, "host");
            let node = legacy_branch(&identity, host, BranchKind::Legacy).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(case, "addressNode"), "{host}");
            assert_eq!(cx1_of(&node).unwrap(), text(case, "cx1"), "{host}");
            for note in case["notes"].as_array().expect("notes") {
                let purpose = note["purpose"].as_u64().unwrap() as u32;
                let index = note["index"].as_u64().unwrap() as u32;
                let secret = note_secret_key(&node, purpose, index).unwrap();
                assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{host}");
            }
        }
    }

    #[test]
    fn matches_the_legacy_tweak_vectors_with_and_without_purpose() {
        // 0.16.2's `legacy` set: the purposed tweak and the pre-purpose one,
        // per mnemonic at every host, the node hashing the host as stored.
        let vectors = fixture("lud26-part2");
        let legacy = &vectors["legacy"];
        assert_eq!(legacy["superseded"], true);
        let seeds = vectors["branches"].as_array().unwrap();
        let mut pre_purpose = 0;
        for branch in legacy["branches"].as_array().expect("branches") {
            let host = text(branch, "host");
            let seed = seeds
                .iter()
                .find(|b| b["mnemonic"] == branch["mnemonic"])
                .map(|b| text(b, "seedHex"))
                .expect("the mnemonic's seed");
            let root = derive_cash_root(&hex_decode(seed).unwrap()).unwrap();
            let node = legacy_branch_at(&root, host, BranchKind::Legacy).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(branch, "addressNode"), "{host}");
            assert_eq!(cx1_of(&node).unwrap(), text(branch, "cx1"), "{host}");
            for note in branch["notes"].as_array().expect("notes") {
                let purpose = note["purpose"].as_u64().unwrap() as u32;
                let index = note["index"].as_u64().unwrap() as u32;
                let secret = note_secret_key(&node, purpose, index).unwrap();
                assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{host} {purpose}/{index}");
                assert_eq!(encode_cp1(&note_pubkey(&secret).unwrap()), text(note, "cp1"));
            }
            for note in branch["prePurpose"].as_array().expect("prePurpose") {
                let index = note["index"].as_u64().unwrap() as u32;
                let secret = pre_purpose_note_secret_key(&node, index).unwrap();
                assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{host} pre-purpose {index}");
                assert_eq!(hex_encode(&note_pubkey(&secret).unwrap()), text(note, "notePubkey"));
                pre_purpose += 1;
            }
        }
        assert!(pre_purpose >= 4);
    }

    #[test]
    fn the_tweak_is_reduced_mod_n() {
        assert_eq!(reduce_mod_n([0u8; 32]), [0u8; 32]);
        let mut below = CURVE_ORDER;
        below[31] -= 1;
        assert_eq!(reduce_mod_n(below), below);
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0u8; 32]);
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut above = CURVE_ORDER;
        above[31] += 1;
        assert_eq!(reduce_mod_n(above), one);
        // 2^256 - 1 is n + 0x1_4551231950b75fc4402da1732fc9bebe
        let top = reduce_mod_n([0xff; 32]);
        // 2^256 - 1 - n, arithmetic rather than a key // pragma: allow-secret
        assert_eq!(hex_encode(&top), "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe"); // pragma: allow-secret
    }

    // ---- claims ----

    const LA: u32 = PURPOSE_LIGHTNING_ADDRESS;

    fn share_pubkey(identity: &[u8; 32], host: &str, share: u32, index: u32) -> [u8; 32] {
        note_pubkey(&share_note_key(&share_node(identity, host, share).unwrap(), index).unwrap()).unwrap()
    }

    #[test]
    fn a_claim_finds_a_key_on_any_share_it_could_be_on() {
        for share in [0, 3, SHARE_LIMIT - 1] {
            let paid = share_pubkey(&IDENTITY, "moneyer.dev", share, 5);
            for hint in [None, Some(share), Some((share + 1) % SHARE_LIMIT)] {
                let found = claim_note_key(&IDENTITY, "moneyer.dev", 5, Some(&paid), hint, LA).unwrap();
                assert_eq!(found.pubkey, paid, "{share} {hint:?}");
                assert_eq!(note_pubkey(&found.secret).unwrap(), paid);
                assert_eq!(found.origin, KeyOrigin::Share(share));
            }
        }
        // the port is not in the domain a share hashes
        let paid = share_pubkey(&IDENTITY, "moneyer.dev", 2, 0);
        assert_eq!(
            claim_note_key(&IDENTITY, "moneyer.dev:8443", 0, Some(&paid), None, LA).unwrap().origin,
            KeyOrigin::Share(2)
        );
    }

    #[test]
    fn a_claim_checks_the_key_it_is_paid_to() {
        let paid = share_pubkey(&IDENTITY, "moneyer.dev", 1, 3);
        let not_ours = |identity: &[u8; 32], host: &str, index: u32| {
            claim_note_key(identity, host, index, Some(&paid), None, LA).err()
        };
        // another index, another mint and another identity are all other keys
        assert_eq!(not_ours(&IDENTITY, "moneyer.dev", 4), Some(NOT_OURS));
        assert_eq!(not_ours(&IDENTITY, "mint.example", 3), Some(NOT_OURS));
        assert_eq!(not_ours(&[8u8; 32], "moneyer.dev", 3), Some(NOT_OURS));
        // a share past the ones handed out is never searched, nor named
        let beyond = note_pubkey(
            &share_note_key(
                &derive_cash_child(&share_chain(&IDENTITY, "moneyer.dev").unwrap(), SHARE_LIMIT | HARDENED).unwrap(),
                3,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(claim_note_key(&IDENTITY, "moneyer.dev", 3, Some(&beyond), None, LA).is_err());
        assert!(claim_note_key(&IDENTITY, "moneyer.dev", 3, Some(&paid), Some(SHARE_LIMIT), LA).is_err());
        // the wallet and change chains are never a share's
        let service = service_root(&IDENTITY, "moneyer.dev").unwrap();
        let account = derive_cash_child(&service, ACCOUNT_ZERO).unwrap();
        for chain in [0, 1] {
            let wallet = derive_cash_child(&derive_cash_child(&account, chain).unwrap(), 3).unwrap();
            let pk = note_pubkey(&wallet.private_key).unwrap();
            assert!(claim_note_key(&IDENTITY, "moneyer.dev", 3, Some(&pk), None, LA).is_err(), "chain {chain}");
        }
    }

    #[test]
    fn a_claim_without_its_key_needs_the_share_and_derives_only_that() {
        assert!(claim_note_key(&IDENTITY, "moneyer.dev", 3, None, None, LA).is_err());
        let found = claim_note_key(&IDENTITY, "moneyer.dev", 3, None, Some(4), LA).unwrap();
        assert_eq!(found.pubkey, share_pubkey(&IDENTITY, "moneyer.dev", 4, 3));
        assert_eq!(found.origin, KeyOrigin::Share(4));
        // an index at or above 2^31 is no share note
        assert!(claim_note_key(&IDENTITY, "moneyer.dev", HARDENED, None, Some(0), LA).is_err());
    }

    #[test]
    fn a_claim_still_finds_a_note_paid_to_a_legacy_branch() {
        // The two live names were registered with whole branches; a mint
        // keeps crediting those on the purposed tweak, and may once have used
        // the pre-purpose one.
        for kind in [BranchKind::Legacy, BranchKind::Superseded] {
            let node = legacy_branch(&IDENTITY, "moneyer.dev", kind).unwrap();
            for index in [0, 7, u32::MAX] {
                let purposed = note_pubkey(&note_secret_key(&node, LA, index).unwrap()).unwrap();
                let pre = note_pubkey(&pre_purpose_note_secret_key(&node, index).unwrap()).unwrap();
                for paid in [purposed, pre] {
                    let found = claim_note_key(&IDENTITY, "moneyer.dev", index, Some(&paid), None, LA).unwrap();
                    assert_eq!((found.pubkey, found.origin), (paid, KeyOrigin::Branch(kind)), "{kind:?} {index}");
                    assert_eq!(note_pubkey(&found.secret).unwrap(), paid);
                }
            }
            // the purpose narrows the purposed leg only
            let wallet = note_pubkey(&note_secret_key(&node, PURPOSE_WALLET, 2).unwrap()).unwrap();
            assert!(claim_note_key(&IDENTITY, "moneyer.dev", 2, Some(&wallet), None, LA).is_err());
            let found = claim_note_key(&IDENTITY, "moneyer.dev", 2, Some(&wallet), None, PURPOSE_WALLET).unwrap();
            assert_eq!(found.origin, KeyOrigin::Branch(kind));
        }
        // a legacy branch hashes the host as stored, port and all
        let ported = legacy_branch(&IDENTITY, "moneyer.dev:8443", BranchKind::Legacy).unwrap();
        let paid = note_pubkey(&note_secret_key(&ported, LA, 0).unwrap()).unwrap();
        assert!(claim_note_key(&IDENTITY, "moneyer.dev:8443", 0, Some(&paid), None, LA).is_ok());
        assert!(claim_note_key(&IDENTITY, "moneyer.dev", 0, Some(&paid), None, LA).is_err());
    }

    #[test]
    fn a_ck1_is_bound_to_its_mint() {
        let found = claim_note_key(&IDENTITY, "moneyer.dev", 0, None, Some(0), LA).unwrap();
        let here = ck1_of(&found.secret, "moneyer.dev/w").unwrap();
        // the endpoint path and a port do not change the domain
        assert_eq!(here, ck1_of(&found.secret, "moneyer.dev").unwrap());
        assert_eq!(here, ck1_of(&found.secret, "moneyer.dev:443/w").unwrap());
        assert_ne!(here, ck1_of(&found.secret, "mint.example/w").unwrap());
    }

    #[test]
    fn shares_are_per_mint_per_identity_and_per_number() {
        let cx1 = |identity: &[u8; 32], host, n| share_cx1_of(&share_node(identity, host, n).unwrap()).unwrap();
        let a = cx1(&IDENTITY, "moneyer.dev", 0);
        assert_eq!(a.len(), 113);
        assert_eq!(a, cx1(&IDENTITY, "moneyer.dev:443", 0), "the port is not hashed");
        assert_ne!(a, cx1(&IDENTITY, "moneyer.dev", 1));
        assert_ne!(a, cx1(&IDENTITY, "mint.example", 0));
        assert_ne!(a, cx1(&[8u8; 32], "moneyer.dev", 0));
        assert!(share_node(&IDENTITY, "moneyer.dev", SHARE_LIMIT).is_err());
        assert!(share_node(&IDENTITY, "moneyer.dev", u32::MAX).is_err());
    }

    // ---- proofs ----

    fn share_cx1(n: u32) -> String {
        share_cx1_of(&share_node(&IDENTITY, "moneyer.dev", n).unwrap()).unwrap()
    }

    fn legacy_cx1(kind: BranchKind) -> String {
        cx1_of(&legacy_branch(&IDENTITY, "moneyer.dev", kind).unwrap()).unwrap()
    }

    #[test]
    fn a_proof_key_is_found_from_its_cx1() {
        for n in [0, 5, SHARE_LIMIT - 1] {
            let cx1 = share_cx1(n);
            assert_eq!(proof_key_of(&IDENTITY, "moneyer.dev", &cx1, None), Ok((ProofKey::Share(n), cx1.clone())));
            assert_eq!(proof_key_of(&IDENTITY, "moneyer.dev", &cx1, Some(n)), Ok((ProofKey::Share(n), cx1.clone())));
            // uppercase is the same cx1, spelt back in lowercase
            let upper = proof_key_of(&IDENTITY, "moneyer.dev", &cx1.to_ascii_uppercase(), None).unwrap();
            assert_eq!(upper, (ProofKey::Share(n), cx1.clone()));
            // a share named wrong is refused, not searched past
            assert!(proof_key_of(&IDENTITY, "moneyer.dev", &cx1, Some((n + 1) % SHARE_LIMIT)).is_err());
        }
        for kind in [BranchKind::Legacy, BranchKind::Superseded] {
            let cx1 = legacy_cx1(kind);
            assert_eq!(proof_key_of(&IDENTITY, "moneyer.dev", &cx1, None), Ok((ProofKey::Branch(kind), cx1.clone())));
            assert!(proof_key_of(&IDENTITY, "moneyer.dev", &cx1, Some(0)).is_err());
        }
        let theirs = share_cx1_of(&share_node(&[8u8; 32], "moneyer.dev", 0).unwrap()).unwrap();
        let elsewhere = share_cx1_of(&share_node(&IDENTITY, "mint.example", 0).unwrap()).unwrap();
        let their_branch = cx1_of(&legacy_branch(&[8u8; 32], "moneyer.dev", BranchKind::Legacy).unwrap()).unwrap();
        let ours = share_cx1(0);
        let mixed = format!("{}{}", &ours[..10], ours[10..].to_ascii_uppercase());
        for bad in [theirs.as_str(), &elsewhere, &their_branch, "", "cx1", "cp1qqqq", &mixed] {
            assert!(proof_key_of(&IDENTITY, "moneyer.dev", bad, None).is_err(), "{bad}");
        }
        // part2's off-curve and wrong-prefix share cx1s are never ours
        for case in fixture("lud26-part2")["invalid"].as_array().unwrap() {
            if text(case, "type") == "cx1" {
                assert!(proof_key_of(&IDENTITY, "moneyer.dev", text(case, "value"), None).is_err());
            }
        }
    }

    fn request(action: AddressAction, share: Option<u32>, signer: ProofKey) -> ProofRequest<'static> {
        ProofRequest { action, host: "moneyer.dev", username: "alice", share, signer }
    }

    fn verify(proof: &AddressProof, action: AddressAction, cx1: Option<&str>, node: &CashNode) {
        let digest = address_proof_digest(action, "moneyer.dev", "alice", cx1).unwrap();
        assert_eq!(*proof, sign_address_proof(node, &digest).unwrap());
    }

    #[test]
    fn a_register_is_signed_by_the_share_it_registers() {
        let proofs = address_proofs(&IDENTITY, &request(AddressAction::Register, Some(3), ProofKey::Share(3))).unwrap();
        assert_eq!(proofs.cx1.as_deref(), Some(share_cx1(3).as_str()));
        assert!(proofs.newsig.is_none());
        let node = share_node(&IDENTITY, "moneyer.dev", 3).unwrap();
        verify(&proofs.sig, AddressAction::Register, Some(&share_cx1(3)), &node);
        assert_eq!(proofs.sig.pubkey, note_pubkey(&node.private_key).unwrap());
        // by anything else, it is no register
        for signer in [ProofKey::Share(4), ProofKey::Branch(BranchKind::Legacy)] {
            assert!(address_proofs(&IDENTITY, &request(AddressAction::Register, Some(3), signer)).is_err());
        }
        assert!(address_proofs(&IDENTITY, &request(AddressAction::Register, None, ProofKey::Share(3))).is_err());
    }

    #[test]
    fn an_update_from_old_keys_is_signed_by_the_branch_key_and_the_new_share() {
        for kind in [BranchKind::Legacy, BranchKind::Superseded] {
            let proofs =
                address_proofs(&IDENTITY, &request(AddressAction::Update, Some(0), ProofKey::Branch(kind))).unwrap();
            let cx1 = share_cx1(0);
            assert_eq!(proofs.cx1.as_deref(), Some(cx1.as_str()));
            let branch = legacy_branch(&IDENTITY, "moneyer.dev", kind).unwrap();
            verify(&proofs.sig, AddressAction::Update, Some(&cx1), &branch);
            // x(P): the key the 64-byte cx1 on file carries
            assert_eq!(proofs.sig.pubkey, branch_of(&branch).unwrap().pubkey);
            let share = share_node(&IDENTITY, "moneyer.dev", 0).unwrap();
            verify(&proofs.newsig.unwrap(), AddressAction::Register, Some(&cx1), &share);
        }
        // from one share to another
        let proofs = address_proofs(&IDENTITY, &request(AddressAction::Update, Some(2), ProofKey::Share(1))).unwrap();
        verify(&proofs.sig, AddressAction::Update, Some(&share_cx1(2)), &share_node(&IDENTITY, "moneyer.dev", 1).unwrap());
        // never onto the share already on file, and always to a share
        assert!(address_proofs(&IDENTITY, &request(AddressAction::Update, Some(1), ProofKey::Share(1))).is_err());
        assert!(address_proofs(&IDENTITY, &request(AddressAction::Update, None, ProofKey::Share(1))).is_err());
    }

    #[test]
    fn an_unregister_is_signed_by_the_key_on_file_and_binds_nothing() {
        for signer in [ProofKey::Share(6), ProofKey::Branch(BranchKind::Legacy), ProofKey::Branch(BranchKind::Superseded)] {
            let proofs = address_proofs(&IDENTITY, &request(AddressAction::Unregister, None, signer)).unwrap();
            assert!(proofs.cx1.is_none() && proofs.newsig.is_none());
            verify(&proofs.sig, AddressAction::Unregister, None, &proof_node(&IDENTITY, "moneyer.dev", signer).unwrap());
        }
        assert!(address_proofs(&IDENTITY, &request(AddressAction::Unregister, Some(6), ProofKey::Share(6))).is_err());
    }

    #[test]
    fn a_proof_is_bound_to_the_name_and_the_bare_domain() {
        let base = address_proofs(&IDENTITY, &request(AddressAction::Register, Some(0), ProofKey::Share(0))).unwrap().sig;
        let mut bob = request(AddressAction::Register, Some(0), ProofKey::Share(0));
        bob.username = "bob";
        assert_ne!(address_proofs(&IDENTITY, &bob).unwrap().sig, base);
        let mut ported = request(AddressAction::Register, Some(0), ProofKey::Share(0));
        ported.host = "moneyer.dev:8443";
        // the same share (the port is not hashed) and the same domain
        assert_eq!(address_proofs(&IDENTITY, &ported).unwrap().sig, base);
        for name in ["al", "Alice", "_alice", "al:ce", "al+ce", "alice@x", ""] {
            let mut bad = request(AddressAction::Register, Some(0), ProofKey::Share(0));
            bad.username = name;
            assert!(address_proofs(&IDENTITY, &bad).is_err(), "{name}");
        }
    }

    #[test]
    fn the_username_rule_is_the_mints() {
        for good in ["abc", "0ab", "a.b", "a-b", "a_b", "alice", &"z".repeat(32)] {
            assert!(valid_username(good), "{good}");
        }
        for bad in ["", "ab", ".ab", "-ab", "_ab", "Abc", "abC", "a b", "a:b", "a/b", "a+b", "é12", &"z".repeat(33)] {
            assert!(!valid_username(bad), "{bad}");
        }
        for (text, action) in [
            ("register", AddressAction::Register),
            ("update", AddressAction::Update),
            ("unregister", AddressAction::Unregister),
        ] {
            assert_eq!(AddressAction::parse(text), Some(action));
            assert_eq!(action.as_str(), text);
        }
        for bad in ["", "Register", "clear", "register ", "put"] {
            assert_eq!(AddressAction::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_branch_host_is_the_endpoint_without_its_path() {
        assert_eq!(branch_host("moneyer.dev/w"), "moneyer.dev");
        assert_eq!(branch_host("127.0.0.1:8899/w"), "127.0.0.1:8899");
        assert_eq!(branch_host("moneyer.dev"), "moneyer.dev");
        assert_eq!(spend_domain("127.0.0.1:8899/w"), "127.0.0.1");
        assert_eq!(spend_domain("moneyer.dev/w"), "moneyer.dev");
    }
}
