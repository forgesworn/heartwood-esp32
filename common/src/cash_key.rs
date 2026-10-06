//! LUD-25 key-path notes on this device: notes paid to its own keys.
//!
//! A key-path note (the half of the draft once called Part 2) is a BIP-341
//! output key `Q` that is the holder's own key, used as is with no BIP-86
//! tweak. The mint only ever learns `cp1<Q>`, and the note is spent with a
//! `ck1`: `Q` and a BIP-340 key-path signature over the sighash of one
//! canonical, never-broadcast transaction whose prevout is bound to the
//! mint's domain. A mint that holds a watch-only `cx1` for a lightning address
//! mints each payment straight to the holder's next key, so the gift wrap that
//! tells the holder about it carries no secret at all, only where to look and
//! at which index.
//!
//! **Where this device's receiving keys come from.** A lightning address on a
//! Nostr-native mint belongs to an npub: the key that signed the registration
//! owns the name, and payments are wrapped to it. That key lives here and
//! never leaves, so it is the root:
//!
//! ```text
//! seed    = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//! branch  = m/139'/d1/d2/d3/d4 from that seed, d1..d4 from HMAC-SHA256(m/139'/0, host)
//! t       = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(purpose) || ser32_be(i)) mod n
//! sk_i    = (P has even y ? p : n - p) + t   (mod n)
//! Q       = x(sk_i * G)
//! ck1     = Q || BIP-340(sk_i, key-path sighash of the canonical spend for the domain), aux_rand = 0
//! ```
//!
//! The first line is this device's own, and the only one. Everything below it
//! is LUD-25 (lnurl/luds `50d740a`) exactly, so lnurlcash-kit, handed this
//! seed, finds every note. It exists because this device never holds a BIP-32
//! master (see [`crate::cash`]): what it holds is the identity key, which the
//! owner's recovery phrase already backs up. So these notes come back from the
//! heartwood's phrase, and nothing paired with the device can spend them
//! without it.
//!
//! **Purposes.** One `cx1` covers three counters: 0 for the wallet's own
//! notes, 1 for a split's change, and 2 for Lightning Address auto-mint and
//! internal transfer. A mint mints to this device's keys only on purpose 2.
//!
//! **The superseded branch.** Before LUD-25 `50d740a` this device, following
//! lnurl-wallet's `cashSecrets.ts`, hung the branch off `m/139'/1'` (hashing
//! key `m/139'/1'/0`). Every `cx1` it handed out before then is on that
//! branch, and a mint keeps paying whatever `cx1` a name was registered with,
//! now under the purposed tweak. So a claim that names the key it expects
//! falls back to that branch: until the name is registered again, it is where
//! the money lands. Nothing new is ever handed out on it.
//!
//! **The pre-purpose ladder.** Before purposes, this device and the mints
//! that paid it derived from that same superseded branch with no
//! `ser32(purpose)` in the tweak (lnurl/luds `6e865b1`). A note a mint paid
//! there before it moved to `50d740a`, whose wrap was never opened, is still
//! this device's money, so a claim that names its key tries that ladder last
//! ([`claim_note_key`]). The current branch was never on it.
//!
//! HMAC keyed by the secret with a fixed label is the shape
//! [`crate::derive::nsec_to_tree_root`] already uses. The label is not an
//! nsec-tree message (those all start `nsec-tree`), so the seed is never a key
//! nsec-tree hands out as an identity.
//!
//! Graded in the tests below against lnurlcash-conformance's `part2.json` and
//! `nostr-seed.json` (0.15.0, luds `50d740a`).

use alloc::string::String;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cash::{derive_cash_child, derive_cash_domain_node, derive_cash_root, CashNode};
use crate::derive::backend;
use crate::encoding::{encode_ck1, encode_cx1};
use crate::taproot::tagged_hash;

type HmacSha256 = Hmac<Sha256>;

/// What the seed step hashes, keyed by the identity's secret.
pub const NOSTR_SEED_LABEL: &[u8] = b"LNURLcash/nostr-seed";

/// The wallet's own notes, a split's `p1` and every rotate or merge output.
pub const PURPOSE_WALLET: u32 = 0;
/// A split's change `p2`.
pub const PURPOSE_CHANGE: u32 = 1;
/// Lightning Address auto-mint and internal transfer: the only purpose a mint
/// mints to on its own, so the one a wrapped key note is on.
pub const PURPOSE_LIGHTNING_ADDRESS: u32 = 2;

/// `m/139'/1'`: where this device hung its address branch before LUD-25
/// `50d740a`. Read only, to claim what is still paid to a `cx1` it handed out
/// then; see the module docs.
const SUPERSEDED_ADDRESS_BRANCH: u32 = 1 | 0x8000_0000;

const NOTE_DERIVE_TAG: &[u8] = b"LNURLcash/derive";

/// secp256k1's group order, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The seed a Nostr identity's address branches hang off.
pub fn nostr_cash_seed(identity_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(identity_secret).expect("HMAC accepts any key length");
    mac.update(NOSTR_SEED_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// One mint's address branch for a Nostr identity: bearer material for every
/// note ever paid to it, so it stays on this device. Hand out [`cx1_of`].
///
/// `host` is the mint as a wallet spells it (see [`crate::cash`]): lowercase,
/// port included, no scheme and no path.
pub fn address_node(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
    let seed = nostr_cash_seed(identity_secret);
    derive_cash_domain_node(&derive_cash_root(seed.as_ref())?, host)
}

/// The same mint's branch on the superseded `m/139'/1'` path. Never handed
/// out; only claimed from, and asked to agree to moving a name off it
/// ([`address_proof_for`]).
pub(crate) fn superseded_address_node(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
    let seed = nostr_cash_seed(identity_secret);
    let root = derive_cash_child(&derive_cash_root(seed.as_ref())?, SUPERSEDED_ADDRESS_BRANCH)?;
    derive_cash_domain_node(&root, host)
}

/// A branch as a watcher holds it: its x coordinate, which names the even-y
/// point, and its chain code. Enough to derive every note's public key and no
/// note's secret.
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

/// What a mint is told so it can mint straight to this branch.
pub fn cx1_of(node: &CashNode) -> Result<String, &'static str> {
    let branch = branch_of(node)?;
    Ok(encode_cx1(&branch.pubkey, &branch.chain_code))
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

fn note_tweak(branch: &Branch, purpose: u32, index: u32) -> [u8; 32] {
    reduce_mod_n(tagged_hash(
        NOTE_DERIVE_TAG,
        &[&branch.pubkey, &branch.chain_code, &purpose.to_be_bytes(), &index.to_be_bytes()],
    ))
}

/// The tweak before purposes (lnurl/luds `6e865b1`): no `ser32(purpose)` at
/// all. Only ever derived to claim a note a mint paid there; see the module
/// docs.
fn pre_purpose_tweak(branch: &Branch, index: u32) -> [u8; 32] {
    reduce_mod_n(tagged_hash(NOTE_DERIVE_TAG, &[&branch.pubkey, &branch.chain_code, &index.to_be_bytes()]))
}

/// The key of note `index` on one `purpose` of a branch. Both are any uint32
/// and never hardened: a watcher holding only the `cx1` derives the matching
/// public key at every one, which is the point of the scheme.
///
/// The branch key is negated first when its point has odd y, because the `cx1`
/// carries only x and x names the even-y point. Skipping that would give a key
/// whose public key is not the one the mint minted to.
pub fn note_secret_key(node: &CashNode, purpose: u32, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    tweaked_key(node, |branch| note_tweak(branch, purpose, index))
}

/// The key of note `index` on the pre-purpose ladder of a branch.
fn pre_purpose_secret_key(node: &CashNode, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    tweaked_key(node, |branch| pre_purpose_tweak(branch, index))
}

fn tweaked_key(
    node: &CashNode,
    tweak_of: impl FnOnce(&Branch) -> [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let (branch, odd) = watch(node)?;
    let tweak = tweak_of(&branch);
    let base = if odd {
        Zeroizing::new(backend::negate(&node.private_key)?)
    } else {
        Zeroizing::new(node.private_key)
    };
    // The tweak is already reduced mod n, as LUD-25 requires, so the only
    // refusal left is a zero sum: a ~2^-256 event, and the answer is the next
    // index, since a wrong key is a note nobody finds.
    backend::tweak_add(&base, &tweak)
        .map(Zeroizing::new)
        .map_err(|_| "this note index is unusable on this branch")
}

/// `x(sk * G)`: the note's output key Q, what it is filed under, and what its
/// `cp1` encodes.
pub fn note_pubkey(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    backend::pubkey_from_secret(secret)
}

/// The mint a note's withdraw endpoint belongs to: `moneyer.dev/w` is at
/// `moneyer.dev`. The locker stores the endpoint; a branch is per mint.
pub fn branch_host(note_host: &str) -> &str {
    note_host.split('/').next().unwrap_or(note_host)
}

/// The domain a spend is bound to: the mint's hostname, lowercase, never its
/// scheme, path or port. The branch still hashes the host exactly as stored,
/// port included; only the spend drops it.
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
    // Built field by field, and graded intermediate by intermediate against
    // LUD-25's vector 3, in crate::taproot.
    crate::taproot::key_path_sighash(output_key, domain)
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

/// The key a note paid to `identity` at (`purpose`, `index`) answers to,
/// checked against the public key the note is said to be minted to.
///
/// This is the whole of what a device that cannot reach the mint can know: a
/// wrap naming a key this device does not hold is refused here, before any
/// card is drawn, rather than kept as money that is not ours. A claim that
/// names its key is also tried on the superseded branch, where a name
/// registered before LUD-25 `50d740a` is still paid, and last on that
/// branch's pre-purpose ladder, where a mint paid it before it moved to
/// `50d740a`. Returns the key and its public key.
pub fn claim_note_key(
    identity_secret: &[u8; 32],
    host: &str,
    purpose: u32,
    index: u32,
    expected: Option<&[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), &'static str> {
    let at = |node: &CashNode| -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), &'static str> {
        let secret = note_secret_key(node, purpose, index)?;
        let pubkey = note_pubkey(&secret)?;
        Ok((secret, pubkey))
    };
    let current = at(&address_node(identity_secret, host)?)?;
    let Some(want) = expected else {
        return Ok(current);
    };
    if current.1 == *want {
        return Ok(current);
    }
    let old_node = superseded_address_node(identity_secret, host)?;
    let superseded = at(&old_node)?;
    if superseded.1 == *want {
        return Ok(superseded);
    }
    // An index unusable on the old ladder (a ~2^-256 zero sum) is a key
    // nothing was paid to, so it is the same refusal.
    if let Ok(secret) = pre_purpose_secret_key(&old_node, index) {
        let pubkey = note_pubkey(&secret)?;
        if pubkey == *want {
            return Ok((secret, pubkey));
        }
    }
    Err("that note is paid to a key this device does not hold")
}

// ---- address proofs: the branch on file agrees to a change of name ----
//
// A `cx1` is public, so a mint will not point a name at one, or away from
// one, on the say-so of whoever holds the name's NIP-98 key alone: LUD-25
// (`50d740a`) wants the branch itself to agree. Agreement is a BIP-340
// signature by the branch's purpose-0 index-0 key over
// `sha256(utf8("LNURLcash:<action>:<domain>:<username>"))`. A fresh name is
// proven by the branch it is pointed at; changing or clearing a name's `cx1`
// is proven by the branch CURRENTLY on file, which for a name registered
// before `50d740a` is this device's superseded branch. So a proof is asked
// for by naming the branch, and signed by whichever of this device's two
// branches that is.

/// What an address proof says the branch agrees to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressAction {
    /// Point the name at a branch, or move it off the one on file.
    Register,
    /// Clear the name's branch, so its payments are no longer minted to keys.
    Unregister,
}

impl AddressAction {
    pub fn parse(action: &str) -> Option<Self> {
        match action {
            "register" => Some(Self::Register),
            "unregister" => Some(Self::Unregister),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Unregister => "unregister",
        }
    }
}

/// Which of this device's branches at a mint holds a given `cx1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchKind {
    /// `m/139'/d1..d4`, the only one handed out since LUD-25 `50d740a`.
    Current,
    /// `m/139'/1'/...`, from before then; see the module docs.
    Superseded,
}

impl BranchKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Superseded => "superseded",
        }
    }
}

/// A lightning-address username as a Nostr-native mint registers one:
/// `^[a-z0-9][a-z0-9._-]{2,31}$`, the rule moneyer's `NAME_RULE` applies to the
/// name it then checks the proof against. Exact, never folded: the proof signs
/// the name as written, and a mint lowercases before it checks, so an
/// uppercase name here would be a signature over a name no mint ever sees.
/// It also keeps `:` out of the message, so no two (domain, username) pairs
/// can sign the same string.
pub fn valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=32).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// `sha256(utf8("LNURLcash:<action>:<domain>:<username>"))`: what an address
/// proof signs. A plain hash, not a tagged one, exactly as LUD-25 and moneyer's
/// `addressProofVerifies` compute it. The domain is the mint's own, so a proof
/// one mint has seen cannot be replayed at another; the action and the name
/// keep a register from being replayed as an unregister, or for another name.
pub fn address_proof_digest(action: AddressAction, domain: &str, username: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"LNURLcash:")
        .chain_update(action.as_str().as_bytes())
        .chain_update(b":")
        .chain_update(domain.as_bytes())
        .chain_update(b":")
        .chain_update(username.as_bytes())
        .finalize()
        .into()
}

/// An address proof and the key it verifies under: the branch's purpose-0
/// index-0 public key, which a mint derives from the `cx1` alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressProof {
    pub signature: [u8; 64],
    pub pubkey: [u8; 32],
    pub branch: BranchKind,
}

/// Sign an address proof with a branch's purpose-0 index-0 key, aux_rand zero
/// as LUD-25 has a wallet sign everything, so the same request always gets the
/// same proof. Returns the signature and that key's public key.
pub fn sign_address_proof(
    node: &CashNode,
    action: AddressAction,
    domain: &str,
    username: &str,
) -> Result<([u8; 64], [u8; 32]), &'static str> {
    let secret = note_secret_key(node, PURPOSE_WALLET, 0)?;
    let pubkey = note_pubkey(&secret)?;
    let signature =
        backend::sign_bip340_zero_aux(&secret, &address_proof_digest(action, domain, username))?;
    Ok((signature, pubkey))
}

/// Which of this identity's branches at `host` is the one `cx1` names, and
/// the branch itself. Compared as decoded bytes, so an all-uppercase `cx1`
/// (valid bech32m) names the same branch as its lowercase spelling. Anything
/// else is refused: this device proves only for branches it holds.
fn branch_holding(identity_secret: &[u8; 32], host: &str, cx1: &str) -> Result<(BranchKind, CashNode), &'static str> {
    let (pubkey, chain_code) = crate::encoding::decode_cx1(cx1).ok_or("that is not a cx1")?;
    let named = Branch { pubkey, chain_code };
    let current = address_node(identity_secret, host)?;
    if branch_of(&current)? == named {
        return Ok((BranchKind::Current, current));
    }
    let superseded = superseded_address_node(identity_secret, host)?;
    if branch_of(&superseded)? == named {
        return Ok((BranchKind::Superseded, superseded));
    }
    Err("that cx1 is not one of this device's branches at that mint")
}

/// Which of this device's branches at `host` a `cx1` is, if either. For a
/// check made before anything is shown to the owner.
pub fn branch_kind_of(identity_secret: &[u8; 32], host: &str, cx1: &str) -> Result<BranchKind, &'static str> {
    branch_holding(identity_secret, host, cx1).map(|(kind, _)| kind)
}

/// The proof that the branch `cx1` names agrees to `action` for `username` at
/// the mint `host`, signed by whichever of this device's two branches at that
/// mint (current or superseded) it is.
///
/// The caller names the branch because LUD-25 wants the proof from the branch
/// on file, which only the caller knows and which may be the superseded one.
/// Any other `cx1` is refused rather than proven: a proof by a key this device
/// does not hold is not one it can make, and a proof by a key it does hold for
/// a branch the caller did not name is not the proof that was asked for.
///
/// `host` is the mint as [`address_node`] takes it (port included); the proof
/// is bound to its [`spend_domain`]. Never returns the key.
pub fn address_proof_for(
    identity_secret: &[u8; 32],
    host: &str,
    cx1: &str,
    action: AddressAction,
    username: &str,
) -> Result<AddressProof, &'static str> {
    if !valid_username(username) {
        return Err("a name is 3 to 32 of a-z, 0-9, dot, dash or underscore, starting with a letter or digit");
    }
    let (branch, node) = branch_holding(identity_secret, host, cx1)?;
    let (signature, pubkey) = sign_address_proof(&node, action, &spend_domain(host), username)?;
    Ok(AddressProof { signature, pubkey, branch })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::{cash_domain_indices, cash_node_to_bytes};
    use crate::encoding::encode_cp1;
    use crate::hex::{hex_decode, hex_encode};
    use serde_json::Value;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex_decode(text).expect("hex").try_into().expect("length")
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    fn check_notes(node: &CashNode, domain: &str, notes: &Value, label: &str) {
        let mut purposes = [false; 3];
        for note in notes.as_array().expect("notes") {
            let purpose = note["purpose"].as_u64().expect("purpose") as u32;
            let index = note["index"].as_u64().expect("index") as u32;
            purposes[purpose as usize] = true;
            let at = format!("{label} purpose {purpose} index {index}");
            let secret = note_secret_key(node, purpose, index).unwrap();
            assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{at} sk");
            let pubkey = note_pubkey(&secret).unwrap();
            assert_eq!(hex_encode(&pubkey), text(note, "notePubkey"), "{at} pk");
            assert_eq!(encode_cp1(&pubkey), text(note, "cp1"), "{at} cp1");
            assert_eq!(hex_encode(&key_path_sighash(domain, &pubkey)), text(note, "sighash"), "{at} sighash");
            let spend = key_path_spend(&secret, domain).unwrap();
            assert_eq!(hex_encode(&spend[32..]), text(note, "keyPathSignature"), "{at} signature");
            assert_eq!(encode_ck1(&spend), text(note, "ck1"), "{at} ck1");
        }
        // every purpose a vector set lists was reached, so none went untested
        assert_eq!(purposes, [true; 3], "{label}");
    }

    #[test]
    fn matches_the_part2_vectors() {
        // Eight branches, both parities, a host with a port, and indices up
        // to u32::MAX on purpose 0, then the first two of purposes 1 and 2.
        let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap();
        let branches = vectors["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 8);
        let mut odd_seen = false;
        let mut port_seen = false;
        for branch in branches {
            let host = text(branch, "host");
            let domain = text(branch, "domain");
            assert_eq!(spend_domain(host), domain, "{host}");
            port_seen |= host != domain;
            let seed = hex_decode(text(branch, "seedHex")).unwrap();
            let root = derive_cash_root(&seed).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&root).as_ref()), text(branch, "cashRoot"), "{host}");
            let indices: Vec<u64> = cash_domain_indices(&root, host).unwrap().iter().map(|&d| d as u64).collect();
            let want: Vec<u64> = branch["domainIndices"].as_array().unwrap().iter().map(|d| d.as_u64().unwrap()).collect();
            assert_eq!(indices, want, "{host}");
            let node = derive_cash_domain_node(&root, host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(branch, "addressNode"), "{host}");

            let (watched, odd) = watch(&node).unwrap();
            assert_eq!(hex_encode(&watched.pubkey), text(branch, "branchPubkey"), "{host}");
            assert_eq!(hex_encode(&watched.chain_code), text(branch, "chainCode"), "{host}");
            assert_eq!(odd, text(branch, "branchParity") == "odd", "{host}");
            odd_seen |= odd;
            assert_eq!(cx1_of(&node).unwrap(), text(branch, "cx1"), "{host}");

            check_notes(&node, domain, &branch["notes"], host);
        }
        // The negation is the easy thing to get wrong, and silent when wrong:
        // an odd branch must be in the set or it went untested. Likewise a
        // port, which the branch hashes and the spend domain drops.
        assert!(odd_seen);
        assert!(port_seen);
    }

    #[test]
    fn matches_the_nostr_seed_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/lud25-nostr-seed.json")).unwrap();
        for case in vectors["cases"].as_array().expect("cases") {
            let identity = unhex::<32>(text(case, "identity"));
            let host = text(case, "host");
            assert_eq!(spend_domain(host), text(case, "domain"), "{host}");
            assert_eq!(hex_encode(nostr_cash_seed(&identity).as_ref()), text(case, "seed"), "{host}");
            let node = address_node(&identity, host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(case, "addressNode"), "{host}");
            assert_eq!(cx1_of(&node).unwrap(), text(case, "cx1"), "{host}");
            check_notes(&node, text(case, "domain"), &case["notes"], host);
        }
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

    #[test]
    fn a_claim_checks_the_key_it_is_paid_to() {
        let identity = [7u8; 32];
        let la = PURPOSE_LIGHTNING_ADDRESS;
        let (secret, pubkey) = claim_note_key(&identity, "moneyer.dev", la, 3, None).unwrap();
        assert_eq!(note_pubkey(&secret).unwrap(), pubkey);
        assert!(claim_note_key(&identity, "moneyer.dev", la, 3, Some(&pubkey)).is_ok());
        // the next index, another purpose, another mint and another identity
        // are all other keys
        assert!(claim_note_key(&identity, "moneyer.dev", la, 4, Some(&pubkey)).is_err());
        assert!(claim_note_key(&identity, "moneyer.dev", PURPOSE_WALLET, 3, Some(&pubkey)).is_err());
        assert!(claim_note_key(&identity, "mint.example", la, 3, Some(&pubkey)).is_err());
        assert!(claim_note_key(&[8u8; 32], "moneyer.dev", la, 3, Some(&pubkey)).is_err());
    }

    #[test]
    fn a_claim_finds_a_note_paid_to_the_superseded_branch() {
        // A name registered with a cx1 from before LUD-25 50d740a: the mint
        // derives from that cx1 with today's purposed tweak.
        let identity = [7u8; 32];
        let old = superseded_address_node(&identity, "moneyer.dev").unwrap();
        assert_ne!(cx1_of(&old).unwrap(), cx1_of(&address_node(&identity, "moneyer.dev").unwrap()).unwrap());
        let paid = note_pubkey(&note_secret_key(&old, PURPOSE_LIGHTNING_ADDRESS, 0).unwrap()).unwrap();
        let (secret, pubkey) =
            claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 0, Some(&paid)).unwrap();
        assert_eq!(pubkey, paid);
        assert_eq!(note_pubkey(&secret).unwrap(), paid);
        // without the key named, a claim is on the current branch only
        let (_, unnamed) = claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 0, None).unwrap();
        assert_ne!(unnamed, paid);
        // and the superseded branch still answers only its own keys
        assert!(claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 1, Some(&paid)).is_err());
    }

    #[test]
    fn the_pre_purpose_ladder_derives_6e865b1s_keys() {
        // LUD-25 vectors 1 and 2's branches, at index 0 before purposes, as
        // lnurl/luds 6e865b1 gave them: what a mint paid before 50d740a.
        let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-taproot.json")).unwrap();
        for label in ["vector1", "vector2"] {
            let v = &vectors[label];
            let seed = hex_decode(text(v, "seed")).unwrap();
            let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), text(v, "domain")).unwrap();
            assert_eq!(cx1_of(&node).unwrap(), text(v, "cx1"), "{label}");
            let old = &v["prePurpose"];
            let index = old["index"].as_u64().unwrap() as u32;
            let sk = pre_purpose_secret_key(&node, index).unwrap();
            assert_eq!(hex_encode(sk.as_ref()), text(old, "sk"), "{label}");
            assert_eq!(hex_encode(&note_pubkey(&sk).unwrap()), text(old, "pk"), "{label}");
            // and it is on no purpose
            for purpose in [PURPOSE_WALLET, PURPOSE_CHANGE, PURPOSE_LIGHTNING_ADDRESS] {
                assert_ne!(note_secret_key(&node, purpose, index).unwrap().as_ref(), sk.as_ref(), "{label}");
            }
        }

        // And lnurlcash-conformance's prePurpose table, on the part2 branch
        // with the same cx1.
        let part2: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap();
        let old = &part2["prePurpose"];
        let branch = part2["branches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["cx1"] == old["cx1"])
            .expect("the prePurpose branch is one of part2's");
        let seed = hex_decode(text(branch, "seedHex")).unwrap();
        let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), text(old, "host")).unwrap();
        let notes = old["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 3);
        for note in notes {
            let index = note["index"].as_u64().unwrap() as u32;
            let sk = pre_purpose_secret_key(&node, index).unwrap();
            assert_eq!(hex_encode(sk.as_ref()), text(note, "noteSecretKey"), "part2 i {index}");
            let pk = note_pubkey(&sk).unwrap();
            assert_eq!(hex_encode(&pk), text(note, "notePubkey"), "part2 i {index}");
            assert_eq!(encode_cp1(&pk), text(note, "cp1"), "part2 i {index}");
        }
    }

    #[test]
    fn a_claim_finds_a_note_paid_on_the_pre_purpose_ladder() {
        // Paid to the superseded branch's cx1 by a mint from before purposes,
        // and never claimed: the wrap names the key, so the claim finds it.
        let identity = [7u8; 32];
        let old = superseded_address_node(&identity, "moneyer.dev").unwrap();
        let paid = note_pubkey(&pre_purpose_secret_key(&old, 3).unwrap()).unwrap();
        for purpose in [PURPOSE_LIGHTNING_ADDRESS, PURPOSE_WALLET] {
            let (_, on_purpose) = claim_note_key(&identity, "moneyer.dev", purpose, 3, None).unwrap();
            assert_ne!(on_purpose, paid);
        }
        let (secret, pubkey) =
            claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 3, Some(&paid)).unwrap();
        assert_eq!(pubkey, paid);
        assert_eq!(note_pubkey(&secret).unwrap(), paid);
        // Only with the key named, and only at its own index, mint and identity.
        let (_, unnamed) = claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 3, None).unwrap();
        assert_ne!(unnamed, paid);
        assert!(claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 4, Some(&paid)).is_err());
        assert!(claim_note_key(&identity, "mint.example", PURPOSE_LIGHTNING_ADDRESS, 3, Some(&paid)).is_err());
        assert!(claim_note_key(&[8u8; 32], "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 3, Some(&paid)).is_err());
        // The current branch was never on the old ladder.
        let current = address_node(&identity, "moneyer.dev").unwrap();
        let never = note_pubkey(&pre_purpose_secret_key(&current, 3).unwrap()).unwrap();
        assert!(claim_note_key(&identity, "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 3, Some(&never)).is_err());
    }

    #[test]
    fn a_ck1_is_bound_to_its_mint() {
        let (secret, _) = claim_note_key(&[7u8; 32], "moneyer.dev", PURPOSE_LIGHTNING_ADDRESS, 0, None).unwrap();
        let here = ck1_of(&secret, "moneyer.dev/w").unwrap();
        // the endpoint path and a port do not change the domain
        assert_eq!(here, ck1_of(&secret, "moneyer.dev").unwrap());
        assert_eq!(here, ck1_of(&secret, "moneyer.dev:443/w").unwrap());
        assert_ne!(here, ck1_of(&secret, "mint.example/w").unwrap());
    }

    #[test]
    fn a_branch_is_per_mint_and_per_identity() {
        let a = cx1_of(&address_node(&[7u8; 32], "moneyer.dev").unwrap()).unwrap();
        let b = cx1_of(&address_node(&[7u8; 32], "moneyer.dev:443").unwrap()).unwrap();
        let c = cx1_of(&address_node(&[8u8; 32], "moneyer.dev").unwrap()).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn matches_the_address_proof_vectors() {
        // Four proofs by the purpose-0 index-0 key of the first part2 branch
        // (mint.example): register and unregister for alice, register for bob,
        // and alice again at another domain.
        let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap();
        let branch = &vectors["branches"][0];
        let host = text(branch, "host");
        let root = derive_cash_root(&hex_decode(text(branch, "seedHex")).unwrap()).unwrap();
        let node = derive_cash_domain_node(&root, host).unwrap();
        let proofs = vectors["addressProofs"].as_array().expect("addressProofs");
        assert_eq!(proofs.len(), 4);
        let mut seen = (false, false, false);
        for proof in proofs {
            let action = AddressAction::parse(text(proof, "action")).expect("action");
            let domain = text(proof, "domain");
            let username = text(proof, "username");
            let at = format!("{} {domain} {username}", action.as_str());
            assert!(valid_username(username), "{at}");
            assert_eq!(
                format!("LNURLcash:{}:{domain}:{username}", action.as_str()),
                text(proof, "message"),
                "{at}"
            );
            assert_eq!(hex_encode(&address_proof_digest(action, domain, username)), text(proof, "digest"), "{at}");
            // The key is the branch's own purpose-0 index-0 note key.
            let secret = note_secret_key(&node, PURPOSE_WALLET, 0).unwrap();
            assert_eq!(hex_encode(secret.as_ref()), text(proof, "indexZeroSecretKey"), "{at}");
            // aux_rand zero reproduces the published signature exactly.
            let (signature, pubkey) = sign_address_proof(&node, action, domain, username).unwrap();
            assert_eq!(hex_encode(&pubkey), text(proof, "indexZeroPubkey"), "{at}");
            assert_eq!(hex_encode(&signature), text(proof, "signature"), "{at}");
            seen.0 |= action == AddressAction::Unregister;
            seen.1 |= username != "alice";
            seen.2 |= domain != host;
        }
        // Each thing the message separates was in the set.
        assert_eq!(seen, (true, true, true));
    }

    #[test]
    fn an_address_proof_is_signed_by_the_branch_named() {
        let identity = [7u8; 32];
        let host = "moneyer.dev";
        let current = address_node(&identity, host).unwrap();
        let old = superseded_address_node(&identity, host).unwrap();
        for (node, kind) in [(&current, BranchKind::Current), (&old, BranchKind::Superseded)] {
            let cx1 = cx1_of(node).unwrap();
            for action in [AddressAction::Register, AddressAction::Unregister] {
                let proof = address_proof_for(&identity, host, &cx1, action, "alice").unwrap();
                assert_eq!(proof.branch, kind);
                let (signature, pubkey) = sign_address_proof(node, action, "moneyer.dev", "alice").unwrap();
                assert_eq!((proof.signature, proof.pubkey), (signature, pubkey));
                assert_eq!(pubkey, note_pubkey(&note_secret_key(node, PURPOSE_WALLET, 0).unwrap()).unwrap());
                // never a key note's key: that is purpose 2, and a different key
                assert_ne!(
                    pubkey,
                    note_pubkey(&note_secret_key(node, PURPOSE_LIGHTNING_ADDRESS, 0).unwrap()).unwrap()
                );
            }
            // all-uppercase bech32m is the same cx1
            let upper = address_proof_for(&identity, host, &cx1.to_ascii_uppercase(), AddressAction::Register, "alice");
            assert_eq!(upper.unwrap().branch, kind);
            assert_eq!(branch_kind_of(&identity, host, &cx1), Ok(kind));
        }
        let cx1 = cx1_of(&current).unwrap();
        let register = address_proof_for(&identity, host, &cx1, AddressAction::Register, "alice").unwrap();
        // deterministic
        assert_eq!(register, address_proof_for(&identity, host, &cx1, AddressAction::Register, "alice").unwrap());
        // the action, the name and the mint's domain are all in what is signed
        let unregister = address_proof_for(&identity, host, &cx1, AddressAction::Unregister, "alice").unwrap();
        assert_ne!(register.signature, unregister.signature);
        let bob = address_proof_for(&identity, host, &cx1, AddressAction::Register, "bob").unwrap();
        assert_ne!(register.signature, bob.signature);
        // a port is in the branch, not in the domain: the same mint behind a
        // port is another branch, but its proof is bound to the bare hostname
        let ported = address_node(&identity, "moneyer.dev:8443").unwrap();
        let ported_cx1 = cx1_of(&ported).unwrap();
        let proof = address_proof_for(&identity, "moneyer.dev:8443", &ported_cx1, AddressAction::Register, "alice").unwrap();
        assert_eq!(
            (proof.signature, proof.pubkey),
            sign_address_proof(&ported, AddressAction::Register, "moneyer.dev", "alice").unwrap()
        );
    }

    #[test]
    fn an_address_proof_refuses_a_branch_this_device_does_not_hold() {
        let identity = [7u8; 32];
        let ours = cx1_of(&address_node(&identity, "moneyer.dev").unwrap()).unwrap();
        let theirs = cx1_of(&address_node(&[8u8; 32], "moneyer.dev").unwrap()).unwrap();
        let other_mint = cx1_of(&address_node(&identity, "mint.example").unwrap()).unwrap();
        let reg = AddressAction::Register;
        // another identity's branch, and our own branch at another mint
        assert!(address_proof_for(&identity, "moneyer.dev", &theirs, reg, "alice").is_err());
        assert!(address_proof_for(&identity, "moneyer.dev", &other_mint, reg, "alice").is_err());
        assert!(branch_kind_of(&identity, "moneyer.dev", &theirs).is_err());
        // not a cx1 at all, or a mixed-case one (invalid bech32m)
        let mixed = format!("{}{}", &ours[..10], ours[10..].to_ascii_uppercase());
        for bad in ["", "cx1", "cp1qqqq", mixed.as_str()] {
            assert!(address_proof_for(&identity, "moneyer.dev", bad, reg, "alice").is_err(), "{bad}");
        }
        // names outside the rule
        for name in ["al", "Alice", "_alice", "al:ce", "a".repeat(33).as_str(), "alice@x", ""] {
            assert!(address_proof_for(&identity, "moneyer.dev", &ours, reg, name).is_err(), "{name}");
        }
        assert!(address_proof_for(&identity, "moneyer.dev", &ours, reg, &"a".repeat(32)).is_ok());
    }

    #[test]
    fn the_username_rule_is_the_mints() {
        for good in ["abc", "0ab", "a.b", "a-b", "a_b", "alice", &"z".repeat(32)] {
            assert!(valid_username(good), "{good}");
        }
        for bad in ["", "ab", ".ab", "-ab", "_ab", "Abc", "abC", "a b", "a:b", "a/b", "é12", &"z".repeat(33)] {
            assert!(!valid_username(bad), "{bad}");
        }
        assert_eq!(AddressAction::parse("register"), Some(AddressAction::Register));
        assert_eq!(AddressAction::parse("unregister"), Some(AddressAction::Unregister));
        for bad in ["", "Register", "clear", "register "] {
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
