//! LUD-25 Part 2 on this device: notes paid to its own keys.
//!
//! A key note is a taproot output key `Q` that is simply the note key's own
//! public key. Its holder keeps the key, the mint only ever learns
//! `cp1<Q>`, and the note is spent with a `ck1`: `Q` and a BIP-340 signature
//! over the canonical spend's key-path sighash for that one mint
//! ([`crate::taproot`]). A mint that holds a watch-only `cx1` for a lightning
//! address mints each payment straight to the holder's next key, so the gift
//! wrap that tells the holder about it carries no secret at all, only where
//! to look and at which index.
//!
//! **Where this device's receiving keys come from.** A lightning address on a
//! Nostr-native mint belongs to an npub: the key that signed the registration
//! owns the name, and payments are wrapped to it. That key lives here and
//! never leaves, so it is the root:
//!
//! ```text
//! seed   = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//! branch = m/139'/1'/d1/d2/d3/d4 from that seed, d1..d4 from HMAC-SHA256(m/139'/1'/0, host)
//! t      = tagged_hash("LNURLcash/derive", P || chainCode || ser32(purpose) || ser32(i))  (mod n)
//! sk_i   = (P has even y ? p : n - p) + t   (mod n)
//! ck1    = Q || BIP-340(sk_i, key_path_sighash(Q, mint domain), aux_rand = 0),  Q = x(sk_i·G)
//! ```
//!
//! **Purposes.** LUD-25 splits each branch into three counters: purpose 0
//! for the wallet's own notes (and the index-0 key that signs a lightning
//! address registration), 1 for split change, and 2 for what a mint credits
//! to a lightning address, auto-mint and internal transfer alike. This device
//! is paid on purpose 2. Before purposes the tweak had no `ser32(purpose)` in
//! it at all, and a mint has already paid notes to keys on that ladder, so
//! it is kept as [`KeyLadder::PrePurpose`] and a claim tries it after
//! purpose 2 (see [`claim_note_key`]).
//!
//! The first line is this device's own, and the only one. Everything below it
//! is lnurlcash-kit's address path and LUD-25's tweak exactly, so the kit's
//! `deriveCashRoot` and `deriveCashAddressNode`, handed this seed, find every
//! note. LUD-25 and lnurl-wallet now root the branch one level higher, at
//! `m/139'/d1..d4` with its hashing key at `m/139'/0`; the `1'` here predates
//! that and is kept, since moving it would move every key note already
//! paid. It changes nothing a mint sees: a mint derives from the `cx1`, not
//! from the path. It exists because this device never
//! holds a BIP-32 master (see [`crate::cash`]): what it holds is the identity
//! key, which the owner's recovery phrase already backs up. So these notes come
//! back from the heartwood's phrase, and nothing paired with the device can
//! spend them without it.
//!
//! HMAC keyed by the secret with a fixed label is the shape
//! [`crate::derive::nsec_to_tree_root`] already uses. The label is not an
//! nsec-tree message (those all start `nsec-tree`), so the seed is never a key
//! nsec-tree hands out as an identity.
//!
//! Graded in the tests below against lnurlcash-kit's `part2.json` (generated
//! from lnurl-wallet, checked against lnurl-mint) and against vectors the kit
//! computed for the seed step, `tests/fixtures/lud25-nostr-seed.json`.

use alloc::string::String;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cash::{derive_cash_child, derive_cash_domain_node, derive_cash_root, CashNode};
use crate::derive::backend;
use crate::encoding::{encode_ck1, encode_cx1, encode_legacy_ck1};
use crate::taproot::{key_path_sighash, tagged_hash};

type HmacSha256 = Hmac<Sha256>;

/// What the seed step hashes, keyed by the identity's secret.
pub const NOSTR_SEED_LABEL: &[u8] = b"LNURLcash/nostr-seed";

/// `m/139'/1'`: lnurl-wallet's address branches, beside `m/139'/d1..d4`, the
/// Part 1 ladder. Kept apart so a SERVICE holding a `cx1` can link the
/// payments made to it and nothing else.
const ADDRESS_BRANCH: u32 = 1 | 0x8000_0000;

const NOTE_DERIVE_TAG: &[u8] = b"LNURLcash/derive";

/// LUD-25's purpose 0: the wallet's own notes, and the index-0 key a
/// lightning address registration proof is signed with.
pub const PURPOSE_WALLET: u32 = 0;
/// LUD-25's purpose 1: a split's change note.
pub const PURPOSE_CHANGE: u32 = 1;
/// LUD-25's purpose 2: what a mint credits to a lightning address, whether
/// a payment arrived there (auto-mint) or another wallet on the same mint
/// transferred to it. The purpose this device is paid on.
pub const PURPOSE_ADDRESS: u32 = 2;

/// Which of a branch's derivations a key sits on.
///
/// LUD-25 splits a branch into independent counters by purpose (0 wallet,
/// 1 change, 2 lightning address) and hashes `ser32(purpose)` in ahead of
/// the index. This firmware derived keys before that, with no purpose in the
/// hash at all, and a mint has paid notes to those keys, so that ladder is a
/// value of its own here rather than a purpose number nobody uses.
///
/// A stored key note does not record it: the key is the stored secret, so
/// nothing needs it to spend, and trying [`CLAIM_LADDERS`] against the note's
/// public key recovers it if anything ever does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLadder {
    /// `t = tagged_hash("LNURLcash/derive", P || chaincode || ser32(i))`:
    /// every key note this firmware claimed before purposes.
    PrePurpose,
    /// `t = tagged_hash("LNURLcash/derive", P || chaincode || ser32(purpose) || ser32(i))`.
    Purpose(u32),
}

/// Where a claim looks for the key a note is paid to, in order: the purpose
/// a mint pays a name on today, then the ladder it paid on before purposes.
pub const CLAIM_LADDERS: [KeyLadder; 2] = [KeyLadder::Purpose(PURPOSE_ADDRESS), KeyLadder::PrePurpose];

/// The fixed message the deprecated recoverable `ck1` signed
/// ([`legacy_ck1_of`]). A spend now signs the canonical transaction instead.
pub const OWNERSHIP_MESSAGE: &[u8] = b"LNURLcash";

/// The seed a Nostr identity's address branches hang off.
pub fn nostr_cash_seed(identity_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(identity_secret).expect("HMAC accepts any key length");
    mac.update(NOSTR_SEED_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `m/139'/1'` under a BIP-32 seed.
pub fn address_root(seed: &[u8]) -> Result<CashNode, &'static str> {
    derive_cash_child(&derive_cash_root(seed)?, ADDRESS_BRANCH)
}

/// One mint's address branch for a Nostr identity: bearer material for every
/// note ever paid to it, so it stays on this device. Hand out [`cx1_of`].
///
/// `host` is the mint as a wallet spells it (see [`crate::cash`]): lowercase,
/// port included, no scheme and no path.
pub fn address_node(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
    let seed = nostr_cash_seed(identity_secret);
    derive_cash_domain_node(&address_root(seed.as_ref())?, host)
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

fn note_tweak(branch: &Branch, ladder: KeyLadder, index: u32) -> [u8; 32] {
    let index = index.to_be_bytes();
    reduce_mod_n(match ladder {
        KeyLadder::PrePurpose => tagged_hash(NOTE_DERIVE_TAG, &[&branch.pubkey, &branch.chain_code, &index]),
        KeyLadder::Purpose(purpose) => tagged_hash(
            NOTE_DERIVE_TAG,
            &[&branch.pubkey, &branch.chain_code, &purpose.to_be_bytes(), &index],
        ),
    })
}

/// secp256k1's group order n, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `t mod n`, as the spec requires and lnurl-wallet does (lnurl-mint refuses
/// `t >= n` instead; at ~2^-128 the two never meet). A 32-byte value is below
/// 2n, so one subtraction reduces it. Done here rather than in a backend, so
/// all three agree.
fn reduce_mod_n(t: [u8; 32]) -> [u8; 32] {
    if t < CURVE_ORDER {
        return t;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let d = 0x100 + u16::from(t[i]) - u16::from(CURVE_ORDER[i]) - borrow;
        out[i] = d as u8;
        borrow = u16::from(d < 0x100);
    }
    out
}

/// The key of note `index` on one of a branch's ladders. `index` is any
/// uint32 and is never hardened: a watcher holding only the `cx1` derives
/// the matching public key at every index on every purpose, which is the
/// point of the scheme.
///
/// The branch key is negated first when its point has odd y, because the `cx1`
/// carries only x and x names the even-y point. Skipping that would give a key
/// whose public key is not the one the mint minted to.
pub fn note_secret_key(
    node: &CashNode,
    ladder: KeyLadder,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let (branch, odd) = watch(node)?;
    let tweak = note_tweak(&branch, ladder, index);
    let base = if odd {
        Zeroizing::new(backend::negate(&node.private_key)?)
    } else {
        Zeroizing::new(node.private_key)
    };
    // the tweak is already below n, so tweak_add refuses only a zero sum, a
    // ~2^-128 event whose answer is the next index
    backend::tweak_add(&base, &tweak)
        .map(Zeroizing::new)
        .map_err(|_| "this note index is unusable on this branch")
}

/// `x(sk * G)`: the note's `Q` (a key note takes no BIP-86 tweak), what the
/// mint files it under, and what its `cp1` encodes.
pub fn note_pubkey(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    backend::pubkey_from_secret(secret)
}

/// The note's bearer credential at one mint: what a wallet presents as `k1`
/// to spend it there. Disclosing it is disclosing the note, exactly as a
/// bearer note's preimage is.
///
/// `Q || sig`, 96 bytes: a BIP-340 signature by the note's key over the
/// canonical spend's key-path sighash, whose prevout binds `mint`'s domain.
/// So a `ck1` one mint has seen is refused at every other, and `aux_rand`
/// is all zeros, so the same key and mint always give the same string: a key
/// re-derived from the seed spends its note with nothing else stored.
///
/// `mint` is the note's withdraw endpoint as the locker keeps it
/// (`moneyer.dev/w`, with any port and path), or the bare domain; [`spend_domain`]
/// takes it down to the hostname the signature binds.
pub fn ck1_of(secret: &[u8; 32], mint: &str) -> Result<String, &'static str> {
    let domain = spend_domain(mint);
    if domain.is_empty() {
        return Err("a ck1 is bound to a mint, and this note names none");
    }
    let output_key = note_pubkey(secret)?;
    let mut signature = backend::sign_bip340(secret, &key_path_sighash(&output_key, domain))?;
    let ck1 = encode_ck1(&output_key, &signature);
    zeroize::Zeroize::zeroize(&mut signature);
    Ok(ck1)
}

fn ownership_digest() -> [u8; 32] {
    let inner = Sha256::new()
        .chain_update(b"Lightning Signed Message:")
        .chain_update(OWNERSHIP_MESSAGE)
        .finalize();
    Sha256::digest(inner).into()
}

/// The deprecated ownership proof, `r || s || recovery id` over the fixed
/// Lightning message: what [`legacy_ck1_of`] encodes.
pub fn ownership_signature(secret: &[u8; 32]) -> Result<[u8; 65], &'static str> {
    backend::sign_recoverable(secret, &ownership_digest())
}

/// The 65-byte recoverable `ck1` this device emitted before spends were
/// bound to a mint. Bound to none, and deprecated; mints following the
/// reference still accept it, so every one already handed out stays
/// redeemable. Nothing on the device's own paths makes one any more. It is
/// kept because it is what a mint that predates the domain-bound form
/// accepts, and so the notes spent with it can be reproduced from the key.
pub fn legacy_ck1_of(secret: &[u8; 32]) -> Result<String, &'static str> {
    let mut signature = ownership_signature(secret)?;
    let ck1 = encode_legacy_ck1(&signature);
    zeroize::Zeroize::zeroize(&mut signature);
    Ok(ck1)
}

/// The mint a note's withdraw endpoint belongs to: `moneyer.dev/w` is at
/// `moneyer.dev`. The locker stores the endpoint; a branch is per mint.
pub fn branch_host(note_host: &str) -> &str {
    note_host.split('/').next().unwrap_or(note_host)
}

/// The domain a spend of a note at `note_host` is bound to: the bare
/// hostname, never the scheme, the port or the path (lnurl-wallet's
/// `spendDomainOf`, which is `new URL(..).hostname`). Not lowercased here;
/// [`crate::taproot::spend_prevout`] does that.
///
/// Not [`branch_host`], which keeps the port. The branch a key sits on is
/// named by host and port as a wallet spells it (lnurl-wallet's `serverOf`),
/// while a spend binds the hostname alone, so a mint on a non-default port
/// derives by one string and signs by another. Both are LUD-25's choices.
pub fn spend_domain(note_host: &str) -> &str {
    let rest = note_host.split_once("://").map_or(note_host, |(_, rest)| rest);
    let authority = rest.split(&['/', '?', '#'][..]).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if host.starts_with('[') {
        // An IPv6 literal keeps its brackets, as a URL's hostname does.
        return host.find(']').map_or(host, |end| &host[..=end]);
    }
    host.split(':').next().unwrap_or(host)
}

/// What a registration proof authorises: LUD-25 has a mint register or
/// unregister a lightning-address username against a `cx1` only on a proof
/// from that branch, never on an assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressAction {
    Register,
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

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Unregister => "unregister",
        }
    }
}

/// Longest username the device signs a proof for. LUD-16 sets no limit; this
/// is a bound on what an approval card has to show, not a mint's rule.
pub const MAX_USERNAME_LEN: usize = 64;

/// A username the device will sign a proof for: LUD-16's alphabet
/// (`a-z0-9-_.`) and nothing else. That keeps the signed message the fixed
/// `LNURLcash:<action>:<domain>:<username>`: with a `:` allowed in a name,
/// one message could be read as another.
pub fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_LEN
        && username
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// `sha256("LNURLcash:" || action || ":" || domain || ":" || username)`, the
/// digest a registration proof signs. `domain` is the mint's bare lowercase
/// hostname, which is what stops a proof one mint has seen being replayed at
/// another.
pub fn address_proof_digest(action: AddressAction, domain: &str, username: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"LNURLcash:")
        .chain_update(action.as_str())
        .chain_update(b":")
        .chain_update(domain)
        .chain_update(b":")
        .chain_update(username)
        .finalize()
        .into()
}

/// A BIP-340 signature by a branch's purpose-0 index-0 key over
/// [`address_proof_digest`], with a zero `aux_rand` like every other
/// signature here. Takes the fixed message's parts, never a digest, so
/// nothing that reaches this can have it sign anything else.
pub fn sign_address_proof(
    index_zero_secret: &[u8; 32],
    action: AddressAction,
    domain: &str,
    username: &str,
) -> Result<[u8; 64], &'static str> {
    if domain.is_empty() || !valid_username(username) {
        return Err("a registration proof needs a mint domain and a lightning-address username");
    }
    backend::sign_bip340(index_zero_secret, &address_proof_digest(action, domain, username))
}

/// The proof the served identity's branch at `host` gives for `action` on
/// `username`: what a mint requires before it registers the name against
/// that branch's `cx1` (the one [`cx1_of`] hands out for the same `host`), or
/// unregisters it. Signed by the key at index 0 on [`PURPOSE_WALLET`], the
/// `pk_0` a mint derives from that `cx1`, as LUD-25 says; never by a key on
/// the purpose the name is paid on.
///
/// `host` names the branch as `address_node` does, port and all; the proof
/// binds its bare hostname ([`spend_domain`]), lowercased, as LUD-25 says.
pub fn address_proof(
    identity_secret: &[u8; 32],
    host: &str,
    action: AddressAction,
    username: &str,
) -> Result<[u8; 64], &'static str> {
    let domain = spend_domain(host).to_ascii_lowercase();
    let node = address_node(identity_secret, host)?;
    let index_zero = note_secret_key(&node, KeyLadder::Purpose(PURPOSE_WALLET), 0)?;
    sign_address_proof(&index_zero, action, &domain, username)
}

/// A key a claim found: the key, its public key, and the ladder it is on.
pub struct ClaimedKey {
    pub secret: Zeroizing<[u8; 32]>,
    pub pubkey: [u8; 32],
    pub ladder: KeyLadder,
}

/// The key at `index` on one ladder of a branch.
fn key_at(node: &CashNode, ladder: KeyLadder, index: u32) -> Result<ClaimedKey, &'static str> {
    let secret = note_secret_key(node, ladder, index)?;
    let pubkey = note_pubkey(&secret)?;
    Ok(ClaimedKey { secret, pubkey, ladder })
}

/// The key a note paid to `identity` at `index` answers to, checked against
/// the public key the note is said to be minted to.
///
/// This is the whole of what a device that cannot reach the mint can know: a
/// wrap naming a key this device does not hold is refused here, before any
/// card is drawn, rather than kept as money that is not ours.
///
/// A mint pays a name on [`PURPOSE_ADDRESS`], and before purposes it paid on
/// [`KeyLadder::PrePurpose`], whose notes are still ours. A payment says only
/// `index` and the key, never which ladder, so with `expected` both are
/// tried, purpose 2 first, and the one whose key matches is the claim; a key
/// on neither is refused. The two cannot both match: that would be two
/// tagged hashes colliding.
///
/// The key is required: without it there is nothing to tell the ladders
/// apart, and a claim would store whatever key it derived whether or not
/// anything was paid to it. Every wrap names it, and so does the one client
/// that claims (notecase's scan).
pub fn claim_note_key(
    identity_secret: &[u8; 32],
    host: &str,
    index: u32,
    expected: &[u8; 32],
) -> Result<ClaimedKey, &'static str> {
    let node = address_node(identity_secret, host)?;
    for ladder in CLAIM_LADDERS {
        // An index unusable on one ladder (a ~2^-128 zero sum) says nothing
        // about the other.
        let Ok(found) = key_at(&node, ladder, index) else { continue };
        if found.pubkey == *expected {
            return Ok(found);
        }
    }
    Err("that note is paid to a key this device does not hold")
}

/// The public key at `index` on one ladder of `identity`'s branch at `host`,
/// as a mint derives it from the `cx1`. What a claim is checked against.
pub fn paid_to(identity_secret: &[u8; 32], host: &str, ladder: KeyLadder, index: u32) -> Result<[u8; 32], &'static str> {
    let secret = note_secret_key(&address_node(identity_secret, host)?, ladder, index)?;
    note_pubkey(&secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::cash_node_to_bytes;
    use crate::encoding::{encode_cp1, Ck1};
    use crate::hex::{hex_decode, hex_encode};
    use serde_json::Value;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex_decode(text).expect("hex").try_into().expect("length")
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    /// The kit's part2 and nostr-seed fixtures predate purposes: every note
    /// in them is on the pre-purpose ladder, which is what keeps it tested.
    fn check_notes(node: &CashNode, notes: &Value, label: &str) {
        for note in notes.as_array().expect("notes") {
            let index = note["index"].as_u64().expect("index") as u32;
            let secret = note_secret_key(node, KeyLadder::PrePurpose, index).unwrap();
            assert_eq!(hex_encode(secret.as_ref()), text(note, "noteSecretKey"), "{label} sk {index}");
            let pubkey = note_pubkey(&secret).unwrap();
            assert_eq!(hex_encode(&pubkey), text(note, "notePubkey"), "{label} pk {index}");
            assert_eq!(encode_cp1(&pubkey), text(note, "cp1"), "{label} cp1 {index}");
            if let Some(signature) = note.get("ownershipSignature").and_then(Value::as_str) {
                assert_eq!(
                    hex_encode(&ownership_signature(&secret).unwrap()),
                    signature,
                    "{label} signature {index}"
                );
            }
            // These fixtures predate spends bound to a mint: their ck1 is the
            // recoverable shape, which a key re-derived today still makes.
            assert_eq!(legacy_ck1_of(&secret).unwrap(), text(note, "ck1"), "{label} ck1 {index}");
            // Today's ck1 names the same key the note is filed under.
            match crate::encoding::decode_ck1(&ck1_of(&secret, "mint.example").unwrap()) {
                Some(Ck1::KeyPath { output_key, .. }) => assert_eq!(output_key, pubkey, "{label} Q {index}"),
                other => panic!("{label} {index}: not a key-path ck1: {other:?}"),
            }
        }
    }

    fn taproot_vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/lud25-taproot.json")).unwrap()
    }

    /// The spec's branch for one of vectors 1 and 2: `m/139'/d1..d4` from a
    /// BIP-32 seed, which cash.rs derives. The address path above is the
    /// same walk one level lower (`m/139'/1'`), so these are also the check
    /// that nothing but that hop differs from the spec.
    fn spec_branch(v: &Value, odd_y: bool) -> CashNode {
        let seed = hex_decode(text(v, "seed")).unwrap();
        let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), text(v, "domain")).unwrap();
        let (branch, odd) = watch(&node).unwrap();
        assert_eq!(hex_encode(&branch.pubkey), text(v, "branchPubkey"));
        assert_eq!(hex_encode(&branch.chain_code), text(v, "chainCode"));
        assert_eq!(cx1_of(&node).unwrap(), text(v, "cx1"));
        assert_eq!(odd, odd_y, "the vector's branch parity");
        node
    }

    /// Every note in a spec vector's table, on its purpose: the tweak, `Q`
    /// in full, `pk`, `sk` and `cp1`.
    fn check_spec_notes(node: &CashNode, v: &Value, label: &str) -> usize {
        let (branch, _) = watch(node).unwrap();
        let notes = v["notes"].as_array().expect("notes");
        for note in notes {
            let purpose = note["purpose"].as_u64().expect("purpose") as u32;
            let index = note["index"].as_u64().expect("index") as u32;
            let ladder = KeyLadder::Purpose(purpose);
            let at = format!("{label} purpose {purpose} i {index}");
            assert_eq!(hex_encode(&note_tweak(&branch, ladder, index)), text(note, "tweak"), "{at} t");
            let sk = note_secret_key(node, ladder, index).unwrap();
            assert_eq!(hex_encode(sk.as_ref()), text(note, "sk"), "{at} sk");
            let pk = note_pubkey(&sk).unwrap();
            assert_eq!(hex_encode(&pk), text(note, "pk"), "{at} pk");
            assert_eq!(encode_cp1(&pk), text(note, "cp1"), "{at} cp1");
            // Q in full is lift_x(P) + t·G, from the cx1 alone: what a watcher
            // and a mint derive, and it names the same x.
            let q = backend::compressed_pubkey(&sk).unwrap();
            assert_eq!(hex_encode(&q), text(note, "q"), "{at} Q");
            let (watched, _) = backend::xonly_tweak_add(&branch.pubkey, &note_tweak(&branch, ladder, index)).unwrap();
            assert_eq!(watched, pk, "{at} watched");
        }
        notes.len()
    }

    #[test]
    fn matches_the_specs_purposed_derivation() {
        // LUD-25 test vectors 1 (odd-y branch, purposes 0, 1 and 2) and 2
        // (even-y branch, purpose 0), every value in their tables.
        let vectors = taproot_vectors();
        let v1 = &vectors["vector1"];
        assert_eq!(check_spec_notes(&spec_branch(v1, true), v1, "vector 1"), 6);
        let v2 = &vectors["vector2"];
        assert_eq!(check_spec_notes(&spec_branch(v2, false), v2, "vector 2"), 3);
        // The table covers all three purposes at index 0.
        let purposes: Vec<u64> = v1["notes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["index"] == 0)
            .map(|n| n["purpose"].as_u64().unwrap())
            .collect();
        assert_eq!(purposes, [PURPOSE_WALLET, PURPOSE_CHANGE, PURPOSE_ADDRESS].map(u64::from));
    }

    #[test]
    fn the_pre_purpose_ladder_still_derives_its_old_keys() {
        // The same two branches' index-0 keys as LUD-25 6e865b1 gave them,
        // before purposes: what every key note this firmware stored before
        // now was derived on, and what a mint already paid.
        let vectors = taproot_vectors();
        for (label, odd) in [("vector1", true), ("vector2", false)] {
            let v = &vectors[label];
            let old = &v["prePurpose"];
            let node = spec_branch(v, odd);
            let index = old["index"].as_u64().unwrap() as u32;
            let sk = note_secret_key(&node, KeyLadder::PrePurpose, index).unwrap();
            assert_eq!(hex_encode(sk.as_ref()), text(old, "sk"), "{label}");
            assert_eq!(hex_encode(&note_pubkey(&sk).unwrap()), text(old, "pk"), "{label}");
            // and it is on no purpose: purpose 0 at the same index is another key
            let purposed = note_secret_key(&node, KeyLadder::Purpose(PURPOSE_WALLET), index).unwrap();
            assert_ne!(purposed.as_ref(), sk.as_ref(), "{label}");
        }
    }

    #[test]
    fn matches_the_specs_key_path_spend() {
        // LUD-25 test vector 3: vector 1's purpose-0 index-0 key, and that
        // key's ck1 at mint.example.
        let vectors = taproot_vectors();
        let (v1, v3) = (&vectors["vector1"], &vectors["vector3"]);
        let node = spec_branch(v1, true);
        let sk = note_secret_key(&node, KeyLadder::Purpose(PURPOSE_WALLET), 0).unwrap();
        assert_eq!(hex_encode(sk.as_ref()), text(v3, "sk"));
        assert_eq!(hex_encode(&note_pubkey(&sk).unwrap()), text(v3, "outputKey"));

        let ck1 = ck1_of(&sk, text(v3, "domain")).unwrap();
        assert_eq!(ck1, text(v3, "ck1"));
        // The same key signs the same ck1 every time (zero aux_rand)...
        assert_eq!(ck1_of(&sk, text(v3, "domain")).unwrap(), ck1);
        // ...and the same one from the endpoint the locker stores, whatever
        // its path, port or case: only the hostname is signed.
        for mint in ["mint.example/w", "mint.example:8443/w", "https://Mint.Example/w?x=1", "MINT.EXAMPLE"] {
            assert_eq!(ck1_of(&sk, mint).unwrap(), ck1, "{mint}");
        }
        // Another mint is another ck1, and no mint is no ck1.
        assert_ne!(ck1_of(&sk, "moneyer.dev/w").unwrap(), ck1);
        assert!(ck1_of(&sk, "").is_err());
        assert!(ck1_of(&sk, "/w").is_err());
    }

    #[test]
    fn matches_the_specs_registration_proof() {
        // LUD-25 test vector 2: the even-y branch at cash.example.com, its
        // purpose-0 index-0 key, and that key's register and unregister
        // proofs for "alice".
        let vectors = taproot_vectors();
        let v = &vectors["vector2"];
        let node = spec_branch(v, false);
        let sk0 = note_secret_key(&node, KeyLadder::Purpose(PURPOSE_WALLET), 0).unwrap();
        let first = &v["notes"][0];
        assert_eq!((first["purpose"].as_u64(), first["index"].as_u64()), (Some(0), Some(0)));
        assert_eq!(hex_encode(sk0.as_ref()), text(first, "sk"));

        let (domain, name) = (text(v, "proofDomain"), text(v, "username"));
        for (action, message, digest, sig) in [
            (AddressAction::Register, "registerMessage", "registerDigest", "registerSig"),
            (AddressAction::Unregister, "unregisterMessage", "unregisterDigest", "unregisterSig"),
        ] {
            assert_eq!(
                format!("LNURLcash:{}:{domain}:{name}", action.as_str()),
                text(v, message)
            );
            assert_eq!(hex_encode(&address_proof_digest(action, domain, name)), text(v, digest));
            assert_eq!(
                hex_encode(&sign_address_proof(&sk0, action, domain, name).unwrap()),
                text(v, sig),
                "{message}"
            );
        }
    }

    #[test]
    fn a_registration_proof_signs_only_its_fixed_message() {
        let identity = [7u8; 32];
        let proof = |host: &str, action, name: &str| address_proof(&identity, host, action, name);
        let register = proof("moneyer.dev", AddressAction::Register, "alice").unwrap();
        // It is the branch's purpose-0 index-0 key over the fixed message for
        // the bare hostname: the key the mint derives pk_0 from the cx1 with.
        let wallet = KeyLadder::Purpose(PURPOSE_WALLET);
        let sk0 = note_secret_key(&address_node(&identity, "moneyer.dev").unwrap(), wallet, 0).unwrap();
        assert_eq!(
            register,
            sign_address_proof(&sk0, AddressAction::Register, "moneyer.dev", "alice").unwrap()
        );
        // The mint checks it against pk_0, which it derives from the cx1
        // alone, lift_x(P) + t_0·G: this key's public key.
        let (branch, _) = watch(&address_node(&identity, "moneyer.dev").unwrap()).unwrap();
        let (pk0, _) = backend::xonly_tweak_add(&branch.pubkey, &note_tweak(&branch, wallet, 0)).unwrap();
        assert_eq!(pk0, note_pubkey(&sk0).unwrap());
        // Not the key at index 0 on the purpose the name is paid on, nor the
        // pre-purpose ladder's.
        for other in [KeyLadder::Purpose(PURPOSE_ADDRESS), KeyLadder::PrePurpose] {
            let node = address_node(&identity, "moneyer.dev").unwrap();
            let sk = note_secret_key(&node, other, 0).unwrap();
            let signed = sign_address_proof(&sk, AddressAction::Register, "moneyer.dev", "alice").unwrap();
            assert_ne!(signed, register, "{other:?}");
        }
        // Deterministic, and bound to the action, the name and the mint.
        assert_eq!(proof("moneyer.dev", AddressAction::Register, "alice").unwrap(), register);
        assert_ne!(proof("moneyer.dev", AddressAction::Unregister, "alice").unwrap(), register);
        assert_ne!(proof("moneyer.dev", AddressAction::Register, "alicf").unwrap(), register);
        assert_ne!(proof("mint.example", AddressAction::Register, "alice").unwrap(), register);
        // A port names another branch (as cx1_of's host does) but the same
        // domain in the message.
        let ported = proof("moneyer.dev:8443", AddressAction::Register, "alice").unwrap();
        let sk0_ported = note_secret_key(&address_node(&identity, "moneyer.dev:8443").unwrap(), wallet, 0).unwrap();
        assert_eq!(
            ported,
            sign_address_proof(&sk0_ported, AddressAction::Register, "moneyer.dev", "alice").unwrap()
        );

        // Nothing outside LUD-16's alphabet, so no name can smuggle a `:`.
        for bad in ["", "Alice", "al:ice", "al ice", "alice@moneyer.dev", "ålice", &"a".repeat(65)] {
            assert!(!valid_username(bad), "{bad}");
            assert!(proof("moneyer.dev", AddressAction::Register, bad).is_err(), "{bad}");
        }
        for good in ["a", "alice", "a.b-c_d", "0x", &"a".repeat(64)] {
            assert!(valid_username(good), "{good}");
        }
        assert_eq!(AddressAction::parse("register"), Some(AddressAction::Register));
        assert_eq!(AddressAction::parse("unregister"), Some(AddressAction::Unregister));
        assert_eq!(AddressAction::parse("Register"), None);
        assert_eq!(AddressAction::parse("sign"), None);
    }

    #[test]
    fn a_spend_binds_the_hostname_and_a_branch_the_host() {
        for (endpoint, domain) in [
            ("moneyer.dev/w", "moneyer.dev"),
            ("moneyer.dev", "moneyer.dev"),
            ("127.0.0.1:8899/w", "127.0.0.1"),
            ("mint.example:443", "mint.example"),
            ("https://mint.example/w", "mint.example"),
            ("lnurlw://mint.example/w?k1=00", "mint.example"),
            ("user@mint.example:8443/w", "mint.example"),
            ("[::1]:8899/w", "[::1]"),
            ("mint.example?p=1", "mint.example"),
        ] {
            assert_eq!(spend_domain(endpoint), domain, "{endpoint}");
        }
        // The branch keeps the port the spend drops.
        assert_eq!(branch_host("127.0.0.1:8899/w"), "127.0.0.1:8899");
    }

    #[test]
    fn the_ownership_digest_is_the_specs() {
        let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap();
        assert_eq!(
            hex_encode(&ownership_digest()),
            text(&vectors["conventions"], "ownershipDigest")
        );
    }

    #[test]
    fn matches_the_part2_vectors() {
        // Eight branches, both parities, a host with a port, and indices up
        // to u32::MAX: lnurl-wallet's own output, which lnurl-mint agrees with.
        let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/lud25-part2.json")).unwrap();
        let branches = vectors["branches"].as_array().expect("branches");
        assert_eq!(branches.len(), 8);
        let mut odd_seen = false;
        for branch in branches {
            let host = text(branch, "host");
            let seed = hex_decode(text(branch, "seed")).unwrap();
            let node = derive_cash_domain_node(&address_root(&seed).unwrap(), host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(branch, "addressNode"), "{host}");

            let (watched, odd) = watch(&node).unwrap();
            assert_eq!(hex_encode(&watched.pubkey), text(branch, "branchPubkey"), "{host}");
            assert_eq!(hex_encode(&watched.chain_code), text(branch, "chainCode"), "{host}");
            assert_eq!(odd, text(branch, "branchParity") == "odd", "{host}");
            odd_seen |= odd;
            assert_eq!(cx1_of(&node).unwrap(), text(branch, "cx1"), "{host}");

            check_notes(&node, &branch["notes"], host);
        }
        // The negation is the easy thing to get wrong, and silent when wrong:
        // an odd branch must be in the set or it went untested.
        assert!(odd_seen);
    }

    #[test]
    fn matches_the_nostr_seed_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/lud25-nostr-seed.json")).unwrap();
        for case in vectors["cases"].as_array().expect("cases") {
            let identity = unhex::<32>(text(case, "identity"));
            let host = text(case, "host");
            assert_eq!(hex_encode(nostr_cash_seed(&identity).as_ref()), text(case, "seed"), "{host}");
            let node = address_node(&identity, host).unwrap();
            assert_eq!(hex_encode(cash_node_to_bytes(&node).as_ref()), text(case, "addressNode"), "{host}");
            assert_eq!(cx1_of(&node).unwrap(), text(case, "cx1"), "{host}");
            check_notes(&node, &case["notes"], host);
        }
    }

    /// The public key at `index` on one ladder, as a mint derives it from
    /// the cx1 alone.
    fn watched(identity: &[u8; 32], host: &str, ladder: KeyLadder, index: u32) -> [u8; 32] {
        let (branch, _) = watch(&address_node(identity, host).unwrap()).unwrap();
        backend::xonly_tweak_add(&branch.pubkey, &note_tweak(&branch, ladder, index)).unwrap().0
    }

    #[test]
    fn a_claim_finds_a_note_paid_on_purpose_2() {
        let identity = [7u8; 32];
        let address = KeyLadder::Purpose(PURPOSE_ADDRESS);
        let pubkey = watched(&identity, "moneyer.dev", address, 3);
        assert_eq!(paid_to(&identity, "moneyer.dev", address, 3).unwrap(), pubkey);
        let found = claim_note_key(&identity, "moneyer.dev", 3, &pubkey).unwrap();
        assert_eq!((found.pubkey, found.ladder), (pubkey, address));
        assert_eq!(note_pubkey(&found.secret).unwrap(), pubkey);
    }

    #[test]
    fn a_claim_finds_a_note_paid_on_the_pre_purpose_ladder() {
        // Paid before purposes: the same index, the old ladder's key.
        let identity = [7u8; 32];
        let pubkey = watched(&identity, "moneyer.dev", KeyLadder::PrePurpose, 3);
        assert_ne!(pubkey, paid_to(&identity, "moneyer.dev", KeyLadder::Purpose(PURPOSE_ADDRESS), 3).unwrap());
        let found = claim_note_key(&identity, "moneyer.dev", 3, &pubkey).unwrap();
        assert_eq!((found.pubkey, found.ladder), (pubkey, KeyLadder::PrePurpose));
        assert_eq!(note_pubkey(&found.secret).unwrap(), pubkey);
    }

    #[test]
    fn a_claim_refuses_a_key_this_device_does_not_hold() {
        let identity = [7u8; 32];
        let refused = Err("that note is paid to a key this device does not hold");
        let claim = |identity: &[u8; 32], host: &str, index: u32, want: &[u8; 32]| {
            claim_note_key(identity, host, index, want).map(|found| (found.pubkey, found.ladder))
        };
        // A foreign key outright.
        assert_eq!(claim(&identity, "moneyer.dev", 3, &[0x42; 32]), refused);
        for ladder in CLAIM_LADDERS {
            let pubkey = watched(&identity, "moneyer.dev", ladder, 3);
            // The next index, another mint and another identity are all other keys.
            assert_eq!(claim(&identity, "moneyer.dev", 4, &pubkey), refused, "{ladder:?}");
            assert_eq!(claim(&identity, "mint.example", 3, &pubkey), refused, "{ladder:?}");
            assert_eq!(claim(&[8u8; 32], "moneyer.dev", 3, &pubkey), refused, "{ladder:?}");
        }
        // Purposes 0 and 1 are the wallet's own counters, never what a name
        // is paid on: a claim does not reach them.
        for purpose in [PURPOSE_WALLET, PURPOSE_CHANGE] {
            let pubkey = watched(&identity, "moneyer.dev", KeyLadder::Purpose(purpose), 3);
            assert_eq!(claim(&identity, "moneyer.dev", 3, &pubkey), refused, "purpose {purpose}");
        }
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
    fn the_branch_host_is_the_endpoint_without_its_path() {
        assert_eq!(branch_host("moneyer.dev/w"), "moneyer.dev");
        assert_eq!(branch_host("127.0.0.1:8899/w"), "127.0.0.1:8899");
        assert_eq!(branch_host("moneyer.dev"), "moneyer.dev");
    }

    #[test]
    fn a_tweak_at_or_above_n_is_reduced_mod_n() {
        let mut five = [0u8; 32];
        five[31] = 5;
        let mut above = CURVE_ORDER;
        above[31] += 5;
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0u8; 32]);
        assert_eq!(reduce_mod_n(above), five);
        assert_eq!(reduce_mod_n(five), five);
        // 2^256 - 1 reduces to 2^256 - 1 - n, which n then takes back to all ones
        let top = reduce_mod_n([0xff; 32]);
        assert!(top < CURVE_ORDER);
        let mut sum = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let s = u16::from(top[i]) + u16::from(CURVE_ORDER[i]) + carry;
            sum[i] = s as u8;
            carry = s >> 8;
        }
        assert_eq!((sum, carry), ([0xff; 32], 0));
    }
}
