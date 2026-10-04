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
const MINT_PREVOUT_TAG: &[u8] = b"LNURLcash/mint";
const TAP_SIGHASH_TAG: &[u8] = b"TapSighash";

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
/// out; only claimed from.
fn superseded_address_node(identity_secret: &[u8; 32], host: &str) -> Result<CashNode, &'static str> {
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

fn note_tweak(branch: &Branch, purpose: u32, index: u32) -> [u8; 32] {
    reduce_mod_n(tagged_hash(
        NOTE_DERIVE_TAG,
        &[&branch.pubkey, &branch.chain_code, &purpose.to_be_bytes(), &index.to_be_bytes()],
    ))
}

/// The key of note `index` on one `purpose` of a branch. Both are any uint32
/// and never hardened: a watcher holding only the `cx1` derives the matching
/// public key at every one, which is the point of the scheme.
///
/// The branch key is negated first when its point has odd y, because the `cx1`
/// carries only x and x names the even-y point. Skipping that would give a key
/// whose public key is not the one the mint minted to.
pub fn note_secret_key(node: &CashNode, purpose: u32, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let (branch, odd) = watch(node)?;
    let tweak = note_tweak(&branch, purpose, index);
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

/// The key a note paid to `identity` at (`purpose`, `index`) answers to,
/// checked against the public key the note is said to be minted to.
///
/// This is the whole of what a device that cannot reach the mint can know: a
/// wrap naming a key this device does not hold is refused here, before any
/// card is drawn, rather than kept as money that is not ours. A claim that
/// names its key is also tried on the superseded branch, where a name
/// registered before LUD-25 `50d740a` is still paid. Returns the key and its
/// public key.
pub fn claim_note_key(
    identity_secret: &[u8; 32],
    host: &str,
    purpose: u32,
    index: u32,
    expected: Option<&[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), &'static str> {
    let at = |node: CashNode| -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), &'static str> {
        let secret = note_secret_key(&node, purpose, index)?;
        let pubkey = note_pubkey(&secret)?;
        Ok((secret, pubkey))
    };
    let current = at(address_node(identity_secret, host)?)?;
    let Some(want) = expected else {
        return Ok(current);
    };
    if current.1 == *want {
        return Ok(current);
    }
    let superseded = at(superseded_address_node(identity_secret, host)?)?;
    if superseded.1 == *want {
        return Ok(superseded);
    }
    Err("that note is paid to a key this device does not hold")
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
    fn the_branch_host_is_the_endpoint_without_its_path() {
        assert_eq!(branch_host("moneyer.dev/w"), "moneyer.dev");
        assert_eq!(branch_host("127.0.0.1:8899/w"), "127.0.0.1:8899");
        assert_eq!(branch_host("moneyer.dev"), "moneyer.dev");
        assert_eq!(spend_domain("127.0.0.1:8899/w"), "127.0.0.1");
        assert_eq!(spend_domain("moneyer.dev/w"), "moneyer.dev");
    }
}
