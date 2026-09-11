//! LUD-25 Part 2 on this device: notes paid to its own keys.
//!
//! A Part 2 note is keyed by a public key rather than a hash. Its holder keeps
//! the key, the mint only ever learns `cp1<pk>`, and the note is spent with a
//! `ck1`: a recoverable signature the key makes over one fixed message, from
//! which the mint recovers `pk` and finds the note. A mint that holds a
//! watch-only `cx1` for a lightning address mints each payment straight to the
//! holder's next key, so the gift wrap that tells the holder about it carries
//! no secret at all, only where to look and at which index.
//!
//! **Where this device's receiving keys come from.** A lightning address on a
//! Nostr-native mint belongs to an npub: the key that signed the registration
//! owns the name, and payments are wrapped to it. That key lives here and
//! never leaves, so it is the root:
//!
//! ```text
//! seed   = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//! branch = m/139'/1'/d1/d2/d3/d4 from that seed, d1..d4 from HMAC-SHA256(m/139'/1'/0, host)
//! t      = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i))
//! sk_i   = (P has even y ? p : n - p) + t   (mod n)
//! ck1    = recoverable ECDSA by sk_i over sha256(sha256("Lightning Signed Message:" || "LNURLcash"))
//! ```
//!
//! The first line is this device's own, and the only one. Everything below it
//! is lnurl-wallet's address path (`cashSecrets.ts`) and LUD-25's tweak
//! exactly, so lnurlcash-kit's `deriveCashRoot` and `deriveCashAddressNode`,
//! handed this seed, find every note. It exists because this device never
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
use crate::encoding::{encode_ck1, encode_cx1};

type HmacSha256 = Hmac<Sha256>;

/// What the seed step hashes, keyed by the identity's secret.
pub const NOSTR_SEED_LABEL: &[u8] = b"LNURLcash/nostr-seed";

/// `m/139'/1'`: lnurl-wallet's address branches, beside `m/139'/d1..d4`, the
/// Part 1 ladder. Kept apart so a SERVICE holding a `cx1` can link the
/// payments made to it and nothing else.
const ADDRESS_BRANCH: u32 = 1 | 0x8000_0000;

const NOTE_DERIVE_TAG: &[u8] = b"LNURLcash/derive";

/// The one message every ownership proof signs, so a note has exactly one
/// `ck1` from its holder: the value that spends it is the value that proves
/// it, and re-deriving the key reproduces it (RFC6979).
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

fn note_tweak(branch: &Branch, index: u32) -> [u8; 32] {
    let tag = Sha256::digest(NOTE_DERIVE_TAG);
    Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(branch.pubkey)
        .chain_update(branch.chain_code)
        .chain_update(index.to_be_bytes())
        .finalize()
        .into()
}

/// The key of note `index` on a branch. `index` is any uint32 and is never
/// hardened: a watcher holding only the `cx1` derives the matching public key
/// at every index, which is the point of the scheme.
///
/// The branch key is negated first when its point has odd y, because the `cx1`
/// carries only x and x names the even-y point. Skipping that would give a key
/// whose public key is not the one the mint minted to.
pub fn note_secret_key(node: &CashNode, index: u32) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let (branch, odd) = watch(node)?;
    let tweak = note_tweak(&branch, index);
    let base = if odd {
        Zeroizing::new(backend::negate(&node.private_key)?)
    } else {
        Zeroizing::new(node.private_key)
    };
    // tweak_add refuses t >= n and a zero sum, the same two cases BIP-341 and
    // lnurl-mint refuse. Either is a ~2^-128 event, and the answer is the
    // next index, never a reduced tweak: a wrong key is a note nobody finds.
    backend::tweak_add(&base, &tweak)
        .map(Zeroizing::new)
        .map_err(|_| "this note index is unusable on this branch")
}

/// `x(sk * G)`: what the note is filed under, and what its `cp1` encodes.
pub fn note_pubkey(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    backend::pubkey_from_secret(secret)
}

fn ownership_digest() -> [u8; 32] {
    let inner = Sha256::new()
        .chain_update(b"Lightning Signed Message:")
        .chain_update(OWNERSHIP_MESSAGE)
        .finalize();
    Sha256::digest(inner).into()
}

/// A note's ownership proof, `r || s || recovery id`.
pub fn ownership_signature(secret: &[u8; 32]) -> Result<[u8; 65], &'static str> {
    backend::sign_recoverable(secret, &ownership_digest())
}

/// The note's bearer credential: what a wallet presents as `k1` to spend it.
/// Disclosing it is disclosing the note, exactly as a Part 1 secret is.
pub fn ck1_of(secret: &[u8; 32]) -> Result<String, &'static str> {
    let mut signature = ownership_signature(secret)?;
    let ck1 = encode_ck1(&signature);
    zeroize::Zeroize::zeroize(&mut signature);
    Ok(ck1)
}

/// The mint a note's withdraw endpoint belongs to: `moneyer.dev/w` is at
/// `moneyer.dev`. The locker stores the endpoint; a branch is per mint.
pub fn branch_host(note_host: &str) -> &str {
    note_host.split('/').next().unwrap_or(note_host)
}

/// The key a note paid to `identity` at `index` answers to, checked against
/// the public key the note is said to be minted to.
///
/// This is the whole of what a device that cannot reach the mint can know: a
/// wrap naming a key this device does not hold is refused here, before any
/// card is drawn, rather than kept as money that is not ours. Returns the
/// key and its public key.
pub fn claim_note_key(
    identity_secret: &[u8; 32],
    host: &str,
    index: u32,
    expected: Option<&[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), &'static str> {
    let node = address_node(identity_secret, host)?;
    let secret = note_secret_key(&node, index)?;
    let pubkey = note_pubkey(&secret)?;
    if expected.is_some_and(|want| *want != pubkey) {
        return Err("that note is paid to a key this device does not hold");
    }
    Ok((secret, pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::cash_node_to_bytes;
    use crate::encoding::encode_cp1;
    use crate::hex::{hex_decode, hex_encode};
    use serde_json::Value;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex_decode(text).expect("hex").try_into().expect("length")
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    fn check_notes(node: &CashNode, notes: &Value, label: &str) {
        for note in notes.as_array().expect("notes") {
            let index = note["index"].as_u64().expect("index") as u32;
            let secret = note_secret_key(node, index).unwrap();
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
            assert_eq!(ck1_of(&secret).unwrap(), text(note, "ck1"), "{label} ck1 {index}");
        }
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

    #[test]
    fn a_claim_checks_the_key_it_is_paid_to() {
        let identity = [7u8; 32];
        let (secret, pubkey) = claim_note_key(&identity, "moneyer.dev", 3, None).unwrap();
        assert_eq!(note_pubkey(&secret).unwrap(), pubkey);
        assert!(claim_note_key(&identity, "moneyer.dev", 3, Some(&pubkey)).is_ok());
        // the next index, another mint and another identity are all other keys
        assert!(claim_note_key(&identity, "moneyer.dev", 4, Some(&pubkey)).is_err());
        assert!(claim_note_key(&identity, "mint.example", 3, Some(&pubkey)).is_err());
        assert!(claim_note_key(&[8u8; 32], "moneyer.dev", 3, Some(&pubkey)).is_err());
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
}
