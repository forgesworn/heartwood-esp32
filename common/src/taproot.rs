//! LUD-25's taproot arithmetic: what a note's `Q` is, and what a spend of it
//! signs.
//!
//! Every LUD-25 note is a BIP-341 output key `Q`, and a mint files, looks up
//! and certifies every note by `hex(Q)`. This device holds two kinds:
//!
//!  - a **key note** ([`crate::cash_key`]), whose `Q` is its own public key
//!    with no BIP-86 tweak, spent by a `ck1` that signs [`key_path_sighash`];
//!  - a **bearer note** ([`crate::note_store`]'s plain note), whose `Q` is one
//!    `OP_SHA256 <h> OP_EQUAL` leaf under BIP-341's NUMS point
//!    ([`bearer_output_key`]), spent by revealing its preimage.
//!
//! **What a signature signs.** Never a text message: BIP-341's sighash of
//! input 0 of one fixed, never-broadcast transaction whose prevout is
//! `tagged_hash("LNURLcash/mint", domain)`. That prevout is what stops a
//! spend one mint has seen being replayed at another. A key path always
//! claims locktime 0 and sequence `0xffffffff`, so only the domain and `Q`
//! reach its signature, and the 174-byte SigMsg is built here field by field
//! rather than by a transaction library: its shape cannot change, and a
//! library would be most of an image slot for one hash.
//!
//! Graded in the tests below against LUD-25's test vectors 3 and 5
//! (`tests/fixtures/lud25-taproot.json`), every intermediate byte for byte,
//! on both curve backends. The same arithmetic as lnurl-wallet's `spend.ts`
//! and moneyer's port of it.

use alloc::string::String;

use sha2::{Digest, Sha256};

use crate::derive::backend;

/// BIP-341's tapscript leaf version, the only one LUD-25 accepts.
pub const TAPLEAF_VERSION: u8 = 0xc0;

/// BIP-341's nothing-up-my-sleeve point `H`, x-only: the x coordinate is the
/// hash of `G`'s uncompressed encoding, so nobody knows its discrete log and
/// a note built on it has no key path, only its leaf.
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// A key path's time claim: none. Locktime 0, sequence final.
pub const KEY_PATH_LOCKTIME: u32 = 0;
pub const KEY_PATH_SEQUENCE: u32 = 0xffff_ffff;

/// hash_type, nVersion, nLockTime, five 32-byte hashes, spend_type and
/// input_index.
pub const SIG_MSG_LEN: usize = 1 + 4 + 4 + 5 * 32 + 1 + 4;

/// A bearer note's leaf: `OP_SHA256 OP_PUSHBYTES_32 <h> OP_EQUAL`.
pub const BEARER_LEAF_LEN: usize = 35;

const OP_1: u8 = 0x51;
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_SHA256: u8 = 0xa8;
const OP_EQUAL: u8 = 0x87;
/// BIP-341 hash_type 0x00 and spend_type 0x00 (key path, no annex).
const SIGHASH_DEFAULT: u8 = 0x00;
const KEY_PATH_SPEND: u8 = 0x00;
/// The canonical spend transaction's `nVersion`.
const TX_VERSION: u32 = 2;

/// `sha256(sha256(tag) || sha256(tag) || parts...)`: BIP-340's tagged hash,
/// which BIP-341, BIP-342 and LUD-25 all build on. `parts` are hashed as one
/// concatenation, so no caller has to allocate to join them.
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Bitcoin's CompactSize length prefix, as the leaf hash commits to it. A
/// bearer leaf needs only the one-byte form, but a leaf is any script, and a
/// wrong prefix is a wrong `Q` with no other symptom.
fn compact_size(len: usize) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let used = if len < 0xfd {
        out[0] = len as u8;
        1
    } else if len <= 0xffff {
        out[0] = 0xfd;
        out[1..3].copy_from_slice(&(len as u16).to_le_bytes());
        3
    } else if len as u64 <= 0xffff_ffff {
        out[0] = 0xfe;
        out[1..5].copy_from_slice(&(len as u32).to_le_bytes());
        5
    } else {
        out[0] = 0xff;
        out[1..9].copy_from_slice(&(len as u64).to_le_bytes());
        9
    };
    (out, used)
}

/// `tagged_hash("TapLeaf", 0xc0 || compact_size(len) || script)`.
pub fn tapleaf_hash(script: &[u8]) -> [u8; 32] {
    let (prefix, used) = compact_size(script.len());
    tagged_hash(b"TapLeaf", &[&[TAPLEAF_VERSION], &prefix[..used], script])
}

/// A taproot output key, and the parity of its y that a control block
/// records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputKey {
    pub x: [u8; 32],
    pub odd_y: bool,
}

/// BIP-341's output key for internal key `P` committing to a script tree:
/// `Q = lift_x(P) + tagged_hash("TapTweak", P || merkle_root)·G`.
pub fn taproot_tweak(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> Result<OutputKey, &'static str> {
    let tweak = tagged_hash(b"TapTweak", &[internal_key, merkle_root]);
    let (x, odd_y) = backend::xonly_tweak_add(internal_key, &tweak)?;
    Ok(OutputKey { x, odd_y })
}

/// `OP_SHA256 <h> OP_EQUAL`: true only for a witness that hashes to `h`,
/// with no signature in it, so a bearer note is bound to no mint.
pub fn bearer_leaf(h: &[u8; 32]) -> [u8; BEARER_LEAF_LEN] {
    let mut leaf = [0u8; BEARER_LEAF_LEN];
    leaf[0] = OP_SHA256;
    leaf[1] = OP_PUSHBYTES_32;
    leaf[2..34].copy_from_slice(h);
    leaf[34] = OP_EQUAL;
    leaf
}

/// A bearer note's `Q`: its one hashlock leaf under [`NUMS_H`]. What a mint
/// keying notes by `Q` files a plain note under. Everything in it follows
/// from `h`, which is why `h` stays a valid short form for it on the wire.
pub fn bearer_output_key(h: &[u8; 32]) -> Result<OutputKey, &'static str> {
    taproot_tweak(&NUMS_H, &tapleaf_hash(&bearer_leaf(h)))
}

/// The control block that opens a bearer note's leaf: `(0xc0 | parity(Q))
/// || H`. One leaf, so no merkle path follows.
pub fn bearer_control_block(h: &[u8; 32]) -> Result<[u8; 33], &'static str> {
    let output = bearer_output_key(h)?;
    let mut block = [0u8; 33];
    block[0] = TAPLEAF_VERSION | u8::from(output.odd_y);
    block[1..].copy_from_slice(&NUMS_H);
    Ok(block)
}

/// `OP_1 <Q>`: the spent output's scriptPubKey, which is what binds a spend
/// to its note.
pub fn p2tr_script_pubkey(output_key: &[u8; 32]) -> [u8; 34] {
    let mut script = [0u8; 34];
    script[0] = OP_1;
    script[1] = OP_PUSHBYTES_32;
    script[2..].copy_from_slice(output_key);
    script
}

/// The canonical spend's prevout txid, `tagged_hash("LNURLcash/mint",
/// domain)`, which is what binds a spend to its mint. Lowercased here, as
/// LUD-25 says the domain is, so a host written in any case binds the same
/// mint.
pub fn spend_prevout(domain: &str) -> [u8; 32] {
    let domain: String = domain.to_ascii_lowercase();
    tagged_hash(b"LNURLcash/mint", &[domain.as_bytes()])
}

fn put(msg: &mut [u8; SIG_MSG_LEN], at: &mut usize, bytes: &[u8]) {
    msg[*at..*at + bytes.len()].copy_from_slice(bytes);
    *at += bytes.len();
}

/// BIP-341's SigMsg for input 0 of the canonical spend, key path, under
/// `SIGHASH_DEFAULT`. Fields in BIP-341's order, integers little-endian.
pub fn key_path_sig_msg(output_key: &[u8; 32], domain: &str) -> [u8; SIG_MSG_LEN] {
    let zero_value = 0i64.to_le_bytes();
    let script_pubkey = p2tr_script_pubkey(output_key);
    let mut msg = [0u8; SIG_MSG_LEN];
    let mut at = 0;
    put(&mut msg, &mut at, &[SIGHASH_DEFAULT]);
    put(&mut msg, &mut at, &TX_VERSION.to_le_bytes());
    put(&mut msg, &mut at, &KEY_PATH_LOCKTIME.to_le_bytes());
    // sha_prevouts: the one input's outpoint, (txid, vout 0).
    put(&mut msg, &mut at, &sha256(&[&spend_prevout(domain), &0u32.to_le_bytes()]));
    // sha_amounts: the spent value is always 0. The mint enforces a note's
    // value from its own records, so no signature ever commits to one.
    put(&mut msg, &mut at, &sha256(&[&zero_value]));
    // sha_scriptpubkeys: CompactSize(34) || OP_1 <Q>.
    put(&mut msg, &mut at, &sha256(&[&[script_pubkey.len() as u8], &script_pubkey]));
    put(&mut msg, &mut at, &sha256(&[&KEY_PATH_SEQUENCE.to_le_bytes()]));
    // sha_outputs: one output, value 0, empty scriptPubKey.
    put(&mut msg, &mut at, &sha256(&[&zero_value, &[0x00]]));
    put(&mut msg, &mut at, &[KEY_PATH_SPEND]);
    put(&mut msg, &mut at, &0u32.to_le_bytes());
    debug_assert_eq!(at, SIG_MSG_LEN);
    msg
}

/// What a `ck1`'s signature signs: `tagged_hash("TapSighash", 0x00 ||
/// SigMsg)`, the leading byte being BIP-341's epoch.
pub fn key_path_sighash(output_key: &[u8; 32], domain: &str) -> [u8; 32] {
    tagged_hash(b"TapSighash", &[&[0x00], &key_path_sig_msg(output_key, domain)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{hex_decode, hex_encode};
    use alloc::vec::Vec;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/lud25-taproot.json")).unwrap()
    }

    fn text<'a>(value: &'a Value, key: &str) -> &'a str {
        value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex_decode(text).expect("hex").try_into().expect("length")
    }

    #[test]
    fn tagged_hash_is_bip340s() {
        // The tag's hash twice, then the data, and data given in parts hashes
        // as its concatenation.
        let tag = Sha256::digest(b"TapLeaf");
        let direct: [u8; 32] = Sha256::new()
            .chain_update(tag)
            .chain_update(tag)
            .chain_update(b"abcdef")
            .finalize()
            .into();
        assert_eq!(tagged_hash(b"TapLeaf", &[b"abcdef"]), direct);
        assert_eq!(tagged_hash(b"TapLeaf", &[b"abc", b"", b"def"]), direct);
        assert_ne!(tagged_hash(b"TapBranch", &[b"abcdef"]), direct);
    }

    #[test]
    fn compact_size_uses_each_width_at_its_boundary() {
        let bytes = |len| {
            let (out, used) = compact_size(len);
            out[..used].to_vec()
        };
        assert_eq!(bytes(0), [0x00]);
        assert_eq!(bytes(35), [0x23]);
        assert_eq!(bytes(0xfc), [0xfc]);
        assert_eq!(bytes(0xfd), [0xfd, 0xfd, 0x00]);
        assert_eq!(bytes(0xffff), [0xfd, 0xff, 0xff]);
        assert_eq!(bytes(0x1_0000), [0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn vector_3_every_intermediate_of_the_key_path_sighash() {
        let v = &vectors()["vector3"];
        let q = unhex::<32>(text(v, "outputKey"));
        let domain = text(v, "domain");

        assert_eq!(hex_encode(&spend_prevout(domain)), text(v, "prevoutTxid"));
        assert_eq!(hex_encode(&p2tr_script_pubkey(&q)), text(v, "spentScriptPubKey"));

        let msg = key_path_sig_msg(&q, domain);
        let fields = &v["sigMsgFields"];
        let mut at = 0;
        for (name, len) in [
            ("hash_type", 1),
            ("nVersion", 4),
            ("nLockTime", 4),
            ("sha_prevouts", 32),
            ("sha_amounts", 32),
            ("sha_scriptpubkeys", 32),
            ("sha_sequences", 32),
            ("sha_outputs", 32),
            ("spend_type", 1),
            ("input_index", 4),
        ] {
            assert_eq!(hex_encode(&msg[at..at + len]), text(fields, name), "{name}");
            at += len;
        }
        assert_eq!(at, SIG_MSG_LEN);
        assert_eq!(hex_encode(&msg), text(v, "sigMsg"));
        assert_eq!(hex_encode(&key_path_sighash(&q, domain)), text(v, "sighash"));
    }

    #[test]
    fn vector_3_the_signature_is_zero_aux_bip340_over_the_sighash() {
        let v = &vectors()["vector3"];
        let sk = unhex::<32>(text(v, "sk"));
        let q = unhex::<32>(text(v, "outputKey"));
        assert_eq!(text(v, "auxRand"), "00".repeat(32));
        assert_eq!(backend::pubkey_from_secret(&sk).unwrap(), q);
        let sighash = key_path_sighash(&q, text(v, "domain"));
        let signature = backend::sign_bip340_zero_aux(&sk, &sighash).unwrap();
        assert_eq!(hex_encode(&signature), text(v, "signature"));

        // And that signature, as the one witness item of the canonical spend
        // transaction, is the transaction the vector says Bitcoin Core
        // accepted: this is the whole of what the SigMsg above describes.
        let mut tx: Vec<u8> = Vec::new();
        tx.extend_from_slice(&TX_VERSION.to_le_bytes());
        tx.extend_from_slice(&[0x00, 0x01]); // segwit marker and flag
        tx.push(1); // one input
        tx.extend_from_slice(&spend_prevout(text(v, "domain")));
        tx.extend_from_slice(&0u32.to_le_bytes()); // vout
        tx.push(0); // empty scriptSig
        tx.extend_from_slice(&KEY_PATH_SEQUENCE.to_le_bytes());
        tx.push(1); // one output
        tx.extend_from_slice(&0i64.to_le_bytes());
        tx.push(0); // empty scriptPubKey
        tx.push(1); // one witness item
        tx.push(64);
        tx.extend_from_slice(&signature);
        tx.extend_from_slice(&KEY_PATH_LOCKTIME.to_le_bytes());
        assert_eq!(hex_encode(&tx), text(v, "spendTx"));
    }

    #[test]
    fn a_key_path_sighash_binds_the_mint_and_the_note() {
        let v = &vectors()["vector3"];
        let q = unhex::<32>(text(v, "outputKey"));
        let here = key_path_sighash(&q, "mint.example");
        // The domain is lowercased, so case never picks another mint...
        assert_eq!(key_path_sighash(&q, "MINT.Example"), here);
        // ...but any other domain, a port or another note is another hash.
        assert_ne!(key_path_sighash(&q, "mint.example.com"), here);
        assert_ne!(key_path_sighash(&q, "mint.example:443"), here);
        let mut other = q;
        other[31] ^= 1;
        assert_ne!(key_path_sighash(&other, "mint.example"), here);
    }

    #[test]
    fn vector_5_a_bearer_notes_output_key() {
        let v = &vectors()["vector5"];
        let preimage = unhex::<32>(text(v, "preimage"));
        let h: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(hex_encode(&h), text(v, "h"));

        let leaf = bearer_leaf(&h);
        assert_eq!(hex_encode(&leaf), text(v, "leaf"));
        let leaf_hash = tapleaf_hash(&leaf);
        assert_eq!(hex_encode(&leaf_hash), text(v, "tapleafHash"));
        assert_eq!(hex_encode(&NUMS_H), text(v, "nums"));
        assert_eq!(
            hex_encode(&tagged_hash(b"TapTweak", &[&NUMS_H, &leaf_hash])),
            text(v, "tweak")
        );

        let q = bearer_output_key(&h).unwrap();
        assert_eq!(hex_encode(&q.x), text(v, "outputKey"));
        assert_eq!(crate::encoding::encode_cp1(&q.x), text(v, "cp1"));
        let control = bearer_control_block(&h).unwrap();
        assert_eq!(hex_encode(&control), text(v, "controlBlock"));

        // The full cw1 the preimage is the short form of: locktime and
        // sequence big-endian, then u16-length-prefixed leaf, control block
        // and witness. Heartwood never sends one (the preimage is the
        // shorter spelling of the same spend), but it pins the parity bit.
        let mut cw1: Vec<u8> = Vec::new();
        cw1.extend_from_slice(&KEY_PATH_LOCKTIME.to_be_bytes());
        cw1.extend_from_slice(&KEY_PATH_SEQUENCE.to_be_bytes());
        for item in [&leaf[..], &control[..], &preimage[..]] {
            cw1.extend_from_slice(&(item.len() as u16).to_be_bytes());
            cw1.extend_from_slice(item);
        }
        let hrp = bech32::Hrp::parse("cw").unwrap();
        assert_eq!(bech32::encode::<bech32::Bech32m>(hrp, &cw1).unwrap(), text(v, "cw1"));
    }

    #[test]
    fn vector_5_a_bearer_notes_certificate_is_over_its_q() {
        // What a unified mint's cs1 for a bearer note signs: hex(Q), not h.
        let v = &vectors()["vector5"];
        let h = unhex::<32>(text(v, "h"));
        let q = bearer_output_key(&h).unwrap();
        let message = alloc::format!("LNURLcash:{}:{}", v["amountMsat"], hex_encode(&q.x));
        assert_eq!(message, text(v, "message"));
        let inner = Sha256::new()
            .chain_update(b"Lightning Signed Message:")
            .chain_update(message.as_bytes())
            .finalize();
        assert_eq!(hex_encode(&Sha256::digest(inner)), text(v, "digest"));
        assert_eq!(
            crate::encoding::decode_cs1(text(v, "cs1")).map(|sig| hex_encode(&sig)),
            Some(text(v, "certificate").into())
        );
    }

    #[test]
    fn a_bearer_note_is_per_hash_and_a_bad_internal_key_is_refused() {
        let a = bearer_output_key(&[1u8; 32]).unwrap();
        let b = bearer_output_key(&[2u8; 32]).unwrap();
        assert_ne!(a.x, b.x);
        // x = 0 is not on the curve (0^3 + 7 = 7 has no square root mod p).
        assert!(taproot_tweak(&[0u8; 32], &[0u8; 32]).is_err());
        // Nor is anything at or above the field prime.
        assert!(taproot_tweak(&[0xff; 32], &[0u8; 32]).is_err());
    }
}
