//! LUD-25 seed-recoverable note secrets, derived on the device.
//!
//! Every secret a WALLET generates in LUD-25 — a rotate/split/merge preimage
//! behind `h`/`h2`, and the mint-time secret behind a `comment`'s hash — is
//! plain randomness as the rest of the draft specifies it. That is fine for
//! the SERVICE, which never sees one, and a real gap for whoever holds the
//! money: an ordinary backup is a seed phrase, and a seed phrase backs up
//! nothing that was never derived from it. Today this locker draws note
//! secrets from the RNG (`note_store::new_secret`), so a dead board is money
//! nobody can recover even with the words written down.
//!
//! The scheme, quoted from LUD-25's "Seed-recoverable note secrets":
//!
//! ```text
//! cashHashingKey   = derive(masterKey, m/139'/0)
//! domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//! (d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//! secret_i         = derive(masterKey, m/139'/d1/d2/d3/d4/i')
//! ```
//!
//! `d1..d4` are raw uint32 read off a hash, and BIP-32 reads any index at or
//! above 2^31 as hardened, so roughly half of any given mint's four levels
//! land hardened by magnitude alone. Nothing is masked and nothing is forced:
//! "exactly as LUD-05" is what the draft says of those two lines, and LUD-05's
//! existing corpus is what settles it. Only `i` is deliberately hardened, by
//! the draft's own `i'`.
//!
//! **Why this module is bigger than [`crate::mnemonic`]'s walk.** That one is
//! hardened at every level, so it never needs a public key: a hardened step
//! hashes over `0x00 || ser256(kpar)`. An unhardened step hashes over
//! `serP(point(kpar))` instead, which is a point multiply. `lnurl-vault` has
//! no elliptic curve at all and works around it by being provisioned with the
//! domain node, since every unhardened level sits at or above it. This board
//! already links secp256k1, so it does the whole path itself and nothing
//! outside it ever holds a node from which a note secret could be derived.
//!
//! Byte-identical to `lnurlcash-kit`'s `src/cash.ts` and the reference
//! wallet's `src/cashSecrets.ts`, graded against `lnurlcash-conformance`
//! 0.7.0's `cash-derivation.json` (and BIP-32's own published vector 1) in
//! this module's tests. That is the whole point of it: a secret this device
//! derives and a secret the wallet derives from the same words have to be the
//! same 32 bytes, or the money is only findable from one of them.
//!
//! Nothing here touches storage, the RNG or a screen. Recovery scanning stays
//! host-driven — the device re-derives on request, and the host does the
//! network half.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;

/// LUD-25's own purpose, alongside LUD-05's `m/138'` linking-key branch so
/// the two can never share key material.
pub const CASH_PURPOSE: u32 = 139;

const HARDENED: u32 = 0x8000_0000;

/// The highest note index this will derive. `i` is hardened by the draft's
/// `i'`, so it has the low 31 bits to live in; anything at or above 2^31
/// would collide with a hardened index that is not this one.
pub const MAX_NOTE_INDEX: u32 = HARDENED - 1;

/// A BIP-32 extended private key, reduced to the two things a child step
/// needs. Bearer material: every note secret beneath a node is derivable by
/// whoever holds it, so it is zeroized on drop and never leaves this device.
#[derive(Clone)]
pub struct CashNode {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl Drop for CashNode {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
    }
}

impl core::fmt::Debug for CashNode {
    /// Deliberately says nothing. A node in a log line is every note secret at
    /// that mint, and the one place this would ever be printed is a panic
    /// message nobody chose the contents of.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CashNode(redacted)")
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn split_node(material: &[u8; 64]) -> CashNode {
    let mut node = CashNode {
        private_key: [0u8; 32],
        chain_code: [0u8; 32],
    };
    node.private_key.copy_from_slice(&material[0..32]);
    node.chain_code.copy_from_slice(&material[32..64]);
    node
}

/// BIP-32 master from a seed. `seed` is raw bytes — a 64-byte BIP-39 seed is
/// the interop case and what [`crate::mnemonic`] already produces, but nothing
/// here depends on BIP-39.
pub fn cash_master(seed: &[u8]) -> Result<CashNode, &'static str> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err("a BIP-32 seed must be 16 to 64 bytes");
    }
    let material = hmac_sha512(b"Bitcoin seed", seed);
    let node = split_node(&material);
    // Rejected rather than assumed: a master key of zero or one at/above the
    // curve order is a ~2^-127 event, and a silent wrong answer here is a note
    // that cannot be spent.
    crate::derive::backend::compressed_pubkey(&node.private_key)
        .map_err(|_| "this seed does not produce a valid BIP-32 master key")?;
    Ok(node)
}

/// BIP-32 CKDpriv. Hardened when `index >= 2^31`, by the index's own magnitude
/// and nothing else — which is the whole of the convention question LUD-25
/// leaves to LUD-05. The caller passes the raw uint32 and this decides.
///
/// Public so a bench or a host tool can walk this against BIP-32's own test
/// vectors rather than taking the derivation on trust.
pub fn derive_cash_child(node: &CashNode, index: u32) -> Result<CashNode, &'static str> {
    let mut data = Zeroizing::new([0u8; 37]);
    if index >= HARDENED {
        // 0x00 || ser256(kpar). The leading zero pads the 32-byte scalar out
        // to the 33 bytes a serialised point occupies, so the hardened and
        // unhardened legs hash over the same length and can never collide.
        data[1..33].copy_from_slice(&node.private_key);
    } else {
        data[0..33].copy_from_slice(&crate::derive::backend::compressed_pubkey(
            &node.private_key,
        )?);
    }
    data[33..37].copy_from_slice(&index.to_be_bytes());

    let material = hmac_sha512(&node.chain_code, data.as_slice());
    let il: [u8; 32] = material[0..32].try_into().expect("32 of 64 bytes");
    // BIP-32's own escape hatch says to skip to the next index when I_L is at
    // or above the order, or the sum is zero. tweak_add rejects both; this
    // surfaces the refusal rather than retrying, because silently deriving a
    // DIFFERENT index would put the note somewhere the wallet will not look.
    let mut child = CashNode {
        private_key: crate::derive::backend::tweak_add(&node.private_key, &il)?,
        chain_code: [0u8; 32],
    };
    child.chain_code.copy_from_slice(&material[32..64]);
    Ok(child)
}

/// `m/139'` — this wallet's root for note secrets.
pub fn derive_cash_root(seed: &[u8]) -> Result<CashNode, &'static str> {
    derive_cash_child(&cash_master(seed)?, CASH_PURPOSE | HARDENED)
}

/// The four raw uint32 levels a mint's subtree hangs off.
///
/// `host` is the SERVICE domain exactly as the wallet spells it: lowercase,
/// port included where there is one (`127.0.0.1:8899`), no scheme and no path.
/// Byte-identical to `lnurlcash-kit`'s `serverOf`, because a device and a
/// wallet that disagree by one byte here derive two different trees and each
/// finds nothing in the other's.
pub fn cash_domain_indices(root: &CashNode, host: &str) -> Result<[u32; 4], &'static str> {
    let hashing_key = derive_cash_child(root, 0)?;
    let mut mac =
        HmacSha256::new_from_slice(&hashing_key.private_key).expect("HMAC accepts any key length");
    mac.update(host.as_bytes());
    let material = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut out = [0u32; 4];
    for (slot, chunk) in out.iter_mut().zip(material.chunks_exact(4)) {
        *slot = u32::from_be_bytes(chunk.try_into().expect("4 of 32 bytes"));
    }
    Ok(out)
}

/// `m/139'/d1/d2/d3/d4` for one mint: everything above a note's own index.
pub fn derive_cash_domain_node(root: &CashNode, host: &str) -> Result<CashNode, &'static str> {
    let mut node = root.clone();
    for index in cash_domain_indices(root, host)? {
        node = derive_cash_child(&node, index)?;
    }
    Ok(node)
}

/// The i-th note secret beneath a mint's domain node: 32 bytes, used directly
/// as the `k1` a note is worth. The SERVICE can tell no difference between one
/// of these and a randomly drawn one — it only ever receives `sha256(k1)`.
pub fn cash_secret_at(
    domain_node: &CashNode,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if index > MAX_NOTE_INDEX {
        return Err("a note index must be below 2^31");
    }
    Ok(Zeroizing::new(
        derive_cash_child(domain_node, index | HARDENED)?.private_key,
    ))
}

/// The convenience form, from the root. Re-derives the domain node each call,
/// which is up to four point multiplies — fine for one secret, wasteful for a
/// run of them. Hold the domain node for those.
pub fn derive_cash_secret(
    root: &CashNode,
    host: &str,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    cash_secret_at(&derive_cash_domain_node(root, host)?, index)
}

/// `private_key || chain_code`, 64 bytes. Not a BIP-32 extended key: no
/// version bytes, no depth, no parent fingerprint, no base58check. The same
/// 64 bytes the reference wallet persists for its own root, and the same shape
/// `lnurl-vault` is provisioned with — which is why it exists here at all,
/// since this board derives its own and needs no provisioning.
pub fn cash_node_to_bytes(node: &CashNode) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    out[0..32].copy_from_slice(&node.private_key);
    out[32..64].copy_from_slice(&node.chain_code);
    out
}

pub fn cash_node_from_bytes(bytes: &[u8; 64]) -> CashNode {
    split_node(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::new();
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    // BIP-32 test vector 1, the chain the published spec walks:
    // m -> m/0' -> m/0'/1 -> m/0'/1/2' . The unhardened middle step is the
    // one this module needed a public key for, and the one heartwood's own
    // all-hardened tree never exercises.
    const BIP32_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn walks_bip32_published_vector_1() {
        let master = cash_master(&unhex::<16>(BIP32_SEED)).unwrap();
        assert_eq!(
            hex(cash_node_to_bytes(&master).as_ref()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35\
             873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );

        let hardened = derive_cash_child(&master, 0x8000_0000).unwrap();
        assert_eq!(
            hex(cash_node_to_bytes(&hardened).as_ref()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea\
             47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );

        // the unhardened step: serP(point(kpar)), not 0x00 || ser256(kpar)
        let normal = derive_cash_child(&hardened, 1).unwrap();
        assert_eq!(
            hex(cash_node_to_bytes(&normal).as_ref()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368\
             2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );

        let again = derive_cash_child(&normal, 0x8000_0002).unwrap();
        assert_eq!(
            hex(&again.private_key),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        );
    }

    #[test]
    fn a_hardened_and_an_unhardened_step_are_different_derivations() {
        // The parity byte is the whole difference, and getting it wrong is
        // silent: both legs produce a valid-looking 32-byte secret.
        let master = cash_master(&unhex::<16>(BIP32_SEED)).unwrap();
        let normal = derive_cash_child(&master, 1).unwrap();
        let hardened = derive_cash_child(&master, 1 | HARDENED).unwrap();
        assert_ne!(normal.private_key, hardened.private_key);
    }

    // lnurlcash-conformance 0.7.0, vectors/cash-derivation.json. Frozen here
    // rather than read from the file: this crate builds for a board with no
    // filesystem, and a secret that stops matching these is money the wallet
    // will not find.
    struct Case {
        seed: &'static str,
        host: &'static str,
        index: u32,
        cash_root: &'static str,
        domain_indices: [u32; 4],
        domain_node: &'static str,
        k1: &'static str,
    }

    const CASES: [Case; 5] = [
        Case {
            // "abandon abandon ... about", the standard BIP-39 phrase
            seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            host: "mint.example",
            index: 0,
            cash_root: "c7a2496e9b453a67c5d2a1f04936ec1259440d45454c795a99a66269e4cd3005111e1cc966fca2fe32f054f14caceab90449e536d94cf6935ea12a087e414f60",
            domain_indices: [2589708612, 3693348916, 172082394, 3793182078],
            domain_node: "72056e5cde21458b13689c3950904dfd327415a506d064290e5e5f4296a40543dd5e9504ddb6eefbafa4ad3b00ad421858fafc0ed9ea4abd9cb68793f845cfc1",
            k1: "de5b81405a12e1297b350d80e2ad85043ed5b9436a0c5592d3302778de330499",
        },
        Case {
            seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            host: "mint.example",
            index: 1,
            cash_root: "c7a2496e9b453a67c5d2a1f04936ec1259440d45454c795a99a66269e4cd3005111e1cc966fca2fe32f054f14caceab90449e536d94cf6935ea12a087e414f60",
            domain_indices: [2589708612, 3693348916, 172082394, 3793182078],
            domain_node: "72056e5cde21458b13689c3950904dfd327415a506d064290e5e5f4296a40543dd5e9504ddb6eefbafa4ad3b00ad421858fafc0ed9ea4abd9cb68793f845cfc1",
            k1: "267570df5ba8098d728e839a698f729c2df6fa7b8b7ae7c9c7ffa7dda3417e1d",
        },
        Case {
            // one past a 20-index gap limit
            seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            host: "mint.example",
            index: 20,
            cash_root: "c7a2496e9b453a67c5d2a1f04936ec1259440d45454c795a99a66269e4cd3005111e1cc966fca2fe32f054f14caceab90449e536d94cf6935ea12a087e414f60",
            domain_indices: [2589708612, 3693348916, 172082394, 3793182078],
            domain_node: "72056e5cde21458b13689c3950904dfd327415a506d064290e5e5f4296a40543dd5e9504ddb6eefbafa4ad3b00ad421858fafc0ed9ea4abd9cb68793f845cfc1",
            k1: "1f2b8080d4c9431b1dec780abb4eee3c4aaf7ff03f7dd126a7e005ec7af372e0",
        },
        Case {
            seed: "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
            host: "mint.example",
            index: 0,
            cash_root: "e58252908e0c10965d15d1e3894cbf206a2102c20eb9519e466e2e0e852075d430afaa22bb69ef2151cdffacc463e51068e854152b0b7c08fa2f93e6b8d16741",
            domain_indices: [3862277158, 545631060, 182776155, 2195829862],
            domain_node: "df3c9156afc2e416286df9bbfda49c6ab72305ba3d65ae0b7e2214caf581b111959d96bc0c075185ff7304214496a78f43b22ea511f97a7bf408454a7e3d3a85",
            k1: "d5376fa38f01b39d55be6dc0ea8f3aa6b91f37c183c5a394bb7e30b624855a78",
        },
        Case {
            // a host carrying a port: the string is hashed exactly as spelled
            seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            host: "127.0.0.1:8899",
            index: 0,
            cash_root: "c7a2496e9b453a67c5d2a1f04936ec1259440d45454c795a99a66269e4cd3005111e1cc966fca2fe32f054f14caceab90449e536d94cf6935ea12a087e414f60",
            domain_indices: [2087962263, 3073061246, 2281736429, 1205328740],
            domain_node: "80bdd2d71f0235bd9e22d5838a4a4f346cf5415309ada559942a409a630e102ce214425b89b36d03d4835fdf6592d2619c74d37b746711b4ed85759ea1d358a6",
            k1: "d7bcc5c9e7015ca2688ed10e24db3f82163d5b59fc887e5dd346abf2426b1270",
        },
    ];

    #[test]
    fn matches_the_conformance_vectors() {
        for case in &CASES {
            let seed = unhex::<64>(case.seed);
            let root = derive_cash_root(&seed).unwrap();
            assert_eq!(hex(cash_node_to_bytes(&root).as_ref()), case.cash_root, "{}", case.host);

            let indices = cash_domain_indices(&root, case.host).unwrap();
            assert_eq!(indices, case.domain_indices, "{}", case.host);

            let node = derive_cash_domain_node(&root, case.host).unwrap();
            assert_eq!(hex(cash_node_to_bytes(&node).as_ref()), case.domain_node, "{}", case.host);

            let secret = cash_secret_at(&node, case.index).unwrap();
            assert_eq!(hex(secret.as_ref()), case.k1, "{} index {}", case.host, case.index);
            // and the convenience form agrees with the two-step one
            assert_eq!(
                derive_cash_secret(&root, case.host, case.index).unwrap().as_ref(),
                secret.as_ref()
            );
        }
    }

    #[test]
    fn a_port_is_part_of_the_host() {
        // Two mints on one address differ only by port. Dropping it would put
        // both their notes on one ladder, and a restore at either would walk
        // secrets that belong to the other.
        let seed = unhex::<64>(CASES[0].seed);
        let root = derive_cash_root(&seed).unwrap();
        assert_ne!(
            cash_domain_indices(&root, "127.0.0.1").unwrap(),
            cash_domain_indices(&root, "127.0.0.1:8899").unwrap()
        );
    }

    #[test]
    fn an_index_at_or_above_two_to_the_31_is_refused() {
        // `i'` is hardened by the draft's own notation, so `i` has the low 31
        // bits. Accepting more would silently derive a DIFFERENT hardened
        // index from the one asked for.
        let seed = unhex::<64>(CASES[0].seed);
        let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), "mint.example").unwrap();
        assert!(cash_secret_at(&node, MAX_NOTE_INDEX).is_ok());
        assert!(cash_secret_at(&node, MAX_NOTE_INDEX + 1).is_err());
        assert!(cash_secret_at(&node, u32::MAX).is_err());
    }

    #[test]
    fn a_seed_of_the_wrong_size_is_refused() {
        assert!(cash_master(&[0u8; 15]).is_err());
        assert!(cash_master(&[7u8; 16]).is_ok());
        assert!(cash_master(&[7u8; 64]).is_ok());
        assert!(cash_master(&[0u8; 65]).is_err());
    }

    #[test]
    fn a_node_survives_the_byte_round_trip() {
        // The shape lnurl-vault is provisioned with. This board derives its
        // own, but the two have to agree on the encoding or a bench tool
        // written for one cannot drive the other.
        let seed = unhex::<64>(CASES[0].seed);
        let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), "mint.example").unwrap();
        let bytes = cash_node_to_bytes(&node);
        let back = cash_node_from_bytes(&bytes);
        assert_eq!(back.private_key, node.private_key);
        assert_eq!(back.chain_code, node.chain_code);
    }

    #[test]
    fn every_index_gives_a_different_secret() {
        let seed = unhex::<64>(CASES[0].seed);
        let node = derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), "mint.example").unwrap();
        let a = cash_secret_at(&node, 0).unwrap();
        let b = cash_secret_at(&node, 1).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
