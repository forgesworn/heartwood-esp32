// common/src/derive.rs
//
// nsec-tree child key derivation via HMAC-SHA256.
// Matches heartwood-core byte-for-byte.
//
// Two backends: k256 (default, for host/tests) and secp256k1 (C FFI, for
// Xtensa firmware where k256's field arithmetic hangs).
//
// Only one backend may be active at a time. Activating both is a compile error.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


#[cfg(all(feature = "k256-backend", feature = "secp256k1-backend"))]
compile_error!("heartwood-common: `k256-backend` and `secp256k1-backend` are mutually exclusive — enable exactly one");

#[cfg(all(feature = "ledger-backend", any(feature = "k256-backend", feature = "secp256k1-backend")))]
compile_error!("heartwood-common: `ledger-backend` is mutually exclusive with the other curve backends — enable exactly one");

#[cfg(all(feature = "ledger-backend", feature = "mnemonic"))]
compile_error!("heartwood-common: `mnemonic` is unsupported with `ledger-backend` — on a Ledger the BIP-32 walk happens in the OS (os_perso_derive_node_bip32), never in-app");

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::encode_npub;
use crate::types::{Identity, TreeRoot, DOMAIN_PREFIX};
use crate::validate::validate_purpose;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Backend: secret → (valid secp256k1 scalar?, x-only pubkey bytes)
// ---------------------------------------------------------------------------

#[cfg(feature = "k256-backend")]
pub(crate) mod backend {
    use k256::schnorr::SigningKey;

    /// Validate a 32-byte secret as a secp256k1 scalar and return the x-only
    /// public key bytes, or None if the scalar is invalid (zero / ≥ order).
    pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let sk = SigningKey::from_bytes(secret).map_err(|_| "invalid secret key")?;
        Ok(sk.verifying_key().to_bytes().into())
    }

    /// BIP-32 hardened-child scalar step: `(tweak + key) mod n`, used by
    /// `mnemonic::derive_root_secret`. Errors if `tweak` (I_L) is ≥ the curve
    /// order or the sum is zero — both invalid per BIP-32. The backend-agnostic
    /// counterpart of the secp256k1 version, so the mnemonic path derives the
    /// same key on whichever curve backend is active.
    #[cfg(feature = "mnemonic")]
    pub fn tweak_add(key: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        use k256::elliptic_curve::ff::PrimeField;
        let parse = |b: &[u8; 32]| -> Option<k256::Scalar> {
            Option::from(k256::Scalar::from_repr(k256::FieldBytes::from(*b)))
        };
        let k = parse(key).ok_or("BIP-32 parent key out of range")?;
        let t = parse(tweak).ok_or("BIP-32 I_L out of range")?;
        let child = k + t;
        if bool::from(child.is_zero()) {
            return Err("BIP-32 derived a zero key");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(child.to_repr().as_ref());
        Ok(out)
    }
}

#[cfg(feature = "secp256k1-backend")]
pub(crate) mod backend {
    use secp256k1::{Keypair, Secp256k1};

    pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let secp = Secp256k1::signing_only();
        let keypair = Keypair::from_seckey_slice(&secp, secret)
            .map_err(|_| "invalid secret key")?;
        let (xonly, _) = keypair.x_only_public_key();
        Ok(xonly.serialize())
    }

    /// BIP-32 hardened-child scalar step: `(tweak + key) mod n` via secp256k1's
    /// scalar arithmetic. See the k256 backend's `tweak_add` for the contract.
    #[cfg(feature = "mnemonic")]
    pub fn tweak_add(key: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        use secp256k1::{Scalar, SecretKey};
        let parent = SecretKey::from_slice(key).map_err(|_| "BIP-32 parent key out of range")?;
        let t = Scalar::from_be_bytes(*tweak).map_err(|_| "BIP-32 I_L out of range")?;
        let child = parent.add_tweak(&t).map_err(|_| "BIP-32 derived a zero key")?;
        Ok(child.secret_bytes())
    }
}

#[cfg(feature = "ledger-backend")]
pub(crate) mod backend {
    //! Curve ops through the Ledger OS (BOLOS cx syscalls): every
    //! secret-dependent operation — public-key derivation, ECDH — runs in the
    //! secure element's hardened implementation, never in app RAM. Verified
    //! end-to-end by heartwood-ledger's Speculos proof, which checks results
    //! against host-side k256.

    use core::mem::MaybeUninit;

    use ledger_secure_sdk_sys::{
        cx_ecdh_no_throw, cx_ecfp_generate_pair_no_throw, cx_ecfp_init_private_key_no_throw,
        cx_ecfp_private_key_t, cx_ecfp_public_key_t, cx_math_addm_no_throw,
        cx_math_multm_no_throw, cx_math_powm_no_throw, cx_math_subm_no_throw,
        CX_CURVE_SECP256K1, CX_ECDH_X, CX_OK, CX_RND_PROVIDED, CX_SHA256,
    };
    use zeroize::Zeroize;

    // Re-exported so a Ledger app signs through the same backend that derives
    // (one place holds every syscall touching key material).
    pub use signing::sign_bip340;

    /// secp256k1 field prime `p`.
    const P: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xff, 0xff, 0xfc, 0x2f,
    ];
    /// `(p + 1) / 4` — the square-root exponent (valid because p ≡ 3 mod 4).
    const SQRT_EXP: [u8; 32] = [
        0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbf, 0xff, 0xff, 0x0c,
    ];
    const SEVEN: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 7;
        b
    };
    const ZERO: [u8; 32] = [0u8; 32];

    fn init_private_key(secret: &[u8; 32]) -> Result<cx_ecfp_private_key_t, &'static str> {
        let mut pvkey = MaybeUninit::<cx_ecfp_private_key_t>::uninit();
        unsafe {
            if cx_ecfp_init_private_key_no_throw(
                CX_CURVE_SECP256K1,
                secret.as_ptr(),
                secret.len(),
                pvkey.as_mut_ptr(),
            ) != CX_OK
            {
                return Err("invalid secret key");
            }
            Ok(pvkey.assume_init())
        }
    }

    /// Validate a 32-byte secret as a secp256k1 scalar and return the x-only
    /// public key bytes, or an error if the scalar is invalid.
    pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut pvkey = init_private_key(secret)?;
        let mut pubkey = MaybeUninit::<cx_ecfp_public_key_t>::uninit();
        let rc = unsafe {
            cx_ecfp_generate_pair_no_throw(
                CX_CURVE_SECP256K1,
                pubkey.as_mut_ptr(),
                &mut pvkey,
                true, // keep the provided private key
            )
        };
        pvkey.d.zeroize();
        if rc != CX_OK {
            return Err("invalid secret key");
        }
        let pubkey = unsafe { pubkey.assume_init() };
        if pubkey.W_len != 65 {
            return Err("unexpected public key encoding");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&pubkey.W[1..33]);
        Ok(out)
    }

    /// BIP-340 `lift_x`: decompress an x-only key to the uncompressed SEC1
    /// point with even y. Pure public-data maths (the peer's key), via the OS
    /// modular-arithmetic syscalls: y = (x³+7)^((p+1)/4) mod p, negated if odd,
    /// and rejected (not on the curve) unless y² ≡ x³+7.
    fn lift_x_even(x: &[u8; 32]) -> Result<[u8; 65], &'static str> {
        if *x >= P {
            return Err("peer pubkey x out of field range");
        }
        let mut y2 = [0u8; 32];
        let mut y = [0u8; 32];
        let mut check = [0u8; 32];
        unsafe {
            // y2 = x*x*x + 7 mod p
            if cx_math_multm_no_throw(y2.as_mut_ptr(), x.as_ptr(), x.as_ptr(), P.as_ptr(), 32)
                != CX_OK
                || cx_math_multm_no_throw(y2.as_mut_ptr(), y2.as_ptr(), x.as_ptr(), P.as_ptr(), 32)
                    != CX_OK
                || cx_math_addm_no_throw(y2.as_mut_ptr(), y2.as_ptr(), SEVEN.as_ptr(), P.as_ptr(), 32)
                    != CX_OK
                // y = y2 ^ ((p+1)/4) mod p
                || cx_math_powm_no_throw(y.as_mut_ptr(), y2.as_ptr(), SQRT_EXP.as_ptr(), 32, P.as_ptr(), 32)
                    != CX_OK
                // on-curve check: y*y mod p must reproduce y2
                || cx_math_multm_no_throw(check.as_mut_ptr(), y.as_ptr(), y.as_ptr(), P.as_ptr(), 32)
                    != CX_OK
            {
                return Err("field arithmetic failed");
            }
            if check != y2 {
                return Err("peer pubkey is not on the curve");
            }
            if y[31] & 1 == 1 {
                // odd y → take p - y (the even root)
                let mut neg = [0u8; 32];
                if cx_math_subm_no_throw(neg.as_mut_ptr(), ZERO.as_ptr(), y.as_ptr(), P.as_ptr(), 32)
                    != CX_OK
                {
                    return Err("field arithmetic failed");
                }
                y = neg;
            }
        }
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(&y);
        Ok(point)
    }

    /// x-coordinate of the ECDH shared point with an x-only peer key (lifted
    /// with even y, the NIP-44 convention).
    pub fn ecdh_x(our_secret: &[u8; 32], peer_x_only: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let point = lift_x_even(peer_x_only)?;
        let mut pvkey = init_private_key(our_secret)?;
        let mut out = [0u8; 32];
        let rc = unsafe {
            cx_ecdh_no_throw(&pvkey, CX_ECDH_X, point.as_ptr(), point.len(), out.as_mut_ptr(), 32)
        };
        pvkey.d.zeroize();
        if rc != CX_OK {
            return Err("ecdh failed");
        }
        Ok(out)
    }

    mod signing {
        use super::*;

        /// BIP-340 Schnorr sign a 32-byte message on the secure element.
        /// `CX_RND_PROVIDED` reads the aux data from the signature buffer on
        /// entry; it is zeroed, so nonces are deterministic (key + message)
        /// and signing needs no RNG — matching the radio-off ESP signers.
        pub fn sign_bip340(secret: &[u8; 32], message: &[u8; 32]) -> Result<[u8; 64], &'static str> {
            use ledger_secure_sdk_sys::cx_ecschnorr_sign_no_throw;
            const CX_ECSCHNORR_BIP0340: u32 = 0;

            let mut pvkey = super::init_private_key(secret)?;
            let mut sig = [0u8; 64];
            let mut sig_len: usize = sig.len();
            let rc = unsafe {
                cx_ecschnorr_sign_no_throw(
                    &pvkey,
                    CX_ECSCHNORR_BIP0340 | CX_RND_PROVIDED,
                    CX_SHA256,
                    message.as_ptr(),
                    message.len(),
                    sig.as_mut_ptr(),
                    &mut sig_len,
                )
            };
            pvkey.d.zeroize();
            if rc != CX_OK || sig_len != sig.len() {
                return Err("signing failed");
            }
            Ok(sig)
        }
    }
}

#[cfg(not(any(
    feature = "k256-backend",
    feature = "secp256k1-backend",
    feature = "ledger-backend"
)))]
compile_error!("heartwood-common requires exactly one curve backend feature: `k256-backend`, `secp256k1-backend` or `ledger-backend`");

// A Ledger app's own signing/pubkey path goes through the same secure-element
// seam the derivation uses — public re-exports, since `backend` is crate-only.
#[cfg(feature = "ledger-backend")]
pub use backend::{
    pubkey_from_secret as ledger_pubkey_from_secret, sign_bip340 as ledger_sign_bip340,
};

// ---------------------------------------------------------------------------
// Public API (backend-agnostic)
// ---------------------------------------------------------------------------

/// Derive a tree root secret from a raw nsec via HMAC-SHA256.
///
/// Matches PROTOCOL.md §1.2 and the reference implementations in
/// `nsec-tree/src/root-nsec.ts` and `heartwood-core/src/root.rs`:
///
///   tree_root = HMAC-SHA256(key = nsec_bytes, msg = utf8("nsec-tree-root"))
///
/// The returned 32-byte secret can be passed to `create_tree_root` to get a
/// fully usable `TreeRoot` for child derivation. This is the on-demand path
/// used by Bunker mode, where the stored master secret is a raw nsec.
pub fn nsec_to_tree_root(nsec: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    let mut mac = HmacSha256::new_from_slice(nsec)
        .map_err(|_| "HMAC init failed")?;
    mac.update(b"nsec-tree-root");
    let result = mac.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result.into_bytes());
    Ok(zeroize::Zeroizing::new(root))
}

/// Create a TreeRoot directly from a 32-byte secret (no HMAC intermediate).
///
/// The secret goes straight to the signing backend — this is the raw-secret
/// path, NOT the nsec import path (which applies an extra HMAC).
pub fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, &'static str> {
    let pubkey_bytes = backend::pubkey_from_secret(secret)?;
    let npub = encode_npub(&pubkey_bytes);
    Ok(TreeRoot::new(zeroize::Zeroizing::new(*secret), npub))
}

/// Build the HMAC context message for child key derivation.
///
/// Format: `b"nsec-tree\0" || purpose_utf8 || 0x00 || index_u32_big_endian`
fn build_context(purpose: &str, index: u32) -> Vec<u8> {
    let purpose_bytes = purpose.as_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + purpose_bytes.len() + 1 + 4);
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(purpose_bytes);
    msg.push(0x00);
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// Derive a child identity from a TreeRoot.
///
/// Uses HMAC-SHA256 with the root secret as key and a context message
/// containing the domain prefix, purpose, and index. Skips indices that
/// produce invalid secp256k1 scalars.
///
/// The purpose string is validated against PROTOCOL.md §3 rules (non-empty,
/// ≤255 bytes, no null bytes, not whitespace-only, no `|`) before derivation.
/// Previously this function hashed any caller-supplied `&str` without
/// checking, which meant a null byte in purpose would silently corrupt the
/// derivation message framing — an attacker who could inject bytes into a
/// NIP-46 RPC parameter could collide derivations between purposes.
pub fn derive(root: &TreeRoot, purpose: &str, index: u32) -> Result<Identity, &'static str> {
    validate_purpose(purpose)?;

    let secret = root.secret();
    let mut current_index = index;

    loop {
        let context = build_context(purpose, current_index);

        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| "HMAC init failed")?;
        mac.update(&context);
        let result = mac.finalize();
        let mut derived: [u8; 32] = result.into_bytes().into();

        match backend::pubkey_from_secret(&derived) {
            Ok(public_key) => {
                return Ok(Identity {
                    npub: encode_npub(&public_key),
                    private_key: zeroize::Zeroizing::new(derived),
                    public_key,
                    purpose: String::from(purpose),
                    index: current_index,
                });
            }
            Err(_) => {
                derived.zeroize();
                if current_index == u32::MAX {
                    return Err("index overflow: no valid key found");
                }
                current_index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 1 test vector — must match heartwood-core byte-for-byte.
    #[test]
    fn test_child_derivation_matches_heartwood_core() {
        let root_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let root = create_tree_root(&root_secret).unwrap();
        let identity = derive(&root, "persona/test", 0).unwrap();

        assert_eq!(
            identity.npub,
            "npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t",
            "derived npub does not match heartwood-core"
        );
    }

    /// PROTOCOL.md §3.1 + Vector 6 — a persona is the child at purpose
    /// `nostr:persona:<name>`. The signer's `heartwood_derive_persona` builds
    /// exactly this purpose, so a persona reproduces byte-for-byte across the
    /// library, signet, and the nsec-tree CLI. If this drifts, a persona
    /// derived on the device stops matching the same persona elsewhere.
    #[test]
    fn persona_purpose_matches_protocol_vector_6() {
        // tree_root for the abandon…about mnemonic (PROTOCOL Vector 4/6).
        let tree_root: [u8; 32] = [
            0xcc, 0x92, 0xd2, 0x13, 0xb5, 0xec, 0xcd, 0x19,
            0xeb, 0x85, 0xc1, 0x2c, 0x2c, 0xf6, 0xfd, 0x16,
            0x8f, 0x27, 0xc2, 0xcc, 0x34, 0x7c, 0x51, 0xa7,
            0xc4, 0xc6, 0x2a, 0xc6, 0x77, 0x95, 0xfc, 0x65,
        ];
        let root = create_tree_root(&tree_root).unwrap();
        let id = derive(&root, "nostr:persona:social", 0).unwrap();
        assert_eq!(
            id.npub,
            "npub1qdztfxg9z46k8qg4707n747y9rt7kl3f954lju2pneesmc3ypf2q83gm0e",
            "persona derivation drifted from PROTOCOL v1.1 Vector 6"
        );
    }

    /// Persona derivation as the signers actually build it: a persona is the
    /// child at `format!("nostr:persona:{name}")`. Anchors "social"/0 to the
    /// frozen Vector 6 npub, then proves distinct names derive distinct keys —
    /// guarding against a derivation change that stopped binding the persona
    /// name into the HMAC context (which would collide every persona).
    #[test]
    fn persona_names_derive_distinct_anchored_keys() {
        let tree_root: [u8; 32] = [
            0xcc, 0x92, 0xd2, 0x13, 0xb5, 0xec, 0xcd, 0x19,
            0xeb, 0x85, 0xc1, 0x2c, 0x2c, 0xf6, 0xfd, 0x16,
            0x8f, 0x27, 0xc2, 0xcc, 0x34, 0x7c, 0x51, 0xa7,
            0xc4, 0xc6, 0x2a, 0xc6, 0x77, 0x95, 0xfc, 0x65,
        ];
        let root = create_tree_root(&tree_root).unwrap();
        let persona = |name: &str, index: u32| {
            derive(&root, &format!("nostr:persona:{name}"), index).unwrap().npub
        };

        assert_eq!(
            persona("social", 0),
            "npub1qdztfxg9z46k8qg4707n747y9rt7kl3f954lju2pneesmc3ypf2q83gm0e",
            "the device's persona purpose format drifted from Vector 6",
        );

        let names = ["social", "work", "private", "dev"];
        let mut npubs: Vec<String> = names.iter().map(|n| persona(n, 0)).collect();
        npubs.sort();
        npubs.dedup();
        assert_eq!(npubs.len(), names.len(), "persona names must derive distinct keys");
    }

    /// The index is bound into derivation: the same persona at different indices
    /// must differ, and re-deriving a given (purpose, index) is deterministic.
    /// Guards against `build_context` dropping the index.
    #[test]
    fn persona_index_is_bound_and_deterministic() {
        let root = create_tree_root(&[0x42u8; 32]).unwrap();
        let at = |i: u32| derive(&root, "nostr:persona:social", i).unwrap().npub;
        assert_ne!(at(0), at(1), "index must change the derived key");
        assert_ne!(at(1), at(2));
        assert_eq!(at(0), derive(&root, "nostr:persona:social", 0).unwrap().npub);
    }

    /// Bunker (tree-nsec) mode: the device stores a raw nsec and HMACs it to a
    /// tree root on demand (`nsec_to_tree_root`), then derives personas from THAT
    /// root. A persona via this path must be stable across re-derivation and
    /// bound to the master — the same persona name from a different root is a
    /// different key.
    #[test]
    fn tree_nsec_persona_path_is_stable_and_master_bound() {
        let nsec = [0x01u8; 32];
        let root = create_tree_root(&nsec_to_tree_root(&nsec).unwrap()).unwrap();
        let a = derive(&root, "nostr:persona:social", 0).unwrap().npub;

        // Stable: the same nsec → the same persona npub.
        let root2 = create_tree_root(&nsec_to_tree_root(&nsec).unwrap()).unwrap();
        assert_eq!(a, derive(&root2, "nostr:persona:social", 0).unwrap().npub);

        // Master-bound: the same persona name from the mnemonic-vector root differs.
        let other = create_tree_root(&[
            0xcc, 0x92, 0xd2, 0x13, 0xb5, 0xec, 0xcd, 0x19,
            0xeb, 0x85, 0xc1, 0x2c, 0x2c, 0xf6, 0xfd, 0x16,
            0x8f, 0x27, 0xc2, 0xcc, 0x34, 0x7c, 0x51, 0xa7,
            0xc4, 0xc6, 0x2a, 0xc6, 0x77, 0x95, 0xfc, 0x65,
        ]).unwrap();
        assert_ne!(a, derive(&other, "nostr:persona:social", 0).unwrap().npub);
    }

    /// nsec-to-tree-root HMAC vector — must match PROTOCOL.md §6.1 Vector 1
    /// and the reference implementations in nsec-tree and heartwood-core.
    #[test]
    fn test_nsec_to_tree_root_matches_frozen_vector() {
        let nsec_bytes = [0x01u8; 32];
        let root_secret = nsec_to_tree_root(&nsec_bytes).expect("nsec_to_tree_root must succeed");

        assert_eq!(
            crate::hex::hex_encode(&*root_secret),
            "8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f",
            "tree_root does not match PROTOCOL.md §6.1 Vector 1"
        );

        let root = create_tree_root(&root_secret).expect("invalid root secret");
        assert_eq!(
            root.master_npub,
            "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u",
            "master npub does not match PROTOCOL.md §6.1 Vector 1"
        );
        root.destroy();
    }
}
