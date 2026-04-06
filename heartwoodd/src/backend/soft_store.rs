// Encrypted keyfile read/write for Soft mode.
//
// Keys are stored on disk as an Argon2id-derived XChaCha20-Poly1305
// ciphertext envelope. The plaintext is a JSON-serialised `Keystore`.
// Atomic writes (write-to-tmp, fsync, rename) prevent partial-write
// corruption on power loss.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use heartwood_common::policy::ConnectSlot;

// ---------------------------------------------------------------------------
// KDF constants
// ---------------------------------------------------------------------------

pub const DEFAULT_M_COST: u32 = 65_536; // 64 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Serialised to disk as JSON. Contains all parameters needed to re-derive
/// the encryption key and decrypt the keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEnvelope {
    pub version: u32,
    pub kdf: String,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    /// 32-byte random salt, base64-encoded.
    pub salt: String,
    /// 24-byte random nonce, base64-encoded.
    pub nonce: String,
    /// Encrypted keystore JSON, base64-encoded.
    pub ciphertext: String,
}

/// In-memory keystore, held after unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub masters: Vec<SoftMaster>,
}

/// A single master identity held in Soft mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftMaster {
    pub slot: u8,
    pub label: String,
    /// 64 hex chars (32-byte secret key).
    pub secret_key: String,
    /// Always "soft" for this backend.
    pub mode: String,
    pub connection_slots: Vec<ConnectSlot>,
}

// ---------------------------------------------------------------------------
// Internal KDF
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `passphrase` and `salt` using Argon2id.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| format!("argon2 kdf error: {e}"))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Public crypto functions
// ---------------------------------------------------------------------------

/// Encrypt a `Keystore` with a new random salt and nonce.
///
/// Returns a `KeystoreEnvelope` ready to serialise and write to disk.
pub fn encrypt_keystore(
    keystore: &Keystore,
    passphrase: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeystoreEnvelope, String> {
    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom salt: {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("getrandom nonce: {e}"))?;

    let key = derive_key(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost)?;

    let plaintext =
        serde_json::to_vec(keystore).map_err(|e| format!("serialise keystore: {e}"))?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), plaintext.as_slice())
        .map_err(|_| "encryption failed".to_string())?;

    Ok(KeystoreEnvelope {
        version: 1,
        kdf: "argon2id".to_string(),
        argon2_m_cost: m_cost,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Decrypt a `KeystoreEnvelope` using `passphrase`.
///
/// Returns the decrypted `Keystore` and the derived key. The key is returned
/// so the caller can cache it for re-encryption without prompting for the
/// passphrase again.
pub fn decrypt_keystore(
    envelope: &KeystoreEnvelope,
    passphrase: &str,
) -> Result<(Keystore, Zeroizing<[u8; 32]>), String> {
    let salt = B64
        .decode(&envelope.salt)
        .map_err(|e| format!("base64 salt: {e}"))?;
    let nonce_bytes = B64
        .decode(&envelope.nonce)
        .map_err(|e| format!("base64 nonce: {e}"))?;
    let ciphertext = B64
        .decode(&envelope.ciphertext)
        .map_err(|e| format!("base64 ciphertext: {e}"))?;

    let key = derive_key(
        passphrase.as_bytes(),
        &salt,
        envelope.argon2_m_cost,
        envelope.argon2_t_cost,
        envelope.argon2_p_cost,
    )?;

    // chacha20poly1305 needs a fixed-size [u8; 24] nonce reference.
    if nonce_bytes.len() != NONCE_LEN {
        return Err(format!(
            "invalid nonce length: expected {NONCE_LEN}, got {}",
            nonce_bytes.len()
        ));
    }
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher
        .decrypt(nonce_arr.as_ref().into(), ciphertext.as_slice())
        .map_err(|_| "wrong passphrase or corrupted ciphertext".to_string())?;

    let keystore: Keystore = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("deserialise keystore: {e}"))?;

    Ok((keystore, key))
}

/// Re-encrypt a `Keystore` with the already-derived `key`.
///
/// A fresh nonce is generated each time. The original salt is preserved so
/// the caller does not need to re-derive the key from the passphrase.
pub fn reencrypt_keystore(
    keystore: &Keystore,
    key: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &str,
) -> Result<KeystoreEnvelope, String> {
    // Fresh nonce, same salt.
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("getrandom nonce: {e}"))?;

    let plaintext =
        serde_json::to_vec(keystore).map_err(|e| format!("serialise keystore: {e}"))?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), plaintext.as_slice())
        .map_err(|_| "encryption failed".to_string())?;

    Ok(KeystoreEnvelope {
        version: 1,
        kdf: "argon2id".to_string(),
        argon2_m_cost: m_cost,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        salt: salt.to_string(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Write a `KeystoreEnvelope` to `path` atomically.
///
/// Writes to `path.tmp`, fsyncs, then renames over `path`. This prevents
/// a partial write from leaving a corrupted keyfile after power loss.
pub fn write_envelope(path: &Path, envelope: &KeystoreEnvelope) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(envelope).map_err(|e| format!("serialise envelope: {e}"))?;

    let tmp_path = path.with_extension("tmp");

    {
        let mut file =
            File::create(&tmp_path).map_err(|e| format!("create tmp file: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("write tmp file: {e}"))?;
        file.flush().map_err(|e| format!("flush tmp file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("fsync tmp file: {e}"))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("rename tmp to keyfile: {e}"))?;

    Ok(())
}

/// Read and parse a `KeystoreEnvelope` from `path`.
pub fn read_envelope(path: &Path) -> Result<KeystoreEnvelope, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read keyfile: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse keyfile: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Low-cost Argon2 params for fast tests -- never use in production.
    const M: u32 = 256;
    const T: u32 = 1;
    const P: u32 = 1;

    fn test_keystore() -> Keystore {
        Keystore {
            masters: vec![SoftMaster {
                slot: 0,
                label: "personal".to_string(),
                secret_key: "a".repeat(64),
                mode: "soft".to_string(),
                connection_slots: vec![],
            }],
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ks = test_keystore();
        let env = encrypt_keystore(&ks, "hunter2", M, T, P).unwrap();
        let (decrypted, _key) = decrypt_keystore(&env, "hunter2").unwrap();
        assert_eq!(decrypted.masters.len(), 1);
        let m = &decrypted.masters[0];
        assert_eq!(m.slot, 0);
        assert_eq!(m.label, "personal");
        assert_eq!(m.secret_key, "a".repeat(64));
        assert_eq!(m.mode, "soft");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ks = test_keystore();
        let env = encrypt_keystore(&ks, "correct", M, T, P).unwrap();
        let err = decrypt_keystore(&env, "wrong").unwrap_err();
        assert!(
            err.contains("wrong passphrase"),
            "expected 'wrong passphrase' in error, got: {err}"
        );
    }

    #[test]
    fn reencrypt_produces_different_ciphertext() {
        let ks = test_keystore();
        let env1 = encrypt_keystore(&ks, "pass", M, T, P).unwrap();
        let (ks2, key) = decrypt_keystore(&env1, "pass").unwrap();

        let env2 = reencrypt_keystore(&ks2, &key, M, T, P, &env1.salt).unwrap();

        // Different ciphertext and nonce due to fresh random nonce.
        assert_ne!(env2.ciphertext, env1.ciphertext);
        assert_ne!(env2.nonce, env1.nonce);
        // Salt is preserved.
        assert_eq!(env2.salt, env1.salt);

        // Re-encrypted envelope must decrypt correctly.
        let (ks3, _) = decrypt_keystore(&env2, "pass").unwrap();
        assert_eq!(ks3.masters.len(), ks2.masters.len());
        assert_eq!(ks3.masters[0].label, ks2.masters[0].label);
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let ks = test_keystore();
        let env = encrypt_keystore(&ks, "pass", M, T, P).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let env2: KeystoreEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env2.version, env.version);
        assert_eq!(env2.kdf, env.kdf);
        assert_eq!(env2.salt, env.salt);
        assert_eq!(env2.nonce, env.nonce);
        assert_eq!(env2.ciphertext, env.ciphertext);
    }

    #[test]
    fn atomic_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");

        let ks = test_keystore();
        let env = encrypt_keystore(&ks, "pass", M, T, P).unwrap();

        write_envelope(&path, &env).unwrap();

        // File must exist, .tmp must be gone.
        assert!(path.exists());
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists());

        // Read back and decrypt.
        let env2 = read_envelope(&path).unwrap();
        let (ks2, _) = decrypt_keystore(&env2, "pass").unwrap();
        assert_eq!(ks2.masters[0].label, "personal");
    }

    #[test]
    fn empty_keystore_roundtrip() {
        let ks = Keystore { masters: vec![] };
        let env = encrypt_keystore(&ks, "empty", M, T, P).unwrap();
        let (decrypted, _) = decrypt_keystore(&env, "empty").unwrap();
        assert!(decrypted.masters.is_empty());
    }

    #[test]
    fn multiple_masters_roundtrip() {
        let ks = Keystore {
            masters: vec![
                SoftMaster {
                    slot: 0,
                    label: "personal".to_string(),
                    secret_key: "0".repeat(64),
                    mode: "soft".to_string(),
                    connection_slots: vec![],
                },
                SoftMaster {
                    slot: 1,
                    label: "work".to_string(),
                    secret_key: "1".repeat(64),
                    mode: "soft".to_string(),
                    connection_slots: vec![],
                },
            ],
        };
        let env = encrypt_keystore(&ks, "multi", M, T, P).unwrap();
        let (decrypted, _) = decrypt_keystore(&env, "multi").unwrap();
        assert_eq!(decrypted.masters.len(), 2);
        assert_eq!(decrypted.masters[0].slot, 0);
        assert_eq!(decrypted.masters[0].label, "personal");
        assert_eq!(decrypted.masters[1].slot, 1);
        assert_eq!(decrypted.masters[1].label, "work");
    }
}
