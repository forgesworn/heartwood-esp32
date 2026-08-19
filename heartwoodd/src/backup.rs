// heartwoodd/src/backup.rs
//
// Encrypted backup envelope creation and decryption, plus passphrase storage.
//
// Uses the same Argon2id + XChaCha20-Poly1305 pattern as soft_store.rs.
// The backup passphrase itself is stored encrypted on disk using
// HMAC-SHA256(api_token, "backup-passphrase") as the XChaCha20-Poly1305 key.
// This way the passphrase is not plaintext on disk, but the running daemon can
// decrypt it using the API token it already holds.
//
// Atomic writes (write-to-tmp, fsync, rename) prevent partial-write corruption
// on power loss.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use heartwood_common::backup::BackupPayload;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub const DEFAULT_M_COST: u32 = 65_536; // 64 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

/// Ceilings for KDF parameters read from an uploaded backup envelope. The
/// envelope is attacker-controlled (any API-token holder can upload one), and
/// unbounded values let a crafted file demand absurd Argon2 resources
/// (m_cost up to ~4 TiB) and abort the daemon (HD-L2).
const MAX_M_COST: u32 = 262_144; // 256 MiB
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 4;

/// Clamp envelope-supplied KDF parameters to sane ceilings before deriving.
/// Clamping rather than rejecting keeps honest envelopes working: anything
/// pushed over the ceiling derives a wrong key and fails at the AEAD step
/// like any other corrupted backup.
fn clamp_kdf_params(p: &KdfParams) -> (u32, u32, u32) {
    (
        p.m_cost.min(MAX_M_COST),
        p.t_cost.min(MAX_T_COST),
        p.p_cost.min(MAX_P_COST),
    )
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// KDF parameters stored inside the backup envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Encrypted backup envelope. Serialised to disk as JSON.
///
/// Contains all parameters needed to re-derive the key and decrypt the backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub version: u32,
    pub kdf: String,
    pub kdf_params: KdfParams,
    /// 32-byte random salt, base64-encoded.
    pub salt: String,
    /// 24-byte random nonce, base64-encoded.
    pub nonce: String,
    /// Encrypted backup JSON, base64-encoded.
    pub ciphertext: String,
}

/// Encrypted passphrase file. Not public -- only used internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PassphraseEnvelope {
    /// 24-byte random nonce, base64-encoded.
    nonce: String,
    /// XChaCha20-Poly1305 ciphertext of the passphrase UTF-8 bytes, base64-encoded.
    ciphertext: String,
}

/// Metadata about a backup file, readable without decrypting.
#[derive(Debug, Clone)]
pub struct BackupStatus {
    pub version: u32,
    /// Unix timestamp from the decrypted payload's `created_at` field.
    /// Approximated here as the file's last-modified time.
    pub last_modified: u64,
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

/// Encrypt a `BackupPayload` with a new random salt and nonce.
///
/// Returns a `BackupEnvelope` ready to serialise and write to disk.
pub fn encrypt_backup(
    payload: &BackupPayload,
    passphrase: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<BackupEnvelope, String> {
    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom salt: {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("getrandom nonce: {e}"))?;

    let key = derive_key(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost)?;

    let plaintext =
        serde_json::to_vec(payload).map_err(|e| format!("serialise backup payload: {e}"))?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), plaintext.as_slice())
        .map_err(|_| "encryption failed".to_string())?;

    Ok(BackupEnvelope {
        version: 1,
        kdf: "argon2id".to_string(),
        kdf_params: KdfParams {
            m_cost,
            t_cost,
            p_cost,
        },
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Decrypt a `BackupEnvelope` using `passphrase`.
///
/// Returns the plaintext `BackupPayload`.
pub fn decrypt_backup(
    envelope: &BackupEnvelope,
    passphrase: &str,
) -> Result<BackupPayload, String> {
    let salt = B64
        .decode(&envelope.salt)
        .map_err(|e| format!("base64 salt: {e}"))?;
    let nonce_bytes = B64
        .decode(&envelope.nonce)
        .map_err(|e| format!("base64 nonce: {e}"))?;
    let ciphertext = B64
        .decode(&envelope.ciphertext)
        .map_err(|e| format!("base64 ciphertext: {e}"))?;

    let (m_cost, t_cost, p_cost) = clamp_kdf_params(&envelope.kdf_params);
    let key = derive_key(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(format!(
            "invalid nonce length: expected {NONCE_LEN}, got {}",
            nonce_bytes.len()
        ));
    }
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(cipher
        .decrypt(nonce_arr.as_ref().into(), ciphertext.as_slice())
        .map_err(|_| "wrong passphrase or corrupted ciphertext".to_string())?);

    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("deserialise backup payload: {e}"))?;

    Ok(payload)
}

// ---------------------------------------------------------------------------
// Passphrase wrapping
// ---------------------------------------------------------------------------

/// Derive a 32-byte wrapping key from an API token.
///
/// Uses HMAC-SHA256(api_token, "backup-passphrase") so the passphrase file
/// is bound to the API token and cannot be decrypted without it.
fn passphrase_wrapping_key(api_token: &str) -> Zeroizing<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(api_token.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(b"backup-passphrase");
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    key
}

/// Read the backup passphrase from `path`.
///
/// Fails closed when no passphrase file exists: backups encrypt the bridge
/// secret and every connection-slot secret, so we never fall back to a
/// publicly known default passphrase. The operator must set one explicitly
/// first (PUT /api/backup/passphrase, no old passphrase required on initial
/// set). If the file exists, decrypts and returns the stored passphrase.
pub fn read_passphrase(path: &Path, api_token: &str) -> Result<String, String> {
    if !path.exists() {
        return Err(
            "no backup passphrase set — set one via PUT /api/backup/passphrase before creating backups"
                .to_string(),
        );
    }

    let data = fs::read_to_string(path)
        .map_err(|e| format!("read passphrase file: {e}"))?;
    let env: PassphraseEnvelope = serde_json::from_str(&data)
        .map_err(|e| format!("parse passphrase file: {e}"))?;

    let nonce_bytes = B64
        .decode(&env.nonce)
        .map_err(|e| format!("base64 passphrase nonce: {e}"))?;
    let ciphertext = B64
        .decode(&env.ciphertext)
        .map_err(|e| format!("base64 passphrase ciphertext: {e}"))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(format!(
            "invalid passphrase nonce length: expected {NONCE_LEN}, got {}",
            nonce_bytes.len()
        ));
    }
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();

    let wrapping_key = passphrase_wrapping_key(api_token);
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let plaintext = cipher
        .decrypt(nonce_arr.as_ref().into(), ciphertext.as_slice())
        .map_err(|_| "wrong api token or corrupted passphrase file".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("passphrase utf-8: {e}"))
}

/// Encrypt `passphrase` with a key derived from `api_token` and write atomically to `path`.
pub fn write_passphrase(path: &Path, passphrase: &str, api_token: &str) -> Result<(), String> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("getrandom passphrase nonce: {e}"))?;

    let wrapping_key = passphrase_wrapping_key(api_token);
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), passphrase.as_bytes())
        .map_err(|_| "passphrase encryption failed".to_string())?;

    let env = PassphraseEnvelope {
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    };

    let json = serde_json::to_string_pretty(&env)
        .map_err(|e| format!("serialise passphrase envelope: {e}"))?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("create passphrase tmp file: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("write passphrase tmp file: {e}"))?;
        file.flush()
            .map_err(|e| format!("flush passphrase tmp file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("fsync passphrase tmp file: {e}"))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("rename passphrase tmp to final: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Write a `BackupEnvelope` to `path` atomically.
///
/// Writes to `path.tmp`, fsyncs, then renames over `path`. This prevents
/// a partial write from leaving a corrupted backup after power loss. The tmp
/// file is created with mode 0600 (matching api-token/vault.key): encrypted
/// or not, it is offline-crackable material (HD-L6).
pub fn write_backup(path: &Path, envelope: &BackupEnvelope) -> Result<(), String> {
    let json = serde_json::to_string_pretty(envelope)
        .map_err(|e| format!("serialise backup envelope: {e}"))?;

    let tmp_path = path.with_extension("tmp");

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("create backup tmp file: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("write backup tmp file: {e}"))?;
        file.flush()
            .map_err(|e| format!("flush backup tmp file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("fsync backup tmp file: {e}"))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("rename backup tmp to final: {e}"))?;

    Ok(())
}

/// Read and parse a `BackupEnvelope` from `path`.
pub fn read_backup(path: &Path) -> Result<BackupEnvelope, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read backup file: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse backup file: {e}"))
}

/// Return metadata about a backup file without decrypting it.
///
/// Returns `None` if the file does not exist or cannot be parsed.
pub fn backup_status(path: &Path) -> Option<BackupStatus> {
    let envelope = read_backup(path).ok()?;

    let last_modified = path
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Some(BackupStatus {
        version: envelope.version,
        last_modified,
    })
}

/// Current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use heartwood_common::backup::BackupMaster;

    // Low-cost Argon2 params for fast tests -- never use in production.
    const M: u32 = 256;
    const T: u32 = 1;
    const P: u32 = 1;

    fn test_payload() -> BackupPayload {
        BackupPayload {
            created_at: 1_700_000_000,
            device_id: "ab".repeat(32),
            bridge_secret: "cd".repeat(32),
            masters: vec![BackupMaster {
                slot: 0,
                label: "personal".to_string(),
                mode: 1,
                pubkey: "ef".repeat(32),
                connection_slots: vec![],
            }],
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let payload = test_payload();
        let env = encrypt_backup(&payload, "hunter2", M, T, P).unwrap();
        let decrypted = decrypt_backup(&env, "hunter2").unwrap();

        assert_eq!(decrypted.created_at, payload.created_at);
        assert_eq!(decrypted.device_id, payload.device_id);
        assert_eq!(decrypted.bridge_secret, payload.bridge_secret);
        assert_eq!(decrypted.masters.len(), 1);
        assert_eq!(decrypted.masters[0].slot, 0);
        assert_eq!(decrypted.masters[0].label, "personal");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let payload = test_payload();
        let env = encrypt_backup(&payload, "correct", M, T, P).unwrap();
        let err = decrypt_backup(&env, "wrong").unwrap_err();
        assert!(
            err.contains("wrong passphrase"),
            "expected 'wrong passphrase' in error, got: {err}"
        );
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let payload = test_payload();
        let env = encrypt_backup(&payload, "pass", M, T, P).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let env2: BackupEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(env2.version, env.version);
        assert_eq!(env2.kdf, env.kdf);
        assert_eq!(env2.salt, env.salt);
        assert_eq!(env2.nonce, env.nonce);
        assert_eq!(env2.ciphertext, env.ciphertext);
    }

    #[test]
    fn passphrase_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup-passphrase.json");

        write_passphrase(&path, "my-secret-passphrase", "api-token-abc").unwrap();
        let result = read_passphrase(&path, "api-token-abc").unwrap();

        assert_eq!(result, "my-secret-passphrase");
    }

    #[test]
    fn passphrase_missing_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup-passphrase.json");

        // File does not exist yet.
        assert!(!path.exists());

        let err = read_passphrase(&path, "any-token").unwrap_err();

        // No default passphrase, and no file is created.
        assert!(
            err.contains("no backup passphrase set"),
            "expected 'no backup passphrase set' in error, got: {err}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn passphrase_wrong_token_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup-passphrase.json");

        write_passphrase(&path, "secret", "token-a").unwrap();
        let err = read_passphrase(&path, "token-b").unwrap_err();

        assert!(
            err.contains("wrong api token"),
            "expected 'wrong api token' in error, got: {err}"
        );
    }

    #[test]
    fn backup_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");

        let payload = test_payload();
        let env = encrypt_backup(&payload, "pass", M, T, P).unwrap();
        write_backup(&path, &env).unwrap();

        assert!(path.exists());
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists());

        let env2 = read_backup(&path).unwrap();
        let decrypted = decrypt_backup(&env2, "pass").unwrap();

        assert_eq!(decrypted.created_at, payload.created_at);
        assert_eq!(decrypted.bridge_secret, payload.bridge_secret);
        assert_eq!(decrypted.masters.len(), 1);
    }

    #[test]
    fn backup_status_reads_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");

        let payload = test_payload();
        let env = encrypt_backup(&payload, "pass", M, T, P).unwrap();
        write_backup(&path, &env).unwrap();

        let status = backup_status(&path).unwrap();
        assert_eq!(status.version, 1);
        assert!(status.last_modified > 0, "last_modified should be non-zero");
    }

    #[test]
    fn backup_status_returns_none_for_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let status = backup_status(&path);
        assert!(status.is_none());
    }

    #[test]
    fn kdf_params_are_clamped_to_ceilings() {
        // Attacker-crafted envelope values are pulled down to the ceilings
        // (HD-L2) rather than fed to Argon2 unbounded.
        let hostile = KdfParams {
            m_cost: u32::MAX,
            t_cost: u32::MAX,
            p_cost: u32::MAX,
        };
        assert_eq!(
            clamp_kdf_params(&hostile),
            (MAX_M_COST, MAX_T_COST, MAX_P_COST)
        );

        // Honest envelopes (at or below the ceilings) pass through untouched.
        let honest = KdfParams {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        };
        assert_eq!(
            clamp_kdf_params(&honest),
            (DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)
        );
    }

    #[test]
    fn backup_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");

        let payload = test_payload();
        let env = encrypt_backup(&payload, "pass", M, T, P).unwrap();
        write_backup(&path, &env).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn passphrase_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup-passphrase.json");
        write_passphrase(&path, "my-secret-passphrase", "api-token-abc").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
