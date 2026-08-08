// heartwoodd/src/vault.rs
//
// Vault-key storage for Hard-mode at-rest encryption.
//
// The vault key is a 32-byte random secret generated and held by the host --
// it is never stored on the device. The device wraps its master seeds under
// this key (VAULT_SET, 0x62) and decrypts them when the host delivers the key
// again (VAULT_UNLOCK, 0x63). File storage mirrors the API-token pattern:
// hex-encoded, mode 0600, inside the daemon data dir.
//
// Security notes:
//   * The key is a 256-bit bearer credential -- never log it, not even
//     partially, and zeroize in-RAM copies after each use (callers' duty).
//   * Generation is lazy (first vault operation, not every boot) so hosts
//     that never enable the vault never carry an unused credential on disk.

use std::io::Write;
use std::path::{Path, PathBuf};

use heartwood_common::hex::{hex_decode, hex_encode};

/// Filename of the vault key inside the data dir.
pub const VAULT_KEY_FILENAME: &str = "vault.key";

/// Path to the vault key file for a given data dir.
pub fn vault_key_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join(VAULT_KEY_FILENAME)
}

/// Decode a 64-character hex string into a 32-byte vault key.
/// Surrounding whitespace is tolerated (hand-edited files, trailing newline).
pub fn decode_vault_key_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!(
            "vault key must be 64 hex chars (32 bytes), got {} chars",
            s.len()
        ));
    }
    let bytes = hex_decode(s).map_err(|e| format!("vault key is not valid hex: {e}"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Load the vault key from `path`, if present.
///
/// Returns Ok(None) when the file does not exist; Err when it exists but is
/// unreadable or malformed. A malformed key must surface loudly rather than
/// masquerade as "no key", or the operator would never notice their escrowed
/// copy drifting from what the daemon actually uses.
pub fn load_vault_key(path: &Path) -> Result<Option<[u8; 32]>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let hex = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let key = decode_vault_key_hex(&hex)
        .map_err(|e| format!("{}: {e} -- delete the file to regenerate", path.display()))?;
    Ok(Some(key))
}

/// Load the vault key, generating a fresh one (32 random bytes, hex-encoded,
/// file mode 0600) when the file does not exist yet.
pub fn load_or_generate_vault_key(path: &Path) -> Result<[u8; 32], String> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(key) = load_vault_key(path)? {
        return Ok(key);
    }

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| format!("getrandom vault key: {e}"))?;
    let hex = hex_encode(&key);

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(hex.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))?;

    Ok(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_generate_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_KEY_FILENAME);

        let key = load_or_generate_vault_key(&path).unwrap();
        assert_ne!(key, [0u8; 32], "random key should not be all zeroes");

        let loaded = load_vault_key(&path).unwrap().expect("key file written");
        assert_eq!(key, loaded);

        // A second call reuses the existing file rather than regenerating.
        let again = load_or_generate_vault_key(&path).unwrap();
        assert_eq!(key, again);
    }

    #[test]
    fn generated_file_is_64_hex_chars_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_KEY_FILENAME);
        load_or_generate_vault_key(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.len(), 64);
        assert!(contents.chars().all(|c| c.is_ascii_hexdigit()));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_KEY_FILENAME);
        assert_eq!(load_vault_key(&path).unwrap(), None);
    }

    #[test]
    fn rejects_wrong_length_hex() {
        assert!(decode_vault_key_hex("abcd").is_err());
        assert!(decode_vault_key_hex(&"a".repeat(62)).is_err());
        assert!(decode_vault_key_hex(&"a".repeat(66)).is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let bad = format!("{}zz", "a".repeat(62));
        assert!(decode_vault_key_hex(&bad).is_err());
    }

    #[test]
    fn accepts_uppercase_and_surrounding_whitespace() {
        let hex = "AB".repeat(32);
        let key = decode_vault_key_hex(&format!("  {hex}\n")).unwrap();
        assert_eq!(key, [0xABu8; 32]);
    }

    #[test]
    fn malformed_file_is_error_not_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_KEY_FILENAME);
        std::fs::write(&path, "not-hex").unwrap();
        assert!(load_vault_key(&path).is_err());
    }

    #[test]
    fn vault_set_payload_length_contract() {
        // The device accepts exactly 0 (disable) or 32 (enable) payload bytes
        // for VAULT_SET; assert the frames we build honour that contract.
        use heartwood_common::frame;
        use heartwood_common::types::FRAME_TYPE_VAULT_SET;

        let enable = frame::build_frame(FRAME_TYPE_VAULT_SET, &[0u8; 32]).unwrap();
        let parsed = frame::parse_frame(&enable).unwrap();
        assert_eq!(parsed.payload.len(), 32);

        let disable = frame::build_frame(FRAME_TYPE_VAULT_SET, &[]).unwrap();
        let parsed = frame::parse_frame(&disable).unwrap();
        assert!(parsed.payload.is_empty());
    }
}
