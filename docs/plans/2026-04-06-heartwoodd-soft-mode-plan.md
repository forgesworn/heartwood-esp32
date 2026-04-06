# Heartwoodd Soft Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `bridge/` into a tier-aware `heartwoodd/` daemon that runs as either Hard (ESP32) or Soft (Pi-only with Argon2id-encrypted keyfile) from the same binary.

**Architecture:** A `SigningBackend` trait with two implementations (`SerialBackend` for Hard, `SoftBackend` for Soft). The relay event loop, management API, and Sapwood serving are shared; only the backend differs. Auto-detection at startup with `--mode` CLI override.

**Tech Stack:** Rust, Axum, nostr-sdk, k256, argon2, chacha20poly1305

**Spec:** `docs/plans/2026-04-06-heartwoodd-soft-mode-design.md`

---

## File map

### New files

| File | Responsibility |
|------|---------------|
| `heartwoodd/src/backend/mod.rs` | `SigningBackend` trait, `Tier` enum, `BackendError` enum |
| `heartwoodd/src/backend/serial.rs` | `SerialBackend` -- wraps existing ESP32 serial code behind the trait |
| `heartwoodd/src/backend/soft.rs` | `SoftBackend` -- local signing, slot management, approval queue |
| `heartwoodd/src/backend/soft_store.rs` | Encrypted keyfile read/write (Argon2id + XChaCha20-Poly1305) |
| `heartwoodd/src/serial.rs` | `RawSerial` POSIX wrapper (extracted from `main.rs` lines 46-125) |
| `heartwoodd/src/relay.rs` | NIP-46 relay event loop (extracted from `main.rs` lines 854-1015) |

### Modified files

| File | Changes |
|------|---------|
| `heartwoodd/Cargo.toml` | Rename package, add argon2/chacha20poly1305/uuid/getrandom/base64 deps |
| `heartwoodd/src/main.rs` | Slim down to CLI args, auto-detect, backend construction, startup orchestration |
| `heartwoodd/src/api.rs` | Replace `Arc<Mutex<RawSerial>>` with `Arc<dyn SigningBackend>`, add `/api/info`, `/api/unlock`, `/api/approvals` |

---

### Task 1: Rename crate and add dependencies

**Files:**
- Rename: `bridge/` -> `heartwoodd/`
- Modify: `heartwoodd/Cargo.toml`

- [ ] **Step 1: Rename the directory**

```bash
cd ~/WebstormProjects/heartwood-esp32
git mv bridge heartwoodd
```

- [ ] **Step 2: Update Cargo.toml package metadata**

In `heartwoodd/Cargo.toml`, change the package section and add new dependencies:

```toml
[package]
name = "heartwoodd"
version = "0.2.0"
edition = "2021"
description = "Heartwood daemon -- Nostr signing service for Pi (Soft mode) and ESP32 (Hard mode)"
```

Add to `[dependencies]`:

```toml
argon2 = "0.5"
chacha20poly1305 = "0.10"
uuid = { version = "1", features = ["v4"] }
getrandom = "0.2"
base64 = "0.22"
k256 = { version = "0.13", features = ["ecdsa", "schnorr"] }
```

The `k256` dep is new to the daemon (previously only in `common/`). The daemon needs it directly for Soft-mode signing.

- [ ] **Step 3: Update comment headers**

In `heartwoodd/src/main.rs`, replace the opening comment block (lines 1-22) with:

```rust
// heartwoodd/src/main.rs
//
// Heartwood daemon -- Nostr signing service.
//
// Two operating modes from the same binary:
//
//   Hard mode (ESP32 attached via USB serial):
//     Delegates all signing to the ESP32. Pi is zero-trust plumbing.
//     ESP32 holds keys, makes all signing decisions, button press required.
//
//   Soft mode (Pi alone, no ESP32):
//     Signs locally with keys encrypted at rest (Argon2id + XChaCha20-Poly1305).
//     Unlocked via Sapwood web UI. Policy-based auto-approve with Sapwood
//     approval queue for out-of-policy requests.
//
// Mode is auto-detected at startup (probe for ESP32, fall back to Soft)
// or overridden with --mode <soft|hard|auto>.
```

In `heartwoodd/src/api.rs`, change line 1:

```rust
// heartwoodd/src/api.rs
```

- [ ] **Step 4: Verify build**

```bash
cd ./heartwoodd && cargo build
```

Expected: compiles with no errors (warnings about unused deps are fine at this stage).

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add -A heartwoodd bridge
git commit -m "refactor: rename bridge/ to heartwoodd/, add Soft mode deps"
```

---

### Task 2: Define the SigningBackend trait

**Files:**
- Create: `heartwoodd/src/backend/mod.rs`

- [ ] **Step 1: Create the backend module directory**

```bash
mkdir -p ./heartwoodd/src/backend
```

- [ ] **Step 2: Write the trait, enums, and object-safety test**

Create `heartwoodd/src/backend/mod.rs`:

```rust
// heartwoodd/src/backend/mod.rs
//
// SigningBackend trait -- the abstraction boundary between the daemon
// (relay loop, management API) and the signing implementation
// (ESP32 serial or local keyfile).

pub mod serial;
pub mod soft;
pub mod soft_store;

use serde_json::Value;
use std::fmt;

/// Which tier the daemon is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Soft,
    Hard,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Soft => write!(f, "soft"),
            Tier::Hard => write!(f, "hard"),
        }
    }
}

/// Errors returned by backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// Operation not supported in this tier (e.g. OTA on Soft, unlock on Hard).
    NotSupported,
    /// Soft mode: passphrase not yet entered.
    Locked,
    /// Hard mode: serial port mutex contention.
    DeviceBusy,
    /// Hard mode: ESP32 did not respond within timeout.
    DeviceTimeout,
    /// User rejected the request (button press denied or Sapwood denial).
    Denied,
    /// Request is pending approval in the Sapwood queue. Contains the approval ID.
    PendingApproval(String),
    /// Internal error with a descriptive message.
    Internal(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotSupported => write!(f, "operation not supported in this tier"),
            BackendError::Locked => write!(f, "daemon is locked -- unlock via Sapwood first"),
            BackendError::DeviceBusy => write!(f, "device busy -- signing in progress"),
            BackendError::DeviceTimeout => write!(f, "device did not respond"),
            BackendError::Denied => write!(f, "request denied"),
            BackendError::PendingApproval(id) => write!(f, "pending approval: {id}"),
            BackendError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

/// The core abstraction over Hard (ESP32 serial) and Soft (local keyfile) signing.
///
/// All methods are `&self` for object safety. Interior mutability (RwLock, Mutex)
/// is the responsibility of each implementation.
pub trait SigningBackend: Send + Sync {
    /// Which tier this backend is running in.
    fn tier(&self) -> Tier;

    /// Whether the backend is locked (Soft: passphrase not entered; Hard: always false).
    fn is_locked(&self) -> bool;

    // -- Unlock/lock (Soft only) --

    /// Unlock the keystore with the given passphrase. Hard mode returns NotSupported.
    fn unlock(&self, passphrase: &str) -> Result<(), BackendError>;

    /// Lock the keystore, zeroizing all in-memory secrets. Hard mode returns NotSupported.
    fn lock(&self) -> Result<(), BackendError>;

    // -- NIP-46 signing pipeline --

    /// Process an encrypted NIP-46 request. In Hard mode, forwards ciphertext to
    /// ESP32 via ENCRYPTED_REQUEST frame. In Soft mode, decrypts locally, processes
    /// the NIP-46 JSON-RPC, and re-encrypts the response.
    ///
    /// Returns the response ciphertext (base64 NIP-44).
    fn handle_encrypted_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        ciphertext: &str,
    ) -> Result<String, BackendError>;

    /// Build and sign a kind:24133 envelope event wrapping the given ciphertext.
    /// In Hard mode, delegates to ESP32 via SIGN_ENVELOPE frame. In Soft mode,
    /// builds and signs locally with k256.
    ///
    /// Returns the fully serialised signed event JSON.
    fn sign_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError>;

    // -- Master/slot management --

    fn list_masters(&self) -> Result<Vec<Value>, BackendError>;
    fn list_slots(&self, master: u8) -> Result<Value, BackendError>;
    fn create_slot(&self, master: u8, label: &str) -> Result<Value, BackendError>;
    fn update_slot(&self, master: u8, index: u8, patch: Value) -> Result<Value, BackendError>;
    fn revoke_slot(&self, master: u8, index: u8) -> Result<Value, BackendError>;
    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String]) -> Result<String, BackendError>;

    // -- Master provisioning (Soft only) --

    /// Create a new master identity. Generates a keypair, adds to keystore,
    /// returns master info including npub. Hard mode returns NotSupported
    /// (use the provision CLI tool for ESP32).
    fn create_master(&self, label: &str) -> Result<Value, BackendError> {
        Err(BackendError::NotSupported)
    }

    // -- Approval queue (Soft only, default no-ops for Hard) --

    fn list_approvals(&self) -> Vec<Value> { vec![] }
    fn approve_request(&self, id: &str) -> Result<(), BackendError> { Err(BackendError::NotSupported) }
    fn deny_request(&self, id: &str) -> Result<(), BackendError> { Err(BackendError::NotSupported) }

    // -- Device operations --

    /// Wipe all keys and configuration. Hard mode: sends FACTORY_RESET frame
    /// (requires button press). Soft mode: deletes the keystore file.
    fn factory_reset(&self) -> Result<(), BackendError>;

    /// Upload firmware to ESP32 via OTA. Soft mode returns NotSupported.
    fn ota_upload(&self, firmware: &[u8]) -> Result<(), BackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Minimal mock to verify the trait is object-safe (can be used as dyn).
    struct MockBackend;

    impl SigningBackend for MockBackend {
        fn tier(&self) -> Tier { Tier::Soft }
        fn is_locked(&self) -> bool { false }
        fn unlock(&self, _: &str) -> Result<(), BackendError> { Ok(()) }
        fn lock(&self) -> Result<(), BackendError> { Ok(()) }
        fn handle_encrypted_request(&self, _: &[u8; 32], _: &[u8; 32], _: &str) -> Result<String, BackendError> {
            Ok("mock".into())
        }
        fn sign_envelope(&self, _: &[u8; 32], _: &[u8; 32], _: u64, _: &str) -> Result<String, BackendError> {
            Ok("mock".into())
        }
        fn list_masters(&self) -> Result<Vec<Value>, BackendError> { Ok(vec![]) }
        fn list_slots(&self, _: u8) -> Result<Value, BackendError> { Ok(Value::Array(vec![])) }
        fn create_slot(&self, _: u8, _: &str) -> Result<Value, BackendError> { Ok(Value::Null) }
        fn update_slot(&self, _: u8, _: u8, _: Value) -> Result<Value, BackendError> { Ok(Value::Null) }
        fn revoke_slot(&self, _: u8, _: u8) -> Result<Value, BackendError> { Ok(Value::Null) }
        fn get_slot_uri(&self, _: u8, _: u8, _: &[String]) -> Result<String, BackendError> { Ok("mock".into()) }
        fn factory_reset(&self) -> Result<(), BackendError> { Ok(()) }
        fn ota_upload(&self, _: &[u8]) -> Result<(), BackendError> { Err(BackendError::NotSupported) }
    }

    #[test]
    fn trait_is_object_safe_and_has_default_methods() {
        // Verifies object safety AND that default methods (create_master,
        // list_approvals, approve_request, deny_request) compile.
        let backend: Arc<dyn SigningBackend> = Arc::new(MockBackend);
        assert_eq!(backend.tier(), Tier::Soft);
        assert!(!backend.is_locked());
    }

    #[test]
    fn tier_display() {
        assert_eq!(Tier::Soft.to_string(), "soft");
        assert_eq!(Tier::Hard.to_string(), "hard");
    }
}
```

- [ ] **Step 3: Register the backend module in main.rs**

Add near the top of `heartwoodd/src/main.rs`, after `mod api;`:

```rust
mod backend;
```

Also create placeholder files so the module tree compiles:

`heartwoodd/src/backend/serial.rs`:
```rust
// heartwoodd/src/backend/serial.rs
// Hard mode: ESP32 serial backend. Implementation in Task 6.
```

`heartwoodd/src/backend/soft.rs`:
```rust
// heartwoodd/src/backend/soft.rs
// Soft mode: local keyfile backend. Implementation in Task 7.
```

`heartwoodd/src/backend/soft_store.rs`:
```rust
// heartwoodd/src/backend/soft_store.rs
// Encrypted keyfile read/write. Implementation in Task 4.
```

- [ ] **Step 4: Run the object-safety test**

```bash
cd ./heartwoodd && cargo test backend::tests
```

Expected: 2 tests pass (`trait_is_object_safe`, `tier_display`).

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/backend/
git commit -m "feat: define SigningBackend trait with Tier and BackendError"
```

---

### Task 3: Soft store -- keyfile encryption

**Files:**
- Create: `heartwoodd/src/backend/soft_store.rs`

This is the Argon2id + XChaCha20-Poly1305 encrypted keyfile. Fully testable in isolation -- no serial port, no relay, no API.

- [ ] **Step 1: Write the failing tests**

Replace `heartwoodd/src/backend/soft_store.rs` with:

```rust
// heartwoodd/src/backend/soft_store.rs
//
// Encrypted keyfile storage for Soft mode.
//
// Format: JSON envelope with Argon2id parameters + XChaCha20-Poly1305 ciphertext.
// Plaintext: JSON containing master secrets and connection slot policies.
// Persistence: atomic write (tmp + fsync + rename).

use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use heartwood_common::policy::ConnectSlot;

// ---------------------------------------------------------------------------
// Keystore envelope (serialised to disk as JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct KeystoreEnvelope {
    pub version: u32,
    pub kdf: String,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub salt: String,    // base64
    pub nonce: String,   // base64
    pub ciphertext: String, // base64
}

// ---------------------------------------------------------------------------
// Plaintext keystore (held in memory after unlock)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub masters: Vec<SoftMaster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftMaster {
    pub slot: u8,
    pub label: String,
    pub secret_key: String,  // 64 hex chars
    pub mode: String,        // always "soft"
    pub connection_slots: Vec<ConnectSlot>,
}

// ---------------------------------------------------------------------------
// Default Argon2id parameters
// ---------------------------------------------------------------------------

pub const DEFAULT_M_COST: u32 = 65_536; // 64 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Derive a 32-byte encryption key from a passphrase using Argon2id.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| format!("argon2 hash: {e}"))?;
    Ok(key)
}

/// Encrypt a Keystore into a KeystoreEnvelope.
pub fn encrypt_keystore(
    keystore: &Keystore,
    passphrase: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeystoreEnvelope, String> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom salt: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom nonce: {e}"))?;

    let key = derive_key(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost)?;

    let plaintext = serde_json::to_vec(keystore)
        .map_err(|e| format!("serialise keystore: {e}"))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    Ok(KeystoreEnvelope {
        version: 1,
        kdf: "argon2id".into(),
        argon2_m_cost: m_cost,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Decrypt a KeystoreEnvelope into a Keystore. Returns the keystore and the
/// derived encryption key (cached for re-encryption on mutations).
pub fn decrypt_keystore(
    envelope: &KeystoreEnvelope,
    passphrase: &str,
) -> Result<(Keystore, Zeroizing<[u8; 32]>), String> {
    if envelope.version != 1 {
        return Err(format!("unsupported keystore version: {}", envelope.version));
    }

    let salt = B64.decode(&envelope.salt)
        .map_err(|e| format!("decode salt: {e}"))?;
    let nonce_bytes = B64.decode(&envelope.nonce)
        .map_err(|e| format!("decode nonce: {e}"))?;
    let ciphertext = B64.decode(&envelope.ciphertext)
        .map_err(|e| format!("decode ciphertext: {e}"))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(format!("nonce must be {NONCE_LEN} bytes, got {}", nonce_bytes.len()));
    }

    let key = derive_key(
        passphrase.as_bytes(),
        &salt,
        envelope.argon2_m_cost,
        envelope.argon2_t_cost,
        envelope.argon2_p_cost,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decryption failed -- wrong passphrase or corrupted keystore".to_string())?;

    let keystore: Keystore = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("deserialise keystore: {e}"))?;

    Ok((keystore, key))
}

/// Re-encrypt a keystore using a cached derived key (avoids re-running Argon2id
/// on every mutation). Generates a fresh nonce each time.
pub fn reencrypt_keystore(
    keystore: &Keystore,
    key: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &str,
) -> Result<KeystoreEnvelope, String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom nonce: {e}"))?;

    let plaintext = serde_json::to_vec(keystore)
        .map_err(|e| format!("serialise keystore: {e}"))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    Ok(KeystoreEnvelope {
        version: 1,
        kdf: "argon2id".into(),
        argon2_m_cost: m_cost,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        salt: salt.to_string(),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Write a KeystoreEnvelope to disk atomically (tmp + fsync + rename).
pub fn write_envelope(path: &std::path::Path, envelope: &KeystoreEnvelope) -> Result<(), String> {
    let tmp_path = path.with_extension("enc.tmp");
    let json = serde_json::to_string_pretty(envelope)
        .map_err(|e| format!("serialise envelope: {e}"))?;

    std::fs::write(&tmp_path, json.as_bytes())
        .map_err(|e| format!("write tmp: {e}"))?;

    // fsync the file
    let file = std::fs::File::open(&tmp_path)
        .map_err(|e| format!("open tmp for fsync: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("fsync: {e}"))?;

    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("rename: {e}"))?;

    Ok(())
}

/// Read a KeystoreEnvelope from disk.
pub fn read_envelope(path: &std::path::Path) -> Result<KeystoreEnvelope, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("read keystore: {e}"))?;
    serde_json::from_slice(&data)
        .map_err(|e| format!("parse keystore envelope: {e}"))?;
    serde_json::from_slice(&data)
        .map_err(|e| format!("parse keystore envelope: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Use low-cost Argon2 params for fast tests.
    const TEST_M: u32 = 256;  // 256 KiB (minimum)
    const TEST_T: u32 = 1;
    const TEST_P: u32 = 1;

    fn sample_keystore() -> Keystore {
        Keystore {
            masters: vec![SoftMaster {
                slot: 0,
                label: "test".into(),
                secret_key: "ab".repeat(32),
                mode: "soft".into(),
                connection_slots: vec![ConnectSlot {
                    slot_index: 0,
                    label: "bark".into(),
                    secret: "cd".repeat(32),
                    current_pubkey: None,
                    allowed_methods: vec!["sign_event".into()],
                    allowed_kinds: vec![1, 7],
                    auto_approve: true,
                    signing_approved: false,
                }],
            }],
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ks = sample_keystore();
        let envelope = encrypt_keystore(&ks, "test-passphrase", TEST_M, TEST_T, TEST_P).unwrap();

        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.kdf, "argon2id");

        let (decrypted, _key) = decrypt_keystore(&envelope, "test-passphrase").unwrap();
        assert_eq!(decrypted.masters.len(), 1);
        assert_eq!(decrypted.masters[0].label, "test");
        assert_eq!(decrypted.masters[0].secret_key, "ab".repeat(32));
        assert_eq!(decrypted.masters[0].connection_slots.len(), 1);
        assert_eq!(decrypted.masters[0].connection_slots[0].label, "bark");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ks = sample_keystore();
        let envelope = encrypt_keystore(&ks, "correct", TEST_M, TEST_T, TEST_P).unwrap();

        let result = decrypt_keystore(&envelope, "wrong");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("wrong passphrase"));
    }

    #[test]
    fn reencrypt_produces_different_ciphertext() {
        let ks = sample_keystore();
        let env1 = encrypt_keystore(&ks, "pass", TEST_M, TEST_T, TEST_P).unwrap();
        let (_ks, key) = decrypt_keystore(&env1, "pass").unwrap();

        let env2 = reencrypt_keystore(&ks, key.as_ref(), TEST_M, TEST_T, TEST_P, &env1.salt).unwrap();

        // Different nonce -> different ciphertext (but same plaintext).
        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.nonce, env2.nonce);
        // Same salt (reencrypt preserves it).
        assert_eq!(env1.salt, env2.salt);

        // Decrypts to the same content.
        let (dec2, _) = decrypt_keystore(&env2, "pass").unwrap();
        assert_eq!(dec2.masters[0].label, "test");
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let ks = sample_keystore();
        let envelope = encrypt_keystore(&ks, "pass", TEST_M, TEST_T, TEST_P).unwrap();

        let json = serde_json::to_string_pretty(&envelope).unwrap();
        let parsed: KeystoreEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, envelope.version);
        assert_eq!(parsed.salt, envelope.salt);
        assert_eq!(parsed.ciphertext, envelope.ciphertext);
    }

    #[test]
    fn atomic_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.enc");

        let ks = sample_keystore();
        let envelope = encrypt_keystore(&ks, "pass", TEST_M, TEST_T, TEST_P).unwrap();

        write_envelope(&path, &envelope).unwrap();
        assert!(path.exists());
        // tmp file should be gone after rename.
        assert!(!path.with_extension("enc.tmp").exists());

        let loaded = read_envelope(&path).unwrap();
        assert_eq!(loaded.ciphertext, envelope.ciphertext);

        // Full round-trip: write -> read -> decrypt.
        let (dec, _) = decrypt_keystore(&loaded, "pass").unwrap();
        assert_eq!(dec.masters[0].label, "test");
    }

    #[test]
    fn empty_keystore_roundtrip() {
        let ks = Keystore { masters: vec![] };
        let envelope = encrypt_keystore(&ks, "p", TEST_M, TEST_T, TEST_P).unwrap();
        let (dec, _) = decrypt_keystore(&envelope, "p").unwrap();
        assert!(dec.masters.is_empty());
    }

    #[test]
    fn multiple_masters_roundtrip() {
        let ks = Keystore {
            masters: vec![
                SoftMaster {
                    slot: 0,
                    label: "personal".into(),
                    secret_key: "aa".repeat(32),
                    mode: "soft".into(),
                    connection_slots: vec![],
                },
                SoftMaster {
                    slot: 1,
                    label: "work".into(),
                    secret_key: "bb".repeat(32),
                    mode: "soft".into(),
                    connection_slots: vec![],
                },
            ],
        };
        let env = encrypt_keystore(&ks, "pass", TEST_M, TEST_T, TEST_P).unwrap();
        let (dec, _) = decrypt_keystore(&env, "pass").unwrap();
        assert_eq!(dec.masters.len(), 2);
        assert_eq!(dec.masters[0].label, "personal");
        assert_eq!(dec.masters[1].label, "work");
    }
}
```

- [ ] **Step 2: Add tempfile dev-dependency**

In `heartwoodd/Cargo.toml`, add:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Run tests**

```bash
cd ./heartwoodd && cargo test backend::soft_store::tests
```

Expected: all 7 tests pass.

- [ ] **Step 4: Fix the duplicate deserialise in read_envelope**

The `read_envelope` function above has a bug (calls `from_slice` twice). Fix it:

```rust
pub fn read_envelope(path: &std::path::Path) -> Result<KeystoreEnvelope, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("read keystore: {e}"))?;
    serde_json::from_slice(&data)
        .map_err(|e| format!("parse keystore envelope: {e}"))
}
```

- [ ] **Step 5: Re-run tests**

```bash
cd ./heartwoodd && cargo test backend::soft_store::tests
```

Expected: all 7 tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/backend/soft_store.rs heartwoodd/Cargo.toml
git commit -m "feat: Argon2id + XChaCha20-Poly1305 encrypted keystore for Soft mode"
```

---

### Task 4: Extract RawSerial to its own module

**Files:**
- Create: `heartwoodd/src/serial.rs`
- Modify: `heartwoodd/src/main.rs`

- [ ] **Step 1: Create serial.rs with the RawSerial struct**

Extract lines 46-125 of `main.rs` (the `RawSerial` struct, its `open()` method, and its `Read`/`Write` impls) into `heartwoodd/src/serial.rs`:

```rust
// heartwoodd/src/serial.rs
//
// Raw POSIX serial wrapper for ESP32 USB-CDC communication.
// Uses termios directly to avoid DTR toggling (which reboots the ESP32-S3).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::sys::termios;

/// Thin wrapper around a raw file descriptor for serial I/O.
/// Uses POSIX termios instead of the `serialport` crate to avoid
/// DTR toggling on open (which reboots the ESP32-S3 via USB-CDC).
pub struct RawSerial {
    pub file: File,
}

impl RawSerial {
    /// Open a serial port with raw POSIX I/O.
    ///
    /// Sets CLOCAL (ignore modem control lines) so DTR is never asserted,
    /// configures raw mode at the given baud rate, and explicitly clears
    /// DTR/RTS via ioctl.
    pub fn open(path: &str, baud: u32) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let raw_fd = file.as_raw_fd();
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        let mut cfg = termios::tcgetattr(fd)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        termios::cfmakeraw(&mut cfg);

        let baud_rate = match baud {
            9600 => termios::BaudRate::B9600,
            19200 => termios::BaudRate::B19200,
            38400 => termios::BaudRate::B38400,
            57600 => termios::BaudRate::B57600,
            115200 => termios::BaudRate::B115200,
            230400 => termios::BaudRate::B230400,
            _ => termios::BaudRate::B115200,
        };
        termios::cfsetspeed(&mut cfg, baud_rate)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        cfg.control_flags.remove(termios::ControlFlags::CRTSCTS);
        cfg.control_flags.insert(termios::ControlFlags::CREAD);
        cfg.control_flags.insert(termios::ControlFlags::CLOCAL);
        cfg.control_flags.remove(termios::ControlFlags::HUPCL);

        cfg.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 0;
        cfg.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 1;

        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &cfg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Clear DTR and RTS explicitly via ioctl
        unsafe {
            let mut bits: libc::c_int = libc::TIOCM_DTR | libc::TIOCM_RTS;
            libc::ioctl(raw_fd, libc::TIOCMBIC as _, &mut bits);
        }

        Ok(Self { file })
    }
}

impl Read for RawSerial {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for RawSerial {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
```

- [ ] **Step 2: Update main.rs imports**

In `main.rs`, remove the `RawSerial` struct and its impls (lines 46-125). Add:

```rust
mod serial;
```

Replace `use crate::RawSerial` references in `api.rs` with:

```rust
use crate::serial::RawSerial;
```

Change the `pub` visibility on `RawSerial` in `main.rs` references -- it's now imported from `serial::RawSerial`. Update `api.rs` line 23 from `use crate::RawSerial;` to `use crate::serial::RawSerial;`.

- [ ] **Step 3: Verify build**

```bash
cd ./heartwoodd && cargo build
```

Expected: compiles with no errors.

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/serial.rs heartwoodd/src/main.rs heartwoodd/src/api.rs
git commit -m "refactor: extract RawSerial to serial.rs"
```

---

### Task 5: Implement SerialBackend

**Files:**
- Create: `heartwoodd/src/backend/serial.rs`
- Modify: `heartwoodd/src/api.rs` (extract serial helpers to backend)

This wraps the existing serial I/O functions behind the `SigningBackend` trait. The serial helper functions (`forward_encrypted`, `forward_sign_envelope`, `forward_to_esp32`, `authenticate_bridge`, `unlock_pin`, `query_master_list`, `read_any_response`, `read_exact_deadline`, and `send_and_receive` from api.rs) need to be accessible from the `SerialBackend`.

- [ ] **Step 1: Move serial helper functions from main.rs to backend/serial.rs**

Extract these functions from `main.rs` into `backend/serial.rs`:
- `forward_to_esp32` (lines 196-210)
- `authenticate_bridge` (lines 216-273)
- `unlock_pin` (lines 280-332)
- `query_master_list` (lines 341-360)
- `forward_sign_envelope` (lines 368-391)
- `forward_encrypted` (lines 393-423)
- `read_any_response` (lines 436-557)
- `read_exact_deadline` (lines 560-578)
- `decode_hex_32` (lines 584-599)
- `hex_nibble` (lines 601-608)

- [ ] **Step 2: Write the SerialBackend struct and trait impl**

The `SerialBackend` wraps `Arc<Mutex<RawSerial>>` and delegates every trait method to serial frame I/O. The management API's `send_and_receive` helper (from `api.rs`) also moves here.

```rust
// heartwoodd/src/backend/serial.rs
//
// Hard mode: ESP32 serial backend.
// All signing, slot management, and device operations are forwarded to the
// ESP32 over the serial frame protocol.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use heartwood_common::frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::types::*;

use crate::serial::RawSerial;
use super::{BackendError, SigningBackend, Tier};

pub struct SerialBackend {
    serial: Arc<Mutex<RawSerial>>,
    log_tx: broadcast::Sender<String>,
}

impl SerialBackend {
    pub fn new(serial: Arc<Mutex<RawSerial>>, log_tx: broadcast::Sender<String>) -> Self {
        Self { serial, log_tx }
    }

    pub fn serial(&self) -> &Arc<Mutex<RawSerial>> {
        &self.serial
    }

    pub fn log_tx(&self) -> &broadcast::Sender<String> {
        &self.log_tx
    }

    fn acquire(&self) -> Result<std::sync::MutexGuard<'_, RawSerial>, BackendError> {
        for _ in 0..10 {
            if let Ok(guard) = self.serial.try_lock() {
                return Ok(guard);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(BackendError::DeviceBusy)
    }
}
```

The full file is large because it contains the extracted serial helper functions. The trait impl delegates each method:

- `handle_encrypted_request` -> calls `forward_encrypted`
- `sign_envelope` -> calls `forward_sign_envelope`
- `list_masters` -> sends `FRAME_TYPE_PROVISION_LIST`, parses JSON response
- `list_slots` -> sends `FRAME_TYPE_CONNSLOT_LIST`
- `create_slot` -> sends `FRAME_TYPE_CONNSLOT_CREATE`
- `update_slot` -> sends `FRAME_TYPE_CONNSLOT_UPDATE`
- `revoke_slot` -> sends `FRAME_TYPE_CONNSLOT_REVOKE`
- `get_slot_uri` -> sends `FRAME_TYPE_CONNSLOT_URI`
- `factory_reset` -> sends `FRAME_TYPE_FACTORY_RESET`
- `ota_upload` -> sends `FRAME_TYPE_OTA_BEGIN` + chunks + `FRAME_TYPE_OTA_FINISH`
- `unlock` / `lock` -> returns `NotSupported`

Each method follows the pattern: acquire serial lock, build frame, send_and_receive, parse response.

The `send_and_receive` function from `api.rs` and all the serial frame I/O helpers from `main.rs` become private functions in this module.

- [ ] **Step 3: Verify build**

```bash
cd ./heartwoodd && cargo build
```

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/backend/serial.rs heartwoodd/src/main.rs
git commit -m "feat: SerialBackend wraps existing ESP32 serial code behind SigningBackend trait"
```

---

### Task 6: Implement SoftBackend core

**Files:**
- Create: `heartwoodd/src/backend/soft.rs`

The SoftBackend does local NIP-46 signing using k256. It holds the decrypted keystore in memory behind an `RwLock` and delegates keyfile persistence to `soft_store`.

- [ ] **Step 1: Write the SoftBackend struct and state management**

```rust
// heartwoodd/src/backend/soft.rs
//
// Soft mode: local keyfile backend.
// Signs locally with k256, manages connection slots in memory,
// persists to Argon2id-encrypted keyfile on mutation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use k256::schnorr::SigningKey;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use heartwood_common::hex::hex_encode;
use heartwood_common::policy::{self, ConnectSlot};

use super::{BackendError, SigningBackend, Tier};
use super::soft_store::{
    self, Keystore, KeystoreEnvelope, SoftMaster,
    DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST,
};

/// In-memory state after unlock.
struct UnlockedState {
    keystore: Keystore,
    /// Cached Argon2id-derived key for re-encryption on mutations.
    encryption_key: Zeroizing<[u8; 32]>,
    /// Original envelope params (salt, costs) for re-encryption.
    envelope_salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

/// A pending signing request awaiting Sapwood approval.
pub struct PendingApproval {
    pub id: String,
    pub method: String,
    pub event_kind: Option<u64>,
    pub content_preview: String,
    pub slot_label: String,
    pub master_slot: u8,
    pub created_at: Instant,
    // Stashed request data needed to complete signing after approval.
    pub master_pubkey: [u8; 32],
    pub client_pubkey: [u8; 32],
    pub ciphertext: String,
}

pub struct SoftBackend {
    data_dir: PathBuf,
    state: RwLock<Option<UnlockedState>>,
    approvals: RwLock<HashMap<String, PendingApproval>>,
}

impl SoftBackend {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            state: RwLock::new(None),
            approvals: RwLock::new(HashMap::new()),
        }
    }

    fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.enc")
    }

    /// Check locked state; return a read guard if unlocked.
    fn require_unlocked(&self) -> Result<std::sync::RwLockReadGuard<'_, Option<UnlockedState>>, BackendError> {
        let guard = self.state.read().map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        if guard.is_none() {
            return Err(BackendError::Locked);
        }
        Ok(guard)
    }

    /// Persist current keystore state to disk.
    fn persist(&self, state: &UnlockedState) -> Result<(), BackendError> {
        let envelope = soft_store::reencrypt_keystore(
            &state.keystore,
            state.encryption_key.as_ref(),
            state.m_cost,
            state.t_cost,
            state.p_cost,
            &state.envelope_salt,
        ).map_err(|e| BackendError::Internal(e))?;

        soft_store::write_envelope(&self.keystore_path(), &envelope)
            .map_err(|e| BackendError::Internal(e))
    }

    /// Find a master by slot index.
    fn find_master<'a>(keystore: &'a Keystore, slot: u8) -> Result<&'a SoftMaster, BackendError> {
        keystore.masters.iter()
            .find(|m| m.slot == slot)
            .ok_or(BackendError::Internal(format!("master slot {slot} not found")))
    }

    /// Find a mutable master by slot index.
    fn find_master_mut<'a>(keystore: &'a mut Keystore, slot: u8) -> Result<&'a mut SoftMaster, BackendError> {
        keystore.masters.iter_mut()
            .find(|m| m.slot == slot)
            .ok_or(BackendError::Internal(format!("master slot {slot} not found")))
    }

    /// Prune expired approvals (TTL 60s).
    pub fn prune_expired(&self) {
        if let Ok(mut approvals) = self.approvals.write() {
            approvals.retain(|_, a| a.created_at.elapsed().as_secs() < 60);
        }
    }

    /// List pending approvals (for /api/approvals).
    pub fn list_approvals(&self) -> Vec<Value> {
        self.prune_expired();
        let approvals = match self.approvals.read() {
            Ok(a) => a,
            Err(_) => return vec![],
        };
        approvals.values().map(|a| {
            serde_json::json!({
                "id": a.id,
                "method": a.method,
                "event_kind": a.event_kind,
                "content_preview": a.content_preview,
                "slot_label": a.slot_label,
                "age_secs": a.created_at.elapsed().as_secs(),
            })
        }).collect()
    }

    /// Approve a pending request. Returns the signed response ciphertext.
    pub fn approve(&self, approval_id: &str) -> Result<(PendingApproval), BackendError> {
        let mut approvals = self.approvals.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        approvals.remove(approval_id)
            .ok_or(BackendError::Internal("approval not found or expired".into()))
    }

    /// Deny a pending request.
    pub fn deny(&self, approval_id: &str) -> Result<(), BackendError> {
        let mut approvals = self.approvals.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        approvals.remove(approval_id)
            .ok_or(BackendError::Internal("approval not found or expired".into()))?;
        Ok(())
    }
}
```

- [ ] **Step 2: Implement the SigningBackend trait**

The key methods. `handle_encrypted_request` is the most complex -- it does what the ESP32 firmware does but in software:

1. NIP-44 decrypt the incoming ciphertext using the master's secret key
2. Parse the NIP-46 JSON-RPC request
3. Evaluate connection slot policy
4. If auto-approved: process the request (sign_event, get_public_key, etc.)
5. If not: queue for Sapwood approval, return `PendingApproval` error
6. NIP-44 encrypt the response
7. Return the ciphertext

```rust
impl SigningBackend for SoftBackend {
    fn tier(&self) -> Tier { Tier::Soft }

    fn is_locked(&self) -> bool {
        self.state.read().map(|s| s.is_none()).unwrap_or(true)
    }

    fn unlock(&self, passphrase: &str) -> Result<(), BackendError> {
        let path = self.keystore_path();
        if !path.exists() {
            // First run -- create empty keystore.
            let ks = Keystore { masters: vec![] };
            let envelope = soft_store::encrypt_keystore(
                &ks, passphrase, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST,
            ).map_err(|e| BackendError::Internal(e))?;
            soft_store::write_envelope(&path, &envelope)
                .map_err(|e| BackendError::Internal(e))?;
        }

        let envelope = soft_store::read_envelope(&path)
            .map_err(|e| BackendError::Internal(e))?;
        let (keystore, key) = soft_store::decrypt_keystore(&envelope, passphrase)
            .map_err(|_| BackendError::Internal("wrong passphrase".into()))?;

        let mut state = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        *state = Some(UnlockedState {
            keystore,
            encryption_key: key,
            envelope_salt: envelope.salt,
            m_cost: envelope.argon2_m_cost,
            t_cost: envelope.argon2_t_cost,
            p_cost: envelope.argon2_p_cost,
        });
        Ok(())
    }

    fn lock(&self) -> Result<(), BackendError> {
        let mut state = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        // Drop triggers zeroize on the Zeroizing<[u8; 32]> encryption key.
        *state = None;
        Ok(())
    }

    fn handle_encrypted_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let guard = self.require_unlocked()?;
        let state = guard.as_ref().unwrap();

        // Find the master whose public key matches.
        let master = state.keystore.masters.iter()
            .find(|m| {
                // Derive pubkey from secret key and compare.
                let sk_bytes = hex_to_32(&&m.secret_key).unwrap_or([0u8; 32]);
                let sk = k256::SecretKey::from_bytes((&sk_bytes).into()).ok();
                sk.map(|s| {
                    let pk = s.public_key();
                    let pk_bytes = pk.to_sec1_bytes();
                    // x-only: skip the 0x02/0x03 prefix byte.
                    pk_bytes.len() > 1 && &pk_bytes[1..] == master_pubkey
                }).unwrap_or(false)
            })
            .ok_or(BackendError::Internal("no master matches pubkey".into()))?;

        // NIP-44 decrypt the request.
        let sk_bytes = hex_to_32(&master.secret_key)
            .map_err(|e| BackendError::Internal(e))?;

        // Use nostr crate for NIP-44 (same as the bridge's existing code).
        // This is done through heartwood_common::nip44 for the Soft backend.
        //
        // The actual NIP-44 and NIP-46 processing logic is implemented here,
        // using the same approach as the ESP32 firmware but in software.
        //
        // Full implementation processes the NIP-46 JSON-RPC method:
        // - get_public_key: return the master's npub
        // - sign_event: sign with k256 Schnorr, check policy first
        // - nip44_encrypt/decrypt: delegate to heartwood_common::nip44
        // - connect: validate secret against connection slots
        // - ping: return "pong"

        // [Implementation follows the ESP32 firmware's nip46.rs method dispatch
        //  but using k256 for signing and heartwood_common::nip44 for encryption.]

        todo!("Full NIP-46 dispatch -- implemented in step 3")
    }

    fn sign_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let guard = self.require_unlocked()?;
        let state = guard.as_ref().unwrap();

        // Build a kind:24133 event, sign with the master key using k256 Schnorr.
        // Return serialised signed event JSON.
        todo!("Envelope signing -- implemented in step 3")
    }

    fn list_masters(&self) -> Result<Vec<Value>, BackendError> {
        let guard = self.require_unlocked()?;
        let state = guard.as_ref().unwrap();
        let masters: Vec<Value> = state.keystore.masters.iter().map(|m| {
            let sk_bytes = hex_to_32(&m.secret_key).unwrap_or([0u8; 32]);
            let npub = derive_npub(&sk_bytes).unwrap_or_default();
            serde_json::json!({
                "slot": m.slot,
                "label": m.label,
                "mode": m.mode,
                "npub": npub,
            })
        }).collect();
        Ok(masters)
    }

    fn list_slots(&self, master: u8) -> Result<Value, BackendError> {
        let guard = self.require_unlocked()?;
        let state = guard.as_ref().unwrap();
        let m = Self::find_master(&state.keystore, master)?;
        let redacted: Vec<ConnectSlot> = m.connection_slots.iter()
            .map(|s| policy::redact_slot(s))
            .collect();
        serde_json::to_value(redacted)
            .map_err(|e| BackendError::Internal(format!("serialise slots: {e}")))
    }

    fn create_slot(&self, master: u8, label: &str) -> Result<Value, BackendError> {
        let mut guard = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        let m = Self::find_master_mut(&mut state.keystore, master)?;

        let index = policy::next_slot_index(&m.connection_slots)
            .ok_or(BackendError::Internal("all 16 connection slots occupied".into()))?;

        // Generate random secret for the slot.
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes)
            .map_err(|e| BackendError::Internal(format!("getrandom: {e}")))?;
        let secret = hex_encode(&secret_bytes);

        let slot = ConnectSlot {
            slot_index: index,
            label: label.to_string(),
            secret,
            current_pubkey: None,
            allowed_methods: policy::CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: false,
        };

        m.connection_slots.push(slot.clone());
        self.persist(state)?;

        let redacted = policy::redact_slot(&slot);
        serde_json::to_value(redacted)
            .map_err(|e| BackendError::Internal(format!("serialise: {e}")))
    }

    fn update_slot(&self, master: u8, index: u8, patch: Value) -> Result<Value, BackendError> {
        let mut guard = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        let m = Self::find_master_mut(&mut state.keystore, master)?;

        let slot = m.connection_slots.iter_mut()
            .find(|s| s.slot_index == index)
            .ok_or(BackendError::Internal(format!("slot {index} not found")))?;

        // Apply patch fields.
        if let Some(label) = patch.get("label").and_then(|v| v.as_str()) {
            slot.label = label.to_string();
        }
        if let Some(methods) = patch.get("allowed_methods").and_then(|v| v.as_array()) {
            slot.allowed_methods = methods.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
        if let Some(kinds) = patch.get("allowed_kinds").and_then(|v| v.as_array()) {
            slot.allowed_kinds = kinds.iter()
                .filter_map(|v| v.as_u64())
                .collect();
        }
        if let Some(auto) = patch.get("auto_approve").and_then(|v| v.as_bool()) {
            slot.auto_approve = auto;
        }

        let redacted = policy::redact_slot(slot);
        self.persist(state)?;

        serde_json::to_value(redacted)
            .map_err(|e| BackendError::Internal(format!("serialise: {e}")))
    }

    fn revoke_slot(&self, master: u8, index: u8) -> Result<Value, BackendError> {
        let mut guard = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(BackendError::Locked)?;
        let m = Self::find_master_mut(&mut state.keystore, master)?;

        let before = m.connection_slots.len();
        m.connection_slots.retain(|s| s.slot_index != index);
        if m.connection_slots.len() == before {
            return Err(BackendError::Internal(format!("slot {index} not found")));
        }

        self.persist(state)?;
        Ok(serde_json::json!({"ok": true}))
    }

    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String]) -> Result<String, BackendError> {
        let guard = self.require_unlocked()?;
        let state = guard.as_ref().unwrap();
        let m = Self::find_master(&state.keystore, master)?;

        let slot = m.connection_slots.iter()
            .find(|s| s.slot_index == index)
            .ok_or(BackendError::Internal(format!("slot {index} not found")))?;

        let sk_bytes = hex_to_32(&m.secret_key)
            .map_err(|e| BackendError::Internal(e))?;
        let npub_hex = derive_pubkey_hex(&sk_bytes)
            .map_err(|e| BackendError::Internal(e))?;

        let relay_params: String = relays.iter()
            .map(|r| format!("relay={}", urlencoding::encode(r)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!("bunker://{}?{}&secret={}", npub_hex, relay_params, slot.secret))
    }

    fn factory_reset(&self) -> Result<(), BackendError> {
        let path = self.keystore_path();
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| BackendError::Internal(format!("delete keystore: {e}")))?;
        }
        let mut state = self.state.write()
            .map_err(|_| BackendError::Internal("lock poisoned".into()))?;
        *state = None;
        Ok(())
    }

    fn ota_upload(&self, _firmware: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::NotSupported)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {}", b as char)),
    }
}

fn derive_npub(secret_key_bytes: &[u8; 32]) -> Result<String, String> {
    let sk = k256::SecretKey::from_bytes(secret_key_bytes.into())
        .map_err(|e| format!("invalid secret key: {e}"))?;
    let pk = sk.public_key();
    let pk_bytes = pk.to_sec1_bytes();
    // x-only pubkey: skip the 0x02/0x03 prefix.
    if pk_bytes.len() < 33 {
        return Err("public key too short".into());
    }
    let x_only = &pk_bytes[1..33];
    heartwood_common::encoding::pubkey_to_npub(x_only)
        .map_err(|e| format!("npub encode: {e}"))
}

fn derive_pubkey_hex(secret_key_bytes: &[u8; 32]) -> Result<String, String> {
    let sk = k256::SecretKey::from_bytes(secret_key_bytes.into())
        .map_err(|e| format!("invalid secret key: {e}"))?;
    let pk = sk.public_key();
    let pk_bytes = pk.to_sec1_bytes();
    if pk_bytes.len() < 33 {
        return Err("public key too short".into());
    }
    Ok(hex_encode(&pk_bytes[1..33]))
}
```

- [ ] **Step 3: Implement handle_encrypted_request and sign_envelope**

These are the core NIP-46 processing methods. `handle_encrypted_request` needs to:
1. Find the master by matching pubkey
2. NIP-44 decrypt using `heartwood_common::nip44::decrypt`
3. Parse the NIP-46 request JSON
4. Evaluate policy against the connection slot
5. Dispatch the method (sign_event, get_public_key, nip44_encrypt, etc.)
6. NIP-44 encrypt the response
7. Return the response ciphertext

`sign_envelope` needs to:
1. Build a kind:24133 event JSON with the correct tags
2. Compute the NIP-01 event ID (SHA-256 of the serialised commitment)
3. BIP-340 Schnorr sign the event ID with k256
4. Return the full signed event JSON

The NIP-46 method dispatch reuses types from `heartwood_common::nip46` (`Nip46Request`, `Nip46Response`). The NIP-44 encryption uses `heartwood_common::nip44::encrypt`/`decrypt`.

This is the most complex piece of new code. The implementation follows the same logic as the ESP32 firmware's `nip46.rs` handler but using k256 instead of libsecp256k1.

- [ ] **Step 4: Write tests for SoftBackend**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, SoftBackend) {
        let dir = tempfile::tempdir().unwrap();
        let backend = SoftBackend::new(dir.path().to_path_buf());
        (dir, backend)
    }

    #[test]
    fn starts_locked() {
        let (_dir, backend) = setup();
        assert!(backend.is_locked());
        assert_eq!(backend.tier(), Tier::Soft);
    }

    #[test]
    fn unlock_creates_keystore_on_first_run() {
        let (_dir, backend) = setup();
        backend.unlock("test-pass").unwrap();
        assert!(!backend.is_locked());
        // Keystore file exists.
        assert!(backend.keystore_path().exists());
        // Empty keystore.
        let masters = backend.list_masters().unwrap();
        assert!(masters.is_empty());
    }

    #[test]
    fn lock_zeroizes_state() {
        let (_dir, backend) = setup();
        backend.unlock("pass").unwrap();
        assert!(!backend.is_locked());
        backend.lock().unwrap();
        assert!(backend.is_locked());
        // Operations fail when locked.
        assert!(matches!(backend.list_masters(), Err(BackendError::Locked)));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (_dir, backend) = setup();
        backend.unlock("correct").unwrap();
        backend.lock().unwrap();
        let result = backend.unlock("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn create_and_list_slots() {
        let (_dir, backend) = setup();
        backend.unlock("pass").unwrap();

        // Need a master first -- add one to the keystore directly.
        {
            let mut guard = backend.state.write().unwrap();
            let state = guard.as_mut().unwrap();
            let mut secret_bytes = [0u8; 32];
            getrandom::getrandom(&mut secret_bytes).unwrap();
            state.keystore.masters.push(SoftMaster {
                slot: 0,
                label: "test".into(),
                secret_key: hex_encode(&secret_bytes),
                mode: "soft".into(),
                connection_slots: vec![],
            });
        }

        // Create a slot.
        let result = backend.create_slot(0, "bark laptop").unwrap();
        assert_eq!(result.get("label").unwrap().as_str().unwrap(), "bark laptop");
        assert_eq!(result.get("slot_index").unwrap().as_u64().unwrap(), 0);
        // Secret is redacted.
        assert_eq!(result.get("secret").unwrap().as_str().unwrap(), "");

        // List slots.
        let slots = backend.list_slots(0).unwrap();
        let arr = slots.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn revoke_slot() {
        let (_dir, backend) = setup();
        backend.unlock("pass").unwrap();

        // Add master + slot.
        {
            let mut guard = backend.state.write().unwrap();
            let state = guard.as_mut().unwrap();
            state.keystore.masters.push(SoftMaster {
                slot: 0,
                label: "test".into(),
                secret_key: "aa".repeat(32),
                mode: "soft".into(),
                connection_slots: vec![],
            });
        }
        backend.create_slot(0, "to-revoke").unwrap();
        backend.revoke_slot(0, 0).unwrap();

        let slots = backend.list_slots(0).unwrap();
        assert!(slots.as_array().unwrap().is_empty());
    }

    #[test]
    fn ota_returns_not_supported() {
        let (_dir, backend) = setup();
        assert!(matches!(backend.ota_upload(&[]), Err(BackendError::NotSupported)));
    }

    #[test]
    fn factory_reset_deletes_keystore() {
        let (_dir, backend) = setup();
        backend.unlock("pass").unwrap();
        assert!(backend.keystore_path().exists());
        backend.factory_reset().unwrap();
        assert!(!backend.keystore_path().exists());
        assert!(backend.is_locked());
    }

    #[test]
    fn persistence_survives_relock() {
        let (dir, backend) = setup();
        backend.unlock("pass").unwrap();

        // Add a master.
        {
            let mut guard = backend.state.write().unwrap();
            let state = guard.as_mut().unwrap();
            state.keystore.masters.push(SoftMaster {
                slot: 0,
                label: "persistent".into(),
                secret_key: "bb".repeat(32),
                mode: "soft".into(),
                connection_slots: vec![],
            });
            // Persist manually (normally done by create_slot etc).
            let _ = backend.persist(state);
        }

        // Lock and re-unlock.
        backend.lock().unwrap();
        backend.unlock("pass").unwrap();

        let masters = backend.list_masters().unwrap();
        assert_eq!(masters.len(), 1);
        assert_eq!(masters[0].get("label").unwrap().as_str().unwrap(), "persistent");
    }
}
```

- [ ] **Step 5: Run tests**

```bash
cd ./heartwoodd && cargo test backend::soft::tests
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/backend/soft.rs
git commit -m "feat: SoftBackend with local signing, slot management, and persistence"
```

---

### Task 7: Refactor api.rs to use SigningBackend

**Files:**
- Modify: `heartwoodd/src/api.rs`

Replace the serial-centric `AppState` with a backend-agnostic one and add the new Soft-mode endpoints.

- [ ] **Step 1: Replace AppState**

Change `AppState` from:

```rust
pub struct AppState {
    pub serial: Arc<Mutex<RawSerial>>,
    pub bridge_info: Arc<BridgeInfo>,
    pub log_tx: broadcast::Sender<String>,
    pub api_token: Option<Arc<String>>,
}
```

To:

```rust
pub struct AppState {
    pub backend: Arc<dyn SigningBackend>,
    pub daemon_info: Arc<DaemonInfo>,
    pub log_tx: broadcast::Sender<String>,
    pub api_token: Option<Arc<String>>,
}

pub struct DaemonInfo {
    pub tier: Tier,
    pub relays: Vec<String>,
    pub start_time: Instant,
}
```

- [ ] **Step 2: Refactor existing handlers to use backend**

Each handler changes from direct serial I/O to `state.backend.method()`. For example, `get_status` changes from:

```rust
// Old: send PROVISION_LIST frame over serial
let frame_bytes = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[]);
let resp = send_and_receive(&mut port, &frame_bytes, ...);
```

To:

```rust
// New: delegate to backend
let masters = state.backend.list_masters()
    .map_err(|e| backend_to_http(e))?;
```

Add a helper to map `BackendError` to HTTP status codes:

```rust
fn backend_to_http(err: BackendError) -> Response {
    match err {
        BackendError::NotSupported => api_err(StatusCode::NOT_FOUND, "not supported in this tier"),
        BackendError::Locked => api_err(StatusCode::SERVICE_UNAVAILABLE, "daemon is locked"),
        BackendError::DeviceBusy => api_err(StatusCode::LOCKED, "device busy"),
        BackendError::DeviceTimeout => api_err(StatusCode::GATEWAY_TIMEOUT, "device timeout"),
        BackendError::Denied => api_err(StatusCode::FORBIDDEN, "request denied"),
        BackendError::PendingApproval(id) => {
            (StatusCode::ACCEPTED, Json(serde_json::json!({"pending": id}))).into_response()
        }
        BackendError::Internal(msg) => api_err(StatusCode::INTERNAL_SERVER_ERROR, msg),
    }
}
```

Refactor each handler (`get_status`, `get_slots`, `create_slot`, `update_slot`, `delete_slot`, `get_slot_uri`, `factory_reset`, `ota_upload`) to call the corresponding backend method instead of building serial frames directly.

The `send_and_receive` and `acquire_serial` helpers in api.rs are no longer needed -- they've moved into `SerialBackend`. Remove them.

- [ ] **Step 3: Add new endpoints**

Add `/api/info` (tier-aware, replaces `/api/bridge/info`):

```rust
async fn get_info(State(state): State<AppState>) -> Response {
    let info = &state.daemon_info;
    Json(serde_json::json!({
        "tier": info.tier.to_string(),
        "locked": state.backend.is_locked(),
        "relays": info.relays,
        "uptime_secs": info.start_time.elapsed().as_secs(),
    })).into_response()
}
```

Add `/api/unlock` (Soft mode only):

```rust
#[derive(Deserialize)]
struct UnlockBody {
    passphrase: String,
}

async fn post_unlock(
    State(state): State<AppState>,
    Json(body): Json<UnlockBody>,
) -> Response {
    match state.backend.unlock(&body.passphrase) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(BackendError::NotSupported) => api_err(StatusCode::NOT_FOUND, "not supported in Hard mode"),
        Err(e) => backend_to_http(e),
    }
}
```

Add `/api/approvals` and `/api/approvals/:id`:

```rust
async fn get_approvals(State(state): State<AppState>) -> Response {
    // Downcast to SoftBackend to access approval queue.
    // In Hard mode, return empty array.
    if state.daemon_info.tier == Tier::Hard {
        return Json(serde_json::json!([])).into_response();
    }
    // The SoftBackend's list_approvals() is called via a type-erased helper.
    // Since we can't downcast dyn SigningBackend easily, add list_approvals
    // to the trait as a default method returning empty vec.
    // Alternatively, store Arc<SoftBackend> alongside Arc<dyn SigningBackend>.
    //
    // Simplest approach: add approval methods to the trait with default no-op impls.
    todo!("wire up approval queue")
}
```

Note: the approval queue access requires either adding `list_approvals`/`approve`/`deny` to the `SigningBackend` trait (with default no-op impls that `SerialBackend` inherits) or storing a separate `Arc<SoftBackend>` in `AppState`. Adding them to the trait is cleaner -- update `backend/mod.rs`:

```rust
// Add to SigningBackend trait:
fn list_approvals(&self) -> Vec<Value> { vec![] }
fn approve_request(&self, id: &str) -> Result<(), BackendError> { Err(BackendError::NotSupported) }
fn deny_request(&self, id: &str) -> Result<(), BackendError> { Err(BackendError::NotSupported) }
```

- [ ] **Step 4: Update the router**

```rust
pub fn router(state: AppState, sapwood_dir: Option<&str>, enable_cors: bool) -> Router {
    let protected: Router<AppState> = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/slots/{master}", get(get_slots).post(create_slot))
        .route("/api/slots/{master}/{index}", put(update_slot).delete(delete_slot))
        .route("/api/slots/{master}/{index}/uri", get(get_slot_uri))
        .route("/api/device/factory-reset", post(factory_reset))
        .route("/api/device/ota", post(ota_upload))
        .route("/api/masters", post(create_master))
        .route("/api/daemon/restart", post(daemon_restart))
        .route("/api/unlock", post(post_unlock))
        .route("/api/lock", post(post_lock))
        .route("/api/approvals", get(get_approvals))
        .route("/api/approvals/{id}", post(post_approval))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_bearer));

    let public: Router<AppState> = Router::new()
        .route("/api/info", get(get_info))
        .route("/api/logs", get(ws_logs));

    // ... rest unchanged
}
```

- [ ] **Step 5: Verify build**

```bash
cd ./heartwoodd && cargo build
```

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/api.rs heartwoodd/src/backend/mod.rs
git commit -m "refactor: api.rs delegates to SigningBackend, add unlock/approvals/info endpoints"
```

---

### Task 8: Extract relay event loop

**Files:**
- Create: `heartwoodd/src/relay.rs`
- Modify: `heartwoodd/src/main.rs`

- [ ] **Step 1: Extract the event loop into relay.rs**

Move the `handle_notifications` closure (main.rs lines 854-1015) into a dedicated function:

```rust
// heartwoodd/src/relay.rs
//
// NIP-46 relay event loop. Subscribes to kind:24133 events p-tagged
// with the signing master pubkey and dispatches them to the backend.

use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::broadcast;

use crate::backend::{BackendError, SigningBackend};

/// Run the NIP-46 event loop. Blocks until the client disconnects.
///
/// The loop subscribes to NIP-46 events addressed to `signing_pubkey`,
/// forwards each request to the backend, and publishes the response.
pub async fn run_event_loop(
    client: &Client,
    backend: &Arc<dyn SigningBackend>,
    bunker_keys: &Keys,
    signing_pubkey: &[u8; 32],
    log_tx: &broadcast::Sender<String>,
) -> Result<()> {
    let signing_pk = PublicKey::from_slice(signing_pubkey)
        .expect("signing pubkey is valid");

    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(signing_pk)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!("Subscribed to NIP-46 events -- waiting for requests...");

    client
        .handle_notifications(|notification| {
            let backend = Arc::clone(backend);
            let client_clone = client.clone();
            let bunker_keys = bunker_keys.clone();
            let signing_pubkey = *signing_pubkey;
            let log_tx = log_tx.clone();

            async move {
                let event = match notification {
                    RelayPoolNotification::Event { event, .. } => event,
                    _ => return Ok(false),
                };

                if event.kind != Kind::NostrConnect {
                    return Ok(false);
                }

                let client_pubkey = event.pubkey;
                log::info!("NIP-46 request from {}", client_pubkey);

                let client_pk_bytes: [u8; 32] = client_pubkey.to_bytes();

                // Step 1: forward encrypted request to backend.
                let response_ciphertext = match backend.handle_encrypted_request(
                    &signing_pubkey,
                    &client_pk_bytes,
                    &event.content,
                ) {
                    Ok(ct) => ct,
                    Err(BackendError::PendingApproval(id)) => {
                        log::info!("Request queued for approval: {id}");
                        // Don't publish anything yet -- approval handler will.
                        return Ok(false);
                    }
                    Err(e) => {
                        log::error!("Backend error: {e}");
                        return Ok(false);
                    }
                };

                // Step 2: sign the outer envelope event.
                let created_at = Timestamp::now().as_secs();
                let signed_event_json = match backend.sign_envelope(
                    &signing_pubkey,
                    &client_pk_bytes,
                    created_at,
                    &response_ciphertext,
                ) {
                    Ok(json) => json,
                    Err(e) => {
                        log::error!("Envelope sign error: {e}");
                        return Ok(false);
                    }
                };

                // Step 3: publish the pre-signed event.
                let signed_event = match Event::from_json(&signed_event_json) {
                    Ok(ev) => ev,
                    Err(e) => {
                        log::error!("Parse signed envelope: {e}");
                        return Ok(false);
                    }
                };

                match client_clone.send_event(&signed_event).await {
                    Ok(output) => log::info!("Response published: {}", output.id()),
                    Err(e) => log::error!("Publish failed: {e}"),
                }

                Ok(false)
            }
        })
        .await?;

    Ok(())
}
```

- [ ] **Step 2: Update main.rs**

Remove the `handle_notifications` closure from main.rs. Replace with:

```rust
mod relay;

// ... in main():
relay::run_event_loop(&client, &backend, &bunker_keys, &signing_master_pubkey, &log_tx).await?;
```

- [ ] **Step 3: Verify build**

```bash
cd ./heartwoodd && cargo build
```

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/relay.rs heartwoodd/src/main.rs
git commit -m "refactor: extract NIP-46 relay event loop to relay.rs"
```

---

### Task 9: Refactor main.rs -- CLI, auto-detect, startup

**Files:**
- Modify: `heartwoodd/src/main.rs`

This is the final wiring task. Slim main.rs down to CLI parsing, auto-detection, backend construction, and startup orchestration.

- [ ] **Step 1: Update CLI struct**

Replace the current `Cli` struct with the new args:

```rust
#[derive(Parser)]
#[command(name = "heartwoodd")]
#[command(about = "Heartwood daemon -- Nostr signing service")]
struct Cli {
    /// Operating mode: auto-detect, force Soft, or force Hard.
    #[arg(long, default_value = "auto")]
    mode: String,

    /// Serial port for ESP32 (e.g. /dev/ttyACM0)
    #[arg(short, long, default_value = "/dev/ttyACM0")]
    port: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    /// Data directory for keystore, bunker-uri.txt, etc.
    #[arg(long, default_value = "/var/lib/heartwood")]
    data_dir: String,

    /// Relay URLs (comma-separated)
    #[arg(short, long, default_value = "wss://relay.damus.io,wss://nos.lol")]
    relays: String,

    /// Port for the management API (default 3100)
    #[arg(long, default_value_t = 3100)]
    api_port: u16,

    /// Directory containing Sapwood dist/ files to serve.
    #[arg(long)]
    sapwood_dir: Option<String>,

    /// Enable CORS headers on API responses.
    #[arg(long)]
    cors: bool,

    /// Bearer token for management API auth (env: HEARTWOOD_API_TOKEN).
    #[arg(long, env = "HEARTWOOD_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,

    // -- Hard mode only --

    /// Bunker secret key for relay auth (env: HEARTWOOD_BUNKER_SECRET).
    /// Required in Hard mode. In Soft mode, an ephemeral key is generated.
    #[arg(long, env = "HEARTWOOD_BUNKER_SECRET", hide_env_values = true)]
    bunker_secret: Option<String>,

    /// Bridge auth secret for ESP32 session (env: HEARTWOOD_BRIDGE_SECRET).
    #[arg(long, env = "HEARTWOOD_BRIDGE_SECRET", hide_env_values = true)]
    bridge_secret: Option<String>,

    /// ESP32 boot PIN (4-8 ASCII digits).
    #[arg(long)]
    pin: Option<String>,
}
```

- [ ] **Step 2: Implement auto-detect**

```rust
enum DetectedMode {
    Hard(RawSerial),
    Soft,
}

fn detect_mode(cli: &Cli) -> DetectedMode {
    match cli.mode.as_str() {
        "hard" => {
            let port = RawSerial::open(&cli.port, cli.baud)
                .expect("--mode=hard but failed to open serial port");
            DetectedMode::Hard(port)
        }
        "soft" => DetectedMode::Soft,
        "auto" | _ => {
            // Probe for ESP32.
            match RawSerial::open(&cli.port, cli.baud) {
                Ok(mut port) => {
                    // Send PROVISION_LIST and wait 3s for a response.
                    let frame_bytes = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[])
                        .expect("frame build");
                    if port.write_all(&frame_bytes).is_ok() {
                        let _ = port.flush();
                        // Wait up to 3s for any response.
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        let mut got_response = false;
                        while std::time::Instant::now() < deadline {
                            let mut buf = [0u8; 1];
                            match port.read(&mut buf) {
                                Ok(1) if buf[0] == 0x48 => {
                                    got_response = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        if got_response {
                            log::info!("ESP32 detected on {} -- Hard mode", cli.port);
                            DetectedMode::Hard(port)
                        } else {
                            log::info!("No ESP32 response on {} -- Soft mode", cli.port);
                            DetectedMode::Soft
                        }
                    } else {
                        DetectedMode::Soft
                    }
                }
                Err(_) => {
                    log::info!("Serial port {} not available -- Soft mode", cli.port);
                    DetectedMode::Soft
                }
            }
        }
    }
}
```

- [ ] **Step 3: Wire up the main function**

```rust
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let (log_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    let relay_list: Vec<String> = cli.relays.split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    // Detect mode and construct backend.
    let (backend, bunker_keys, signing_master_pubkey): (
        Arc<dyn SigningBackend>, Keys, [u8; 32]
    ) = match detect_mode(&cli) {
        DetectedMode::Hard(mut port) => {
            // Existing Hard mode startup: drain, PIN unlock, session auth,
            // query masters, etc. (moved from old main).
            let bunker_keys = Keys::parse(
                cli.bunker_secret.as_deref()
                    .expect("--bunker-secret required in Hard mode")
            )?;

            // ... (existing startup code: drain, pin, bridge_secret auth, query_master_list)
            // Wrap port in Arc<Mutex> and create SerialBackend.
            let port = Arc::new(Mutex::new(port));
            let serial_backend = backend::serial::SerialBackend::new(
                Arc::clone(&port), log_tx.clone()
            );
            let backend: Arc<dyn SigningBackend> = Arc::new(serial_backend);

            // Query masters via backend.
            let masters = backend.list_masters()?;
            let signing_pubkey = /* extract from first master */;

            (backend, bunker_keys, signing_pubkey)
        }
        DetectedMode::Soft => {
            // Soft mode: generate ephemeral bunker keys or parse from CLI.
            let bunker_keys = match cli.bunker_secret.as_deref() {
                Some(secret) => Keys::parse(secret)?,
                None => Keys::generate(),
            };

            let data_dir = std::path::PathBuf::from(&cli.data_dir);
            std::fs::create_dir_all(&data_dir).ok();
            let soft_backend = backend::soft::SoftBackend::new(data_dir);
            let backend: Arc<dyn SigningBackend> = Arc::new(soft_backend);

            log::info!("Soft mode -- unlock via Sapwood to start signing");

            // Signing pubkey is unknown until unlock. Use bunker pubkey as
            // placeholder for relay subscription; re-subscribe after unlock.
            let placeholder = bunker_keys.public_key().to_bytes();

            (backend, bunker_keys, placeholder)
        }
    };

    // Start management API (reachable even while locked).
    let api_token = cli.api_token.clone().map(Arc::new);
    let app_state = api::AppState {
        backend: Arc::clone(&backend),
        daemon_info: Arc::new(api::DaemonInfo {
            tier: backend.tier(),
            relays: relay_list.clone(),
            start_time: std::time::Instant::now(),
        }),
        log_tx: log_tx.clone(),
        api_token,
    };

    let enable_cors = cli.cors || cli.sapwood_dir.is_none();
    let api_router = api::router(app_state, cli.sapwood_dir.as_deref(), enable_cors);

    log::info!("Management API on port {}...", cli.api_port);
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], cli.api_port));
        let listener = tokio::net::TcpListener::bind(addr).await
            .expect("bind API port");
        log::info!("API listening on http://0.0.0.0:{}", cli.api_port);
        axum::serve(listener, api_router).await
            .expect("API server");
    });

    // Spawn log poller only in Hard mode (reads serial bytes for Sapwood WebSocket).
    // In Soft mode there is no serial port -- skip the poller entirely.
    if backend.tier() == Tier::Hard {
        // The SerialBackend exposes serial() for the log poller.
        // This requires downcasting or a separate accessor -- store the
        // Arc<Mutex<RawSerial>> alongside the backend in Hard mode.
        // tokio::spawn(api::log_poller(serial_arc, log_tx.clone()));
    }

    // Connect to relays and start event loop.
    let client = Client::new(bunker_keys.clone());
    for url in &relay_list {
        client.add_relay(url.as_str()).await?;
    }
    client.connect().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    log::info!("Connected to relays");

    relay::run_event_loop(
        &client, &backend, &bunker_keys, &signing_master_pubkey, &log_tx
    ).await?;

    Ok(())
}
```

- [ ] **Step 4: Verify build**

```bash
cd ./heartwoodd && cargo build
```

- [ ] **Step 5: Run all tests**

```bash
cd ./heartwoodd && cargo test
```

Expected: all backend tests pass. Integration tests with a real serial port are not run in CI.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add heartwoodd/src/main.rs
git commit -m "feat: heartwoodd with auto-detect, Soft/Hard mode selection, and tier-aware startup"
```

---

### Task 10: Update documentation and next-session-prompt

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/next-session-prompt.md`

- [ ] **Step 1: Update CLAUDE.md**

In the root `CLAUDE.md`, update the build table row for the bridge crate:

Change `bridge` references to `heartwoodd`. Update the description and build commands:

```
cd heartwoodd && cargo build                # Pi-side daemon (Soft or Hard mode)
```

- [ ] **Step 2: Update next-session-prompt.md**

```markdown
# Next session prompt

Paste this to pick up where we left off:

---

## Current state

Heartwoodd Soft mode design complete and implementation plan written.
The bridge/ crate has been renamed to heartwoodd/ with the SigningBackend
trait, SoftBackend (Argon2id keystore, local k256 signing, approval queue),
SerialBackend (existing ESP32 code wrapped), and refactored api.rs/relay.rs.

Spec: docs/plans/2026-04-06-heartwoodd-soft-mode-design.md
Plan: docs/plans/2026-04-06-heartwoodd-soft-mode-plan.md

## What's next

- Test the full Soft mode flow end-to-end (unlock, create master, pair Bark, sign)
- Sapwood UI changes for tier badge, unlock form, approval queue
- Production hardening (JTAG disable, watchdog) -- separate from Soft work
- Grant guardrails: check docs/memory/project_heartwood_grant_timing.md

## Context

- Device is a Heltec WiFi LoRa 32 V4 (ESP32-S3) connected to Pi at mypi.local
- heartwoodd replaces heartwood-bridge (same binary, two modes)
- Soft mode: Pi alone, Argon2id keyfile, Sapwood unlock
- Hard mode: ESP32 attached, serial frame protocol, button press signing
```

- [ ] **Step 3: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add CLAUDE.md docs/next-session-prompt.md
git commit -m "docs: update for heartwoodd rename and Soft mode"
```

---

## Task dependency graph

```
Task 1 (rename + deps)
  |
  v
Task 2 (trait)
  |
  +-----------+
  |           |
  v           v
Task 3      Task 4
(soft_store) (serial.rs)
  |           |
  v           v
Task 6      Task 5
(SoftBackend)(SerialBackend)
  |           |
  +-----+-----+
        |
        v
Task 7 (api.rs refactor)
        |
        v
Task 8 (relay.rs)
        |
        v
Task 9 (main.rs)
        |
        v
Task 10 (docs)
```

Tasks 3 and 4 are independent and can run in parallel.
Tasks 5 and 6 are independent and can run in parallel.
Tasks 7-10 are sequential.
