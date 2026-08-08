// heartwoodd/src/backend/mod.rs
//
// SigningBackend trait -- core abstraction over Hard (ESP32 serial) and Soft
// (local keyfile) modes. The daemon detects the operating mode at startup and
// constructs a concrete backend, then passes it as Arc<dyn SigningBackend>
// throughout the API and relay loop.
//
// All methods take &self; interior mutability is handled by each implementation.

pub mod serial;
pub mod soft;
pub mod soft_store;

use std::fmt;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Tier
// ---------------------------------------------------------------------------

/// Operating tier -- determines which backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Soft mode: Pi alone, keys encrypted at rest, signed locally.
    Soft,
    /// Hard mode: ESP32 attached via USB serial, keys on device.
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

// ---------------------------------------------------------------------------
// BackendError
// ---------------------------------------------------------------------------

/// Errors that a SigningBackend implementation may return.
#[derive(Debug)]
pub enum BackendError {
    /// The requested operation is not supported by this backend.
    NotSupported,
    /// The backend is locked; unlock it first.
    Locked,
    /// The device (ESP32) is busy with another operation.
    DeviceBusy,
    /// A serial/USB timeout occurred waiting for the device.
    DeviceTimeout,
    /// The physical button was not pressed; the request was denied.
    Denied,
    /// The user did not confirm the operation (button not pressed or timed out).
    UserCancelled,
    /// The request has been queued for manual approval. The string is the
    /// approval ID that the caller can poll or display.
    PendingApproval(String),
    /// The request is larger than the signer can carry. Carries the request
    /// size and the limit, both in bytes.
    ///
    /// Distinct from `Internal` on purpose: this is a client mistake with a
    /// specific remedy (send a smaller event), not a daemon fault, and it is
    /// the one signing failure a caller can actually act on. Without it an
    /// oversize request surfaced as a bare frame-build failure or, worse, as a
    /// silent timeout from the device.
    RequestTooLarge { bytes: usize, limit: usize },
    /// An internal error with a human-readable description.
    Internal(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotSupported    => write!(f, "operation not supported by this backend"),
            BackendError::Locked          => write!(f, "backend is locked"),
            BackendError::DeviceBusy      => write!(f, "device is busy"),
            BackendError::DeviceTimeout   => write!(f, "device timed out"),
            BackendError::Denied          => write!(f, "request denied"),
            BackendError::UserCancelled   => write!(f, "user did not confirm"),
            BackendError::PendingApproval(id) => write!(f, "pending approval: {id}"),
            BackendError::RequestTooLarge { bytes, limit } => write!(
                f,
                "request is {bytes} bytes; this signer accepts at most {limit}"
            ),
            BackendError::Internal(msg)   => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SigningBackend trait
// ---------------------------------------------------------------------------

/// Core abstraction for signing backends.
///
/// Implementations must be Send + Sync so they can be wrapped in Arc and
/// shared across Tokio tasks.
pub trait SigningBackend: Send + Sync {
    // -- Identity -----------------------------------------------------------

    /// Returns the tier this backend operates in.
    fn tier(&self) -> Tier;

    // -- Lock / unlock ------------------------------------------------------

    /// Returns true if the backend is currently locked.
    fn is_locked(&self) -> bool;

    /// Unlock the backend using the supplied passphrase.
    fn unlock(&self, passphrase: &str) -> Result<(), BackendError>;

    /// Lock the backend, clearing any in-memory key material.
    fn lock(&self) -> Result<(), BackendError>;

    // -- NIP-46 signing -----------------------------------------------------

    /// Handle a NIP-46 request: decrypt, process, re-encrypt the response,
    /// then build and sign a kind:24133 envelope event. Returns the signed
    /// event JSON ready for relay publication. The `created_at` timestamp
    /// is embedded in the envelope event.
    fn handle_encrypted_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError>;

    /// Current master signing pubkeys this backend can answer for, beyond
    /// any passed to the relay loop at startup. Soft mode's set changes at
    /// runtime (unlock, master creation) and the relay loop polls this to
    /// keep its subscription current. Backends whose pubkeys are fixed at
    /// startup can rely on the default empty implementation.
    fn signing_pubkeys(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }

    /// Deprecated: envelope signing is now inline in handle_encrypted_request.
    /// Kept for backward compatibility with the approval flow.
    fn sign_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let _ = (master_pubkey, client_pubkey, created_at, ciphertext);
        Err(BackendError::NotSupported)
    }

    // -- Master management --------------------------------------------------

    /// List all provisioned masters. Each item is a JSON object with at least
    /// `index` and `npub` fields (no private key material).
    fn list_masters(&self) -> Result<Vec<Value>, BackendError>;

    /// Create a new master. Returns the new master's JSON representation.
    /// Soft mode generates the key in the daemon's encrypted keystore; Hard
    /// mode asks the ESP32 to self-generate (GENERATE_IDENTITY), which plays
    /// the on-device entropy game and shows the recovery phrase on the OLED.
    /// `words` (12 or 24) selects the phrase length for on-device generation;
    /// Soft mode ignores it (soft masters are raw secrets, phraseless).
    fn create_master(&self, label: &str, words: u8) -> Result<Value, BackendError> {
        let _ = (label, words);
        Err(BackendError::NotSupported)
    }

    /// Remove a master identity by slot. Hard mode requires physical button
    /// confirmation on the device (the OLED shows slot + npub first) and the
    /// device reboots afterwards to reload its slot-indexed state.
    fn remove_master(&self, slot: u8) -> Result<(), BackendError> {
        let _ = slot;
        Err(BackendError::NotSupported)
    }

    // -- Connection slot management -----------------------------------------

    /// List all connection slots for a master.
    fn list_slots(&self, master: u8) -> Result<Value, BackendError>;

    /// Create a new connection slot. Returns the new slot's JSON.
    fn create_slot(&self, master: u8, label: &str) -> Result<Value, BackendError>;

    /// Apply a JSON patch to an existing slot. Returns the updated slot JSON.
    fn update_slot(&self, master: u8, index: u8, patch: Value) -> Result<Value, BackendError>;

    /// Revoke (delete) a connection slot.
    fn revoke_slot(&self, master: u8, index: u8) -> Result<Value, BackendError>;

    /// Return a NIP-46 bunker URI for the given slot, embedding the supplied
    /// relay list.
    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String]) -> Result<String, BackendError>;

    // -- Approval queue (Soft mode only) ------------------------------------

    /// Return all pending approval requests. Default implementation returns
    /// an empty vec (Hard mode: approvals happen physically on the device).
    fn list_approvals(&self) -> Vec<Value> {
        Vec::new()
    }

    /// Approve a pending request by ID.
    /// Default implementation returns NotSupported.
    fn approve_request(&self, id: &str) -> Result<(), BackendError> {
        let _ = id;
        Err(BackendError::NotSupported)
    }

    /// Deny a pending request by ID.
    /// Default implementation returns NotSupported.
    fn deny_request(&self, id: &str) -> Result<(), BackendError> {
        let _ = id;
        Err(BackendError::NotSupported)
    }

    // -- Device management --------------------------------------------------

    /// Perform a factory reset, wiping all key material and NVS storage.
    fn factory_reset(&self) -> Result<(), BackendError>;

    /// Enable at-rest vault encryption on the device: sends VAULT_SET with
    /// the host-held 32-byte vault key, which re-encrypts every master seed
    /// under it (replacing any existing PIN wrap). Hard mode only, and the
    /// device gates the change on physical button confirmation (up to 30s).
    fn vault_enable(&self, key: &[u8; 32]) -> Result<(), BackendError> {
        let _ = key;
        Err(BackendError::NotSupported)
    }

    /// Disable at-rest vault encryption: sends VAULT_SET with an empty
    /// payload, restoring plaintext seeds. Also button-gated on the device.
    fn vault_disable(&self) -> Result<(), BackendError> {
        Err(BackendError::NotSupported)
    }

    /// Upload new firmware bytes. Applies via serial OTA (Hard mode) or is
    /// not supported (Soft mode). `signature` is the ed25519 release
    /// signature (see heartwood-common's ota_sign) — required by
    /// signature-enforcing firmware; `None` falls back to the legacy unsigned
    /// OTA_BEGIN that only pre-signature firmware accepts.
    fn ota_upload(&self, firmware: &[u8], signature: Option<&[u8; 64]>) -> Result<(), BackendError>;

    // -- Backup/restore -------------------------------------------------------

    /// Export all connection slots, master metadata, and bridge secret
    /// as a BackupPayload. Used by the backup service.
    fn backup_export(&self) -> Result<heartwood_common::backup::BackupPayload, BackendError>;

    /// Import a BackupPayload, writing slots and bridge secret to the
    /// device. In Hard mode, requires physical button confirmation.
    fn backup_import(
        &self,
        payload: &heartwood_common::backup::BackupPayload,
    ) -> Result<(), BackendError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Minimal mock backend for trait object safety tests.
    struct MockBackend {
        locked: bool,
    }

    impl SigningBackend for MockBackend {
        fn tier(&self) -> Tier { Tier::Soft }

        fn is_locked(&self) -> bool { self.locked }

        fn unlock(&self, _passphrase: &str) -> Result<(), BackendError> {
            Ok(())
        }

        fn lock(&self) -> Result<(), BackendError> {
            Ok(())
        }

        fn handle_encrypted_request(
            &self,
            _master_pubkey: &[u8; 32],
            _client_pubkey: &[u8; 32],
            _created_at: u64,
            _ciphertext: &str,
        ) -> Result<String, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn list_masters(&self) -> Result<Vec<Value>, BackendError> {
            Ok(vec![])
        }

        fn list_slots(&self, _master: u8) -> Result<Value, BackendError> {
            Ok(Value::Array(vec![]))
        }

        fn create_slot(&self, _master: u8, _label: &str) -> Result<Value, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn update_slot(&self, _master: u8, _index: u8, _patch: Value) -> Result<Value, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn revoke_slot(&self, _master: u8, _index: u8) -> Result<Value, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn get_slot_uri(&self, _master: u8, _index: u8, _relays: &[String]) -> Result<String, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn factory_reset(&self) -> Result<(), BackendError> {
            Err(BackendError::NotSupported)
        }

        fn ota_upload(&self, _firmware: &[u8], _signature: Option<&[u8; 64]>) -> Result<(), BackendError> {
            Err(BackendError::NotSupported)
        }

        fn backup_export(&self) -> Result<heartwood_common::backup::BackupPayload, BackendError> {
            Err(BackendError::NotSupported)
        }

        fn backup_import(&self, _payload: &heartwood_common::backup::BackupPayload) -> Result<(), BackendError> {
            Err(BackendError::NotSupported)
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let backend: Arc<dyn SigningBackend> = Arc::new(MockBackend { locked: false });
        assert_eq!(backend.tier(), Tier::Soft);
        assert!(!backend.is_locked());
    }

    #[test]
    fn tier_display() {
        assert_eq!(Tier::Soft.to_string(), "soft");
        assert_eq!(Tier::Hard.to_string(), "hard");
    }
}
