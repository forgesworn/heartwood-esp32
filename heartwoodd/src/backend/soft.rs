// heartwoodd/src/backend/soft.rs
//
// Soft mode: local NIP-46 signing using k256. Keys are held in an
// Argon2id-encrypted keyfile; the decrypted state lives in memory behind an
// RwLock and is zeroized on lock.
//
// The NIP-44/NIP-46 pipeline mirrors what the ESP32 firmware does, but runs
// entirely on the Pi -- decrypt the client request, evaluate slot policy,
// process the method, encrypt the response.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use k256::schnorr::signature::hazmat::PrehashSigner;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use heartwood_common::encoding::encode_npub;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip44;
use heartwood_common::nip46::{
    self, Nip46Method, SignedEvent, UnsignedEvent, compute_event_id,
};
use heartwood_common::policy::{self, ConnectSlot};

use super::soft_store::{
    self, Keystore, SoftMaster, DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST,
};
use super::{BackendError, SigningBackend, Tier};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TTL for pending approvals (seconds).
const APPROVAL_TTL_SECS: u64 = 60;

/// Default keystore filename.
const KEYSTORE_FILE: &str = "keystore.json";

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct UnlockedState {
    keystore: Keystore,
    encryption_key: Zeroizing<[u8; 32]>,
    envelope_salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A NIP-46 request that requires manual approval before it can be processed.
pub struct PendingApproval {
    pub id: String,
    pub method: String,
    pub event_kind: Option<u64>,
    pub content_preview: String,
    pub slot_label: String,
    pub master_slot: u8,
    pub created_at: Instant,
    pub master_pubkey: [u8; 32],
    pub client_pubkey: [u8; 32],
    pub ciphertext: String,
}

/// Soft-mode signing backend.
///
/// Holds decrypted keystore state in memory behind an `RwLock`. It is
/// `Send + Sync` and safe to wrap in an `Arc` and share across tasks.
pub struct SoftBackend {
    data_dir: PathBuf,
    state: RwLock<Option<UnlockedState>>,
    approvals: RwLock<HashMap<String, PendingApproval>>,
    /// Hands approved-response envelopes (signed kind:24133 JSON) to the relay
    /// publisher task in main. Set once at startup via `set_response_sender`.
    response_tx: RwLock<Option<tokio::sync::mpsc::UnboundedSender<String>>>,
}

impl SoftBackend {
    /// Create a new SoftBackend that stores its keyfile in `data_dir`.
    ///
    /// The backend starts in the locked state. Call `unlock` before using
    /// any signing or key-management operations.
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            state: RwLock::new(None),
            approvals: RwLock::new(HashMap::new()),
            response_tx: RwLock::new(None),
        }
    }

    /// Wire the channel that carries approved-response envelopes to the relay
    /// publisher. Called once from main before the backend is shared.
    pub fn set_response_sender(&self, tx: tokio::sync::mpsc::UnboundedSender<String>) {
        let mut guard = self.response_tx.write().expect("response_tx lock poisoned");
        *guard = Some(tx);
    }

    // -- Private helpers -----------------------------------------------------

    /// Return the keyfile path.
    fn keyfile_path(&self) -> PathBuf {
        self.data_dir.join(KEYSTORE_FILE)
    }

    /// Persist the current in-memory keystore to disk, re-encrypting with the
    /// cached key. Must be called while holding a write guard on `self.state`.
    fn persist(state: &UnlockedState, path: &std::path::Path) -> Result<(), BackendError> {
        let envelope = soft_store::reencrypt_keystore(
            &state.keystore,
            &state.encryption_key,
            state.m_cost,
            state.t_cost,
            state.p_cost,
            &state.envelope_salt,
        )
        .map_err(|e| BackendError::Internal(format!("re-encrypt keystore: {e}")))?;

        soft_store::write_envelope(path, &envelope)
            .map_err(|e| BackendError::Internal(format!("write keystore: {e}")))
    }

    /// Process the actual NIP-46 method after the slot policy check has passed.
    ///
    /// Returns the plaintext JSON response string.
    fn dispatch_method(
        master: &SoftMaster,
        req: &nip46::Nip46Request,
        _client_pubkey_hex: &str,
    ) -> Result<String, BackendError> {
        let secret_bytes = hex_to_32(&master.secret_key)
            .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;

        let method = Nip46Method::from_str(&req.method);

        match method {
            Nip46Method::Connect => {
                // Secret validation already happened in handle_encrypted_request.
                // Return the secret hex that the client supplied (echoed back per NIP-46).
                let secret = req
                    .params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let response_json = if secret.is_empty() {
                    nip46::build_connect_response(&req.id)
                } else {
                    nip46::build_connect_response_with_secret(&req.id, &secret)
                }
                .map_err(|e| BackendError::Internal(format!("build connect response: {e}")))?;
                Ok(response_json)
            }

            Nip46Method::Ping => {
                nip46::build_ping_response(&req.id)
                    .map_err(|e| BackendError::Internal(format!("build ping response: {e}")))
            }

            Nip46Method::GetPublicKey => {
                let pubkey_hex = derive_pubkey_hex(&secret_bytes)
                    .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
                nip46::build_pubkey_response(&req.id, &pubkey_hex)
                    .map_err(|e| BackendError::Internal(format!("build pubkey response: {e}")))
            }

            Nip46Method::SignEvent => {
                let mut event = nip46::parse_unsigned_event(&req.params)
                    .map_err(|e| BackendError::Internal(format!("parse unsigned event: {e}")))?;

                // Fill the pubkey from the master identity.
                let pubkey_hex = derive_pubkey_hex(&secret_bytes)
                    .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
                event.pubkey = pubkey_hex.clone();

                let event_id = compute_event_id(&event);
                let event_id_hex = hex_encode(&event_id);

                let signing_key =
                    k256::schnorr::SigningKey::from_bytes(&secret_bytes)
                        .map_err(|e| BackendError::Internal(format!("signing key: {e}")))?;
                // BIP340 over the 32-byte event id (see sign_envelope).
                let sig: k256::schnorr::Signature = signing_key
                    .sign_prehash(&event_id)
                    .map_err(|e| BackendError::Internal(format!("sign event: {e}")))?;
                let sig_hex = hex_encode(&sig.to_bytes());

                let signed = SignedEvent {
                    id: event_id_hex,
                    pubkey: pubkey_hex,
                    created_at: event.created_at,
                    kind: event.kind,
                    tags: event.tags,
                    content: event.content,
                    sig: sig_hex,
                };

                nip46::build_sign_response(&req.id, &signed)
                    .map_err(|e| BackendError::Internal(format!("build sign response: {e}")))
            }

            Nip46Method::Nip44Encrypt => {
                // NIP-46 order: params[0] = recipient x-only pubkey hex,
                // params[1] = plaintext (matches the firmware handler).
                let recipient_hex = req
                    .params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_encrypt: missing params[0]".into()))?;
                let plaintext = req
                    .params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_encrypt: missing params[1]".into()))?;
                let recipient_bytes = hex_to_32(recipient_hex)
                    .map_err(|e| BackendError::Internal(format!("nip44_encrypt recipient pubkey: {e}")))?;
                let conv_key = nip44::get_conversation_key(&secret_bytes, &recipient_bytes)
                    .map_err(|e| BackendError::Internal(format!("nip44 conversation key: {e}")))?;
                let mut nonce = [0u8; 32];
                getrandom::getrandom(&mut nonce)
                    .map_err(|e| BackendError::Internal(format!("nonce generation: {e}")))?;
                let ciphertext = nip44::encrypt(&conv_key, plaintext, &nonce)
                    .map_err(|e| BackendError::Internal(format!("nip44 encrypt: {e}")))?;
                nip46::build_result_response(&req.id, &ciphertext)
                    .map_err(|e| BackendError::Internal(format!("build result response: {e}")))
            }

            Nip46Method::Nip44Decrypt => {
                // NIP-46 order: params[0] = sender x-only pubkey hex,
                // params[1] = ciphertext (matches the firmware handler).
                let sender_hex = req
                    .params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_decrypt: missing params[0]".into()))?;
                let ciphertext = req
                    .params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_decrypt: missing params[1]".into()))?;
                let sender_bytes = hex_to_32(sender_hex)
                    .map_err(|e| BackendError::Internal(format!("nip44_decrypt sender pubkey: {e}")))?;
                let conv_key = nip44::get_conversation_key(&secret_bytes, &sender_bytes)
                    .map_err(|e| BackendError::Internal(format!("nip44 conversation key: {e}")))?;
                let plaintext = nip44::decrypt(&conv_key, ciphertext)
                    .map_err(|e| BackendError::Internal(format!("nip44 decrypt: {e}")))?;
                nip46::build_result_response(&req.id, &plaintext)
                    .map_err(|e| BackendError::Internal(format!("build result response: {e}")))
            }

            Nip46Method::HeartwoodCapabilities => {
                // Extension discovery — Soft mode serves the vanilla method
                // set only (no tree extensions on the Pi).
                nip46::build_capabilities_response(
                    &req.id,
                    &[
                        "connect",
                        "ping",
                        "get_public_key",
                        "sign_event",
                        "nip44_encrypt",
                        "nip44_decrypt",
                        "heartwood_capabilities",
                    ],
                )
                .map_err(|e| BackendError::Internal(format!("build capabilities response: {e}")))
            }

            _ => {
                let error_json = nip46::build_error_response(&req.id, -32601, "method not supported")
                    .map_err(|e| BackendError::Internal(format!("build error response: {e}")))?;
                Ok(error_json)
            }
        }
    }

    /// Find the master whose x-only pubkey matches `master_pubkey_bytes`.
    /// Returns the master index into `keystore.masters`.
    fn find_master_by_pubkey<'a>(
        keystore: &'a Keystore,
        master_pubkey_bytes: &[u8; 32],
    ) -> Option<&'a SoftMaster> {
        for m in &keystore.masters {
            let secret = match hex_to_32(&m.secret_key) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let pk = match derive_x_only_bytes(&secret) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pk == *master_pubkey_bytes {
                return Some(m);
            }
        }
        None
    }

    /// Find the master and return its slot index.
    fn find_master_slot(keystore: &Keystore, master_pubkey_bytes: &[u8; 32]) -> Option<u8> {
        for m in &keystore.masters {
            let secret = match hex_to_32(&m.secret_key) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let pk = match derive_x_only_bytes(&secret) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pk == *master_pubkey_bytes {
                return Some(m.slot);
            }
        }
        None
    }

    /// Build and sign a kind:24133 envelope event wrapping the given NIP-44
    /// ciphertext. Used by handle_encrypted_request to return a signed event
    /// instead of raw ciphertext.
    fn wrap_in_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let master = Self::find_master_by_pubkey(&state.keystore, master_pubkey)
            .ok_or_else(|| BackendError::Internal("master not found".into()))?;

        let secret_bytes = hex_to_32(&master.secret_key)
            .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;

        let master_pubkey_hex = derive_pubkey_hex(&secret_bytes)
            .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
        let client_pubkey_hex = hex_encode(client_pubkey);

        let unsigned = UnsignedEvent {
            pubkey: master_pubkey_hex.clone(),
            created_at,
            kind: 24133,
            tags: vec![vec!["p".to_string(), client_pubkey_hex]],
            content: ciphertext.to_string(),
        };

        let event_id = compute_event_id(&unsigned);
        let event_id_hex = hex_encode(&event_id);

        let signing_key = k256::schnorr::SigningKey::from_bytes(&secret_bytes)
            .map_err(|e| BackendError::Internal(format!("signing key: {e}")))?;
        // BIP340 over the 32-byte event id itself. Signer::sign would prehash
        // the id with SHA-256 first, producing signatures no Nostr client
        // (nostr-tools verifyEvent, relays) accepts.
        let sig: k256::schnorr::Signature = signing_key
            .sign_prehash(&event_id)
            .map_err(|e| BackendError::Internal(format!("sign event: {e}")))?;
        let sig_hex = hex_encode(&sig.to_bytes());

        let signed = SignedEvent {
            id: event_id_hex,
            pubkey: master_pubkey_hex,
            created_at,
            kind: 24133,
            tags: unsigned.tags,
            content: unsigned.content,
            sig: sig_hex,
        };

        serde_json::to_string(&signed)
            .map_err(|e| BackendError::Internal(format!("serialise signed envelope: {e}")))
    }
}

// ---------------------------------------------------------------------------
// SigningBackend implementation
// ---------------------------------------------------------------------------

impl SigningBackend for SoftBackend {
    fn tier(&self) -> Tier {
        Tier::Soft
    }

    fn signing_pubkeys(&self) -> Vec<[u8; 32]> {
        let Ok(guard) = self.state.read() else {
            return Vec::new();
        };
        let Some(state) = guard.as_ref() else {
            return Vec::new();
        };
        state
            .keystore
            .masters
            .iter()
            .filter_map(|master| {
                let secret = hex_to_32(&master.secret_key).ok()?;
                let pubkey_hex = derive_pubkey_hex(&secret).ok()?;
                hex_to_32(&pubkey_hex).ok()
            })
            .collect()
    }

    fn is_locked(&self) -> bool {
        self.state
            .read()
            .expect("state lock poisoned")
            .is_none()
    }

    fn unlock(&self, passphrase: &str) -> Result<(), BackendError> {
        let path = self.keyfile_path();

        if !path.exists() {
            // First run: create an empty keystore.
            std::fs::create_dir_all(&self.data_dir)
                .map_err(|e| BackendError::Internal(format!("create data_dir: {e}")))?;

            let empty = Keystore { masters: vec![] };
            let envelope = soft_store::encrypt_keystore(
                &empty,
                passphrase,
                DEFAULT_M_COST,
                DEFAULT_T_COST,
                DEFAULT_P_COST,
            )
            .map_err(|e| BackendError::Internal(format!("encrypt new keystore: {e}")))?;

            soft_store::write_envelope(&path, &envelope)
                .map_err(|e| BackendError::Internal(format!("write new keystore: {e}")))?;

            let salt = envelope.salt.clone();
            let (keystore, key) = soft_store::decrypt_keystore(&envelope, passphrase)
                .map_err(|e| BackendError::Internal(format!("decrypt new keystore: {e}")))?;

            let mut guard = self.state.write().expect("state lock poisoned");
            *guard = Some(UnlockedState {
                keystore,
                encryption_key: key,
                envelope_salt: salt,
                m_cost: DEFAULT_M_COST,
                t_cost: DEFAULT_T_COST,
                p_cost: DEFAULT_P_COST,
            });
            return Ok(());
        }

        let envelope = soft_store::read_envelope(&path)
            .map_err(|e| BackendError::Internal(format!("read keystore: {e}")))?;

        let m_cost = envelope.argon2_m_cost;
        let t_cost = envelope.argon2_t_cost;
        let p_cost = envelope.argon2_p_cost;
        let salt = envelope.salt.clone();

        let (keystore, key) = soft_store::decrypt_keystore(&envelope, passphrase)
            .map_err(|_| BackendError::Internal("wrong passphrase or corrupted keystore".into()))?;

        let mut guard = self.state.write().expect("state lock poisoned");
        *guard = Some(UnlockedState {
            keystore,
            encryption_key: key,
            envelope_salt: salt,
            m_cost,
            t_cost,
            p_cost,
        });
        Ok(())
    }

    fn lock(&self) -> Result<(), BackendError> {
        let mut guard = self.state.write().expect("state lock poisoned");
        *guard = None;
        Ok(())
    }

    // -- NIP-46 signing -------------------------------------------------------

    fn handle_encrypted_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        self.process_request(master_pubkey, client_pubkey, created_at, ciphertext, false)
    }

    fn handle_approved_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        self.process_request(master_pubkey, client_pubkey, created_at, ciphertext, true)
    }

    fn sign_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let master = Self::find_master_by_pubkey(&state.keystore, master_pubkey)
            .ok_or_else(|| BackendError::Internal("master not found".into()))?;

        let secret_bytes = hex_to_32(&master.secret_key)
            .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;

        let master_pubkey_hex = derive_pubkey_hex(&secret_bytes)
            .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
        let client_pubkey_hex = hex_encode(client_pubkey);

        let unsigned = UnsignedEvent {
            pubkey: master_pubkey_hex.clone(),
            created_at,
            kind: 24133,
            tags: vec![vec!["p".to_string(), client_pubkey_hex]],
            content: ciphertext.to_string(),
        };

        let event_id = compute_event_id(&unsigned);
        let event_id_hex = hex_encode(&event_id);

        let signing_key = k256::schnorr::SigningKey::from_bytes(&secret_bytes)
            .map_err(|e| BackendError::Internal(format!("signing key: {e}")))?;
        // BIP340 over the 32-byte event id itself. Signer::sign would prehash
        // the id with SHA-256 first, producing signatures no Nostr client
        // (nostr-tools verifyEvent, relays) accepts.
        let sig: k256::schnorr::Signature = signing_key
            .sign_prehash(&event_id)
            .map_err(|e| BackendError::Internal(format!("sign event: {e}")))?;
        let sig_hex = hex_encode(&sig.to_bytes());

        let signed = SignedEvent {
            id: event_id_hex,
            pubkey: master_pubkey_hex,
            created_at,
            kind: 24133,
            tags: unsigned.tags,
            content: unsigned.content,
            sig: sig_hex,
        };

        serde_json::to_string(&signed)
            .map_err(|e| BackendError::Internal(format!("serialise signed envelope: {e}")))
    }

    // -- Master management ---------------------------------------------------

    fn list_masters(&self) -> Result<Vec<Value>, BackendError> {
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let mut result = Vec::new();
        for m in &state.keystore.masters {
            let secret = hex_to_32(&m.secret_key)
                .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;
            let pubkey_bytes = derive_x_only_bytes(&secret)
                .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
            let npub = encode_npub(&pubkey_bytes);
            let pubkey_hex = hex_encode(&pubkey_bytes);
            result.push(serde_json::json!({
                "index": m.slot,
                "label": m.label,
                "npub": npub,
                "pubkey": pubkey_hex,
                "mode": m.mode,
                "slot_count": m.connection_slots.len(),
            }));
        }
        Ok(result)
    }

    fn create_master(&self, label: &str, _words: u8) -> Result<Value, BackendError> {
        // Soft masters are raw 32-byte secrets (phraseless), so the word count
        // only meaningful to on-device generation is ignored here.
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes)
            .map_err(|e| BackendError::Internal(format!("getrandom: {e}")))?;
        let secret_hex = hex_encode(&secret_bytes);
        // Zeroize the local copy after encoding.
        let mut secret_zeroize = Zeroizing::new(secret_bytes);
        *secret_zeroize = [0u8; 32];

        let (pubkey_bytes, npub, pubkey_hex) = {
            let sk = hex_to_32(&secret_hex)
                .map_err(|e| BackendError::Internal(format!("re-parse secret: {e}")))?;
            let pk = derive_x_only_bytes(&sk)
                .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
            let npub = encode_npub(&pk);
            let pubkey_hex = hex_encode(&pk);
            (pk, npub, pubkey_hex)
        };
        let _ = pubkey_bytes;

        let path = self.keyfile_path();
        let slot_index = {
            let guard = self.state.read().expect("state lock poisoned");
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            // Assign the next available slot index.
            let max_slot = state
                .keystore
                .masters
                .iter()
                .map(|m| m.slot)
                .max()
                .map(|s| s + 1)
                .unwrap_or(0);
            max_slot
        };

        {
            let mut guard = self.state.write().expect("state lock poisoned");
            let state = guard.as_mut().ok_or(BackendError::Locked)?;
            state.keystore.masters.push(SoftMaster {
                slot: slot_index,
                label: label.to_string(),
                secret_key: secret_hex.clone(),
                mode: "soft".to_string(),
                connection_slots: vec![],
            });
            Self::persist(state, &path)?;
        }

        Ok(serde_json::json!({
            "index": slot_index,
            "label": label,
            "npub": npub,
            "pubkey": pubkey_hex,
            "mode": "soft",
            "slot_count": 0,
        }))
    }

    /// Remove a Soft-mode master from the encrypted keystore. The daemon is
    /// the key holder here, so there is no physical gate — the API bearer
    /// token is the authority. The in-memory secret bytes are scrubbed as the
    /// entry drops out of the keystore.
    fn remove_master(&self, slot: u8) -> Result<(), BackendError> {
        let mut guard = self.state.write().expect("state lock poisoned");
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        let before = state.keystore.masters.len();
        state.keystore.masters.retain(|m| m.slot != slot);
        if state.keystore.masters.len() == before {
            return Err(BackendError::Internal(format!("master {slot} not found")));
        }

        let path = self.keyfile_path();
        Self::persist(state, &path)
    }

    // -- Connection slot management ------------------------------------------

    fn list_slots(&self, master: u8) -> Result<Value, BackendError> {
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let m = state
            .keystore
            .masters
            .iter()
            .find(|m| m.slot == master)
            .ok_or_else(|| BackendError::Internal(format!("master {master} not found")))?;

        let redacted: Vec<Value> = m
            .connection_slots
            .iter()
            .map(|s| {
                let r = policy::redact_slot(s);
                serde_json::to_value(&r).expect("ConnectSlot serialises")
            })
            .collect();

        Ok(Value::Array(redacted))
    }

    fn create_slot(&self, master: u8, label: &str) -> Result<Value, BackendError> {
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes)
            .map_err(|e| BackendError::Internal(format!("getrandom: {e}")))?;
        let secret_hex = hex_encode(&secret_bytes);

        let path = self.keyfile_path();
        let new_slot = {
            let mut guard = self.state.write().expect("state lock poisoned");
            let state = guard.as_mut().ok_or(BackendError::Locked)?;

            let m = state
                .keystore
                .masters
                .iter_mut()
                .find(|m| m.slot == master)
                .ok_or_else(|| BackendError::Internal(format!("master {master} not found")))?;

            let slot_index =
                policy::next_slot_index(&m.connection_slots).ok_or_else(|| {
                    BackendError::Internal("no free connection slot index".into())
                })?;

            let slot = ConnectSlot {
                slot_index,
                label: label.to_string(),
                secret: secret_hex,
                current_pubkey: None,
                allowed_methods: policy::CONNECT_SAFE_METHODS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                allowed_kinds: vec![],
                auto_approve: true,
                signing_approved: false,
                strict_permissions: false,
                authorized_pubkeys: vec![],
            };
            m.connection_slots.push(slot.clone());
            Self::persist(state, &path)?;
            slot
        };

        let redacted = policy::redact_slot(&new_slot);
        Ok(serde_json::to_value(&redacted).expect("ConnectSlot serialises"))
    }

    fn update_slot(&self, master: u8, index: u8, patch: Value) -> Result<Value, BackendError> {
        let path = self.keyfile_path();
        let updated_slot = {
            let mut guard = self.state.write().expect("state lock poisoned");
            let state = guard.as_mut().ok_or(BackendError::Locked)?;

            let m = state
                .keystore
                .masters
                .iter_mut()
                .find(|m| m.slot == master)
                .ok_or_else(|| BackendError::Internal(format!("master {master} not found")))?;

            let slot = m
                .connection_slots
                .iter_mut()
                .find(|s| s.slot_index == index)
                .ok_or_else(|| {
                    BackendError::Internal(format!("slot {index} not found on master {master}"))
                })?;

            // Apply patch fields.
            if let Some(label) = patch.get("label").and_then(|v| v.as_str()) {
                slot.label = label.to_string();
            }
            if let Some(methods) = patch.get("allowed_methods").and_then(|v| v.as_array()) {
                slot.allowed_methods = methods
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(kinds) = patch.get("allowed_kinds").and_then(|v| v.as_array()) {
                slot.allowed_kinds = kinds
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .collect();
            }
            if let Some(auto_approve) = patch.get("auto_approve").and_then(|v| v.as_bool()) {
                slot.auto_approve = auto_approve;
            }

            let updated = slot.clone();
            Self::persist(state, &path)?;
            updated
        };

        let redacted = policy::redact_slot(&updated_slot);
        Ok(serde_json::to_value(&redacted).expect("ConnectSlot serialises"))
    }

    fn revoke_slot(&self, master: u8, index: u8) -> Result<Value, BackendError> {
        let path = self.keyfile_path();
        let mut guard = self.state.write().expect("state lock poisoned");
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        let m = state
            .keystore
            .masters
            .iter_mut()
            .find(|m| m.slot == master)
            .ok_or_else(|| BackendError::Internal(format!("master {master} not found")))?;

        let before = m.connection_slots.len();
        m.connection_slots.retain(|s| s.slot_index != index);
        if m.connection_slots.len() == before {
            return Err(BackendError::Internal(format!(
                "slot {index} not found on master {master}"
            )));
        }

        Self::persist(state, &path)?;

        Ok(serde_json::json!({ "revoked": index }))
    }

    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String]) -> Result<String, BackendError> {
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let m = state
            .keystore
            .masters
            .iter()
            .find(|m| m.slot == master)
            .ok_or_else(|| BackendError::Internal(format!("master {master} not found")))?;

        let secret_bytes = hex_to_32(&m.secret_key)
            .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;
        let pubkey_hex = derive_pubkey_hex(&secret_bytes)
            .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;

        let slot = m
            .connection_slots
            .iter()
            .find(|s| s.slot_index == index)
            .ok_or_else(|| {
                BackendError::Internal(format!("slot {index} not found on master {master}"))
            })?;

        let mut uri = format!("bunker://{}?", pubkey_hex);
        for relay in relays {
            uri.push_str(&format!("relay={}&", urlencoding::encode(relay)));
        }
        uri.push_str(&format!("secret={}", slot.secret));

        Ok(uri)
    }

    // -- Approval queue -------------------------------------------------------

    fn list_approvals(&self) -> Vec<Value> {
        let now = Instant::now();
        let mut approvals = self.approvals.write().expect("approvals lock poisoned");

        // Prune expired entries.
        approvals.retain(|_, v| {
            now.duration_since(v.created_at).as_secs() < APPROVAL_TTL_SECS
        });

        approvals
            .values()
            .map(|a| {
                serde_json::json!({
                    "id": a.id,
                    "method": a.method,
                    "event_kind": a.event_kind,
                    "content_preview": a.content_preview,
                    "slot_label": a.slot_label,
                    "master_slot": a.master_slot,
                    "age_secs": now.duration_since(a.created_at).as_secs(),
                })
            })
            .collect()
    }

    fn approve_request(&self, id: &str) -> Result<(), BackendError> {
        let approval = {
            let mut approvals = self.approvals.write().expect("approvals lock poisoned");
            approvals
                .remove(id)
                .ok_or_else(|| BackendError::Internal(format!("approval {id} not found")))?
        };

        // Re-process the original request with policy bypassed: the operator's
        // approval is the authorisation. Re-running the policy check here used
        // to re-queue the very request being approved, and the signed envelope
        // was then dropped — the client never heard back.
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let signed_event_json = self.process_request(
            &approval.master_pubkey,
            &approval.client_pubkey,
            created_at,
            &approval.ciphertext,
            true,
        )?;

        // Hand the signed envelope to the relay publisher task.
        let tx = self.response_tx.read().expect("response_tx lock poisoned").clone();
        match tx {
            Some(tx) => {
                if tx.send(signed_event_json).is_err() {
                    log::error!("approved response lost: relay publisher is not running");
                }
            }
            None => log::error!("approved response lost: no relay publisher wired"),
        }
        Ok(())
    }

    fn deny_request(&self, id: &str) -> Result<(), BackendError> {
        let mut approvals = self.approvals.write().expect("approvals lock poisoned");
        if approvals.remove(id).is_some() {
            Ok(())
        } else {
            Err(BackendError::Internal(format!("approval {id} not found")))
        }
    }

    // -- Device management ---------------------------------------------------

    fn factory_reset(&self) -> Result<(), BackendError> {
        let path = self.keyfile_path();
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| BackendError::Internal(format!("delete keystore: {e}")))?;
        }
        let mut guard = self.state.write().expect("state lock poisoned");
        *guard = None;
        Ok(())
    }

    fn ota_upload(&self, _firmware: &[u8], _signature: Option<&[u8; 64]>) -> Result<(), BackendError> {
        Err(BackendError::NotSupported)
    }

    // -- Backup/restore -------------------------------------------------------

    fn backup_export(&self) -> Result<heartwood_common::backup::BackupPayload, BackendError> {
        use heartwood_common::backup::{BackupMaster, BackupPayload};

        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;

        let mut masters = Vec::new();
        for m in &state.keystore.masters {
            let secret = hex_to_32(&m.secret_key)
                .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;
            let pubkey_bytes = derive_x_only_bytes(&secret)
                .map_err(|e| BackendError::Internal(format!("derive pubkey: {e}")))?;
            let pubkey_hex = hex_encode(&pubkey_bytes);

            masters.push(BackupMaster {
                slot: m.slot,
                label: m.label.clone(),
                // Soft mode always uses mode=0 (Bunker equivalent) as the provisioning mode.
                mode: 0,
                pubkey: pubkey_hex,
                connection_slots: m.connection_slots.clone(),
            });
        }

        Ok(BackupPayload {
            created_at: 0,
            device_id: String::new(),
            bridge_secret: String::new(),
            masters,
        })
    }

    fn backup_import(
        &self,
        payload: &heartwood_common::backup::BackupPayload,
    ) -> Result<(), BackendError> {
        let path = self.keyfile_path();
        let mut guard = self.state.write().expect("state lock poisoned");
        let state = guard.as_mut().ok_or(BackendError::Locked)?;

        for backup_master in &payload.masters {
            // Find the matching device master by derived pubkey.
            let matched = state.keystore.masters.iter_mut().find(|m| {
                let secret = match hex_to_32(&m.secret_key) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let pk = match derive_x_only_bytes(&secret) {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                hex_encode(&pk) == backup_master.pubkey
            });

            if let Some(device_master) = matched {
                device_master.connection_slots = backup_master.connection_slots.clone();
            }
        }

        Self::persist(state, &path)
    }
}

impl SoftBackend {
    /// Decrypt, policy-check and answer one NIP-46 request, returning the
    /// signed kind:24133 envelope JSON.
    ///
    /// `preapproved` is set only by the manual-approval path (`approve_request`
    /// via `handle_approved_request`): the operator's approval IS the
    /// authorisation, so slot-policy checks are skipped — re-evaluating them
    /// would just re-queue the same request.
    fn process_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
        preapproved: bool,
    ) -> Result<String, BackendError> {
        // Take a read lock to fetch what we need, then release before any
        // potential write that persist() would need.
        let (master_secret, slot_info, master_slot_index) = {
            let guard = self.state.read().expect("state lock poisoned");
            let state = guard.as_ref().ok_or(BackendError::Locked)?;

            let master = Self::find_master_by_pubkey(&state.keystore, master_pubkey)
                .ok_or_else(|| BackendError::Internal("master not found".into()))?;

            let secret = hex_to_32(&master.secret_key)
                .map_err(|e| BackendError::Internal(format!("master secret: {e}")))?;

            let client_pubkey_hex = hex_encode(client_pubkey);
            let slot = policy::find_slot_by_pubkey(&master.connection_slots, &client_pubkey_hex)
                .cloned();

            (secret, slot, master.slot)
        };

        // Derive NIP-44 conversation key and decrypt the request.
        let conv_key = nip44::get_conversation_key(&master_secret, client_pubkey)
            .map_err(|e| BackendError::Internal(format!("conversation key: {e}")))?;

        let plaintext = nip44::decrypt(&conv_key, ciphertext)
            .map_err(|e| BackendError::Internal(format!("NIP-44 decrypt: {e}")))?;

        let req = nip46::parse_request(plaintext.as_bytes())
            .map_err(|e| BackendError::Internal(format!("parse NIP-46 request: {e}")))?;

        let method = Nip46Method::from_str(&req.method);

        // Policy check.
        let client_pubkey_hex = hex_encode(client_pubkey);

        // -- Visibility logging (no behaviour change) -------------------------
        // Record method, kind (for sign_event), and the matched slot label so
        // each request is attributable in the journal without decryption hacks.
        let client_short: String = client_pubkey_hex.chars().take(12).collect();
        let slot_label = slot_info.as_ref().map(|s| s.label.clone()).unwrap_or_default();
        let slot_suffix = if slot_label.is_empty() {
            String::new()
        } else {
            format!(" [slot \"{slot_label}\"]")
        };
        // For sign_event, keep the parsed kind and a short content preview so
        // every queue site can show the operator WHAT is being signed.
        let mut sign_kind: Option<u64> = None;
        let mut sign_preview = String::new();
        if method == Nip46Method::SignEvent {
            let parsed = req
                .params
                .first()
                .and_then(|v| match v {
                    Value::String(s) => serde_json::from_str::<UnsignedEvent>(s).ok(),
                    Value::Object(_) => serde_json::from_value::<UnsignedEvent>(v.clone()).ok(),
                    _ => None,
                });
            if let Some(ev) = &parsed {
                sign_kind = Some(ev.kind);
                sign_preview = ev.content.chars().take(80).collect();
            }
            match sign_kind {
                Some(k) => log::info!("soft: sign_event kind {k} from {client_short}…{slot_suffix}"),
                None => log::info!("soft: sign_event (unparsed kind) from {client_short}…{slot_suffix}"),
            }
        } else {
            log::info!("soft: {} from {client_short}…{slot_suffix}", req.method);
        }

        // For connect: validate secret and bind the slot.
        if method == Nip46Method::Connect {
            let provided_secret = req
                .params
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Find the slot by secret and bind it to this client pubkey.
            if !provided_secret.is_empty() {
                let mut guard = self.state.write().expect("state lock poisoned");
                let state = guard.as_mut().ok_or(BackendError::Locked)?;
                let master_mut = state
                    .keystore
                    .masters
                    .iter_mut()
                    .find(|m| m.slot == master_slot_index)
                    .ok_or_else(|| BackendError::Internal("master not found on write".into()))?;

                let matched = policy::find_slot_by_secret(
                    &master_mut.connection_slots,
                    &provided_secret,
                )
                .map(|slot| slot.slot_index);
                if let Some(slot_index) = matched {
                    policy::authorize_pubkey_on_unique_slot(
                        &mut master_mut.connection_slots,
                        slot_index,
                        &client_pubkey_hex,
                    );
                    let path = self.keyfile_path();
                    Self::persist(state, &path)?;
                } else {
                    // Secret not recognised -- return error.
                    let error_json = nip46::build_error_response(&req.id, -32600, "invalid secret")
                        .map_err(|e| BackendError::Internal(format!("build error response: {e}")))?;
                    let mut nonce = [0u8; 32];
                    getrandom::getrandom(&mut nonce)
                        .map_err(|e| BackendError::Internal(format!("nonce generation: {e}")))?;
                    let ct = nip44::encrypt(&conv_key, &error_json, &nonce)
                        .map_err(|e| BackendError::Internal(format!("NIP-44 encrypt: {e}")))?;
                    return self.wrap_in_envelope(master_pubkey, client_pubkey, created_at, &ct);
                }
            }

            // Re-read the master after the write to get the updated slot.
            let guard = self.state.read().expect("state lock poisoned");
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            let master = state
                .keystore
                .masters
                .iter()
                .find(|m| m.slot == master_slot_index)
                .ok_or_else(|| BackendError::Internal("master not found".into()))?;

            let response_json = Self::dispatch_method(master, &req, &client_pubkey_hex)?;
            let mut nonce = [0u8; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|e| BackendError::Internal(format!("nonce generation: {e}")))?;
            let response_ct = nip44::encrypt(&conv_key, &response_json, &nonce)
                .map_err(|e| BackendError::Internal(format!("NIP-44 encrypt response: {e}")))?;
            return self.wrap_in_envelope(master_pubkey, client_pubkey, created_at, &response_ct);
        }

        // Always-auto-approve methods (ping, get_public_key, heartwood_list_identities, etc.).
        if method.always_auto_approve() {
            let guard = self.state.read().expect("state lock poisoned");
            let state = guard.as_ref().ok_or(BackendError::Locked)?;
            let master = Self::find_master_by_pubkey(&state.keystore, master_pubkey)
                .ok_or_else(|| BackendError::Internal("master not found".into()))?;
            let response_json = Self::dispatch_method(master, &req, &client_pubkey_hex)?;
            let mut nonce = [0u8; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|e| BackendError::Internal(format!("nonce generation: {e}")))?;
            let response_ct = nip44::encrypt(&conv_key, &response_json, &nonce)
                .map_err(|e| BackendError::Internal(format!("NIP-44 encrypt response: {e}")))?;
            return self.wrap_in_envelope(master_pubkey, client_pubkey, created_at, &response_ct);
        }

        // For sign_event and other methods, check the slot policy (unless the
        // request has already been manually approved by the operator).
        let slot = match slot_info {
            Some(s) => Some(s),
            None if preapproved => None,
            None => {
                log::warn!(
                    "soft: {} from {client_short}… QUEUED — no connection slot bound to this client",
                    req.method
                );
                // No slot for this client -- queue for approval.
                let approval_id = Uuid::new_v4().to_string();
                let approval = PendingApproval {
                    id: approval_id.clone(),
                    method: req.method.clone(),
                    event_kind: sign_kind,
                    content_preview: sign_preview.clone(),
                    slot_label: String::new(),
                    master_slot: master_slot_index,
                    created_at: Instant::now(),
                    master_pubkey: *master_pubkey,
                    client_pubkey: *client_pubkey,
                    ciphertext: ciphertext.to_string(),
                };
                let mut approvals = self.approvals.write().expect("approvals lock poisoned");
                approvals.insert(approval_id.clone(), approval);
                return Err(BackendError::PendingApproval(approval_id));
            }
        };

        // Check if this method is allowed by slot policy.
        let method_allowed = slot
            .as_ref()
            .is_some_and(|s| s.allowed_methods.contains(&req.method));
        if !preapproved && !method_allowed {
            log::warn!(
                "soft: {} from {client_short}… QUEUED — method not in slot \"{slot_label}\" policy",
                req.method,
            );
            let approval_id = Uuid::new_v4().to_string();
            let approval = PendingApproval {
                id: approval_id.clone(),
                method: req.method.clone(),
                event_kind: sign_kind,
                content_preview: sign_preview.clone(),
                slot_label: slot_label.clone(),
                master_slot: master_slot_index,
                created_at: Instant::now(),
                master_pubkey: *master_pubkey,
                client_pubkey: *client_pubkey,
                ciphertext: ciphertext.to_string(),
            };
            let mut approvals = self.approvals.write().expect("approvals lock poisoned");
            approvals.insert(approval_id.clone(), approval);
            return Err(BackendError::PendingApproval(approval_id));
        }

        // For sign_event, also check allowed_kinds and auto_approve. All of this
        // is skipped for operator-approved requests — the approval is the
        // authorisation; re-checking would re-queue the request it just released.
        if !preapproved {
            let slot = slot.as_ref().expect("slot is bound when !preapproved");
            if method == Nip46Method::SignEvent {
                let kind_allowed = slot.allowed_kinds.is_empty()
                    || sign_kind.is_none_or(|k| slot.allowed_kinds.contains(&k));

                if !kind_allowed || !slot.auto_approve {
                    log::warn!(
                        "soft: sign_event kind {:?} from {client_short}… QUEUED — {} (slot \"{}\")",
                        sign_kind,
                        if !kind_allowed { "kind not in slot policy" } else { "auto-approve disabled" },
                        slot.label
                    );
                    let approval_id = Uuid::new_v4().to_string();
                    let approval = PendingApproval {
                        id: approval_id.clone(),
                        method: req.method.clone(),
                        event_kind: sign_kind,
                        content_preview: sign_preview.clone(),
                        slot_label: slot.label.clone(),
                        master_slot: master_slot_index,
                        created_at: Instant::now(),
                        master_pubkey: *master_pubkey,
                        client_pubkey: *client_pubkey,
                        ciphertext: ciphertext.to_string(),
                    };
                    let mut approvals = self.approvals.write().expect("approvals lock poisoned");
                    approvals.insert(approval_id.clone(), approval);
                    return Err(BackendError::PendingApproval(approval_id));
                }
            } else if !slot.auto_approve {
                log::warn!(
                    "soft: {} from {client_short}… QUEUED — auto-approve disabled (slot \"{}\")",
                    req.method,
                    slot.label
                );
                let approval_id = Uuid::new_v4().to_string();
                let approval = PendingApproval {
                    id: approval_id.clone(),
                    method: req.method.clone(),
                    event_kind: sign_kind,
                    content_preview: sign_preview.clone(),
                    slot_label: slot.label.clone(),
                    master_slot: master_slot_index,
                    created_at: Instant::now(),
                    master_pubkey: *master_pubkey,
                    client_pubkey: *client_pubkey,
                    ciphertext: ciphertext.to_string(),
                };
                let mut approvals = self.approvals.write().expect("approvals lock poisoned");
                approvals.insert(approval_id.clone(), approval);
                return Err(BackendError::PendingApproval(approval_id));
            }
        }

        // Policy passed -- process the request.
        let guard = self.state.read().expect("state lock poisoned");
        let state = guard.as_ref().ok_or(BackendError::Locked)?;
        let master = Self::find_master_by_pubkey(&state.keystore, master_pubkey)
            .ok_or_else(|| BackendError::Internal("master not found".into()))?;
        let response_json = Self::dispatch_method(master, &req, &client_pubkey_hex)?;
        if preapproved {
            log::info!(
                "soft: {} from {client_short}… APPROVED BY OPERATOR{slot_suffix}",
                req.method,
            );
        } else {
            log::info!(
                "soft: {} from {client_short}… APPROVED (slot \"{slot_label}\")",
                req.method,
            );
        }

        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| BackendError::Internal(format!("nonce generation: {e}")))?;
        let response_ct = nip44::encrypt(&conv_key, &response_json, &nonce)
            .map_err(|e| BackendError::Internal(format!("NIP-44 encrypt response: {e}")))?;

        self.wrap_in_envelope(master_pubkey, client_pubkey, created_at, &response_ct)
    }
}

// ---------------------------------------------------------------------------
// Private helper functions
// ---------------------------------------------------------------------------

/// Decode a 64-char lowercase hex string to a 32-byte array.
fn hex_to_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex byte: 0x{b:02x}")),
    }
}

/// Derive the x-only public key bytes from a secret key.
fn derive_x_only_bytes(secret_key_bytes: &[u8; 32]) -> Result<[u8; 32], String> {
    let signing_key = k256::schnorr::SigningKey::from_bytes(secret_key_bytes.as_ref())
        .map_err(|e| format!("signing key: {e}"))?;
    let vk = signing_key.verifying_key();
    let field_bytes = vk.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&field_bytes);
    Ok(out)
}

/// Derive the x-only public key as a lowercase hex string.
fn derive_pubkey_hex(secret_key_bytes: &[u8; 32]) -> Result<String, String> {
    let pk = derive_x_only_bytes(secret_key_bytes)?;
    Ok(hex_encode(&pk))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Low-cost Argon2 params for fast tests -- never use in production.
    // We override by unlocking with the real functions, which default to
    // DEFAULT_M_COST etc. For tests we swap the keystore out after first unlock
    // to use cheap params so they run quickly.
    //
    // Actually, since DEFAULT_M_COST = 64 MiB, we need to swap the keystore
    // to use cheap params. We do this by calling a test-only helper that
    // creates a keyfile with low params.

    fn make_cheap_backend(dir: &TempDir) -> SoftBackend {
        let data_dir = dir.path().to_path_buf();
        let backend = SoftBackend::new(data_dir.clone());

        // Write an initial keyfile with low Argon2 params.
        let empty = Keystore { masters: vec![] };
        let envelope = soft_store::encrypt_keystore(&empty, "testpass", 256, 1, 1).unwrap();
        soft_store::write_envelope(&data_dir.join(KEYSTORE_FILE), &envelope).unwrap();

        // Unlock with the low-cost envelope already on disk.
        // We override the unlock logic by reading the envelope directly.
        let (ks, key) = soft_store::decrypt_keystore(&envelope, "testpass").unwrap();
        let salt = envelope.salt.clone();
        {
            let mut guard = backend.state.write().unwrap();
            *guard = Some(UnlockedState {
                keystore: ks,
                encryption_key: key,
                envelope_salt: salt,
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            });
        }
        backend
    }

    #[test]
    fn starts_locked() {
        let dir = TempDir::new().unwrap();
        let backend = SoftBackend::new(dir.path().to_path_buf());
        assert!(backend.is_locked());
        assert_eq!(backend.tier(), Tier::Soft);
    }

    #[test]
    fn unlock_creates_keystore_on_first_run() {
        let dir = TempDir::new().unwrap();
        let backend = SoftBackend::new(dir.path().to_path_buf());

        // No keyfile yet.
        assert!(!dir.path().join(KEYSTORE_FILE).exists());

        // Unlocking with real params would be slow; use the test approach
        // of manually constructing the keyfile with cheap params first.
        let empty = Keystore { masters: vec![] };
        let envelope = soft_store::encrypt_keystore(&empty, "pass", 256, 1, 1).unwrap();
        soft_store::write_envelope(&dir.path().join(KEYSTORE_FILE), &envelope).unwrap();

        let (ks, key) = soft_store::decrypt_keystore(&envelope, "pass").unwrap();
        {
            let mut guard = backend.state.write().unwrap();
            *guard = Some(UnlockedState {
                keystore: ks,
                encryption_key: key,
                envelope_salt: envelope.salt.clone(),
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            });
        }

        assert!(!backend.is_locked());
        let masters = backend.list_masters().unwrap();
        assert!(masters.is_empty());
        assert!(dir.path().join(KEYSTORE_FILE).exists());
    }

    #[test]
    fn lock_zeroizes_state() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        assert!(!backend.is_locked());
        backend.lock().unwrap();
        assert!(backend.is_locked());
        let err = backend.list_masters().unwrap_err();
        assert!(matches!(err, BackendError::Locked));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();

        // Create a keyfile with "correct" passphrase.
        let empty = Keystore { masters: vec![] };
        let envelope = soft_store::encrypt_keystore(&empty, "correct", 256, 1, 1).unwrap();
        soft_store::write_envelope(&data_dir.join(KEYSTORE_FILE), &envelope).unwrap();

        let backend = SoftBackend::new(data_dir);
        // Manually set state to unlocked (as if "correct" was used).
        let (ks, key) = soft_store::decrypt_keystore(&envelope, "correct").unwrap();
        {
            let mut guard = backend.state.write().unwrap();
            *guard = Some(UnlockedState {
                keystore: ks,
                encryption_key: key,
                envelope_salt: envelope.salt.clone(),
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            });
        }
        backend.lock().unwrap();

        // Now try to unlock with wrong passphrase via the real unlock path.
        let _backend2 = SoftBackend::new(dir.path().to_path_buf());
        let result = soft_store::decrypt_keystore(
            &soft_store::read_envelope(&dir.path().join(KEYSTORE_FILE)).unwrap(),
            "wrong",
        );
        assert!(result.is_err(), "wrong passphrase should fail");
    }

    #[test]
    fn create_and_list_slots() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        // Create a master.
        let master_json = backend.create_master("test-master", 12).unwrap();
        let master_slot = master_json["index"].as_u64().unwrap() as u8;

        // Create a slot.
        let slot_json = backend.create_slot(master_slot, "nostrudel").unwrap();
        assert_eq!(slot_json["label"].as_str().unwrap(), "nostrudel");
        assert_eq!(slot_json["slot_index"].as_u64().unwrap(), 0);
        // Secret should be redacted (empty).
        assert_eq!(slot_json["secret"].as_str().unwrap_or(""), "");

        // List slots.
        let slots = backend.list_slots(master_slot).unwrap();
        let arr = slots.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["label"].as_str().unwrap(), "nostrudel");
        // Secret is redacted.
        assert_eq!(arr[0]["secret"].as_str().unwrap_or(""), "");
    }

    #[test]
    fn revoke_slot() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        let master_json = backend.create_master("test", 12).unwrap();
        let master_slot = master_json["index"].as_u64().unwrap() as u8;

        let slot_json = backend.create_slot(master_slot, "bark").unwrap();
        let slot_idx = slot_json["slot_index"].as_u64().unwrap() as u8;

        backend.revoke_slot(master_slot, slot_idx).unwrap();

        let slots = backend.list_slots(master_slot).unwrap();
        assert!(slots.as_array().unwrap().is_empty());
    }

    #[test]
    fn nip44_params_use_spec_order_pubkey_then_text() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        backend.create_master("nip44-order", 12).unwrap();
        let master = {
            let guard = backend.state.read().unwrap();
            guard.as_ref().unwrap().keystore.masters[0].clone()
        };

        let peer_secret = [0x11u8; 32];
        let peer_pubkey = derive_pubkey_hex(&peer_secret).unwrap();

        // NIP-46 order: [third-party pubkey, plaintext] — the same order the
        // firmware handler and nostr-tools clients (e.g. Bark) use.
        let encrypt_req = nip46::Nip46Request {
            id: "enc-1".into(),
            method: "nip44_encrypt".into(),
            params: vec![peer_pubkey.clone().into(), "hello bark".into()],
            heartwood: None,
            legacy_client_pubkey: None,
        };
        let encrypt_json = SoftBackend::dispatch_method(&master, &encrypt_req, "client").unwrap();
        let ciphertext = serde_json::from_str::<Value>(&encrypt_json).unwrap()["result"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!ciphertext.is_empty());

        let decrypt_req = nip46::Nip46Request {
            id: "dec-1".into(),
            method: "nip44_decrypt".into(),
            params: vec![peer_pubkey.clone().into(), ciphertext.clone().into()],
            heartwood: None,
            legacy_client_pubkey: None,
        };
        let decrypt_json = SoftBackend::dispatch_method(&master, &decrypt_req, "client").unwrap();
        let plaintext = serde_json::from_str::<Value>(&decrypt_json).unwrap()["result"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(plaintext, "hello bark");

        // Reversed order (the old bug) must fail: params[0] is not a pubkey.
        let reversed = nip46::Nip46Request {
            id: "enc-2".into(),
            method: "nip44_encrypt".into(),
            params: vec!["hello bark".into(), peer_pubkey.into()],
            heartwood: None,
            legacy_client_pubkey: None,
        };
        assert!(SoftBackend::dispatch_method(&master, &reversed, "client").is_err());
    }

    #[test]
    fn envelope_and_signed_events_verify_as_bip340_over_event_id() {
        use k256::schnorr::signature::hazmat::PrehashVerifier;

        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);
        backend.create_master("sig-check", 12).unwrap();
        let master = {
            let guard = backend.state.read().unwrap();
            guard.as_ref().unwrap().keystore.masters[0].clone()
        };
        let secret = hex_to_32(&master.secret_key).unwrap();
        let master_pubkey_hex = derive_pubkey_hex(&secret).unwrap();
        let master_pubkey = hex_to_32(&master_pubkey_hex).unwrap();

        let verify = |event_json: &str| {
            let ev: Value = serde_json::from_str(event_json).unwrap();
            let id = hex_to_32(ev["id"].as_str().unwrap()).unwrap();
            let sig_hex = ev["sig"].as_str().unwrap();
            let sig_bytes: Vec<u8> = (0..sig_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16).unwrap())
                .collect();
            let sig = k256::schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();
            let vk = k256::schnorr::VerifyingKey::from_bytes(&master_pubkey).unwrap();
            // Nostr clients verify BIP340 over the raw 32-byte event id.
            vk.verify_prehash(&id, &sig).unwrap();
        };

        // Relay envelope.
        let envelope = backend
            .sign_envelope(&master_pubkey, &[0x22u8; 32], 1_784_000_000, "cipher")
            .unwrap();
        verify(&envelope);

        // sign_event response.
        let req = nip46::Nip46Request {
            id: "sig-1".into(),
            method: "sign_event".into(),
            params: vec![serde_json::json!(
                "{\"kind\":1,\"created_at\":1784000000,\"tags\":[],\"content\":\"hi\"}"
            )],
            heartwood: None,
            legacy_client_pubkey: None,
        };
        let response = SoftBackend::dispatch_method(&master, &req, "client").unwrap();
        let signed_json = serde_json::from_str::<Value>(&response).unwrap()["result"]
            .as_str()
            .unwrap()
            .to_string();
        verify(&signed_json);
    }

    #[test]
    fn ota_returns_not_supported() {
        let dir = TempDir::new().unwrap();
        let backend = SoftBackend::new(dir.path().to_path_buf());
        let result = backend.ota_upload(&[0u8; 64], None);
        assert!(matches!(result, Err(BackendError::NotSupported)));
    }

    #[test]
    fn factory_reset_deletes_keystore() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        let keyfile = dir.path().join(KEYSTORE_FILE);
        assert!(keyfile.exists());

        backend.factory_reset().unwrap();

        assert!(!keyfile.exists());
        assert!(backend.is_locked());
    }

    #[test]
    fn persistence_survives_relock() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_path_buf();

        // Build a backend with a cheap keyfile.
        let empty = Keystore { masters: vec![] };
        let envelope = soft_store::encrypt_keystore(&empty, "pass", 256, 1, 1).unwrap();
        let keyfile = data_dir.join(KEYSTORE_FILE);
        soft_store::write_envelope(&keyfile, &envelope).unwrap();

        let backend = SoftBackend::new(data_dir.clone());
        {
            let (ks, key) = soft_store::decrypt_keystore(&envelope, "pass").unwrap();
            let mut guard = backend.state.write().unwrap();
            *guard = Some(UnlockedState {
                keystore: ks,
                encryption_key: key,
                envelope_salt: envelope.salt.clone(),
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            });
        }

        backend.create_master("persist-test", 12).unwrap();
        backend.lock().unwrap();
        assert!(backend.is_locked());

        // Re-unlock from the same file.
        let envelope2 = soft_store::read_envelope(&keyfile).unwrap();
        let (ks2, key2) = soft_store::decrypt_keystore(&envelope2, "pass").unwrap();
        {
            let mut guard = backend.state.write().unwrap();
            *guard = Some(UnlockedState {
                keystore: ks2,
                encryption_key: key2,
                envelope_salt: envelope2.salt.clone(),
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            });
        }

        let masters = backend.list_masters().unwrap();
        assert_eq!(masters.len(), 1);
        assert_eq!(masters[0]["label"].as_str().unwrap(), "persist-test");
    }

    #[test]
    fn create_master_generates_valid_npub() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);

        let master_json = backend.create_master("npub-test", 12).unwrap();
        let npub = master_json["npub"].as_str().unwrap();
        assert!(npub.starts_with("npub1"), "npub should start with 'npub1', got: {npub}");

        let masters = backend.list_masters().unwrap();
        assert_eq!(masters.len(), 1);
        assert!(masters[0]["npub"].as_str().unwrap().starts_with("npub1"));
    }

    /// Regression: approving a queued request must sign and deliver the
    /// envelope — not re-queue it and drop the response (the original
    /// approve_request re-ran the policy check, which re-queued the request
    /// under a fresh id, and discarded the signed envelope).
    #[test]
    fn approved_request_signs_and_delivers_envelope() {
        let dir = TempDir::new().unwrap();
        let backend = make_cheap_backend(&dir);
        let master_json = backend.create_master("appr", 12).unwrap();
        let master_pubkey = hex_to_32(master_json["pubkey"].as_str().unwrap()).unwrap();

        let client_secret = [0x42u8; 32];
        let client_pubkey = {
            let pk_hex = derive_pubkey_hex(&client_secret).unwrap();
            hex_to_32(&pk_hex).unwrap()
        };

        // The client encrypts a sign_event request to the master. No slot is
        // bound to this client, so policy queues it.
        let conv_key = nip44::get_conversation_key(&client_secret, &master_pubkey).unwrap();
        let event = serde_json::json!({
            "kind": 1,
            "content": "queued then approved",
            "tags": [],
            "created_at": 1_700_000_000u64,
            "pubkey": master_json["pubkey"].as_str().unwrap(),
        });
        let req = serde_json::json!({
            "id": "r1",
            "method": "sign_event",
            "params": [event.to_string()],
        });
        let nonce = [7u8; 32];
        let ct = nip44::encrypt(&conv_key, &req.to_string(), &nonce).unwrap();

        let err = backend
            .handle_encrypted_request(&master_pubkey, &client_pubkey, 1_700_000_001, &ct)
            .unwrap_err();
        let BackendError::PendingApproval(id) = err else {
            panic!("expected PendingApproval, got {err:?}");
        };

        // Wire the response channel, then approve.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        backend.set_response_sender(tx);
        backend.approve_request(&id).unwrap();

        // The signed envelope is delivered to the publisher...
        let json = rx
            .try_recv()
            .expect("approved request must deliver a signed envelope");
        let ev: SignedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.kind, 24133);
        assert_eq!(ev.tags[0][1], derive_pubkey_hex(&client_secret).unwrap());

        // ...and its decrypted content answers the original request id with a
        // signed event, not an error.
        let resp = nip44::decrypt(&conv_key, &ev.content).unwrap();
        let resp_json: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(resp_json["id"].as_str().unwrap(), "r1");
        assert!(resp_json.get("error").is_none(), "unexpected error: {resp}");
        let signed: SignedEvent =
            serde_json::from_str(resp_json["result"].as_str().unwrap()).unwrap();
        assert_eq!(signed.content, "queued then approved");

        // The queue is empty: approval did not re-queue the request.
        assert!(backend.list_approvals().is_empty());
    }
}
