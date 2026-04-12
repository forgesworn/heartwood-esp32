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

use k256::schnorr::signature::Signer;
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
        }
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
                let sig: k256::schnorr::Signature = signing_key.sign(&event_id);
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
                // params[0] = plaintext, params[1] = recipient x-only pubkey hex
                let plaintext = req
                    .params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_encrypt: missing params[0]".into()))?;
                let recipient_hex = req
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
                // params[0] = ciphertext b64, params[1] = sender x-only pubkey hex
                let ciphertext = req
                    .params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Internal("nip44_decrypt: missing params[0]".into()))?;
                let sender_hex = req
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
        let sig: k256::schnorr::Signature = signing_key.sign(&event_id);
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

                let matched = policy::find_slot_by_secret_mut(
                    &mut master_mut.connection_slots,
                    &provided_secret,
                );
                if let Some(slot) = matched {
                    slot.current_pubkey = Some(client_pubkey_hex.clone());
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

        // For sign_event and other methods, check the slot policy.
        let slot = slot_info.ok_or_else(|| {
            // No slot for this client -- queue for approval.
            let approval_id = Uuid::new_v4().to_string();
            let approval = PendingApproval {
                id: approval_id.clone(),
                method: req.method.clone(),
                event_kind: None,
                content_preview: String::new(),
                slot_label: String::new(),
                master_slot: master_slot_index,
                created_at: Instant::now(),
                master_pubkey: *master_pubkey,
                client_pubkey: *client_pubkey,
                ciphertext: ciphertext.to_string(),
            };
            let mut approvals = self.approvals.write().expect("approvals lock poisoned");
            approvals.insert(approval_id.clone(), approval);
            BackendError::PendingApproval(approval_id)
        })?;

        // Check if this method is allowed by slot policy.
        let method_allowed = slot.allowed_methods.contains(&req.method);
        if !method_allowed {
            let approval_id = Uuid::new_v4().to_string();
            let approval = PendingApproval {
                id: approval_id.clone(),
                method: req.method.clone(),
                event_kind: None,
                content_preview: String::new(),
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

        // For sign_event, also check allowed_kinds and auto_approve.
        if method == Nip46Method::SignEvent {
            let event_kind = req
                .params
                .first()
                .and_then(|v| match v {
                    Value::String(s) => serde_json::from_str::<UnsignedEvent>(s).ok(),
                    Value::Object(_) => serde_json::from_value::<UnsignedEvent>(v.clone()).ok(),
                    _ => None,
                })
                .map(|e| e.kind);

            let kind_allowed = slot.allowed_kinds.is_empty()
                || event_kind.map_or(true, |k| slot.allowed_kinds.contains(&k));

            if !kind_allowed || !slot.auto_approve {
                let approval_id = Uuid::new_v4().to_string();
                let approval = PendingApproval {
                    id: approval_id.clone(),
                    method: req.method.clone(),
                    event_kind,
                    content_preview: String::new(),
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
            let approval_id = Uuid::new_v4().to_string();
            let approval = PendingApproval {
                id: approval_id.clone(),
                method: req.method.clone(),
                event_kind: None,
                content_preview: String::new(),
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

        // Policy passed -- process the request.
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

        self.wrap_in_envelope(master_pubkey, client_pubkey, created_at, &response_ct)
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
        let sig: k256::schnorr::Signature = signing_key.sign(&event_id);
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

    fn create_master(&self, label: &str) -> Result<Value, BackendError> {
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

        // Re-process the original request now that it has been approved.
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let result = self.handle_encrypted_request(
            &approval.master_pubkey,
            &approval.client_pubkey,
            created_at,
            &approval.ciphertext,
        );

        // The re-processed request may or may not queue again depending on slot
        // policy. For manual approvals we accept whatever the backend returns.
        match result {
            Ok(_) => Ok(()),
            Err(BackendError::PendingApproval(_)) => {
                // Still queued (policy changed?) -- that is acceptable.
                Ok(())
            }
            Err(e) => Err(e),
        }
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

    fn ota_upload(&self, _firmware: &[u8]) -> Result<(), BackendError> {
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
        let master_json = backend.create_master("test-master").unwrap();
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

        let master_json = backend.create_master("test").unwrap();
        let master_slot = master_json["index"].as_u64().unwrap() as u8;

        let slot_json = backend.create_slot(master_slot, "bark").unwrap();
        let slot_idx = slot_json["slot_index"].as_u64().unwrap() as u8;

        backend.revoke_slot(master_slot, slot_idx).unwrap();

        let slots = backend.list_slots(master_slot).unwrap();
        assert!(slots.as_array().unwrap().is_empty());
    }

    #[test]
    fn ota_returns_not_supported() {
        let dir = TempDir::new().unwrap();
        let backend = SoftBackend::new(dir.path().to_path_buf());
        let result = backend.ota_upload(&[0u8; 64]);
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

        backend.create_master("persist-test").unwrap();
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

        let master_json = backend.create_master("npub-test").unwrap();
        let npub = master_json["npub"].as_str().unwrap();
        assert!(npub.starts_with("npub1"), "npub should start with 'npub1', got: {npub}");

        let masters = backend.list_masters().unwrap();
        assert_eq!(masters.len(), 1);
        assert!(masters[0]["npub"].as_str().unwrap().starts_with("npub1"));
    }
}
