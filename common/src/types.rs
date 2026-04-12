// common/src/types.rs
//
// Shared types and constants for heartwood-esp32.

use zeroize::Zeroize;

/// HMAC domain prefix: "nsec-tree\0" as bytes.
pub const DOMAIN_PREFIX: &[u8] = b"nsec-tree\0";

/// BIP-32 derivation path for mnemonic root.
/// Matches heartwood-core exactly.
pub const MNEMONIC_PATH: &str = "m/44'/1237'/727'/0'/0'";

/// Serial provisioning magic bytes ("HW").
pub const MAGIC_BYTES: [u8; 2] = [0x48, 0x57];

/// Serial ACK byte.
pub const ACK: u8 = 0x06;

/// Serial NACK byte.
pub const NACK: u8 = 0x15;

/// Total provisioning frame length: 2 magic + 32 secret + 4 CRC32.
pub const PROVISION_FRAME_LEN: usize = 38;

// --- Frame protocol (Phase 3) ---
pub const FRAME_TYPE_PROVISION: u8 = 0x01;
pub const FRAME_TYPE_NIP46_REQUEST: u8 = 0x02;
pub const FRAME_TYPE_NIP46_RESPONSE: u8 = 0x03;
pub const FRAME_TYPE_ACK: u8 = 0x06;
pub const FRAME_TYPE_NACK: u8 = 0x15;

// --- Phase 4: multi-master + transport ---
pub const FRAME_TYPE_PROVISION_REMOVE: u8 = 0x04;
pub const FRAME_TYPE_PROVISION_LIST: u8 = 0x05;
pub const FRAME_TYPE_PROVISION_LIST_RESPONSE: u8 = 0x07;
pub const FRAME_TYPE_ENCRYPTED_REQUEST: u8 = 0x10;
pub const FRAME_TYPE_ENCRYPTED_RESPONSE: u8 = 0x11;
pub const FRAME_TYPE_POLICY_PUSH: u8 = 0x20;
pub const FRAME_TYPE_SESSION_AUTH: u8 = 0x21;
pub const FRAME_TYPE_SESSION_ACK: u8 = 0x22;
pub const FRAME_TYPE_SET_BRIDGE_SECRET: u8 = 0x23;
pub const FRAME_TYPE_FACTORY_RESET: u8 = 0x24;
pub const FRAME_TYPE_SET_PIN: u8 = 0x25;
pub const FRAME_TYPE_PIN_UNLOCK: u8 = 0x26;

// --- Phase 5: policy management ---
pub const FRAME_TYPE_POLICY_LIST_REQUEST: u8 = 0x27;  // host -> device: payload = master_slot (1 byte)
pub const FRAME_TYPE_POLICY_LIST_RESPONSE: u8 = 0x28; // device -> host: payload = JSON Vec<ClientPolicy>
pub const FRAME_TYPE_POLICY_REVOKE: u8 = 0x29;        // host -> device: payload = master_slot (1) + client_pubkey_hex (64 bytes ASCII)
pub const FRAME_TYPE_POLICY_UPDATE: u8 = 0x2A;        // host -> device: payload = master_slot (1) + JSON ClientPolicy
pub const FRAME_TYPE_BUNKER_URI_REQUEST: u8 = 0x2B;   // host -> device: payload = master_slot (1) + relay_urls (JSON string array)
pub const FRAME_TYPE_BUNKER_URI_RESPONSE: u8 = 0x2C;  // device -> host: payload = complete bunker:// URI with secret

// --- Phase 6: per-client connection slots ---
pub const FRAME_TYPE_CONNSLOT_CREATE: u8 = 0x40;           // host -> device: master_slot (1) + label (JSON string)
pub const FRAME_TYPE_CONNSLOT_CREATE_RESP: u8 = 0x41;      // device -> host: slot_index (1) + JSON { secret_hex, bunker_uri }
pub const FRAME_TYPE_CONNSLOT_LIST: u8 = 0x42;             // host -> device: master_slot (1)
pub const FRAME_TYPE_CONNSLOT_LIST_RESP: u8 = 0x43;        // device -> host: JSON Vec<ConnectSlot> (secrets redacted)
pub const FRAME_TYPE_CONNSLOT_UPDATE: u8 = 0x44;           // host -> device: master_slot (1) + JSON ConnectSlot (partial)
pub const FRAME_TYPE_CONNSLOT_UPDATE_RESP: u8 = 0x45;      // device -> host: ok/err JSON
pub const FRAME_TYPE_CONNSLOT_REVOKE: u8 = 0x46;           // host -> device: master_slot (1) + slot_index (1)
pub const FRAME_TYPE_CONNSLOT_REVOKE_RESP: u8 = 0x47;      // device -> host: ok/err JSON
pub const FRAME_TYPE_CONNSLOT_URI: u8 = 0x48;              // host -> device: master_slot (1) + slot_index (1) + relay_urls (JSON)
pub const FRAME_TYPE_CONNSLOT_URI_RESP: u8 = 0x49;         // device -> host: complete bunker:// URI with secret

// --- Phase 7: backup/restore ---
pub const FRAME_TYPE_BACKUP_EXPORT_REQUEST: u8 = 0x50;   // host -> device: empty payload
pub const FRAME_TYPE_BACKUP_EXPORT_RESPONSE: u8 = 0x51;  // device -> host: JSON BackupPayload
pub const FRAME_TYPE_BACKUP_IMPORT_REQUEST: u8 = 0x52;   // host -> device: JSON BackupPayload (matched masters only)
pub const FRAME_TYPE_BACKUP_IMPORT_RESPONSE: u8 = 0x53;  // device -> host: 0x01 success / 0x00 failure

// --- OTA frame types ---
pub const FRAME_TYPE_OTA_BEGIN: u8 = 0x30;
pub const FRAME_TYPE_OTA_CHUNK: u8 = 0x31;
pub const FRAME_TYPE_OTA_FINISH: u8 = 0x32;
pub const FRAME_TYPE_OTA_STATUS: u8 = 0x33;

// --- Envelope signing (NIP-46 outer event signed on-device) ---
//
// host -> device:
//   FRAME_TYPE_SIGN_ENVELOPE (0x34) payload layout:
//     [master_pubkey_32][client_pubkey_32][created_at_u64_be_8][ciphertext_bytes...]
//
//   The device finds the master by pubkey, builds a canonical NIP-46
//   kind:24133 envelope event (pubkey = master_pubkey, p-tag = client_pubkey,
//   content = ciphertext as-is), computes the event id, signs with the
//   matching master secret, and returns a fully serialised signed event.
//
//   Requires bridge session authentication (same as ENCRYPTED_REQUEST).
//   The device restricts this frame to kind:24133 and uses its own copy
//   of the master pubkey so the host cannot coerce the device into signing
//   an arbitrary event; the host-provided master_pubkey is only used as a
//   lookup key, not written into the event.
//
// device -> host:
//   FRAME_TYPE_SIGN_ENVELOPE_RESPONSE (0x35) payload: UTF-8 JSON of the
//   serialised signed event, ready to publish to relays verbatim.
pub const FRAME_TYPE_SIGN_ENVELOPE: u8 = 0x34;
pub const FRAME_TYPE_SIGN_ENVELOPE_RESPONSE: u8 = 0x35;

// OTA status codes (payload byte 0 of OTA_STATUS frame)
pub const OTA_STATUS_READY: u8 = 0x00;
pub const OTA_STATUS_CHUNK_OK: u8 = 0x01;
pub const OTA_STATUS_VERIFIED: u8 = 0x02;
pub const OTA_STATUS_ERR_HASH: u8 = 0x10;
pub const OTA_STATUS_ERR_SIZE: u8 = 0x11;
pub const OTA_STATUS_ERR_WRITE: u8 = 0x12;
pub const OTA_STATUS_ERR_NOT_STARTED: u8 = 0x13;

pub const MAX_PAYLOAD_SIZE: usize = 32768;
pub const FRAME_HEADER_SIZE: usize = 5; // 2 magic + 1 type + 2 length
pub const FRAME_OVERHEAD: usize = FRAME_HEADER_SIZE + 4; // header + CRC32

/// Provisioning mode for a master secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MasterMode {
    /// Raw nsec stored as-is — vanilla NIP-46, no tree derivation.
    Bunker = 0,
    /// BIP-39 mnemonic → derived root secret.
    TreeMnemonic = 1,
    /// Existing nsec → HMAC → tree root.
    TreeNsec = 2,
}

impl MasterMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Bunker),
            1 => Some(Self::TreeMnemonic),
            2 => Some(Self::TreeNsec),
            _ => None,
        }
    }

    pub fn is_tree(&self) -> bool {
        matches!(self, Self::TreeMnemonic | Self::TreeNsec)
    }
}

/// Public metadata for a provisioned master (no secret material).
#[cfg(feature = "nip46")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasterInfo {
    pub slot: u8,
    pub label: String,
    pub mode: u8,
    pub npub: String,
}

/// Master tree root. Owns the secret; zeroised automatically when dropped
/// via the `Zeroizing` wrapper. Call `destroy()` for explicit early cleanup.
pub struct TreeRoot {
    secret: zeroize::Zeroizing<[u8; 32]>,
    pub master_npub: String,
}

impl TreeRoot {
    pub fn new(secret: zeroize::Zeroizing<[u8; 32]>, master_npub: String) -> Self {
        Self { secret, master_npub }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Explicitly destroy the root, zeroising the secret.
    pub fn destroy(mut self) {
        self.secret.zeroize();
    }
}

/// A derived child identity.
pub struct Identity {
    pub npub: String,
    pub private_key: zeroize::Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub purpose: String,
    pub index: u32,
}

impl Identity {
    /// Zero the private key bytes.
    pub fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}
