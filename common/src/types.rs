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

/// Master tree root. Owns the secret; zeroes on drop.
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
