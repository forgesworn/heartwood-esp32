// heartwood-esp32/src/types.rs
//
// Simplified types for the ESP32 spike. No thiserror (not no_std-friendly).

use zeroize::Zeroize;

/// HMAC domain prefix: "nsec-tree\0" as bytes.
pub const DOMAIN_PREFIX: &[u8] = b"nsec-tree\0";

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
