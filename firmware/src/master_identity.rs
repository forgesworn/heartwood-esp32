// Shared by firmware storage and the private allocation custody gate.
use heartwood_common::types::MasterMode;
use zeroize::Zeroize;

/// A loaded master identity.
///
/// When PIN-derived seed encryption is on (P5), a slot's seed is stored as an
/// encrypted blob (`m<slot>_seed_enc`). Such a slot loads as `locked`
/// with `secret` left zeroed — the real seed is filled in only after the PIN
/// decrypts it at boot (see `pin::try_unlock`). Nothing must read `.secret`
/// while `locked` is true.
pub struct LoadedMaster {
    pub slot: u8,
    pub secret: [u8; 32],
    pub label: String,
    pub mode: MasterMode,
    pub derivation_version: u8,
    pub pubkey: [u8; 32],
    /// True when the seed is encrypted at rest and not yet decrypted.
    pub locked: bool,
    /// Optional per-identity management operator. When set, this identity is
    /// managed by this operator IN ADDITION to the device-wide operator — used
    /// to delegate one identity to a partner without granting reach over the
    /// others. `None` = managed by the device operator alone (the historical
    /// behaviour).
    pub operator: Option<[u8; 32]>,
}

impl Drop for LoadedMaster {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
