//! Strict local cryptographic checks, not fresh witness or allocation authority.
use super::InventoryHold;
use ed25519_dalek::SigningKey;
use std::{hint::black_box, sync::OnceLock};
use vmls_core::receipt::{WitnessReceipt, WitnessStatus};
use zeroize::{Zeroize, Zeroizing};

static READY: OnceLock<bool> = OnceLock::new();

/// One fixed boot check. Failure remains false for this boot; no fallback.
pub(super) fn backend_ready() -> bool {
    *READY.get_or_init(known_answer)
}

/// Only the held root's descendant calls this with its domain-separated seed.
/// Dalek's zeroize feature clears SigningKey's seed and expanded secrets on Drop.
pub(super) fn writer_matches(seed: &[u8; 32], expected: &[u8; 32]) -> bool {
    if seed.iter().all(|&b| b == 0) {
        return false;
    }
    SigningKey::from_bytes(seed).verifying_key().as_bytes() == expected
}

struct ClearedReceipt(WitnessReceipt);
impl Drop for ClearedReceipt {
    fn drop(&mut self) {
        self.0.subject.zeroize();
        self.0.seq.zeroize();
        self.0.digest.zeroize();
        self.0.challenge.zeroize();
        self.0.signature.zeroize();
        self.0.status = WitnessStatus::Current;
    }
}

/// Historical challenge is read from the stored frame, not generated here.
/// This authenticates history and its exact binding; it is NOT a freshness gate.
pub(super) fn historical_receipt(
    bytes: &[u8],
    witness: &[u8; 32],
    subject: &[u8; 32],
    seq: u64,
    digest: &[u8; 32],
) -> Result<(), InventoryHold> {
    if !backend_ready() {
        return Err(InventoryHold::Crypto);
    }
    let receipt = ClearedReceipt(WitnessReceipt::parse(bytes).map_err(|_| InventoryHold::Binding)?);
    if receipt.0.status != WitnessStatus::Current
        || &receipt.0.subject != subject
        || receipt.0.seq != seq
        || &receipt.0.digest != digest
        || receipt.0.challenge.iter().all(|&b| b == 0)
        || receipt.0.signature.iter().all(|&b| b == 0)
    {
        return Err(InventoryHold::Binding);
    }
    receipt
        .0
        .verify(witness, &receipt.0.challenge)
        .map_err(|_| InventoryHold::Signature)
}

// PUBLIC SYNTHETIC known answers only. RFC8032 test1 seed/public; the receipt
// is the independent Python Ed25519 journal genesis vector (witness [9;32]).
// No operational root, namespace or witness is opened by this boot check.
const KAT_SEED: [u8; 32] = [
    157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197, 105,
    123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
];
const KAT_PUBLIC: [u8; 32] = [
    215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218,
    166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
];
const KAT_WITNESS: [u8; 32] = [
    253, 23, 36, 56, 90, 160, 199, 91, 100, 251, 120, 205, 96, 47, 161, 217, 145, 253, 235, 247,
    107, 19, 197, 142, 215, 2, 234, 200, 53, 233, 246, 24,
];
const KAT_RECEIPT: [u8; 170] = [
    1, 0, 201, 61, 191, 140, 76, 174, 188, 145, 93, 240, 166, 239, 38, 135, 47, 245, 249, 196, 216,
    59, 229, 247, 11, 233, 44, 212, 125, 25, 81, 9, 41, 158, 0, 0, 0, 0, 0, 0, 0, 0, 116, 183, 168,
    220, 161, 6, 70, 206, 253, 134, 11, 196, 62, 27, 202, 160, 104, 81, 231, 25, 141, 144, 218,
    187, 59, 14, 139, 83, 26, 0, 212, 55, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 251, 83, 250, 183, 39,
    2, 246, 168, 190, 32, 254, 211, 52, 54, 255, 103, 85, 43, 82, 172, 38, 158, 205, 157, 171, 17,
    181, 234, 67, 142, 237, 144, 250, 51, 125, 117, 60, 1, 95, 152, 195, 28, 155, 1, 254, 103, 192,
    145, 128, 204, 18, 168, 90, 191, 177, 239, 73, 120, 158, 145, 208, 175, 65, 8,
];

fn known_answer() -> bool {
    if cfg!(feature = "allocation-crypto-selfcheck-fail") {
        return false;
    }
    let seed = Zeroizing::new(black_box(KAT_SEED));
    if !writer_matches(&seed, &black_box(KAT_PUBLIC)) {
        return false;
    }
    let witness = black_box(KAT_WITNESS);
    let mut receipt = match WitnessReceipt::parse(black_box(&KAT_RECEIPT)) {
        Ok(r) => ClearedReceipt(r),
        Err(_) => return false,
    };
    if receipt.0.verify(&witness, &receipt.0.challenge).is_err() {
        return false;
    }
    let mut wrong_challenge = receipt.0.challenge;
    wrong_challenge[0] ^= 1;
    if receipt.0.verify(&witness, &wrong_challenge).is_ok() {
        return false;
    }
    // Canonical order-two public key; strict verification must reject weak keys.
    let mut weak = [255; 32];
    weak[0] = 236;
    weak[31] = 127;
    if receipt
        .0
        .verify(&black_box(weak), &receipt.0.challenge)
        .is_ok()
    {
        return false;
    }
    // Identity R, S=0 is a hostile signature, never a valid strict receipt.
    receipt.0.signature.fill(0);
    receipt.0.signature[0] = 1;
    receipt.0.verify(&witness, &receipt.0.challenge).is_err()
}

#[cfg(test)]
#[path = "../../common/src/allocation_crypto_host_tests.rs"]
mod tests;
