//! Private canonical framing only. No scope, physical, time or enrolment authority.
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const BYTES: usize = 435;
const TAG: &[u8] = b"HW allocation enrolment candidate v1\0";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FrameError {
    Length,
    Format,
    Binding,
    Point,
}

// Immutable and deliberately neither Clone, Debug, Serialize nor an authority.
// Even nonsecret identity/operation metadata is cleared when its owner drops.
pub(super) struct UnverifiedCandidate {
    bytes: Zeroizing<[u8; BYTES]>,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != 0)
}

fn ed_point(bytes: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(bytes.try_into().expect("fixed frame range")) else {
        return false;
    };
    !key.is_weak() && key.to_edwards().compress().as_bytes() == bytes
}

impl UnverifiedCandidate {
    /// Checks bounded syntax, public hashes and point encodings only. The caller
    /// has no root/witness receipt, scope certificate, continuity or approval here.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != BYTES {
            return Err(FrameError::Length);
        }
        if &bytes[..5] != b"HWEN\x01" || &bytes[37..42] != b"HWAD\x01" || bytes[298] != 1 {
            return Err(FrameError::Format);
        }
        let descriptor = &bytes[37..266];
        if !nonzero(&bytes[5..37])
            || descriptor[5..].chunks_exact(32).any(|b| !nonzero(b))
            || bytes[299..427].chunks_exact(32).any(|b| !nonzero(b))
            || !nonzero(&bytes[266..298])
            || u64::from_be_bytes(bytes[427..435].try_into().expect("fixed frame range")) == 0
        {
            return Err(FrameError::Binding);
        }
        if descriptor[197..229] != hash(&[b"HW allocation journal schema v1\0"])
            || descriptor[165..197]
                != hash(&[b"HW allocation route v1\0", &[1], &descriptor[133..165]])
            || descriptor[37..69] == descriptor[133..165]
        {
            return Err(FrameError::Binding);
        }
        if !ed_point(&descriptor[37..69])
            || !ed_point(&descriptor[133..165])
            || !heartwood_common::derive::is_xonly_public_key(
                descriptor[69..101].try_into().expect("fixed frame range"),
            )
            || !heartwood_common::derive::is_xonly_public_key(
                bytes[299..331].try_into().expect("fixed frame range"),
            )
        {
            return Err(FrameError::Point);
        }
        let pins = hash(&[b"HW allocation pins v1\0", descriptor]);
        let records = hash(&[b"HW allocation record set v1\0", &pins, &[0]]);
        let genesis = hash(&[b"HW allocation state v1\0", &pins, &[0], &records, &[0; 32]]);
        if bytes[266..298] != genesis {
            return Err(FrameError::Binding);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.try_into().expect("exact frame length")),
        })
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        hash(&[TAG, self.bytes.as_ref()])
    }

    /// Retry is complete immutable byte equality, never an inferred operation.
    pub(super) fn exactly_matches(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }

    // No raw-byte getter, signing method, root access or conversion to the
    // dormant writer's nominal pins/capacity/manifest. Transport is not enabled.
}

#[cfg(test)]
#[path = "../../common/src/allocation_enrolment_candidate_host_tests.rs"]
mod tests;
