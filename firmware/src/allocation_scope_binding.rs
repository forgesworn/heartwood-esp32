//! Private non-authoritative scope-body framing; no provisioning or continuity.
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const BYTES: usize = 263;
const TAG: &[u8] = b"HW allocation scope binding v1\0";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FrameError {
    Length,
    Format,
    Binding,
}

// No Clone, Debug, Serialize, raw export or conversion into an authority.
pub(super) struct UnverifiedScopeBinding {
    bytes: Zeroizing<[u8; BYTES]>,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

impl UnverifiedScopeBinding {
    /// Opaque nonzero bindings and fixed hashes/policy only. This proves no
    /// historical identity, component provenance, physical layout or admission.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != BYTES {
            return Err(FrameError::Length);
        }
        if &bytes[..5] != b"HWSB\x01" || bytes[261] != 8 || bytes[262] != 32 {
            return Err(FrameError::Format);
        }
        if bytes[5..229]
            .chunks_exact(32)
            .any(|field| field.iter().all(|&b| b == 0))
            || bytes[165..197] == bytes[197..229]
            || bytes[229..261] != hash(&[b"HW allocation journal schema v1\0"])
        {
            return Err(FrameError::Binding);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.try_into().expect("exact frame length")),
        })
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        hash(&[TAG, self.bytes.as_ref()])
    }

    /// Full immutable body equality; a digest cannot recover missing components.
    pub(super) fn exactly_matches(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

#[cfg(test)]
#[path = "../../common/src/allocation_scope_binding_host_tests.rs"]
mod tests;
