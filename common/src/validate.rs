// common/src/validate.rs
//
// Purpose string validation, matching PROTOCOL.md §3 and the reference
// implementations in `nsec-tree/src/validate.ts` and
// `heartwood-core/src/validate.rs`. Uses `&'static str` errors to stay
// compatible with the firmware's no-alloc error-reporting style.

/// Maximum purpose string length in UTF-8 bytes (PROTOCOL.md §3 rule 2).
const MAX_PURPOSE_BYTES: usize = 255;

/// True if the string contains any C0 control character or DEL
/// (`\x00-\x1F`, `\x7F`).
pub(crate) fn contains_control_char(s: &str) -> bool {
    s.chars().any(|c| {
        let n = c as u32;
        n < 0x20 || n == 0x7F
    })
}

/// Validate a purpose string for derivation.
///
/// Rules (per PROTOCOL.md §3): non-empty, max 255 UTF-8 bytes, no null
/// bytes, not whitespace-only. This implementation additionally rejects
/// `|` at the derivation layer for parity with `heartwood-core` — see the
/// docstring on `heartwood-core::validate::validate_purpose` for history.
pub fn validate_purpose(purpose: &str) -> Result<(), &'static str> {
    if purpose.is_empty() {
        return Err("purpose must not be empty");
    }
    if purpose.len() > MAX_PURPOSE_BYTES {
        return Err("purpose exceeds 255 bytes");
    }
    if purpose.contains('\0') {
        return Err("purpose must not contain null bytes");
    }
    if purpose.contains('|') {
        return Err("purpose must not contain '|' (attestation delimiter)");
    }
    if purpose.trim().is_empty() {
        return Err("purpose must not be whitespace-only");
    }
    Ok(())
}

/// Validate a purpose string for embedding in a linkage-proof attestation.
///
/// Extends `validate_purpose` with rejection of C0 and DEL control
/// characters. Matches the TypeScript `validateProofPurpose` and Rust
/// `heartwood_core::validate::validate_proof_purpose` helpers. Not called
/// anywhere in heartwood-esp32 today because the firmware does not create
/// or verify linkage proofs, but included for API parity and to make
/// future proof support a one-line change.
#[allow(dead_code)]
pub fn validate_proof_purpose(purpose: &str) -> Result<(), &'static str> {
    validate_purpose(purpose)?;
    if contains_control_char(purpose) {
        return Err("purpose used in a linkage proof must not contain control characters");
    }
    Ok(())
}

/// Validate a persona name supplied by an untrusted caller (e.g. via a
/// NIP-46 RPC). Rejects empty, whitespace-only, `|`, control characters, and
/// names that would exceed the purpose length limit once the namespace
/// prefix is prepended. Matches `heartwood_core::persona::validate_persona_name`
/// and the TypeScript `validatePersonaName` in nsec-tree 1.4.4.
pub fn validate_persona_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("persona name must not be empty");
    }
    if name.trim().is_empty() {
        return Err("persona name must not be whitespace-only");
    }
    if name.contains('|') {
        return Err("persona name must not contain '|' (attestation delimiter)");
    }
    if name.contains('\0') {
        return Err("persona name must not contain null bytes");
    }
    if contains_control_char(name) {
        return Err("persona name must not contain control characters");
    }
    // "persona/" prefix is 8 bytes, so the persona name itself cannot exceed
    // MAX_PURPOSE_BYTES - 8 = 247 bytes. Be conservative and cap at 128 — far
    // larger than any reasonable human name but well inside the limit after
    // any future prefix changes.
    if name.len() > 128 {
        return Err("persona name exceeds 128 bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_purposes() {
        assert!(validate_purpose("social").is_ok());
        assert!(validate_purpose("commerce").is_ok());
        assert!(validate_purpose("persona/work").is_ok());
        assert!(validate_purpose("nostr:persona:personal").is_ok());
        assert!(validate_purpose("a").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_purpose("").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(256);
        assert!(validate_purpose(&long).is_err());
    }

    #[test]
    fn accepts_max_length() {
        let max = "a".repeat(255);
        assert!(validate_purpose(&max).is_ok());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_purpose("social\0evil").is_err());
    }

    #[test]
    fn rejects_pipe() {
        assert!(validate_purpose("evil|9999").is_err());
        assert!(validate_purpose("|").is_err());
    }

    #[test]
    fn rejects_whitespace_only() {
        assert!(validate_purpose("   ").is_err());
        assert!(validate_purpose("\t\n").is_err());
    }

    #[test]
    fn proof_purpose_rejects_control_chars() {
        assert!(validate_proof_purpose("foo\nbar").is_err());
        assert!(validate_proof_purpose("foo\tbar").is_err());
        assert!(validate_proof_purpose("foo\rbar").is_err());
        assert!(validate_proof_purpose("foo\x01bar").is_err());
        assert!(validate_proof_purpose("foo\x7fbar").is_err());
    }

    #[test]
    fn proof_purpose_accepts_clean_strings() {
        assert!(validate_proof_purpose("social").is_ok());
        assert!(validate_proof_purpose("nostr:persona:alice").is_ok());
    }

    #[test]
    fn proof_purpose_inherits_base_rules() {
        assert!(validate_proof_purpose("").is_err());
        assert!(validate_proof_purpose("a|b").is_err());
        assert!(validate_proof_purpose("a\0b").is_err());
    }

    #[test]
    fn persona_name_accepts_common_names() {
        assert!(validate_persona_name("personal").is_ok());
        assert!(validate_persona_name("work").is_ok());
        assert!(validate_persona_name("bitcoiner").is_ok());
        assert!(validate_persona_name("alice").is_ok());
    }

    #[test]
    fn persona_name_rejects_empty() {
        assert!(validate_persona_name("").is_err());
    }

    #[test]
    fn persona_name_rejects_whitespace_only() {
        assert!(validate_persona_name("   ").is_err());
        assert!(validate_persona_name("\t\n").is_err());
    }

    #[test]
    fn persona_name_rejects_pipe() {
        assert!(validate_persona_name("bad|evil").is_err());
    }

    #[test]
    fn persona_name_rejects_control_chars() {
        assert!(validate_persona_name("bad\nname").is_err());
        assert!(validate_persona_name("bad\tname").is_err());
        assert!(validate_persona_name("bad\x01name").is_err());
        assert!(validate_persona_name("bad\x7fname").is_err());
    }

    #[test]
    fn persona_name_rejects_null_byte() {
        assert!(validate_persona_name("bad\0name").is_err());
    }

    #[test]
    fn persona_name_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(validate_persona_name(&long).is_err());
    }

    #[test]
    fn persona_name_accepts_max_length() {
        let max = "a".repeat(128);
        assert!(validate_persona_name(&max).is_ok());
    }
}
