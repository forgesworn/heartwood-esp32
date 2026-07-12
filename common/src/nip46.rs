// common/src/nip46.rs
//
// NIP-46 JSON-RPC types and NIP-01 event ID computation.
//
// This module is only compiled when the `nip46` feature is enabled.
// All types derive Serialize/Deserialize directly since serde is guaranteed
// available when this module is compiled.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hex::{hex_decode, hex_encode};

// ---------------------------------------------------------------------------
// NIP-46 request / response types
// ---------------------------------------------------------------------------

/// An optional Heartwood-specific context attached to a NIP-46 request.
/// Allows the remote signer to select a child key by purpose and index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartwoodContext {
    /// Human-readable purpose label (e.g. "identity", "payments").
    pub purpose: String,
    /// Derivation index within the purpose branch (defaults to 0).
    #[serde(default)]
    pub index: u32,
}

/// A NIP-46 JSON-RPC request from the remote client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip46Request {
    /// Request correlation ID — echoed back in the response.
    pub id: String,
    /// Method name, e.g. `"sign_event"`, `"get_public_key"`.
    pub method: String,
    /// Method parameters (method-specific JSON values).
    #[serde(default)]
    pub params: Vec<Value>,
    /// Optional Heartwood extension context.
    pub heartwood: Option<HeartwoodContext>,
}

/// A NIP-46 JSON-RPC response sent back to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip46Response {
    /// Correlation ID from the originating request.
    pub id: String,
    /// Successful result payload (present when no error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Error string (present when the request failed). NIP-46 requires a plain string, not an object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// All supported NIP-46 methods (standard + heartwood extensions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip46Method {
    // Standard NIP-46
    Connect,
    Ping,
    GetPublicKey,
    SignEvent,
    Nip44Encrypt,
    Nip44Decrypt,
    Nip04Encrypt,
    Nip04Decrypt,
    /// Harmless compatibility no-op used by clients such as Coracle during
    /// connection setup. Heartwood does not mutate its relay configuration.
    SwitchRelays,
    // Heartwood extensions
    HeartwoodDerive,
    HeartwoodDerivePersona,
    HeartwoodSwitch,
    HeartwoodListIdentities,
    HeartwoodRecover,
    HeartwoodCreateProof,
    HeartwoodVerifyProof,
    // Unknown method
    Unknown(String),
}

impl Nip46Method {
    pub fn from_str(s: &str) -> Self {
        match s {
            "connect" => Self::Connect,
            "ping" => Self::Ping,
            "get_public_key" => Self::GetPublicKey,
            "sign_event" => Self::SignEvent,
            "nip44_encrypt" => Self::Nip44Encrypt,
            "nip44_decrypt" => Self::Nip44Decrypt,
            "nip04_encrypt" => Self::Nip04Encrypt,
            "nip04_decrypt" => Self::Nip04Decrypt,
            "switch_relays" => Self::SwitchRelays,
            "heartwood_derive" => Self::HeartwoodDerive,
            "heartwood_derive_persona" => Self::HeartwoodDerivePersona,
            "heartwood_switch" => Self::HeartwoodSwitch,
            "heartwood_list_identities" => Self::HeartwoodListIdentities,
            "heartwood_recover" => Self::HeartwoodRecover,
            "heartwood_create_proof" => Self::HeartwoodCreateProof,
            "heartwood_verify_proof" => Self::HeartwoodVerifyProof,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Connect => "connect",
            Self::Ping => "ping",
            Self::GetPublicKey => "get_public_key",
            Self::SignEvent => "sign_event",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::SwitchRelays => "switch_relays",
            Self::HeartwoodDerive => "heartwood_derive",
            Self::HeartwoodDerivePersona => "heartwood_derive_persona",
            Self::HeartwoodSwitch => "heartwood_switch",
            Self::HeartwoodListIdentities => "heartwood_list_identities",
            Self::HeartwoodRecover => "heartwood_recover",
            Self::HeartwoodCreateProof => "heartwood_create_proof",
            Self::HeartwoodVerifyProof => "heartwood_verify_proof",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Whether this method requires button approval regardless of policy.
    pub fn always_requires_button(&self) -> bool {
        matches!(
            self,
            Self::HeartwoodDerive
                | Self::HeartwoodDerivePersona
                | Self::HeartwoodSwitch
                | Self::HeartwoodRecover
                | Self::HeartwoodCreateProof
        )
    }

    /// Whether this method is always auto-approved (no policy check needed).
    pub fn always_auto_approve(&self) -> bool {
        matches!(
            self,
            Self::Connect
                | Self::Ping
                | Self::GetPublicKey
                | Self::SwitchRelays
                | Self::HeartwoodListIdentities
                | Self::HeartwoodVerifyProof
        )
    }

    /// Whether this method is an OLED-notify method (auto but shown on display).
    ///
    /// Identity switching used to live in this tier, but it mutates ambient
    /// per-client signing state and therefore now requires a physical button.
    pub fn is_oled_notify(&self) -> bool {
        false
    }

    /// Whether this method requires tree mode (returns error in bunker mode).
    pub fn requires_tree_mode(&self) -> bool {
        matches!(
            self,
            Self::HeartwoodDerive
                | Self::HeartwoodDerivePersona
                | Self::HeartwoodSwitch
                | Self::HeartwoodRecover
                | Self::HeartwoodCreateProof
        )
    }
}

// ---------------------------------------------------------------------------
// Nostr event types
// ---------------------------------------------------------------------------

/// A Nostr event that has not yet been signed (no `id` or `sig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedEvent {
    /// Hex-encoded public key of the event author.
    /// Optional per NIP-46: the signer fills this from its own identity when absent.
    #[serde(default)]
    pub pubkey: String,
    /// Unix timestamp (seconds since epoch).
    pub created_at: u64,
    /// Event kind number.
    pub kind: u64,
    /// Tag list — each tag is a list of strings (first element is the tag name).
    pub tags: Vec<Vec<String>>,
    /// Plaintext event content.
    pub content: String,
}

/// A fully signed Nostr event ready for relay publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvent {
    /// Hex-encoded SHA-256 event ID (NIP-01 commitment hash).
    pub id: String,
    /// Hex-encoded public key of the event author.
    pub pubkey: String,
    /// Unix timestamp (seconds since epoch).
    pub created_at: u64,
    /// Event kind number.
    pub kind: u64,
    /// Tag list.
    pub tags: Vec<Vec<String>>,
    /// Plaintext event content.
    pub content: String,
    /// Hex-encoded BIP-340 Schnorr signature over `id`.
    pub sig: String,
}

fn decode_event_hex<const N: usize>(
    value: &str,
    malformed: &'static str,
) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 {
        return Err(malformed);
    }
    hex_decode(value)
        .map_err(|_| malformed)?
        .try_into()
        .map_err(|_| malformed)
}

#[cfg(all(feature = "k256-backend", not(feature = "secp256k1-backend")))]
fn verify_event_signature(
    public_key: &[u8; 32],
    event_id: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), &'static str> {
    let verifying_key = k256::schnorr::VerifyingKey::from_bytes(public_key)
        .map_err(|_| "invalid event public key")?;
    let signature = k256::schnorr::Signature::try_from(signature.as_slice())
        .map_err(|_| "invalid event signature")?;
    verifying_key
        .verify_raw(event_id, &signature)
        .map_err(|_| "event signature verification failed")
}

#[cfg(all(feature = "secp256k1-backend", not(feature = "k256-backend")))]
fn verify_event_signature(
    public_key: &[u8; 32],
    event_id: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), &'static str> {
    let verifying_key = secp256k1::XOnlyPublicKey::from_slice(public_key)
        .map_err(|_| "invalid event public key")?;
    let signature = secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| "invalid event signature")?;
    let message = secp256k1::Message::from_digest(*event_id);
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &verifying_key)
        .map_err(|_| "event signature verification failed")
}

#[cfg(not(any(feature = "k256-backend", feature = "secp256k1-backend")))]
fn verify_event_signature(
    _public_key: &[u8; 32],
    _event_id: &[u8; 32],
    _signature: &[u8; 64],
) -> Result<(), &'static str> {
    Err("event signature verification backend unavailable")
}

// ---------------------------------------------------------------------------
// Event ID computation (NIP-01)
// ---------------------------------------------------------------------------

/// Compute the NIP-01 event ID for an unsigned event.
///
/// The commitment is the SHA-256 hash of the canonical JSON serialisation:
/// `[0, pubkey, created_at, kind, tags, content]`
fn compute_event_id_fields(
    pubkey: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // Stream NIP-01's canonical JSON directly into SHA-256. Inbound management
    // events can carry a large encrypted avatar, so allocating another complete
    // JSON string here would recreate the firmware's peak-heap failure mode.
    hasher.update(b"[0,");
    hash_json_string(&mut hasher, pubkey);
    hasher.update(b",");
    hash_u64(&mut hasher, created_at);
    hasher.update(b",");
    hash_u64(&mut hasher, kind);
    hasher.update(b",");
    hash_tags(&mut hasher, tags);
    hasher.update(b",");
    hash_json_string(&mut hasher, content);
    hasher.update(b"]");
    let result = hasher.finalize();

    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

fn hash_u64(hasher: &mut Sha256, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    hasher.update(&digits[start..]);
}

fn hash_tags(hasher: &mut Sha256, tags: &[Vec<String>]) {
    hasher.update(b"[");
    for (tag_index, tag) in tags.iter().enumerate() {
        if tag_index > 0 {
            hasher.update(b",");
        }
        hasher.update(b"[");
        for (value_index, value) in tag.iter().enumerate() {
            if value_index > 0 {
                hasher.update(b",");
            }
            hash_json_string(hasher, value);
        }
        hasher.update(b"]");
    }
    hasher.update(b"]");
}

fn hash_json_string(hasher: &mut Sha256, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    hasher.update(b"\"");
    let bytes = value.as_bytes();
    let mut run_start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let escaped: Option<&[u8]> = match byte {
            b'\"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            0x08 => Some(b"\\b"),
            0x09 => Some(b"\\t"),
            0x0a => Some(b"\\n"),
            0x0c => Some(b"\\f"),
            0x0d => Some(b"\\r"),
            0x00..=0x1f => None,
            _ => continue,
        };
        if run_start < index {
            hasher.update(&bytes[run_start..index]);
        }
        if let Some(escaped) = escaped {
            hasher.update(escaped);
        } else {
            hasher.update(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(byte >> 4) as usize],
                HEX[(byte & 0x0f) as usize],
            ]);
        }
        run_start = index + 1;
    }
    if run_start < bytes.len() {
        hasher.update(&bytes[run_start..]);
    }
    hasher.update(b"\"");
}

pub fn compute_event_id(event: &UnsignedEvent) -> [u8; 32] {
    compute_event_id_fields(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )
}

/// Verify an inbound Nostr event before any relay-side routing or decryption.
/// The relay is an untrusted transport: both the canonical id and its BIP-340
/// signature must bind the author, target tags, kind, timestamp, and ciphertext.
pub fn verify_signed_event(event: &SignedEvent) -> Result<(), &'static str> {
    let claimed_id = decode_event_hex::<32>(&event.id, "invalid event id")?;
    let computed_id = compute_event_id_fields(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    if claimed_id != computed_id {
        return Err("event id does not match canonical content");
    }

    let public_key = decode_event_hex::<32>(&event.pubkey, "invalid event public key")?;
    let signature = decode_event_hex::<64>(&event.sig, "invalid event signature")?;
    verify_event_signature(&public_key, &computed_id, &signature)
}

/// Compute the NIP-01 event ID as a lowercase hex string.
pub fn compute_event_id_hex(event: &UnsignedEvent) -> String {
    hex_encode(&compute_event_id(event))
}

fn truncate_with_ellipsis(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut chars = value.chars();

    for _ in 0..max_chars {
        match chars.next() {
            Some(ch) => out.push(ch),
            None => return value.to_string(),
        }
    }

    if chars.next().is_some() {
        out.push_str("...");
        out
    } else {
        value.to_string()
    }
}

fn json_string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn content_display_preview(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return trimmed.to_string();
    };

    if let Some(description) = json_string_field(&value, "description")
        .or_else(|| json_string_field(&value, "desription"))
    {
        return description.to_string();
    }

    if let Some(subkey) = json_string_field(&value, "subkey") {
        return format!("subkey: {subkey}");
    }

    for key in ["title", "name", "display_name"] {
        if let Some(label) = json_string_field(&value, key) {
            return label.to_string();
        }
    }

    match value {
        Value::String(s) => s.trim().to_string(),
        _ => trimmed.to_string(),
    }
}

/// Return a brief summary of an unsigned event suitable for display on the OLED.
///
/// Returns `(kind, preview)`. JSON app-data content is collapsed to its useful
/// human label when clients provide one; otherwise the raw content is truncated.
pub fn event_display_summary(event: &UnsignedEvent, max_chars: usize) -> (u64, String) {
    let preview = content_display_preview(&event.content);
    (event.kind, truncate_with_ellipsis(&preview, max_chars))
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Deserialise a NIP-46 request from raw JSON bytes.
pub fn parse_request(json: &[u8]) -> Result<Nip46Request, String> {
    serde_json::from_slice(json).map_err(|e| format!("failed to parse NIP-46 request: {e}"))
}

/// Extract an `UnsignedEvent` from NIP-46 `sign_event` params.
///
/// The convention is that `params[0]` is a JSON string whose contents are the
/// event object.
pub fn parse_unsigned_event(params: &[Value]) -> Result<UnsignedEvent, String> {
    let raw = params
        .first()
        .ok_or_else(|| "sign_event params is empty".to_string())?;

    // params[0] may be a JSON string (stringified event) or an object.
    let event: UnsignedEvent = match raw {
        Value::String(s) => {
            serde_json::from_str(s).map_err(|e| format!("failed to parse event string: {e}"))?
        }
        Value::Object(_) => serde_json::from_value(raw.clone())
            .map_err(|e| format!("failed to parse event object: {e}"))?,
        other => {
            return Err(format!(
                "unexpected params[0] type: {}",
                other.as_str().unwrap_or("unknown")
            ))
        }
    };

    Ok(event)
}

/// Build a `sign_event` success response containing the signed event JSON.
pub fn build_sign_response(request_id: &str, signed_event: &SignedEvent) -> Result<String, String> {
    let event_json = serde_json::to_string(signed_event)
        .map_err(|e| format!("failed to serialise signed event: {e}"))?;

    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(event_json),
        error: None,
    };

    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise sign response: {e}"))
}

/// Build a `get_public_key` success response.
pub fn build_pubkey_response(request_id: &str, hex_pubkey: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(hex_pubkey.to_string()),
        error: None,
    };

    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise pubkey response: {e}"))
}

/// Build an error response for any failed NIP-46 request.
pub fn build_error_response(request_id: &str, code: i32, message: &str) -> Result<String, String> {
    let _ = code; // code is retained in the signature for internal logging but not sent on the wire per NIP-46
    let response = Nip46Response {
        id: request_id.to_string(),
        result: None,
        error: Some(message.to_string()),
    };

    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise error response: {e}"))
}

/// Build a `connect` success response (result = "ack").
pub fn build_connect_response(request_id: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some("ack".to_string()),
        error: None,
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise connect response: {e}"))
}

/// Build a `connect` success response where the result is the secret hex string.
///
/// Per NIP-46, when a secret was provided in the `bunker://` URI the response
/// result MUST echo back that same secret rather than the generic `"ack"`.
pub fn build_connect_response_with_secret(request_id: &str, secret_hex: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(secret_hex.to_string()),
        error: None,
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise connect response: {e}"))
}

/// Build a `ping` response (result = "pong").
pub fn build_ping_response(request_id: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some("pong".to_string()),
        error: None,
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise ping response: {e}"))
}

/// Build a generic string result response.
pub fn build_result_response(request_id: &str, result: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(result.to_string()),
        error: None,
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise response: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> UnsignedEvent {
        UnsignedEvent {
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![],
            content: "Hello, Nostr!".to_string(),
        }
    }

    fn frozen_signed_event() -> SignedEvent {
        SignedEvent {
            id: "c8e7c46f50cb296ac79dc9fadffa14631cf5fd5190bb4d1b35230a8ff00df03c"
                .to_string(),
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            created_at: 1_700_000_000,
            kind: 24_134,
            tags: vec![vec!["p".to_string(), "22".repeat(32)]],
            content: "test ciphertext".to_string(),
            sig: "eb501d4b1cff7d76c50ed1f03a6d3e93327db7f7cf625680c57d7f8872e3c9e6ce64837c5ab566f192122bced7b75a2db4e51451356af164b860193353466a75"
                .to_string(),
        }
    }

    #[test]
    fn verifies_frozen_nostr_event_vector() {
        assert_eq!(verify_signed_event(&frozen_signed_event()), Ok(()));
    }

    #[test]
    fn rejects_frozen_event_id_content_and_signature_mutations() {
        let mut wrong_id = frozen_signed_event();
        wrong_id.id.replace_range(..1, "d");
        assert_eq!(
            verify_signed_event(&wrong_id),
            Err("event id does not match canonical content"),
        );

        let mut changed_content = frozen_signed_event();
        changed_content.content.push('!');
        assert_eq!(
            verify_signed_event(&changed_content),
            Err("event id does not match canonical content"),
        );

        let mut wrong_signature = frozen_signed_event();
        wrong_signature.sig.replace_range(..1, "f");
        assert_eq!(
            verify_signed_event(&wrong_signature),
            Err("event signature verification failed"),
        );
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let event = sample_event();
        let id1 = compute_event_id(&event);
        let id2 = compute_event_id(&event);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_changes_with_content() {
        let mut a = sample_event();
        let mut b = sample_event();
        a.content = "Hello".to_string();
        b.content = "World".to_string();
        assert_ne!(compute_event_id(&a), compute_event_id(&b));
    }

    #[test]
    fn test_compute_event_id_changes_with_kind() {
        let mut a = sample_event();
        let mut b = sample_event();
        a.kind = 1;
        b.kind = 4;
        assert_ne!(compute_event_id(&a), compute_event_id(&b));
    }

    #[test]
    fn test_compute_event_id_hex_is_64_chars() {
        let hex = compute_event_id_hex(&sample_event());
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_event_display_summary_truncation() {
        let mut event = sample_event();
        event.content = "A".repeat(100);
        let (kind, summary) = event_display_summary(&event, 20);
        assert_eq!(kind, 1);
        assert!(summary.ends_with("..."));
        // 20 chars of content + 3 dots = 23
        assert_eq!(summary.len(), 23);
    }

    #[test]
    fn test_event_display_summary_short_content() {
        let event = sample_event();
        let (kind, summary) = event_display_summary(&event, 100);
        assert_eq!(kind, 1);
        assert_eq!(summary, "Hello, Nostr!");
        assert!(!summary.ends_with("..."));
    }

    #[test]
    fn test_event_display_summary_uses_json_description() {
        let mut event = sample_event();
        event.kind = 30078;
        event.content = r#"{ "description": "Sync app settings" }"#.to_string();
        let (kind, summary) = event_display_summary(&event, 50);
        assert_eq!(kind, 30078);
        assert_eq!(summary, "Sync app settings");
    }

    #[test]
    fn test_event_display_summary_accepts_primal_description_typo() {
        let mut event = sample_event();
        event.kind = 30078;
        event.content = r#"{"desription":"Get Primal memebeship status"}"#.to_string();
        let (_, summary) = event_display_summary(&event, 50);
        assert_eq!(summary, "Get Primal memebeship status");
    }

    #[test]
    fn test_event_display_summary_uses_json_subkey() {
        let mut event = sample_event();
        event.kind = 30078;
        event.content = r#"{"subkey":"user-home-feeds"}"#.to_string();
        let (_, summary) = event_display_summary(&event, 50);
        assert_eq!(summary, "subkey: user-home-feeds");
    }

    #[test]
    fn test_event_display_summary_truncates_utf8_safely() {
        let mut event = sample_event();
        event.content = "ééééé".to_string();
        let (_, summary) = event_display_summary(&event, 3);
        assert_eq!(summary, "ééé...");
    }

    #[test]
    fn test_parse_request() {
        let json = r#"{"id":"req1","method":"sign_event","params":["{}"],"heartwood":null}"#;
        let req = parse_request(json.as_bytes()).unwrap();
        assert_eq!(req.id, "req1");
        assert_eq!(req.method, "sign_event");
        assert!(req.heartwood.is_none());
    }

    #[test]
    fn test_parse_request_with_heartwood_context() {
        let json = r#"{
            "id": "req2",
            "method": "sign_event",
            "params": [],
            "heartwood": { "purpose": "payments", "index": 3 }
        }"#;
        let req = parse_request(json.as_bytes()).unwrap();
        let ctx = req.heartwood.unwrap();
        assert_eq!(ctx.purpose, "payments");
        assert_eq!(ctx.index, 3);
    }

    #[test]
    fn test_parse_unsigned_event() {
        let event_json = r#"{"pubkey":"aabbcc","created_at":1234,"kind":1,"tags":[["e","abc123"]],"content":"test"}"#;
        let params: Vec<Value> = vec![Value::String(event_json.to_string())];
        let event = parse_unsigned_event(&params).unwrap();
        assert_eq!(event.pubkey, "aabbcc");
        assert_eq!(event.kind, 1);
        assert_eq!(event.tags, vec![vec!["e".to_string(), "abc123".to_string()]]);
        assert_eq!(event.content, "test");
    }

    #[test]
    fn test_parse_unsigned_event_without_pubkey_string() {
        let event_json = r#"{"created_at":1234,"kind":1,"tags":[],"content":"no pubkey"}"#;
        let params: Vec<Value> = vec![Value::String(event_json.to_string())];
        let event = parse_unsigned_event(&params).unwrap();
        assert_eq!(event.pubkey, "");
        assert_eq!(event.kind, 1);
        assert_eq!(event.content, "no pubkey");
    }

    #[test]
    fn test_parse_unsigned_event_without_pubkey_object() {
        let event_obj = serde_json::json!({
            "created_at": 1234,
            "kind": 10002,
            "tags": [["r", "wss://relay.example.com"]],
            "content": ""
        });
        let params: Vec<Value> = vec![event_obj];
        let event = parse_unsigned_event(&params).unwrap();
        assert_eq!(event.pubkey, "");
        assert_eq!(event.kind, 10002);
        assert_eq!(event.tags, vec![vec!["r".to_string(), "wss://relay.example.com".to_string()]]);
    }

    #[test]
    fn test_build_error_response() {
        let json = build_error_response("req99", -32600, "invalid request").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "req99");
        assert_eq!(parsed["error"], "invalid request");
        assert!(parsed["result"].is_null());
    }

    #[test]
    fn test_build_pubkey_response() {
        let hex_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let json = build_pubkey_response("req5", hex_pubkey).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "req5");
        assert_eq!(parsed["result"], hex_pubkey);
        assert!(parsed["error"].is_null());
    }

    #[test]
    fn test_build_sign_response() {
        let event = sample_event();
        let event_id = compute_event_id_hex(&event);

        let signed = SignedEvent {
            id: event_id.clone(),
            pubkey: event.pubkey.clone(),
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: "a".repeat(128),
        };

        let json = build_sign_response("req42", &signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top-level id is echoed back.
        assert_eq!(parsed["id"], "req42");

        // result is a JSON string containing the signed event.
        let result_str = parsed["result"].as_str().expect("result should be a string");
        let inner: serde_json::Value =
            serde_json::from_str(result_str).expect("result should be valid JSON");
        assert_eq!(inner["id"], event_id.as_str());
        assert_eq!(inner["pubkey"], event.pubkey.as_str());
        assert_eq!(inner["kind"], 1u64);
        assert_eq!(inner["sig"], "a".repeat(128).as_str());

        // error field must be absent (not null) when there is no error.
        assert!(parsed.get("error").is_none(), "error key should be absent");
    }

    #[test]
    fn test_nip46_method_from_str() {
        assert_eq!(Nip46Method::from_str("sign_event"), Nip46Method::SignEvent);
        assert_eq!(Nip46Method::from_str("heartwood_derive"), Nip46Method::HeartwoodDerive);
        assert_eq!(Nip46Method::from_str("ping"), Nip46Method::Ping);
        assert_eq!(Nip46Method::from_str("switch_relays"), Nip46Method::SwitchRelays);
        assert!(matches!(Nip46Method::from_str("unknown_method"), Nip46Method::Unknown(_)));
    }

    #[test]
    fn test_nip46_method_approval_tiers() {
        assert!(Nip46Method::Ping.always_auto_approve());
        assert!(Nip46Method::GetPublicKey.always_auto_approve());
        assert!(Nip46Method::SwitchRelays.always_auto_approve());
        assert!(!Nip46Method::SignEvent.always_auto_approve());

        assert!(Nip46Method::HeartwoodDerive.always_requires_button());
        assert!(Nip46Method::HeartwoodSwitch.always_requires_button());
        assert!(!Nip46Method::SignEvent.always_requires_button());

        assert!(!Nip46Method::HeartwoodSwitch.is_oled_notify());
        assert!(!Nip46Method::SignEvent.is_oled_notify());

        assert!(Nip46Method::HeartwoodDerive.requires_tree_mode());
        assert!(!Nip46Method::SignEvent.requires_tree_mode());
    }

    #[test]
    fn test_build_connect_response() {
        let json = build_connect_response("conn-1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "conn-1");
        assert_eq!(parsed["result"], "ack");
    }

    #[test]
    fn test_build_connect_response_with_secret() {
        let secret_hex = "aabbccdd".repeat(8);
        let json = build_connect_response_with_secret("conn-2", &secret_hex).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "conn-2");
        assert_eq!(parsed["result"], secret_hex);
    }

    #[test]
    fn test_build_ping_response() {
        let json = build_ping_response("ping-1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "ping-1");
        assert_eq!(parsed["result"], "pong");
    }

    #[test]
    fn test_event_id_canonical_serialisation() {
        // Manually compute what NIP-01 says the commitment should serialise to,
        // then verify our function produces the matching hash.
        let event = UnsignedEvent {
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: String::new(),
        };

        // Build the expected commitment string exactly as NIP-01 specifies.
        let commitment = format!(
            r#"[0,"{}",{},{},{},"{}"]"#,
            event.pubkey,
            event.created_at,
            event.kind,
            serde_json::to_string(&event.tags).unwrap(),
            event.content,
        );

        let mut hasher = Sha256::new();
        hasher.update(commitment.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(compute_event_id(&event), expected);
    }
}
