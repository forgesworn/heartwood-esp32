// common/src/nip46.rs
//
// NIP-46 JSON-RPC types and NIP-01 event ID computation.
//
// This module is only compiled when the `nip46` feature is enabled.
// All types derive Serialize/Deserialize directly since serde is guaranteed
// available when this module is compiled.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hex::hex_encode;

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
    /// Error details (present when the request failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Nip46Error>,
}

/// A structured error within a NIP-46 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip46Error {
    /// Numeric error code (application-defined).
    pub code: i32,
    /// Human-readable error description.
    pub message: String,
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
                | Self::HeartwoodListIdentities
                | Self::HeartwoodVerifyProof
        )
    }

    /// Whether this method is an OLED-notify method (auto but shown on display).
    pub fn is_oled_notify(&self) -> bool {
        matches!(self, Self::HeartwoodSwitch)
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

// ---------------------------------------------------------------------------
// Event ID computation (NIP-01)
// ---------------------------------------------------------------------------

/// Compute the NIP-01 event ID for an unsigned event.
///
/// The commitment is the SHA-256 hash of the canonical JSON serialisation:
/// `[0, pubkey, created_at, kind, tags, content]`
pub fn compute_event_id(event: &UnsignedEvent) -> [u8; 32] {
    // Build the NIP-01 commitment array as canonical JSON.
    let commitment = serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
    let serialised = commitment.to_string();

    let mut hasher = Sha256::new();
    hasher.update(serialised.as_bytes());
    let result = hasher.finalize();

    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Compute the NIP-01 event ID as a lowercase hex string.
pub fn compute_event_id_hex(event: &UnsignedEvent) -> String {
    hex_encode(&compute_event_id(event))
}

/// Return a brief summary of an unsigned event suitable for display on the OLED.
///
/// Returns `(kind, truncated_content)`. Content longer than `max_chars` is
/// truncated and suffixed with `"..."`.
pub fn event_display_summary(event: &UnsignedEvent, max_chars: usize) -> (u64, String) {
    let content = if event.content.len() > max_chars {
        let truncated = &event.content[..max_chars];
        format!("{truncated}...")
    } else {
        event.content.clone()
    };
    (event.kind, content)
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
    let response = Nip46Response {
        id: request_id.to_string(),
        result: None,
        error: Some(Nip46Error {
            code,
            message: message.to_string(),
        }),
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
    fn test_build_error_response() {
        let json = build_error_response("req99", -32600, "invalid request").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "req99");
        assert_eq!(parsed["error"]["code"], -32600);
        assert_eq!(parsed["error"]["message"], "invalid request");
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
        assert!(matches!(Nip46Method::from_str("unknown_method"), Nip46Method::Unknown(_)));
    }

    #[test]
    fn test_nip46_method_approval_tiers() {
        assert!(Nip46Method::Ping.always_auto_approve());
        assert!(Nip46Method::GetPublicKey.always_auto_approve());
        assert!(!Nip46Method::SignEvent.always_auto_approve());

        assert!(Nip46Method::HeartwoodDerive.always_requires_button());
        assert!(!Nip46Method::SignEvent.always_requires_button());

        assert!(Nip46Method::HeartwoodSwitch.is_oled_notify());
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
