// common/src/nip46.rs
//
// NIP-46 JSON-RPC types and NIP-01 event ID computation.
//
// This module is only compiled when the `nip46` feature is enabled.
// All types derive Serialize/Deserialize directly since serde is guaranteed
// available when this module is compiled.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use core::fmt::Write as _;

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
    /// Relay author injected by legacy bridges that cannot use the encrypted
    /// frame header. Modern encrypted transports supply this out of band.
    #[serde(rename = "_client_pubkey", default, skip_serializing_if = "Option::is_none")]
    pub legacy_client_pubkey: Option<String>,
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
    /// Extension discovery: which methods this signer actually serves.
    HeartwoodCapabilities,
    // Unknown method
    Unknown(String),
}

impl Nip46Method {
    pub fn from_str(s: &str) -> Self {
        match s {
            "connect" => Self::Connect,
            "ping" => Self::Ping,
            "get_public_key" => Self::GetPublicKey,
            // Both spellings are the same operation and MUST resolve to the
            // same variant: permissions, approval tier, the OLED prompt and the
            // audit entry are all keyed off this, and a compact reply is not a
            // reason to take any of them differently. The name is consulted once
            // more, only to choose how the answer is serialised.
            "sign_event" | "sign_event_compact" => Self::SignEvent,
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
            "heartwood_capabilities" => Self::HeartwoodCapabilities,
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
            Self::HeartwoodCapabilities => "heartwood_capabilities",
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
    ///
    /// Capabilities discovery sits here deliberately: like connect/ping it is
    /// handshake-level plumbing a client needs before any slot binding, and
    /// the advertised list is the same for every client of this firmware.
    pub fn always_auto_approve(&self) -> bool {
        matches!(
            self,
            Self::Connect
                | Self::Ping
                | Self::GetPublicKey
                | Self::SwitchRelays
                | Self::HeartwoodListIdentities
                | Self::HeartwoodVerifyProof
                | Self::HeartwoodCapabilities
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

const STRUCTURED_PREVIEW_MAX_BYTES: usize = 2_048;

fn content_display_preview(content: &str, max_chars: usize) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Parsing JSON into Value can allocate a second copy of every string in
    // the content. Large sign_event bodies (documents and terminal art) only
    // need a short OLED preview, so never materialise their whole body here.
    // Small app-data JSON still gets the richer label extraction below.
    let value = if trimmed.len() <= STRUCTURED_PREVIEW_MAX_BYTES {
        serde_json::from_str::<Value>(trimmed).ok()
    } else {
        None
    };

    if let Some(value) = value {
        if let Some(description) = json_string_field(&value, "description")
            .or_else(|| json_string_field(&value, "desription"))
        {
            return truncate_with_ellipsis(description, max_chars);
        }

        if let Some(subkey) = json_string_field(&value, "subkey") {
            return truncate_with_ellipsis(&format!("subkey: {subkey}"), max_chars);
        }

        for key in ["title", "name", "display_name"] {
            if let Some(label) = json_string_field(&value, key) {
                return truncate_with_ellipsis(label, max_chars);
            }
        }
    }

    truncate_with_ellipsis(trimmed, max_chars)
}

/// Return a brief summary of an unsigned event suitable for display on the OLED.
///
/// Returns `(kind, preview)`. JSON app-data content is collapsed to its useful
/// human label when clients provide one; otherwise the raw content is truncated.
pub fn event_display_summary(event: &UnsignedEvent, max_chars: usize) -> (u64, String) {
    (event.kind, content_display_preview(&event.content, max_chars))
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Deserialise a NIP-46 request from raw JSON bytes.
pub fn parse_request(json: &[u8]) -> Result<Nip46Request, String> {
    serde_json::from_slice(json).map_err(|e| format!("failed to parse NIP-46 request: {e}"))
}

/// The method name a client uses to ask for the compact reply.
///
/// `Nip46Method::from_str` maps it onto `SignEvent`, so permissions, approval
/// tier, display prompt and audit entry are the same code and cannot drift into
/// a laxer parallel path. The name is consulted only to size the request and to
/// choose how the answer is serialised.
pub const SIGN_EVENT_COMPACT_METHOD: &str = "sign_event_compact";

/// The ceiling that applies to a decrypted request, decided WITHOUT parsing it.
///
/// Parsing is the hazard, so this has to be answerable from the raw bytes.
/// Two allocations of roughly twice the content sit on the signing path, and
/// each is fatal alone on a no-PSRAM board:
///
/// - the **request** unescape, which only the object form avoids, since NIP-46
///   carries the event as a string whose quotes are escaped a second time;
/// - the **reply**, which echoes the whole signed event back unless the client
///   asked for the compact one.
///
/// So the larger ceiling requires BOTH. Anything else keeps the standard one:
/// an object request still wanting the full event back cleared the parse and
/// then died building the reply.
///
/// Every transport must apply this, not just the relay. The same parse runs on
/// the encrypted bridge path and the plaintext USB path, and a guard that runs
/// after parsing cannot help on any of them.
pub fn request_ceiling(json: &str, standard: usize, object_compact: usize) -> usize {
    if scan_method(json) == Some(SIGN_EVENT_COMPACT_METHOD) && params_first_is_object(json) {
        object_compact
    } else {
        standard
    }
}

/// Read the `method` value out of a request WITHOUT parsing it.
///
/// Same reason as `scan_rpc_id`: the budget a request is allowed depends on what
/// it is asking for, and that has to be known before serde_json touches it.
///
/// Matches the key with unescaped quotes, so an occurrence inside a stringified
/// event (where every quote is backslash-escaped) cannot be mistaken for it.
/// Returns `None` when absent or unterminated, which selects the tighter budget.
pub fn scan_method(json: &str) -> Option<&str> {
    const KEY: &str = "\"method\"";
    let mut from = 0usize;
    loop {
        let at = from + json[from..].find(KEY)?;
        if at > 0 && json.as_bytes()[at - 1] == b'\\' {
            from = at + KEY.len();
            continue;
        }
        let rest = &json[at + KEY.len()..];
        let bytes = rest.as_bytes();
        // Whitespace, colon, whitespace, opening quote. All ASCII, so byte
        // indexing lands on character boundaries.
        let mut i = 0usize;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        let value = &rest[i + 1..];
        let end = value.find(['"', '\\'])?;
        return Some(&value[..end]);
    }
}

/// Whether `params[0]` is a JSON object, decided WITHOUT parsing.
///
/// The two encodings cost wildly different amounts to parse, so the size a
/// request is allowed to be depends on which one it uses, and that has to be
/// known before serde_json touches it.
///
/// NIP-46 specifies `params[0]` as a *stringified* event, so the event's own
/// quotes are escaped a second time and unescaping them grows a Vec by
/// doubling: that doubling is what aborts the chip. An object costs no unescape
/// pass at all. Heartwood accepts either (see `parse_unsigned_event`), so a
/// client that sends the object form can be allowed a much larger event.
///
/// Scans for the `"params":` key with unescaped quotes. Inside a stringified
/// event every quote is backslash-escaped, so an occurrence in the payload
/// cannot be mistaken for the real key; the preceding-backslash check makes
/// that explicit rather than incidental. Returns false when absent or
/// malformed, which is the conservative answer: it selects the tighter budget.
pub fn params_first_is_object(json: &str) -> bool {
    const KEY: &str = "\"params\"";
    let mut from = 0usize;
    while let Some(found) = json[from..].find(KEY) {
        let at = from + found;
        // A backslash immediately before means this sits inside a JSON string.
        if at > 0 && json.as_bytes()[at - 1] == b'\\' {
            from = at + KEY.len();
            continue;
        }
        // Whitespace is legal around each token, so step over it rather than
        // assuming the compact spelling a particular client happens to emit.
        let mut chars = json[at + KEY.len()..].chars().skip_while(|c| c.is_whitespace());
        if chars.next() != Some(':') {
            return false;
        }
        if chars.find(|c| !c.is_whitespace()) != Some('[') {
            return false;
        }
        return chars.find(|c| !c.is_whitespace()) == Some('{');
    }
    false
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

/// Extract only the event kind without materialising its tags or content.
///
/// Relay routing, policy checks and crash breadcrumbs need the kind before the
/// request reaches the signer. Deserialising the complete event at each of
/// those call sites duplicates large document bodies and can exhaust a
/// no-PSRAM device before its response-size guard runs.
pub fn unsigned_event_kind(params: &[Value]) -> Option<u64> {
    #[derive(Deserialize)]
    struct KindOnly {
        kind: u64,
    }

    match params.first()? {
        Value::String(raw) => serde_json::from_str::<KindOnly>(raw).ok().map(|event| event.kind),
        Value::Object(object) => object.get("kind").and_then(Value::as_u64),
        _ => None,
    }
}

/// Consume `sign_event` params while parsing the event.
///
/// The by-value form lets firmware drop the stringified request body as soon
/// as Serde has built the one `UnsignedEvent` that signing actually needs.
pub fn parse_unsigned_event_owned(params: Vec<Value>) -> Result<UnsignedEvent, String> {
    let raw = params
        .into_iter()
        .next()
        .ok_or_else(|| "sign_event params is empty".to_string())?;

    match raw {
        Value::String(raw) => serde_json::from_str(&raw)
            .map_err(|e| format!("failed to parse event string: {e}")),
        Value::Object(object) => serde_json::from_value(Value::Object(object))
            .map_err(|e| format!("failed to parse event object: {e}")),
        other => Err(format!(
            "unexpected params[0] type: {}",
            other.as_str().unwrap_or("unknown")
        )),
    }
}

/// Build a `sign_event` success response containing the signed event JSON.
pub fn build_sign_response(request_id: &str, signed_event: &SignedEvent) -> Result<String, String> {
    // NIP-46's result is itself a JSON-encoded event string. Building the
    // inner event with serde_json::to_string and then serialising that String
    // again briefly holds two full escaped copies. On a no-PSRAM signer that
    // is enough to abort the allocator for an otherwise relay-safe document.
    // Write both escaping layers directly into the final response instead.
    let mut capacity = 256usize.saturating_add(json_string_content_len(request_id));
    for value in [
        signed_event.id.as_str(),
        signed_event.pubkey.as_str(),
        signed_event.content.as_str(),
        signed_event.sig.as_str(),
    ] {
        capacity = capacity.saturating_add(nested_json_string_len(value));
    }
    for tag in &signed_event.tags {
        capacity = capacity.saturating_add(2);
        for value in tag {
            capacity = capacity.saturating_add(nested_json_string_len(value).saturating_add(1));
        }
    }
    let mut response = String::with_capacity(capacity);
    response.push_str("{\"id\":");
    push_json_string(&mut response, request_id);
    response.push_str(",\"result\":\"");

    push_outer_json_fragment(&mut response, "{\"id\":");
    push_nested_json_string(&mut response, &signed_event.id);
    push_outer_json_fragment(&mut response, ",\"pubkey\":");
    push_nested_json_string(&mut response, &signed_event.pubkey);
    push_outer_json_fragment(&mut response, ",\"created_at\":");
    write!(&mut response, "{}", signed_event.created_at)
        .map_err(|_| "failed to serialise sign response".to_string())?;
    push_outer_json_fragment(&mut response, ",\"kind\":");
    write!(&mut response, "{}", signed_event.kind)
        .map_err(|_| "failed to serialise sign response".to_string())?;
    push_outer_json_fragment(&mut response, ",\"tags\":[");
    for (tag_index, tag) in signed_event.tags.iter().enumerate() {
        if tag_index > 0 {
            response.push(',');
        }
        response.push('[');
        for (value_index, value) in tag.iter().enumerate() {
            if value_index > 0 {
                response.push(',');
            }
            push_nested_json_string(&mut response, value);
        }
        response.push(']');
    }
    push_outer_json_fragment(&mut response, "],\"content\":");
    push_nested_json_string(&mut response, &signed_event.content);
    push_outer_json_fragment(&mut response, ",\"sig\":");
    push_nested_json_string(&mut response, &signed_event.sig);
    push_outer_json_fragment(&mut response, "}");
    response.push_str("\"}");
    Ok(response)
}

/// Build a `sign_event` response that returns only what the client cannot
/// compute for itself: the id, the signature, and the two fields the signer may
/// have filled in.
///
/// `build_sign_response` echoes the WHOLE signed event back, so the reply is
/// larger than the request and needs one contiguous allocation of roughly twice
/// the content. On a V4 that is what aborts the chip once the parse cost is
/// removed: an 18432-byte event failed on a 37270-byte response allocation.
///
/// The client already has the event, it wrote it. Returning `{id, sig, pubkey,
/// created_at}` is a couple of hundred bytes whatever the content size, which
/// takes the response out of the ceiling calculation entirely.
///
/// This does NOT weaken anything. The signature is over the id the signer
/// computed from the event it actually received and displayed, so a client
/// cannot pair this sig with different content: the id would not match and the
/// signature would not verify. `pubkey` and `created_at` are returned because
/// the signer is entitled to set them, and a client that assumed its own values
/// would compute a different id.
pub fn build_sign_response_compact(
    request_id: &str,
    signed_event: &SignedEvent,
) -> Result<String, String> {
    // Bounded and small: four short fields plus the caller's id.
    let mut response = String::with_capacity(320 + json_string_content_len(request_id));
    response.push_str("{\"id\":");
    push_json_string(&mut response, request_id);
    response.push_str(",\"result\":\"");
    push_outer_json_fragment(&mut response, "{\"id\":");
    push_nested_json_string(&mut response, &signed_event.id);
    push_outer_json_fragment(&mut response, ",\"pubkey\":");
    push_nested_json_string(&mut response, &signed_event.pubkey);
    push_outer_json_fragment(&mut response, ",\"created_at\":");
    write!(&mut response, "{}", signed_event.created_at)
        .map_err(|_| "failed to serialise sign response".to_string())?;
    push_outer_json_fragment(&mut response, ",\"sig\":");
    push_nested_json_string(&mut response, &signed_event.sig);
    push_outer_json_fragment(&mut response, "}");
    response.push_str("\"}");
    Ok(response)
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    push_json_string_content(out, value);
    out.push('"');
}

fn push_json_string_content(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if (control as u32) <= 0x1f => {
                let byte = control as u8;
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
            other => out.push(other),
        }
    }
}

fn json_string_content_len(value: &str) -> usize {
    value
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' => 2,
            control if (control as u32) <= 0x1f => 6,
            other => other.len_utf8(),
        })
        .fold(0usize, usize::saturating_add)
}

fn nested_json_string_len(value: &str) -> usize {
    value
        .chars()
        .map(|character| match character {
            '"' | '\\' => 4,
            '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' => 3,
            control if (control as u32) <= 0x1f => 7,
            other => other.len_utf8(),
        })
        .fold(4usize, usize::saturating_add)
}

/// Append raw inner-JSON syntax while already inside the outer result String.
fn push_outer_json_fragment(out: &mut String, fragment: &str) {
    push_json_string_content(out, fragment);
}

/// Append one inner event string value through both JSON escaping layers.
fn push_nested_json_string(out: &mut String, value: &str) {
    push_outer_json_fragment(out, "\"");
    for character in value.chars() {
        match character {
            '"' => push_outer_json_fragment(out, "\\\""),
            '\\' => push_outer_json_fragment(out, "\\\\"),
            '\u{0008}' => push_outer_json_fragment(out, "\\b"),
            '\t' => push_outer_json_fragment(out, "\\t"),
            '\n' => push_outer_json_fragment(out, "\\n"),
            '\u{000c}' => push_outer_json_fragment(out, "\\f"),
            '\r' => push_outer_json_fragment(out, "\\r"),
            control if (control as u32) <= 0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let byte = control as u8;
                let escaped = [
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 0x0f) as usize],
                ];
                // All bytes are ASCII by construction.
                push_outer_json_fragment(
                    out,
                    core::str::from_utf8(&escaped).unwrap_or("\\u0000"),
                );
            }
            other => out.push(other),
        }
    }
    push_outer_json_fragment(out, "\"");
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

/// The `["EVENT", <subscription>, <event>]` message a relay pushes to a
/// subscriber, deserialised straight into its typed form.
///
/// The point is what it avoids. Parsing the raw message into a
/// `serde_json::Value` first and then converting the third element builds a
/// complete `Value` tree for the whole message — including a `String` for the
/// event's content — and then `from_value` copies that content a second time
/// into the `SignedEvent`. For a NIP-46 request carrying a large signing
/// payload the message is ~28 KB, so the intermediate tree is ~28 KB of pure
/// waste held at the same moment as both the raw bytes and the final event.
///
/// On a no-PSRAM signer that transient peak is the difference between handling
/// a large request and aborting the allocator: the same 27824-byte message was
/// handled successfully on one occasion and fatally on another
/// (docs/BENCH-2026-08-06-message-sizes.md). Deserialising directly removes one
/// of the three copies.
#[derive(Debug, Deserialize)]
pub struct RelayEventMessage(
    /// Always "EVENT" — kept so the tuple matches the wire shape.
    pub String,
    /// Subscription id the event arrived on.
    pub String,
    /// The event itself.
    pub SignedEvent,
);

/// Read the leading tag of a relay message (`"EVENT"`, `"EOSE"`, `"OK"`, …)
/// without parsing the message.
///
/// Lets the caller route on the tag and pick a typed parse for the big case,
/// instead of building a `Value` tree for every message just to look at its
/// first element. Scans only the first few bytes.
///
/// Returns `None` if the input is not a JSON array whose first element is a
/// string, which is every relay message worth handling.
pub fn relay_message_tag(raw: &[u8]) -> Option<&str> {
    let mut i = 0;
    while i < raw.len() && (raw[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    if raw.get(i)? != &b'[' {
        return None;
    }
    i += 1;
    while i < raw.len() && (raw[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    if raw.get(i)? != &b'"' {
        return None;
    }
    i += 1;
    let start = i;
    // Relay tags are plain uppercase ASCII with no escapes; stop at the closing
    // quote and refuse anything carrying a backslash rather than unescaping.
    while i < raw.len() && raw[i] != b'"' {
        if raw[i] == b'\\' {
            return None;
        }
        i += 1;
    }
    if i >= raw.len() {
        return None;
    }
    core::str::from_utf8(&raw[start..i]).ok()
}

/// Pull `id` out of a `{"id":"...",...}` NIP-46 envelope without parsing it.
///
/// Works on a request or a response: both carry the same client-generated
/// token, and both have a case where parsing is precisely what must not happen.
///
/// - A **response** too large to transport must be replaced by a same-id error,
///   and it is oversize by definition on a device already short of contiguous
///   heap.
/// - A **request** over the parse budget must be refused, and parsing it is the
///   thing that aborts the chip (unescaping the inner event grows a Vec by
///   doubling). Without the id the refusal reaches the client as silence, which
///   apps render as a timeout rather than "too large".
///
/// Scanning allocates only the id. Returns `None` if the field is absent or
/// unterminated. An escape inside the id ends the scan rather than being
/// unescaped, since these ids are client-generated tokens with no reason to
/// contain one.
///
/// Takes the FIRST `"id":"` in the envelope, which is the JSON-RPC id in every
/// well-formed one. A hostile client could bury an earlier match inside a
/// param; the only consequence is that its own error comes back mis-correlated.
pub fn scan_rpc_id(envelope_json: &str) -> Option<&str> {
    let start = envelope_json.find("\"id\":\"")? + 6;
    let rest = envelope_json.get(start..)?;
    let end = rest.find(['"', '\\'])?;
    Some(&rest[..end])
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

/// Version of the Heartwood NIP-46 extension surface advertised by
/// `heartwood_capabilities`. Bump when extension methods change shape.
pub const CAPABILITIES_VERSION: u32 = 1;

/// Build a `heartwood_capabilities` response advertising the methods this
/// signer serves: `{"version":1,"methods":[...]}` as a NIP-46 string result.
///
/// Callers pass their own list — the ESP32, ESP8266 and Soft-mode signers
/// support different subsets — and stubbed methods must be left out: an
/// advertised method is a promise that it works.
pub fn build_capabilities_response(
    request_id: &str,
    methods: &[&str],
) -> Result<String, String> {
    let result = serde_json::json!({
        "version": CAPABILITIES_VERSION,
        "methods": methods,
    });
    build_result_response(request_id, &result.to_string())
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

    #[test]
    fn relay_message_tag_reads_the_leading_tag() {
        assert_eq!(relay_message_tag(br#"["EVENT","sub",{}]"#), Some("EVENT"));
        assert_eq!(relay_message_tag(br#"["EOSE","sub"]"#), Some("EOSE"));
        assert_eq!(relay_message_tag(br#"["OK","id",true,""]"#), Some("OK"));
        // Relays are free to pad with whitespace.
        assert_eq!(relay_message_tag(b"  [ \"NOTICE\" , \"hi\"]"), Some("NOTICE"));
    }

    #[test]
    fn relay_message_tag_rejects_what_is_not_a_tagged_array() {
        assert_eq!(relay_message_tag(b""), None);
        assert_eq!(relay_message_tag(b"{}"), None);
        assert_eq!(relay_message_tag(br#"[1,2]"#), None);
        assert_eq!(relay_message_tag(br#"["unterminated"#), None);
        // An escape in the tag is refused rather than unescaped: no legitimate
        // relay tag contains one, and returning a half-unescaped tag that then
        // routed as "EVENT" would be worse than not routing it at all. The
        // bytes below are a literal backslash inside the tag.
        assert_eq!(relay_message_tag(br#"["EV\ENT","s",{}]"#), None);
    }

    #[test]
    fn relay_event_message_deserialises_without_an_intermediate_value() {
        let signed = SignedEvent {
            id: "aa".repeat(32),
            pubkey: "bb".repeat(32),
            created_at: 1_700_000_000,
            kind: 24133,
            tags: vec![vec!["p".to_string(), "cc".repeat(32)]],
            content: "ciphertext-goes-here".to_string(),
            sig: "dd".repeat(64),
        };
        let wire = format!(
            r#"["EVENT","sub-1",{}]"#,
            serde_json::to_string(&signed).unwrap()
        );

        let parsed: RelayEventMessage = serde_json::from_slice(wire.as_bytes()).unwrap();
        assert_eq!(parsed.0, "EVENT");
        assert_eq!(parsed.1, "sub-1");
        assert_eq!(parsed.2.id, signed.id);
        assert_eq!(parsed.2.kind, 24133);
        assert_eq!(parsed.2.content, "ciphertext-goes-here");
        assert_eq!(parsed.2.sig, signed.sig);
        assert_eq!(parsed.2.tags, signed.tags);
    }

    #[test]
    fn relay_event_message_carries_a_large_content_intact() {
        // The whole point of the type is the big case. A NIP-46 request at the
        // signing ceiling arrives as roughly this much base64 ciphertext.
        let content = "a".repeat(27_000);
        let signed = SignedEvent {
            id: "11".repeat(32),
            pubkey: "22".repeat(32),
            created_at: 1,
            kind: 24133,
            tags: vec![],
            content: content.clone(),
            sig: "33".repeat(64),
        };
        let wire = format!(r#"["EVENT","s",{}]"#, serde_json::to_string(&signed).unwrap());
        let parsed: RelayEventMessage = serde_json::from_slice(wire.as_bytes()).unwrap();
        assert_eq!(parsed.2.content.len(), 27_000);
        assert_eq!(parsed.2.content, content);
    }

    #[test]
    fn relay_event_message_rejects_a_malformed_event() {
        // Must fail cleanly rather than panic: this runs on every inbound
        // message from an untrusted relay.
        assert!(serde_json::from_slice::<RelayEventMessage>(br#"["EVENT","s",{"id":1}]"#).is_err());
        assert!(serde_json::from_slice::<RelayEventMessage>(br#"["EVENT","s"]"#).is_err());
        assert!(serde_json::from_slice::<RelayEventMessage>(br#"["EOSE","s"]"#).is_err());
    }

    #[test]
    fn scan_rpc_id_reads_the_id_without_parsing() {
        let signed = build_sign_response(
            "req-42",
            &SignedEvent {
                id: "aa".repeat(32),
                pubkey: "bb".repeat(32),
                created_at: 1_700_000_000,
                kind: 1,
                tags: vec![],
                content: "hello".to_string(),
                sig: "cc".repeat(64),
            },
        )
        .unwrap();
        // Must agree with the real builder's output, not a hand-written shape.
        assert_eq!(scan_rpc_id(&signed), Some("req-42"));
    }

    #[test]
    fn scan_rpc_id_handles_absent_and_malformed() {
        assert_eq!(scan_rpc_id("{}"), None);
        assert_eq!(scan_rpc_id(""), None);
        // Present but never closed.
        assert_eq!(scan_rpc_id("{\"id\":\"unterminated"), None);
        // Empty id is a real (if useless) value, not a failure.
        assert_eq!(scan_rpc_id("{\"id\":\"\",\"result\":\"x\"}"), Some(""));
    }

    #[test]
    fn request_ceiling_needs_both_halves() {
        let event = r#"{"kind":1,"created_at":1,"tags":[],"content":"hi"}"#;
        let stringified = serde_json::to_string(event).unwrap();
        let req = |method: &str, params: &str| {
            format!(r#"{{"id":"a","method":"{method}","params":[{params}]}}"#)
        };
        const STD: usize = 12288;
        const BIG: usize = 18432;

        // Both halves: the only combination that earns the headroom.
        assert_eq!(
            request_ceiling(&req("sign_event_compact", event), STD, BIG),
            BIG
        );
        // Object request, full reply: still pays the reply allocation.
        assert_eq!(request_ceiling(&req("sign_event", event), STD, BIG), STD);
        // Compact reply, stringified request: still pays the unescape.
        assert_eq!(
            request_ceiling(&req("sign_event_compact", &stringified), STD, BIG),
            STD
        );
        // Neither.
        assert_eq!(request_ceiling(&req("sign_event", &stringified), STD, BIG), STD);
        // Unparseable or unrelated takes the conservative answer.
        assert_eq!(request_ceiling("{}", STD, BIG), STD);
        assert_eq!(request_ceiling("", STD, BIG), STD);
    }

    #[test]
    fn request_ceiling_is_not_fooled_into_the_larger_budget() {
        // A stringified event whose content spells out the compact method and an
        // object opener. Granting the larger budget here would hand the parse
        // exactly the input that aborts the chip.
        let sneaky = format!(
            r#"{{"kind":1,"created_at":1,"tags":[],"content":{}}}"#,
            serde_json::to_string(r#""method":"sign_event_compact","params":[{"#).unwrap()
        );
        let req = format!(
            r#"{{"id":"a","method":"sign_event","params":[{}]}}"#,
            serde_json::to_string(&sneaky).unwrap()
        );
        assert_eq!(request_ceiling(&req, 12288, 18432), 12288);
    }

    #[test]
    fn sign_event_compact_is_policed_exactly_as_sign_event() {
        // Load-bearing invariant, not a formality. `evaluate_slot_policy` is
        // handed `Nip46Method::as_str()`, and it gates on the literal
        // "sign_event" for allowed_methods, signing_approved and allowed_kinds.
        // If the compact spelling ever became its own variant, it would miss
        // every one of those checks and become a way to sign around the slot's
        // permissions. Both spellings must collapse to the same method here.
        let standard = Nip46Method::from_str("sign_event");
        let compact = Nip46Method::from_str("sign_event_compact");
        assert_eq!(compact, standard);
        assert_eq!(compact.as_str(), "sign_event");
        assert_eq!(compact.always_requires_button(), standard.always_requires_button());
        assert_eq!(compact.always_auto_approve(), standard.always_auto_approve());
        assert_eq!(compact.requires_tree_mode(), standard.requires_tree_mode());
    }

    #[test]
    fn scan_method_reads_the_method_before_parsing() {
        let event = r#"{"kind":1,"created_at":1,"tags":[],"content":"hi"}"#;
        let req = format!(
            r#"{{"id":"a","method":"sign_event_compact","params":[{event}]}}"#
        );
        assert_eq!(scan_method(&req), Some("sign_event_compact"));
        // Whitespace around the tokens, and the key appearing after params.
        assert_eq!(
            scan_method(r#"{"params":[{"kind":1}], "method" : "sign_event" }"#),
            Some("sign_event")
        );
        assert_eq!(scan_method("{}"), None);
        assert_eq!(scan_method(r#"{"method":123}"#), None);
        assert_eq!(scan_method(r#"{"method":"unterminated"#), None);
    }

    #[test]
    fn scan_method_is_not_fooled_by_the_payload() {
        // A stringified event whose content names a method must not be read as
        // the envelope's own: granting the larger budget on that basis is
        // exactly the crash this guards.
        let sneaky = r#"{"kind":1,"created_at":1,"tags":[],"content":"\"method\":\"sign_event_compact\""}"#;
        let req = format!(
            r#"{{"id":"a","method":"sign_event","params":[{}]}}"#,
            serde_json::to_string(sneaky).unwrap()
        );
        assert_eq!(scan_method(&req), Some("sign_event"));
    }

    #[test]
    fn params_first_is_object_tells_the_two_encodings_apart() {
        let event = r#"{"kind":1,"created_at":1700000000,"tags":[],"content":"hi"}"#;
        // The NIP-46 form: params[0] is the event as an escaped string.
        let stringified = format!(
            r#"{{"id":"a","method":"sign_event","params":[{}]}}"#,
            serde_json::to_string(event).unwrap()
        );
        assert!(!params_first_is_object(&stringified));
        // The extension form: params[0] is the event itself.
        let object = format!(r#"{{"id":"a","method":"sign_event","params":[{event}]}}"#);
        assert!(params_first_is_object(&object));
        // Whitespace between the tokens must not change the answer.
        assert!(params_first_is_object(
            r#"{"method":"sign_event", "params" : [ {"kind":1} ]}"#
        ));
    }

    #[test]
    fn params_first_is_object_is_not_fooled_by_the_payload() {
        // An event whose CONTENT contains the key. In the stringified form every
        // quote is backslash-escaped, so it must not read as the real params.
        let sneaky = r#"{"kind":1,"created_at":1,"tags":[],"content":"\"params\":[{"}"#;
        let stringified = format!(
            r#"{{"id":"a","method":"sign_event","params":[{}]}}"#,
            serde_json::to_string(sneaky).unwrap()
        );
        assert!(!params_first_is_object(&stringified));
    }

    #[test]
    fn params_first_is_object_defaults_to_the_tighter_budget() {
        // Absent, empty and non-object all pick the conservative answer.
        assert!(!params_first_is_object("{}"));
        assert!(!params_first_is_object(""));
        assert!(!params_first_is_object(r#"{"params":[]}"#));
        assert!(!params_first_is_object(r#"{"params":"nope"}"#));
        assert!(!params_first_is_object(r#"{"params":[123]}"#));
    }

    #[test]
    fn scan_rpc_id_reads_a_request_too_large_to_parse() {
        // The reason this has to work without parsing: an over-budget request
        // is refused precisely because parsing it aborts the chip, and the
        // refusal still has to carry the client's id or it lands as silence.
        // Shaped like the real thing, with the event double-encoded in params.
        let event = r#"{"kind":1,"created_at":1700000000,"tags":[],"content":"aaaa"}"#;
        let request = format!(
            r#"{{"id":"sweep-3","method":"sign_event","params":[{}]}}"#,
            serde_json::to_string(event).unwrap()
        );
        assert_eq!(scan_rpc_id(&request), Some("sweep-3"));
    }

    #[test]
    fn scan_rpc_id_stops_at_an_escape_rather_than_unescaping() {
        // Deliberate: the id is echoed straight back into an error response, so
        // it must never carry a partial escape sequence into fresh JSON.
        assert_eq!(
            scan_rpc_id("{\"id\":\"we\\\"ird\",\"result\":\"x\"}"),
            Some("we")
        );
    }

    #[test]
    fn scan_rpc_id_round_trips_into_an_error_response() {
        // The whole point of the helper: recover the id from a response we
        // cannot send, and correlate the substitute error to the same request.
        let original = build_sign_response(
            "abc-123",
            &SignedEvent {
                id: "11".repeat(32),
                pubkey: "22".repeat(32),
                created_at: 1,
                kind: 1,
                tags: vec![],
                content: "x".repeat(64),
                sig: "33".repeat(64),
            },
        )
        .unwrap();
        let id = scan_rpc_id(&original).unwrap();
        let error = build_error_response(id, -4, "response too large").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&error).unwrap();
        assert_eq!(parsed["id"], "abc-123");
        assert_eq!(parsed["error"], "response too large");
    }

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
    fn event_kind_can_be_read_without_parsing_the_content() {
        let deliberately_invalid_event =
            r#"{"kind":31436,"content":false,"tags":"not an event"}"#;
        let params = vec![Value::String(deliberately_invalid_event.to_string())];

        assert_eq!(unsigned_event_kind(&params), Some(31_436));
        assert!(parse_unsigned_event(&params).is_err());
    }

    #[test]
    fn owned_event_parser_accepts_string_and_object_params() {
        let event_json =
            r#"{"created_at":1234,"kind":31436,"tags":[["d","/"]],"content":"art"}"#;
        let from_string = parse_unsigned_event_owned(vec![Value::String(event_json.to_string())])
            .unwrap();
        let from_object = parse_unsigned_event_owned(vec![serde_json::from_str(event_json).unwrap()])
            .unwrap();

        assert_eq!(from_string.kind, 31_436);
        assert_eq!(from_string.content, "art");
        assert_eq!(from_string.pubkey, from_object.pubkey);
        assert_eq!(from_string.created_at, from_object.created_at);
        assert_eq!(from_string.kind, from_object.kind);
        assert_eq!(from_string.tags, from_object.tags);
        assert_eq!(from_string.content, from_object.content);
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
    fn compact_sign_response_stays_small_however_large_the_event() {
        // The whole point: the reply must drop out of the size calculation, so
        // its length must not track the content it signed.
        let mut event = sample_event();
        event.content = "a".repeat(18432);
        let signed = SignedEvent {
            id: compute_event_id_hex(&event),
            pubkey: event.pubkey.clone(),
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: "a".repeat(128),
        };

        let full = build_sign_response("req42", &signed).unwrap();
        let compact = build_sign_response_compact("req42", &signed).unwrap();
        assert!(full.len() > 18432, "full response carries the content back");
        assert!(
            compact.len() < 512,
            "compact response was {} bytes",
            compact.len()
        );

        let parsed: serde_json::Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["id"], "req42");
        let inner: serde_json::Value =
            serde_json::from_str(parsed["result"].as_str().unwrap()).unwrap();
        // Exactly the fields a client cannot derive for itself, and no content.
        assert_eq!(inner["id"], signed.id.as_str());
        assert_eq!(inner["sig"], signed.sig.as_str());
        assert_eq!(inner["pubkey"], signed.pubkey.as_str());
        assert_eq!(inner["created_at"], signed.created_at);
        assert!(inner.get("content").is_none());
    }

    #[test]
    fn compact_sign_response_id_still_binds_the_content() {
        // The security argument for returning no content: the id is over the
        // event the signer saw, so a client cannot pair this sig with different
        // content without the id ceasing to match.
        let event = sample_event();
        let mut tampered = event.clone();
        tampered.content = "something else entirely".to_string();
        assert_ne!(compute_event_id_hex(&event), compute_event_id_hex(&tampered));
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
    fn sign_response_streaming_matches_serde_exactly() {
        let signed = SignedEvent {
            id: "id-\"\\\n\u{0001}-雪".to_string(),
            pubkey: "pubkey".to_string(),
            created_at: 1_777_777_777,
            kind: 31_436,
            tags: vec![
                vec!["d".to_string(), "path/with \"quotes\"".to_string()],
                vec!["terminal".to_string(), "ansi\\escape\u{001b}".to_string()],
            ],
            content: "line one\nline two\t\\ \" 驴 \u{0008}\u{000c}\r".to_string(),
            sig: "sig".to_string(),
        };
        let event_json = serde_json::to_string(&signed).unwrap();
        let expected = serde_json::to_string(&Nip46Response {
            id: "request-\"\\\n雪".to_string(),
            result: Some(event_json),
            error: None,
        })
        .unwrap();

        assert_eq!(
            build_sign_response("request-\"\\\n雪", &signed).unwrap(),
            expected
        );
    }

    #[test]
    fn large_event_preview_does_not_parse_or_copy_the_whole_json_body() {
        let mut event = sample_event();
        event.content = format!(
            "{{\"description\":\"{}\"}}",
            "high definition terminal art ".repeat(200)
        );

        let (_, summary) = event_display_summary(&event, 50);
        assert_eq!(summary.chars().count(), 53);
        assert!(summary.ends_with("..."));
        assert!(summary.starts_with("{\"description\":"));
    }

    #[test]
    fn test_nip46_method_from_str() {
        assert_eq!(Nip46Method::from_str("sign_event"), Nip46Method::SignEvent);
        assert_eq!(Nip46Method::from_str("heartwood_derive"), Nip46Method::HeartwoodDerive);
        assert_eq!(Nip46Method::from_str("ping"), Nip46Method::Ping);
        assert_eq!(Nip46Method::from_str("switch_relays"), Nip46Method::SwitchRelays);
        assert_eq!(
            Nip46Method::from_str("heartwood_capabilities"),
            Nip46Method::HeartwoodCapabilities
        );
        assert!(matches!(Nip46Method::from_str("unknown_method"), Nip46Method::Unknown(_)));
    }

    #[test]
    fn test_nip46_method_approval_tiers() {
        assert!(Nip46Method::Ping.always_auto_approve());
        assert!(Nip46Method::GetPublicKey.always_auto_approve());
        assert!(Nip46Method::SwitchRelays.always_auto_approve());
        assert!(Nip46Method::HeartwoodCapabilities.always_auto_approve());
        assert!(!Nip46Method::HeartwoodCapabilities.always_requires_button());
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
    fn test_build_capabilities_response() {
        let json = build_capabilities_response("cap-1", &["ping", "heartwood_derive"]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "cap-1");
        // NIP-46 results are strings; the payload is JSON inside that string.
        let result: serde_json::Value =
            serde_json::from_str(parsed["result"].as_str().unwrap()).unwrap();
        assert_eq!(result["version"], CAPABILITIES_VERSION);
        assert_eq!(result["methods"][0], "ping");
        assert_eq!(result["methods"][1], "heartwood_derive");
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
