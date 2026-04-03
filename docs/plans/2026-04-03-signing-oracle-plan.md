# Phase 3: USB Signing Oracle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the ESP32 a NIP-46 signing bunker — it receives signing requests over serial, shows what's being signed on the OLED, and requires physical button approval before signing.

**Architecture:** Host-testable logic (frame protocol, NIP-46 parsing, event ID computation) lives in `common/`. Firmware-specific code (GPIO, OLED, serial I/O) lives in `firmware/`. The `common` crate gains `serde` + `serde_json` + `sha2` dependencies behind a `nip46` feature flag so they don't bloat builds that don't need them.

**Tech Stack:** Rust, ESP-IDF v5.x (std), serde/serde_json for JSON, sha2 for event IDs, k256 for Schnorr signing, esp-idf-hal for GPIO/I2C/USB-serial.

**Spec:** `docs/specs/2026-04-03-signing-oracle-design.md`

**Testing strategy:** Tasks 1–3 are fully host-testable via `cargo test` in `common/` and `provision/`. Tasks 4–8 are firmware that requires hardware verification (flash + serial). Task 9 is a test harness CLI for end-to-end validation.

---

## File Map

### New files

| File | Responsibility |
|------|----------------|
| `common/src/frame.rs` | Frame building, parsing, CRC validation. Shared by firmware and provision CLI. |
| `common/src/nip46.rs` | NIP-46 JSON-RPC types, unsigned event types, NIP-01 event ID computation. Host-testable. |
| `firmware/src/button.rs` | GPIO 0 interrupt handler. Measures press duration, exposes result via `std::sync::mpsc`. |
| `firmware/src/protocol.rs` | Reads frames byte-by-byte from USB-Serial-JTAG using `common::frame` for validation. |
| `firmware/src/nip46_handler.rs` | Dispatches NIP-46 methods. `sign_event` → OLED + button + derive + sign. `get_public_key` → immediate response. |

### Modified files

| File | Changes |
|------|---------|
| `common/Cargo.toml` | Add `serde`, `serde_json`, `sha2` behind `nip46` feature flag. |
| `common/src/lib.rs` | Conditionally export `frame` (always) and `nip46` (behind feature). |
| `common/src/types.rs` | Add frame type constants. Keep `PROVISION_FRAME_LEN` for backward compat but add new constants. |
| `firmware/Cargo.toml` | Add `serde`, `serde_json`. Enable `nip46` feature on `heartwood-common`. |
| `firmware/src/main.rs` | Refactor: init → NVS → provision-or-npub → frame dispatch loop. |
| `firmware/src/provision.rs` | Simplify: receives 32-byte payload only, frame parsing handled by `protocol.rs`. |
| `firmware/src/oled.rs` | Add `show_sign_request()`, `show_result()`, `show_countdown_bar()`. |
| `provision/Cargo.toml` | Enable `nip46` feature on `heartwood-common` (for frame building). |
| `provision/src/main.rs` | Use new frame format with type byte `0x01`. Update `build_frame`. |

### Unchanged files

| File | Reason |
|------|--------|
| `common/src/derive.rs` | Frozen protocol. |
| `common/src/encoding.rs` | No changes needed. |
| `firmware/src/nvs.rs` | NVS storage unchanged. |
| `firmware/src/sign.rs` | BIP-340 signing unchanged — called by `nip46_handler.rs`. |

---

## Task 1: Frame Protocol in Common

**Files:**
- Create: `common/src/frame.rs`
- Modify: `common/src/types.rs`
- Modify: `common/src/lib.rs`
- Modify: `common/Cargo.toml`

This task adds the shared frame format used by both firmware and provision CLI. The frame format is: `[0x48 0x57][type_u8][length_u16_be][payload...][crc32_4]`.

- [ ] **Step 1: Add frame type constants to `common/src/types.rs`**

Add after the existing `PROVISION_FRAME_LEN` constant (line 24):

```rust
// --- Frame protocol (Phase 3) ---

/// Frame type: provision (host → device, 32-byte secret).
pub const FRAME_TYPE_PROVISION: u8 = 0x01;

/// Frame type: NIP-46 request (host → device, JSON-RPC).
pub const FRAME_TYPE_NIP46_REQUEST: u8 = 0x02;

/// Frame type: NIP-46 response (device → host, JSON-RPC).
pub const FRAME_TYPE_NIP46_RESPONSE: u8 = 0x03;

/// Frame type: ACK (device → host, empty payload).
pub const FRAME_TYPE_ACK: u8 = 0x06;

/// Frame type: NACK (device → host, empty payload).
pub const FRAME_TYPE_NACK: u8 = 0x15;

/// Maximum frame payload size in bytes.
pub const MAX_PAYLOAD_SIZE: usize = 4096;

/// Frame header size: 2 (magic) + 1 (type) + 2 (length) = 5 bytes.
pub const FRAME_HEADER_SIZE: usize = 5;

/// Frame overhead: header + CRC32 = 9 bytes.
pub const FRAME_OVERHEAD: usize = FRAME_HEADER_SIZE + 4;
```

- [ ] **Step 2: Add `crc32fast` to `common/Cargo.toml`**

Add to `[dependencies]`:

```toml
crc32fast = "1"
```

- [ ] **Step 3: Write failing tests for frame building and parsing**

Create `common/src/frame.rs`:

```rust
// common/src/frame.rs
//
// Serial frame protocol: [magic_2][type_1][length_2_be][payload...][crc32_4]
// Shared between firmware and host tools.

use crate::types::*;

/// A parsed frame.
#[derive(Debug, PartialEq)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

/// Frame building/parsing errors.
#[derive(Debug, PartialEq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    PayloadTooLarge,
    BadCrc,
}

/// Build a frame from type and payload. Returns the complete byte sequence.
pub fn build_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge);
    }
    let len = payload.len() as u16;
    // CRC covers type + length + payload
    let mut crc_input = Vec::with_capacity(3 + payload.len());
    crc_input.push(frame_type);
    crc_input.extend_from_slice(&len.to_be_bytes());
    crc_input.extend_from_slice(payload);
    let crc = crc32fast::hash(&crc_input);

    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.extend_from_slice(&MAGIC_BYTES);
    frame.push(frame_type);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc.to_be_bytes());
    Ok(frame)
}

/// Parse a complete frame from bytes. Validates magic, length, and CRC.
pub fn parse_frame(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < FRAME_OVERHEAD {
        return Err(FrameError::TooShort);
    }
    if data[0] != MAGIC_BYTES[0] || data[1] != MAGIC_BYTES[1] {
        return Err(FrameError::BadMagic);
    }
    let frame_type = data[2];
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if length > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge);
    }
    let expected_total = FRAME_OVERHEAD + length;
    if data.len() < expected_total {
        return Err(FrameError::TooShort);
    }
    let payload = &data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + length];
    let crc_bytes = &data[FRAME_HEADER_SIZE + length..FRAME_HEADER_SIZE + length + 4];
    let frame_crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);

    // CRC covers type + length + payload
    let mut crc_input = Vec::with_capacity(3 + length);
    crc_input.push(frame_type);
    crc_input.extend_from_slice(&data[3..5]); // length bytes
    crc_input.extend_from_slice(payload);
    let computed_crc = crc32fast::hash(&crc_input);

    if frame_crc != computed_crc {
        return Err(FrameError::BadCrc);
    }

    Ok(Frame {
        frame_type,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_provision_frame() {
        let secret = [0xaa; 32];
        let frame_bytes = build_frame(FRAME_TYPE_PROVISION, &secret).unwrap();

        // Header: 2 magic + 1 type + 2 length = 5
        // Payload: 32
        // CRC: 4
        // Total: 41
        assert_eq!(frame_bytes.len(), 41);
        assert_eq!(&frame_bytes[0..2], &MAGIC_BYTES);
        assert_eq!(frame_bytes[2], FRAME_TYPE_PROVISION);

        let parsed = parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(parsed.payload, secret);
    }

    #[test]
    fn test_build_and_parse_nip46_frame() {
        let json = br#"{"id":"abc","method":"sign_event","params":["{}"]}"#;
        let frame_bytes = build_frame(FRAME_TYPE_NIP46_REQUEST, json).unwrap();
        let parsed = parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_NIP46_REQUEST);
        assert_eq!(parsed.payload, json);
    }

    #[test]
    fn test_build_and_parse_empty_ack() {
        let frame_bytes = build_frame(FRAME_TYPE_ACK, &[]).unwrap();
        assert_eq!(frame_bytes.len(), FRAME_OVERHEAD);
        let parsed = parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_ACK);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut frame_bytes = build_frame(FRAME_TYPE_ACK, &[]).unwrap();
        frame_bytes[0] = 0xFF;
        assert_eq!(parse_frame(&frame_bytes), Err(FrameError::BadMagic));
    }

    #[test]
    fn test_parse_bad_crc() {
        let mut frame_bytes = build_frame(FRAME_TYPE_ACK, &[]).unwrap();
        let last = frame_bytes.len() - 1;
        frame_bytes[last] ^= 0xFF;
        assert_eq!(parse_frame(&frame_bytes), Err(FrameError::BadCrc));
    }

    #[test]
    fn test_parse_too_short() {
        assert_eq!(parse_frame(&[0x48, 0x57]), Err(FrameError::TooShort));
    }

    #[test]
    fn test_payload_too_large() {
        let big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert_eq!(build_frame(FRAME_TYPE_NIP46_REQUEST, &big), Err(FrameError::PayloadTooLarge));
    }

    #[test]
    fn test_roundtrip_max_payload() {
        let payload = vec![0x42; MAX_PAYLOAD_SIZE];
        let frame_bytes = build_frame(FRAME_TYPE_NIP46_REQUEST, &payload).unwrap();
        let parsed = parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.payload, payload);
    }
}
```

- [ ] **Step 4: Export frame module from `common/src/lib.rs`**

Replace contents of `common/src/lib.rs`:

```rust
pub mod derive;
pub mod encoding;
pub mod frame;
pub mod hex;
pub mod types;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ./common && cargo test`

Expected: all existing tests pass + new frame tests pass.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/frame.rs common/src/types.rs common/src/lib.rs common/Cargo.toml
git commit -m "feat: add serial frame protocol to common crate"
```

---

## Task 2: NIP-46 Types and Event ID Computation in Common

**Files:**
- Create: `common/src/nip46.rs`
- Modify: `common/Cargo.toml`
- Modify: `common/src/lib.rs`

Host-testable NIP-46 JSON-RPC types, unsigned Nostr event types, and NIP-01 event ID computation. Behind a `nip46` feature flag so the common crate doesn't pull serde/serde_json for builds that don't need it.

- [ ] **Step 1: Add `nip46` feature flag and dependencies to `common/Cargo.toml`**

Add to `[features]` section (create it if it doesn't exist) and add deps:

```toml
[features]
default = []
nip46 = ["dep:serde", "dep:serde_json"]

[dependencies]
k256 = { version = "0.13", default-features = false, features = ["schnorr", "arithmetic"] }
hmac = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
zeroize = { version = "1", default-features = false, features = ["derive"] }
bech32 = { version = "0.11", default-features = false, features = ["alloc"] }
crc32fast = "1"
serde = { version = "1", features = ["derive"], optional = true }
serde_json = { version = "1", optional = true }

[dev-dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Write `common/src/nip46.rs` with types and event ID computation**

```rust
// common/src/nip46.rs
//
// NIP-46 JSON-RPC types and NIP-01 event ID computation.
// Behind the `nip46` feature flag (requires serde + serde_json).

use sha2::{Sha256, Digest};
use crate::hex::hex_encode;

#[cfg(feature = "nip46")]
use serde::{Deserialize, Serialize};

/// NIP-46 JSON-RPC request.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Deserialize))]
pub struct Nip46Request {
    pub id: String,
    pub method: String,
    #[cfg_attr(feature = "nip46", serde(default))]
    pub params: Vec<serde_json::Value>,
    /// Heartwood extension: identity selection.
    #[cfg_attr(feature = "nip46", serde(default))]
    pub heartwood: Option<HeartwoodContext>,
}

/// Heartwood identity context — which derived identity to sign as.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Deserialize))]
pub struct HeartwoodContext {
    pub purpose: String,
    #[cfg_attr(feature = "nip46", serde(default))]
    pub index: u32,
}

/// NIP-46 JSON-RPC success response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Serialize))]
pub struct Nip46Response {
    pub id: String,
    #[cfg_attr(feature = "nip46", serde(skip_serializing_if = "Option::is_none"))]
    pub result: Option<String>,
    #[cfg_attr(feature = "nip46", serde(skip_serializing_if = "Option::is_none"))]
    pub error: Option<Nip46Error>,
}

/// NIP-46 JSON-RPC error.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Serialize))]
pub struct Nip46Error {
    pub code: i32,
    pub message: String,
}

/// An unsigned Nostr event (as received in sign_event params).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Serialize, Deserialize))]
pub struct UnsignedEvent {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// A signed Nostr event (returned in sign_event result).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nip46", derive(Serialize))]
pub struct SignedEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Compute the NIP-01 event ID from event fields.
///
/// Serialises the commitment array `[0, pubkey, created_at, kind, tags, content]`
/// and SHA-256 hashes it. Returns the 32-byte hash.
pub fn compute_event_id(event: &UnsignedEvent) -> [u8; 32] {
    // Build the commitment array as a serde_json::Value for canonical serialisation
    let commitment = serde_json::json!([
        0,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content
    ]);
    let serialised = serde_json::to_string(&commitment).expect("commitment serialisation");
    let mut hasher = Sha256::new();
    hasher.update(serialised.as_bytes());
    hasher.finalize().into()
}

/// Compute event ID and return it as a hex string.
pub fn compute_event_id_hex(event: &UnsignedEvent) -> String {
    hex_encode(&compute_event_id(event))
}

/// Extract a display summary from an unsigned event for OLED rendering.
/// Returns (kind, content_preview) where content_preview is truncated to max_chars.
pub fn event_display_summary(event: &UnsignedEvent, max_chars: usize) -> (u64, String) {
    let preview = if event.content.len() > max_chars {
        format!("{}...", &event.content[..max_chars])
    } else {
        event.content.clone()
    };
    (event.kind, preview)
}

/// Parse a NIP-46 request from JSON bytes.
#[cfg(feature = "nip46")]
pub fn parse_request(json: &[u8]) -> Result<Nip46Request, String> {
    serde_json::from_slice(json).map_err(|e| format!("invalid NIP-46 request: {e}"))
}

/// Parse an unsigned event from the first param of a sign_event request.
#[cfg(feature = "nip46")]
pub fn parse_unsigned_event(params: &[serde_json::Value]) -> Result<UnsignedEvent, String> {
    if params.is_empty() {
        return Err("sign_event requires one param".into());
    }
    let event_json = match &params[0] {
        serde_json::Value::String(s) => s.as_str(),
        _ => return Err("sign_event param must be a JSON string".into()),
    };
    serde_json::from_str(event_json).map_err(|e| format!("invalid unsigned event: {e}"))
}

/// Build a success response with a signed event JSON string.
#[cfg(feature = "nip46")]
pub fn build_sign_response(request_id: &str, signed_event: &SignedEvent) -> Result<String, String> {
    let event_json = serde_json::to_string(signed_event)
        .map_err(|e| format!("failed to serialise signed event: {e}"))?;
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(event_json),
        error: None,
    };
    serde_json::to_string(&response).map_err(|e| format!("failed to serialise response: {e}"))
}

/// Build a pubkey response.
#[cfg(feature = "nip46")]
pub fn build_pubkey_response(request_id: &str, hex_pubkey: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(hex_pubkey.to_string()),
        error: None,
    };
    serde_json::to_string(&response).map_err(|e| format!("failed to serialise response: {e}"))
}

/// Build an error response (denied, timeout, unknown method, etc.).
#[cfg(feature = "nip46")]
pub fn build_error_response(request_id: &str, code: i32, message: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: None,
        error: Some(Nip46Error {
            code,
            message: message.to_string(),
        }),
    };
    serde_json::to_string(&response).map_err(|e| format!("failed to serialise response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> UnsignedEvent {
        UnsignedEvent {
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "Hello, world!".into(),
        }
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let event = sample_event();
        let id1 = compute_event_id(&event);
        let id2 = compute_event_id(&event);
        assert_eq!(id1, id2, "event ID must be deterministic");
    }

    #[test]
    fn test_compute_event_id_changes_with_content() {
        let mut event = sample_event();
        let id1 = compute_event_id(&event);
        event.content = "Different content".into();
        let id2 = compute_event_id(&event);
        assert_ne!(id1, id2, "different content must produce different event ID");
    }

    #[test]
    fn test_compute_event_id_changes_with_kind() {
        let mut event = sample_event();
        let id1 = compute_event_id(&event);
        event.kind = 30023;
        let id2 = compute_event_id(&event);
        assert_ne!(id1, id2, "different kind must produce different event ID");
    }

    #[test]
    fn test_compute_event_id_hex_is_64_chars() {
        let event = sample_event();
        let hex = compute_event_id_hex(&event);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_event_display_summary_truncation() {
        let event = UnsignedEvent {
            pubkey: "aa".repeat(32),
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: "This is a long message that should be truncated for the OLED display".into(),
        };
        let (kind, preview) = event_display_summary(&event, 20);
        assert_eq!(kind, 1);
        assert_eq!(preview, "This is a long messa...");
    }

    #[test]
    fn test_event_display_summary_short_content() {
        let event = sample_event();
        let (kind, preview) = event_display_summary(&event, 50);
        assert_eq!(kind, 1);
        assert_eq!(preview, "Hello, world!");
    }

    #[test]
    fn test_parse_request() {
        let json = br#"{"id":"req-1","method":"sign_event","params":["{\"pubkey\":\"aa\",\"created_at\":0,\"kind\":1,\"tags\":[],\"content\":\"hi\"}"]}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.id, "req-1");
        assert_eq!(req.method, "sign_event");
        assert_eq!(req.params.len(), 1);
        assert!(req.heartwood.is_none());
    }

    #[test]
    fn test_parse_request_with_heartwood_context() {
        let json = br#"{"id":"req-2","method":"sign_event","params":["{}"],"heartwood":{"purpose":"persona/social","index":0}}"#;
        let req = parse_request(json).unwrap();
        let hw = req.heartwood.unwrap();
        assert_eq!(hw.purpose, "persona/social");
        assert_eq!(hw.index, 0);
    }

    #[test]
    fn test_parse_unsigned_event() {
        let event_json = r#"{"pubkey":"aabb","created_at":1000,"kind":1,"tags":[["p","cc"]],"content":"test"}"#;
        let params = vec![serde_json::Value::String(event_json.into())];
        let event = parse_unsigned_event(&params).unwrap();
        assert_eq!(event.pubkey, "aabb");
        assert_eq!(event.kind, 1);
        assert_eq!(event.content, "test");
        assert_eq!(event.tags, vec![vec!["p".to_string(), "cc".to_string()]]);
    }

    #[test]
    fn test_build_error_response() {
        let json = build_error_response("req-1", -1, "user denied").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "req-1");
        assert_eq!(parsed["error"]["code"], -1);
        assert_eq!(parsed["error"]["message"], "user denied");
        assert!(parsed.get("result").is_none());
    }

    #[test]
    fn test_build_pubkey_response() {
        let json = build_pubkey_response("req-1", "aabbccdd").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "req-1");
        assert_eq!(parsed["result"], "aabbccdd");
        assert!(parsed.get("error").is_none());
    }

    /// NIP-01 event ID test vector.
    /// Uses the example from the Nostr protocol: the commitment array must
    /// serialise identically to produce the correct SHA-256 hash.
    #[test]
    fn test_event_id_canonical_serialisation() {
        // Commitment: [0,"pubkey",created_at,kind,tags,"content"]
        let event = UnsignedEvent {
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            created_at: 1234567890,
            kind: 1,
            tags: vec![vec!["e".into(), "abc".into()]],
            content: "Hello".into(),
        };

        // Manually compute expected: sha256([0,"79be...",1234567890,1,[["e","abc"]],"Hello"])
        let commitment_json = r#"[0,"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",1234567890,1,[["e","abc"]],"Hello"]"#;
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, commitment_json.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();

        let computed = compute_event_id(&event);
        assert_eq!(
            hex_encode(&computed),
            hex_encode(&expected),
            "event ID must match canonical NIP-01 serialisation"
        );
    }
}
```

- [ ] **Step 3: Export nip46 module from `common/src/lib.rs`**

Update `common/src/lib.rs`:

```rust
pub mod derive;
pub mod encoding;
pub mod frame;
pub mod hex;
pub mod types;

#[cfg(feature = "nip46")]
pub mod nip46;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ./common && cargo test --features nip46`

Expected: all tests pass including the new nip46 tests.

Also run without the feature to ensure nothing breaks:

Run: `cd ./common && cargo test`

Expected: original tests pass, nip46 module not compiled.

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/nip46.rs common/src/lib.rs common/Cargo.toml
git commit -m "feat: add NIP-46 types and event ID computation to common crate"
```

---

## Task 3: Update Provision CLI to New Frame Format

**Files:**
- Modify: `provision/Cargo.toml`
- Modify: `provision/src/main.rs`

The provision CLI switches from the old fixed-format frame (`[magic][secret][crc]`) to the new frame protocol (`[magic][type][length][secret][crc]`). Uses `common::frame::build_frame`.

- [ ] **Step 1: Update `provision/Cargo.toml` to depend on common with nip46 feature**

Replace the `heartwood-common` dependency line:

```toml
heartwood-common = { path = "../common", features = ["nip46"] }
```

(The `nip46` feature isn't strictly needed for provisioning, but it enables `frame` which needs `crc32fast`. Actually `frame` doesn't need the nip46 feature — it just needs crc32fast which is now a base dependency. So this can stay as-is. But we do want the frame module. Since `frame` is always exported, no feature needed.)

Keep it as:
```toml
heartwood-common = { path = "../common" }
```

- [ ] **Step 2: Update `build_frame` function in `provision/src/main.rs`**

Replace the existing `build_frame` function (lines 57-65) and update the import:

Old:
```rust
use heartwood_common::types::{MAGIC_BYTES, MNEMONIC_PATH, ACK, NACK, PROVISION_FRAME_LEN};
```

New:
```rust
use heartwood_common::types::{MNEMONIC_PATH, FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION};
use heartwood_common::frame;
```

Replace `build_frame`:
```rust
/// Build the provisioning frame using the new frame protocol.
fn build_provision_frame(secret: &[u8; 32]) -> Vec<u8> {
    frame::build_frame(FRAME_TYPE_PROVISION, secret)
        .expect("provision frame should never exceed max payload")
}
```

- [ ] **Step 3: Update `main()` to use new frame builder and ACK/NACK constants**

In `main()`, replace:
```rust
let frame = build_frame(&root_secret);
```
with:
```rust
let frame = build_provision_frame(&root_secret);
```

Replace ACK/NACK matching (lines 135-143). Change:
```rust
ACK => {
```
to:
```rust
FRAME_TYPE_ACK => {
```

And:
```rust
NACK => {
```
to:
```rust
FRAME_TYPE_NACK => {
```

- [ ] **Step 4: Update tests**

Update `test_build_frame` to use the new function:

```rust
#[test]
fn test_build_provision_frame() {
    let secret = [0xaa; 32];
    let frame_bytes = build_provision_frame(&secret);

    // New format: 2 magic + 1 type + 2 length + 32 payload + 4 CRC = 41
    assert_eq!(frame_bytes.len(), 41);

    // Parse with common frame parser to verify correctness
    let parsed = frame::parse_frame(&frame_bytes).unwrap();
    assert_eq!(parsed.frame_type, FRAME_TYPE_PROVISION);
    assert_eq!(parsed.payload, secret);
}
```

- [ ] **Step 5: Run tests**

Run: `cd ./provision && cargo test`

Expected: all tests pass. The mnemonic derivation and passphrase tests are unchanged.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add provision/src/main.rs provision/Cargo.toml
git commit -m "feat: update provision CLI to new frame protocol"
```

---

## Task 4: Button Handler

**Files:**
- Create: `firmware/src/button.rs`

GPIO 0 (PRG) interrupt handler with press-duration measurement. Uses `std::sync::mpsc` to send button events to the signing flow. No automated tests — requires hardware.

- [ ] **Step 1: Create `firmware/src/button.rs`**

```rust
// firmware/src/button.rs
//
// PRG button (GPIO 0) handler with press-duration measurement.
// Long hold (>=2s) = approve, short press (<2s) = deny.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use esp_idf_hal::gpio::{AnyInputPin, Input, PinDriver, Pull};

/// Button decision after a press/hold cycle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ButtonResult {
    /// Long hold >= 2 seconds — approve.
    Approve,
    /// Short press < 2 seconds — deny.
    Deny,
}

const LONG_HOLD_THRESHOLD: Duration = Duration::from_millis(2000);
const DEBOUNCE: Duration = Duration::from_millis(50);

/// Poll GPIO 0 for a button event. Blocks until a complete press/release cycle
/// occurs or the timeout expires. Returns `None` on timeout.
///
/// This uses polling rather than interrupts for simplicity — the signing flow
/// is already blocking and the poll interval is short enough for responsive UX.
pub fn wait_for_press(
    pin: &PinDriver<'_, AnyInputPin, Input>,
    timeout: Duration,
) -> Option<ButtonResult> {
    let deadline = Instant::now() + timeout;

    // Wait for button press (GPIO 0 is active low — pressed = low)
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        if pin.is_low() {
            break;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }

    // Debounce
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);

    // Button is pressed — measure how long it's held
    let press_start = Instant::now();
    let mut held_long = false;

    loop {
        if Instant::now() >= deadline {
            // Timeout while button is held — treat current duration as the decision
            break;
        }

        let held = Instant::now() - press_start;
        if held >= LONG_HOLD_THRESHOLD && !held_long {
            held_long = true;
            // Could signal OLED feedback here via a callback in the future
        }

        if pin.is_high() {
            // Button released — debounce
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
            break;
        }

        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }

    let held = Instant::now() - press_start;
    if held >= LONG_HOLD_THRESHOLD {
        Some(ButtonResult::Approve)
    } else {
        Some(ButtonResult::Deny)
    }
}
```

- [ ] **Step 2: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/button.rs
git commit -m "feat: add PRG button handler with press-duration measurement"
```

---

## Task 5: OLED Signing Display Functions

**Files:**
- Modify: `firmware/src/oled.rs`

Add display functions for the signing flow: sign request screen (purpose, kind, content preview, countdown) and result screens (signed, denied, timeout).

- [ ] **Step 1: Add signing display functions to `firmware/src/oled.rs`**

Add after the existing `show_error` function (line 121):

```rust
/// Display a signing request on the OLED.
///
/// Layout:
/// ```text
/// Sign as persona/social?
/// Kind 1
/// "Hello world this is
///  a test post that..."
/// [====------] 18s
/// ```
pub fn show_sign_request(
    display: &mut Display<'_>,
    purpose: &str,
    kind: u64,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Line 1: identity
    let identity_line = if purpose.is_empty() || purpose == "master" {
        "Sign as master?".to_string()
    } else {
        let mut s = format!("Sign as {purpose}?");
        s.truncate(CHARS_PER_LINE);
        s
    };
    Text::new(&identity_line, Point::new(0, 8), text_style)
        .draw(display)
        .ok();

    // Line 2: kind
    let kind_line = format!("Kind {kind}");
    Text::new(&kind_line, Point::new(0, 18), text_style)
        .draw(display)
        .ok();

    // Lines 3-4: content preview (two lines, ~25 chars each)
    let preview = if content_preview.len() > 50 {
        &content_preview[..50]
    } else {
        content_preview
    };
    if !preview.is_empty() {
        let line3_end = core::cmp::min(CHARS_PER_LINE, preview.len());
        Text::new(&format!("\"{}",  &preview[..line3_end]), Point::new(0, 28), text_style)
            .draw(display)
            .ok();
        if preview.len() > CHARS_PER_LINE {
            let line4_end = core::cmp::min(CHARS_PER_LINE, preview.len() - CHARS_PER_LINE);
            let suffix = if content_preview.len() > 50 { "...\"" } else { "\"" };
            Text::new(
                &format!(" {}{suffix}", &preview[CHARS_PER_LINE..CHARS_PER_LINE + line4_end]),
                Point::new(0, 38),
                text_style,
            )
            .draw(display)
            .ok();
        } else {
            let suffix = if content_preview.len() > 50 { "...\"" } else { "\"" };
            // Append closing quote to line 3 if short enough
            Text::new(suffix, Point::new((line3_end as i32 + 1) * 5, 28), text_style)
                .draw(display)
                .ok();
        }
    }

    // Line 5: countdown bar
    show_countdown_bar(display, seconds_remaining, 30, text_style);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Draw the countdown bar at the bottom of the display.
fn show_countdown_bar(
    display: &mut Display<'_>,
    remaining: u32,
    total: u32,
    text_style: embedded_graphics::mono_font::MonoTextStyle<'_, BinaryColor>,
) {
    use embedded_graphics::text::Text;

    let bar_width = 16; // chars for the bar
    let filled = if total > 0 {
        ((remaining as usize) * bar_width) / (total as usize)
    } else {
        0
    };
    let empty = bar_width - filled;
    let bar = format!(
        "[{}{}] {}s",
        "=".repeat(filled),
        "-".repeat(empty),
        remaining
    );
    Text::new(&bar, Point::new(0, 56), text_style)
        .draw(display)
        .ok();
}

/// Display a signing result message for 2 seconds.
pub fn show_result(display: &mut Display<'_>, message: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new(message, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}
```

- [ ] **Step 2: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/oled.rs
git commit -m "feat: add OLED signing request and result display functions"
```

---

## Task 6: Serial Frame Reader

**Files:**
- Create: `firmware/src/protocol.rs`
- Modify: `firmware/Cargo.toml`

Reads frames byte-by-byte from USB-Serial-JTAG. Hunts for magic bytes, reads header, reads payload, validates CRC using `common::frame::parse_frame`.

- [ ] **Step 1: Add serde and serde_json to `firmware/Cargo.toml`**

Add to `[dependencies]`:

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

Update heartwood-common to enable nip46 feature:

```toml
heartwood-common = { path = "../common", features = ["nip46"] }
```

- [ ] **Step 2: Create `firmware/src/protocol.rs`**

```rust
// firmware/src/protocol.rs
//
// Serial frame reader. Reads bytes from USB-Serial-JTAG, assembles frames,
// validates using common::frame.

use esp_idf_hal::delay;
use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::frame::{self, Frame, FrameError};
use heartwood_common::types::*;

/// Read a single byte from USB serial, blocking.
fn read_byte(usb: &mut UsbSerialDriver<'_>) -> u8 {
    let mut buf = [0u8; 1];
    loop {
        match usb.read(&mut buf, delay::BLOCK) {
            Ok(1) => return buf[0],
            _ => {}
        }
    }
}

/// Read exactly `n` bytes from USB serial into `buf`, blocking.
fn read_exact(usb: &mut UsbSerialDriver<'_>, buf: &mut [u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        match usb.read(&mut buf[pos..], delay::BLOCK) {
            Ok(n) if n > 0 => pos += n,
            _ => {}
        }
    }
}

/// Wait for and read the next valid frame from USB serial.
///
/// Hunts for magic bytes, reads the header (type + length), reads the payload
/// and CRC, then validates the full frame. Returns the parsed frame on success
/// or an error.
///
/// On CRC or parse errors, logs a warning and continues hunting for the next
/// magic sequence. This handles ESP-IDF log output mixed into the serial stream.
pub fn read_frame(usb: &mut UsbSerialDriver<'_>) -> Frame {
    loop {
        // Hunt for first magic byte
        let b = read_byte(usb);
        if b != MAGIC_BYTES[0] {
            continue;
        }

        // Check second magic byte
        let b = read_byte(usb);
        if b != MAGIC_BYTES[1] {
            continue;
        }

        // Read type + length (3 bytes)
        let mut header = [0u8; 3];
        read_exact(usb, &mut header);
        let frame_type = header[0];
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;

        if length > MAX_PAYLOAD_SIZE {
            log::warn!("Frame too large: {length} bytes");
            continue;
        }

        // Read payload + CRC (length + 4 bytes)
        let mut body = vec![0u8; length + 4];
        read_exact(usb, &mut body);

        // Assemble full frame for validation
        let mut full_frame = Vec::with_capacity(FRAME_OVERHEAD + length);
        full_frame.extend_from_slice(&MAGIC_BYTES);
        full_frame.push(frame_type);
        full_frame.extend_from_slice(&header[1..3]); // length bytes
        full_frame.extend_from_slice(&body);

        match frame::parse_frame(&full_frame) {
            Ok(frame) => return frame,
            Err(e) => {
                log::warn!("Frame parse error: {:?}", e);
                continue;
            }
        }
    }
}

/// Write a frame to USB serial.
pub fn write_frame(
    usb: &mut UsbSerialDriver<'_>,
    frame_type: u8,
    payload: &[u8],
) {
    match frame::build_frame(frame_type, payload) {
        Ok(frame_bytes) => {
            let _ = usb.write(&frame_bytes, delay::BLOCK);
        }
        Err(e) => {
            log::error!("Failed to build frame: {:?}", e);
        }
    }
}
```

- [ ] **Step 3: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/protocol.rs firmware/Cargo.toml
git commit -m "feat: add serial frame reader and writer for firmware"
```

---

## Task 7: NIP-46 Handler and Signing Flow

**Files:**
- Create: `firmware/src/nip46_handler.rs`

Dispatches NIP-46 methods. `sign_event` → parse event, display on OLED, wait for button, derive child key, compute event ID, Schnorr sign, build response. `get_public_key` → immediate response. Uses the k256 alignment workaround (dedicated thread for signing).

- [ ] **Step 1: Create `firmware/src/nip46_handler.rs`**

```rust
// firmware/src/nip46_handler.rs
//
// NIP-46 JSON-RPC dispatch. Handles sign_event and get_public_key methods.

use std::time::Duration;

use esp_idf_hal::gpio::{AnyInputPin, Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;
use zeroize::Zeroize;

use heartwood_common::derive;
use heartwood_common::frame::Frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip46::{
    self, HeartwoodContext, Nip46Request, SignedEvent, UnsignedEvent,
};
use heartwood_common::types::*;

use crate::button::{self, ButtonResult};
use crate::oled::{self, Display};
use crate::protocol;
use crate::sign;

const SIGN_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle a NIP-46 request frame. Parses the JSON-RPC, dispatches by method,
/// and writes the response frame back over serial.
pub fn handle_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    master_secret: &[u8; 32],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, AnyInputPin, Input>,
) {
    let request = match nip46::parse_request(&frame.payload) {
        Ok(req) => req,
        Err(e) => {
            log::warn!("Bad NIP-46 request: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    match request.method.as_str() {
        "sign_event" => handle_sign_event(usb, &request, master_secret, display, button_pin),
        "get_public_key" => handle_get_public_key(usb, &request, master_secret),
        _ => {
            log::warn!("Unknown NIP-46 method: {}", request.method);
            let resp = nip46::build_error_response(&request.id, -2, "unknown method")
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
        }
    }
}

fn handle_sign_event(
    usb: &mut UsbSerialDriver<'_>,
    request: &Nip46Request,
    master_secret: &[u8; 32],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, AnyInputPin, Input>,
) {
    // Parse the unsigned event from params
    let event = match nip46::parse_unsigned_event(&request.params) {
        Ok(ev) => ev,
        Err(e) => {
            log::warn!("Bad unsigned event: {e}");
            let resp = nip46::build_error_response(&request.id, -3, &e)
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
            return;
        }
    };

    // Extract display info
    let (kind, content_preview) = nip46::event_display_summary(&event, 50);
    let purpose = request
        .heartwood
        .as_ref()
        .map(|hw| hw.purpose.as_str())
        .unwrap_or("master");

    // Show signing request on OLED
    oled::show_sign_request(display, purpose, kind, &content_preview, 30);

    // Wait for button decision
    let decision = button::wait_for_press(button_pin, SIGN_TIMEOUT);

    match decision {
        Some(ButtonResult::Approve) => {
            log::info!("User approved signing request");
            oled::show_result(display, "Signing...");

            match do_sign(&event, master_secret, request.heartwood.as_ref()) {
                Ok(signed_event) => {
                    let resp = nip46::build_sign_response(&request.id, &signed_event)
                        .unwrap_or_default();
                    protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
                    oled::show_result(display, "Signed!");
                }
                Err(e) => {
                    log::error!("Signing failed: {e}");
                    let resp = nip46::build_error_response(&request.id, -4, &e)
                        .unwrap_or_default();
                    protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
                    oled::show_result(display, "Sign failed");
                }
            }
        }
        Some(ButtonResult::Deny) => {
            log::info!("User denied signing request");
            let resp = nip46::build_error_response(&request.id, -1, "user denied")
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
            oled::show_result(display, "Denied");
        }
        None => {
            log::info!("Signing request timed out");
            let resp = nip46::build_error_response(&request.id, -1, "timeout")
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
            oled::show_result(display, "Timed out");
        }
    }
}

/// Perform the actual signing in a dedicated thread (k256 alignment workaround).
///
/// Derives the child key (or uses master), computes the NIP-01 event ID,
/// Schnorr signs it, and returns the signed event. All child key material
/// is zeroized after use.
fn do_sign(
    event: &UnsignedEvent,
    master_secret: &[u8; 32],
    heartwood: Option<&HeartwoodContext>,
) -> Result<SignedEvent, String> {
    let event_id_bytes = nip46::compute_event_id(event);
    let event_id_hex = hex_encode(&event_id_bytes);

    // Determine which key to sign with
    let (mut signing_secret, pubkey_hex) = match heartwood {
        Some(hw) => {
            // Derive child key in a dedicated thread (k256 alignment workaround)
            let secret_copy = *master_secret;
            let purpose = hw.purpose.clone();
            let index = hw.index;

            let result = std::thread::Builder::new()
                .name("derive".into())
                .stack_size(32768)
                .spawn(move || {
                    #[repr(align(16))]
                    struct Aligned([u8; 32]);
                    let aligned = Aligned(secret_copy);
                    let root = derive::create_tree_root(&aligned.0)?;
                    let identity = derive::derive(&root, &purpose, index)?;
                    Ok::<([u8; 32], String), &'static str>(
                        (*identity.private_key, hex_encode(&identity.public_key)),
                    )
                })
                .map_err(|e| format!("thread spawn failed: {e}"))?
                .join()
                .map_err(|_| "derivation thread panicked".to_string())?
                .map_err(|e| e.to_string())?;

            result
        }
        None => {
            // Sign with master key — derive pubkey in a thread
            let secret_copy = *master_secret;
            let pubkey = std::thread::Builder::new()
                .name("derive".into())
                .stack_size(32768)
                .spawn(move || {
                    #[repr(align(16))]
                    struct Aligned([u8; 32]);
                    let aligned = Aligned(secret_copy);
                    let root = derive::create_tree_root(&aligned.0)?;
                    Ok::<String, &'static str>(root.master_npub)
                })
                .map_err(|e| format!("thread spawn failed: {e}"))?
                .join()
                .map_err(|_| "derivation thread panicked".to_string())?
                .map_err(|e| e.to_string())?;

            // For master key signing, we need the raw pubkey hex, not npub
            let secret_copy2 = *master_secret;
            let pubkey_hex = std::thread::Builder::new()
                .name("pubkey".into())
                .stack_size(32768)
                .spawn(move || {
                    #[repr(align(16))]
                    struct Aligned([u8; 32]);
                    let aligned = Aligned(secret_copy2);
                    let root = derive::create_tree_root(&aligned.0)
                        .map_err(|e| e.to_string())?;
                    let vk = k256::schnorr::SigningKey::from_bytes(&aligned.0)
                        .map_err(|_| "invalid key".to_string())?;
                    let pubkey_bytes: [u8; 32] = vk.verifying_key().to_bytes().into();
                    Ok::<String, String>(hex_encode(&pubkey_bytes))
                })
                .map_err(|e| format!("thread spawn failed: {e}"))?
                .join()
                .map_err(|_| "pubkey thread panicked".to_string())?
                .map_err(|e| e.to_string())?;

            (*master_secret, pubkey_hex)
        }
    };

    // Sign the event ID in a dedicated thread
    let event_id_copy = event_id_bytes;
    let secret_for_sign = signing_secret;
    let sig_result = std::thread::Builder::new()
        .name("sign".into())
        .stack_size(32768)
        .spawn(move || sign::sign_hash(&secret_for_sign, &event_id_copy))
        .map_err(|e| format!("thread spawn failed: {e}"))?
        .join()
        .map_err(|_| "sign thread panicked".to_string())?
        .map_err(|e| e.to_string())?;

    // Zeroize the signing secret
    signing_secret.zeroize();

    let sig_hex = hex_encode(&sig_result);

    Ok(SignedEvent {
        id: event_id_hex,
        pubkey: pubkey_hex,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
        sig: sig_hex,
    })
}

fn handle_get_public_key(
    usb: &mut UsbSerialDriver<'_>,
    request: &Nip46Request,
    master_secret: &[u8; 32],
) {
    let result = match request.heartwood.as_ref() {
        Some(hw) => {
            let secret_copy = *master_secret;
            let purpose = hw.purpose.clone();
            let index = hw.index;

            std::thread::Builder::new()
                .name("derive".into())
                .stack_size(32768)
                .spawn(move || {
                    #[repr(align(16))]
                    struct Aligned([u8; 32]);
                    let aligned = Aligned(secret_copy);
                    let root = derive::create_tree_root(&aligned.0)?;
                    let identity = derive::derive(&root, &purpose, index)?;
                    Ok::<String, &'static str>(hex_encode(&identity.public_key))
                })
                .ok()
                .and_then(|h| h.join().ok())
                .and_then(|r| r.ok())
        }
        None => {
            let secret_copy = *master_secret;

            std::thread::Builder::new()
                .name("pubkey".into())
                .stack_size(32768)
                .spawn(move || {
                    #[repr(align(16))]
                    struct Aligned([u8; 32]);
                    let aligned = Aligned(secret_copy);
                    let sk = k256::schnorr::SigningKey::from_bytes(&aligned.0).ok()?;
                    let pubkey_bytes: [u8; 32] = sk.verifying_key().to_bytes().into();
                    Some(hex_encode(&pubkey_bytes))
                })
                .ok()
                .and_then(|h| h.join().ok())
                .flatten()
        }
    };

    match result {
        Some(pubkey_hex) => {
            let resp = nip46::build_pubkey_response(&request.id, &pubkey_hex)
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
        }
        None => {
            let resp = nip46::build_error_response(&request.id, -4, "key derivation failed")
                .unwrap_or_default();
            protocol::write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, resp.as_bytes());
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/nip46_handler.rs
git commit -m "feat: add NIP-46 handler with sign_event and get_public_key"
```

---

## Task 8: Refactor Main Loop and Provision Handler

**Files:**
- Modify: `firmware/src/main.rs`
- Modify: `firmware/src/provision.rs`

The boot flow becomes: init peripherals → NVS check → if no secret, enter provisioning → display npub → enter frame dispatch loop. The dispatch loop reads frames and routes by type.

- [ ] **Step 1: Simplify `firmware/src/provision.rs`**

Replace the entire file. Frame reading is now handled by `protocol.rs`. This module just handles the 32-byte provision payload.

```rust
// firmware/src/provision.rs
//
// Provisioning handler. Receives a 32-byte root secret from a provision frame
// and stores it in NVS.

use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::frame::Frame;
use heartwood_common::types::*;

use crate::nvs;
use crate::oled::{self, Display};
use crate::protocol;

/// Handle a provision frame (type 0x01). Extracts the 32-byte secret,
/// stores it in NVS, and sends ACK or NACK.
pub fn handle_provision(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
    display: &mut Display<'_>,
) -> Option<[u8; 32]> {
    if frame.payload.len() != 32 {
        log::warn!("Provision frame payload is {} bytes, expected 32", frame.payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return None;
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&frame.payload);

    match nvs::write_root_secret(nvs, &secret) {
        Ok(()) => {
            log::info!("Provisioned — identity stored in NVS");
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            Some(secret)
        }
        Err(e) => {
            log::error!("NVS write failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            oled::show_error(display, "NVS write failed");
            None
        }
    }
}
```

- [ ] **Step 2: Rewrite `firmware/src/main.rs`**

Replace the entire file:

```rust
// firmware/src/main.rs
//
// Heartwood ESP32 — Phase 3 boot flow.
//
// 1. Init peripherals (LED, Vext, OLED, NVS, USB serial, button).
// 2. Check NVS for stored root secret.
//    - If found: derive and display master npub.
//    - If not found: show "Awaiting secret..." and wait for provision frame.
// 3. Enter frame dispatch loop: read frames, route by type.

mod button;
mod nip46_handler;
mod nvs;
mod oled;
mod protocol;
mod provision;
mod sign;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::units::FromValueType;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use zeroize::Zeroize;
use heartwood_common::derive;
use heartwood_common::types::*;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 3 (signing oracle)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // --- LED ---
    let mut led = PinDriver::output(peripherals.pins.gpio35).expect("LED pin");
    led.set_high().ok();

    // --- Vext (OLED power, active low) ---
    let mut vext = PinDriver::output(peripherals.pins.gpio36).expect("Vext pin");
    vext.set_low().ok();
    esp_idf_hal::delay::FreeRtos::delay_ms(50);

    // --- OLED ---
    log::info!("Initialising OLED...");
    let i2c_config = I2cConfig::new().baudrate(400.kHz().into());
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17,
        peripherals.pins.gpio18,
        &i2c_config,
    )
    .expect("I2C init failed");
    let mut display = oled::init(i2c, peripherals.pins.gpio21.into());
    log::info!("OLED init complete");

    // --- Button (GPIO 0, PRG) ---
    let button_pin = PinDriver::input(peripherals.pins.gpio0.into()).expect("button pin");

    // --- USB serial ---
    let mut usb = UsbSerialDriver::new(
        peripherals.usb_serial,
        peripherals.pins.gpio19,
        peripherals.pins.gpio20,
        &UsbSerialConfig::new().rx_buffer_size(512),
    )
    .expect("USB serial driver init failed");

    // --- NVS ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let (mut nvs, stored_secret) = nvs::read_root_secret(nvs_partition)
        .expect("NVS read failed");

    // --- Get or provision the root secret ---
    let mut root_secret = match stored_secret {
        Some(secret) => {
            log::info!("Booted with stored identity");
            secret
        }
        None => {
            log::info!("No stored secret — entering provisioning mode");
            oled::show_awaiting(&mut display);

            // Wait for a provision frame
            loop {
                let frame = protocol::read_frame(&mut usb);
                if frame.frame_type == FRAME_TYPE_PROVISION {
                    if let Some(secret) = provision::handle_provision(
                        &mut usb, &frame, &mut nvs, &mut display,
                    ) {
                        break secret;
                    }
                } else {
                    log::warn!("Expected provision frame, got type 0x{:02x}", frame.frame_type);
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                }
            }
        }
    };

    // --- Display master npub ---
    // k256 alignment workaround: derive in a dedicated thread.
    let secret_copy = root_secret;
    let npub_result = std::thread::Builder::new()
        .name("derive".into())
        .stack_size(32768)
        .spawn(move || {
            #[repr(align(16))]
            struct Aligned([u8; 32]);
            let aligned = Aligned(secret_copy);
            derive::create_tree_root(&aligned.0)
        })
        .expect("thread spawn failed")
        .join()
        .expect("derivation panicked");

    match &npub_result {
        Ok(tree_root) => {
            log::info!("Identity: {}", tree_root.master_npub);
            oled::show_npub(&mut display, &tree_root.master_npub);
        }
        Err(e) => {
            log::error!("Key derivation failed: {e}");
            oled::show_error(&mut display, "Derivation failed");
        }
    }

    // --- Frame dispatch loop ---
    log::info!("Entering frame dispatch loop");
    loop {
        let frame = protocol::read_frame(&mut usb);

        match frame.frame_type {
            FRAME_TYPE_NIP46_REQUEST => {
                nip46_handler::handle_request(
                    &mut usb,
                    &frame,
                    &root_secret,
                    &mut display,
                    &button_pin,
                );
                // Return to idle display
                if let Ok(ref tree_root) = npub_result {
                    oled::show_npub(&mut display, &tree_root.master_npub);
                }
            }
            FRAME_TYPE_PROVISION => {
                log::warn!("Already provisioned — ignoring provision frame");
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}
```

- [ ] **Step 3: Verify common tests still pass**

Run: `cd ./common && cargo test --features nip46`

Expected: all tests pass.

- [ ] **Step 4: Verify provision tests still pass**

Run: `cd ./provision && cargo test`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/main.rs firmware/src/provision.rs
git commit -m "feat: refactor boot flow with frame dispatch loop and NIP-46 handling"
```

---

## Task 9: Test Harness CLI

**Files:**
- Create: `sign-test/Cargo.toml`
- Create: `sign-test/src/main.rs`
- Create: `sign-test/.cargo/config.toml`
- Create: `sign-test/rust-toolchain.toml`

A host CLI that constructs NIP-46 sign_event requests, frames them, sends over serial, and displays the response. Used to validate the full end-to-end flow.

- [ ] **Step 1: Create `sign-test/Cargo.toml`**

```toml
[package]
name = "heartwood-sign-test"
version = "0.1.0"
edition = "2021"
description = "Test harness for heartwood-esp32 signing oracle"

[dependencies]
heartwood-common = { path = "../common", features = ["nip46"] }
serialport = "4"
crc32fast = "1"
clap = { version = "4", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Create `sign-test/.cargo/config.toml`**

```toml
[build]
target = "x86_64-apple-darwin"
```

- [ ] **Step 3: Create `sign-test/rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
```

- [ ] **Step 4: Create `sign-test/src/main.rs`**

```rust
// sign-test/src/main.rs
//
// Test harness CLI for the heartwood-esp32 signing oracle.
// Sends NIP-46 sign_event requests over serial and prints the response.

use std::io::Read;
use std::time::Duration;

use clap::Parser;
use heartwood_common::frame;
use heartwood_common::types::*;

#[derive(Parser)]
#[command(name = "heartwood-sign-test")]
#[command(about = "Send a test signing request to heartwood-esp32")]
struct Cli {
    /// Serial port (e.g. /dev/cu.usbserial-*)
    #[arg(short, long)]
    port: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    /// NIP-46 method (default: sign_event)
    #[arg(short, long, default_value = "sign_event")]
    method: String,

    /// Purpose for identity derivation (default: master)
    #[arg(long)]
    purpose: Option<String>,

    /// Derivation index (default: 0)
    #[arg(long, default_value_t = 0)]
    index: u32,

    /// Event kind (default: 1)
    #[arg(short, long, default_value_t = 1)]
    kind: u64,

    /// Event content (default: "Hello from sign-test")
    #[arg(short, long, default_value = "Hello from sign-test")]
    content: String,
}

fn main() {
    let cli = Cli::parse();

    // Build the NIP-46 JSON-RPC request
    let request_json = match cli.method.as_str() {
        "sign_event" => {
            let event = serde_json::json!({
                "pubkey": "0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                "kind": cli.kind,
                "tags": [],
                "content": cli.content,
            });
            let event_str = serde_json::to_string(&event).unwrap();

            let mut req = serde_json::json!({
                "id": "test-1",
                "method": "sign_event",
                "params": [event_str],
            });

            if let Some(ref purpose) = cli.purpose {
                req["heartwood"] = serde_json::json!({
                    "purpose": purpose,
                    "index": cli.index,
                });
            }

            serde_json::to_string(&req).unwrap()
        }
        "get_public_key" => {
            let mut req = serde_json::json!({
                "id": "test-1",
                "method": "get_public_key",
                "params": [],
            });

            if let Some(ref purpose) = cli.purpose {
                req["heartwood"] = serde_json::json!({
                    "purpose": purpose,
                    "index": cli.index,
                });
            }

            serde_json::to_string(&req).unwrap()
        }
        _ => {
            eprintln!("Unknown method: {}", cli.method);
            std::process::exit(1);
        }
    };

    println!("Request: {request_json}");

    // Build frame
    let frame_bytes = frame::build_frame(FRAME_TYPE_NIP46_REQUEST, request_json.as_bytes())
        .expect("frame build failed");

    println!("Frame: {} bytes", frame_bytes.len());

    // Open serial port
    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_secs(60))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(2));

    // Send frame
    println!("Sending sign request... (press button on device to approve/deny)");
    std::io::Write::write_all(&mut port, &frame_bytes).expect("write failed");
    std::io::Write::flush(&mut port).expect("flush failed");

    // Read response — hunt for magic bytes
    println!("Waiting for response (60s timeout)...");
    let mut buf = vec![0u8; 4096 + FRAME_OVERHEAD];
    let mut pos = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);

    loop {
        if std::time::Instant::now() > deadline {
            eprintln!("Timeout waiting for response.");
            std::process::exit(1);
        }

        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                buf[pos] = byte[0];
                pos += 1;

                // Try parsing once we have enough bytes
                if pos >= FRAME_OVERHEAD {
                    match frame::parse_frame(&buf[..pos]) {
                        Ok(response_frame) => {
                            println!("\nResponse frame type: 0x{:02x}", response_frame.frame_type);
                            match response_frame.frame_type {
                                FRAME_TYPE_NIP46_RESPONSE => {
                                    let json = String::from_utf8_lossy(&response_frame.payload);
                                    println!("Response: {json}");

                                    // Pretty-print if valid JSON
                                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                                        println!("\nParsed:");
                                        println!("{}", serde_json::to_string_pretty(&parsed).unwrap());
                                    }
                                }
                                FRAME_TYPE_ACK => println!("ACK"),
                                FRAME_TYPE_NACK => println!("NACK"),
                                _ => println!("Unknown type"),
                            }
                            break;
                        }
                        Err(heartwood_common::frame::FrameError::TooShort) => {
                            // Need more bytes
                            continue;
                        }
                        Err(_) => {
                            // Reset — bad frame start, shift buffer
                            // Look for magic bytes in what we have
                            if let Some(magic_pos) = buf[1..pos].windows(2)
                                .position(|w| w == &MAGIC_BYTES)
                            {
                                let new_start = magic_pos + 1;
                                buf.copy_within(new_start..pos, 0);
                                pos -= new_start;
                            } else {
                                pos = 0;
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("Read error: {e}");
                std::process::exit(1);
            }
        }
    }
}
```

- [ ] **Step 5: Build the test harness**

Run: `cd ./sign-test && cargo build`

Expected: builds successfully.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add sign-test/
git commit -m "feat: add sign-test CLI harness for end-to-end signing validation"
```

---

## Task 10: Update CLAUDE.md and README

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

Update project documentation to reflect Phase 3 state.

- [ ] **Step 1: Update CLAUDE.md current state section**

Replace the "Current state" section:

```markdown
## Current state

Phase 3 (signing oracle) implemented. The ESP32 is a NIP-46 bunker — it receives
signing requests over serial, shows what's being signed on the OLED, and requires
physical button approval (long hold to approve, short press to deny). k256
alignment workaround still in place (dedicated thread for all k256 operations).

Next: flash firmware, test end-to-end with sign-test CLI, then integrate with
heartwood-device on the Pi.
```

- [ ] **Step 2: Update README.md roadmap checkboxes**

Check off Phase 3 items and update the Structure section to include the new files.

- [ ] **Step 3: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add CLAUDE.md README.md
git commit -m "docs: update for Phase 3 signing oracle"
```

---

## Verification Checklist

After all tasks are complete:

- [ ] `cd common && cargo test` — all tests pass
- [ ] `cd common && cargo test --features nip46` — all tests pass including NIP-46
- [ ] `cd provision && cargo test` — all tests pass with new frame format
- [ ] `cd sign-test && cargo build` — test harness builds
- [ ] `cd firmware && cargo build` — firmware builds (requires ESP toolchain)
- [ ] Flash firmware, provision with `provision` CLI, verify npub displays on OLED
- [ ] Send sign request with `sign-test` CLI, verify OLED shows request
- [ ] Long-hold PRG button, verify signature returned
- [ ] Short-press PRG button, verify "Denied" response
- [ ] Let timeout expire, verify "Timed out" response
- [ ] Send `get_public_key` request, verify pubkey returned immediately
