# Phase 3: USB Signing Oracle — Design Spec

**Date:** 2026-04-03
**Status:** Approved
**Depends on:** Phase 2 (provisioning) complete, k256 alignment workaround verified

## Overview

The ESP32 is a self-contained Nostr signing device — it holds the identity,
understands NIP-46, and makes all signing decisions. The Pi (or phone, or test
harness) is a dumb transport bridge that forwards NIP-46 messages between Nostr
relays and the ESP32 over serial. The ESP32 shows what's being signed on the
OLED, and the user physically approves or denies with the PRG button.

Private keys never leave the chip. The Pi is optional infrastructure.

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              ESP32 (brain)              │
Relay ←→ Pi (bridge) ←→ USB serial ←→ NIP-46 handler             │
                        │              ├── derive child key       │
                        │              ├── parse sign_event       │
                        │              ├── OLED (show request)    │
                        │              ├── PRG button (approve)   │
                        │              └── BIP-340 sign           │
                        └─────────────────────────────────────────┘

Relay ←→ Phone (bridge) ←→ BLE ←→ ESP32 (same)    [Phase 5]
         Test harness    ←→ TCP ←→ ESP32 (same)    [dev]
```

The ESP32 speaks NIP-46 JSON-RPC natively. The transport (USB serial, BLE, TCP)
is irrelevant to the signing logic — it just delivers and collects JSON.

### What the Pi does

The Pi runs a thin transport bridge:

1. Connects to Nostr relays via WebSocket.
2. Subscribes to NIP-46 request events addressed to the ESP32's pubkey.
3. Receives encrypted NIP-46 events from relays.
4. Strips NIP-44 encryption (Phase 3 — the ESP32 takes over NIP-44 later).
5. Forwards the plaintext NIP-46 JSON-RPC over serial in a thin frame.
6. Reads the ESP32's JSON-RPC response from serial.
7. NIP-44 encrypts the response and publishes to relays.

In Phase 3, the Pi handles NIP-44 encryption/decryption. In a future phase,
the ESP32 handles NIP-44 itself and the Pi becomes a truly dumb relay pipe.

### What the ESP32 does

The ESP32 is the NIP-46 bunker:

1. Receives plaintext NIP-46 JSON-RPC requests over serial.
2. Parses the method and params.
3. For `sign_event`: extracts the event, displays kind/content on OLED,
   waits for button approval, derives the child key, signs, responds.
4. For `get_public_key`: returns the derived pubkey immediately (no approval).
5. Sends JSON-RPC responses back over serial.

## Serial Framing

All communication uses a simple length-prefixed frame. The NIP-46 JSON-RPC
inside is the protocol — the frame is just transport.

```
[0x48 0x57][type_u8][length_u16_be][payload...][crc32_4]
```

- Magic bytes: `0x48 0x57` ("HW") — unchanged from Phase 2.
- `type_u8`: frame type.
- `length_u16_be`: byte count of `payload` only.
- `crc32`: covers `type` + `length` + `payload`.
- Maximum payload: **4096 bytes**.

### Frame types

| Type   | Name             | Direction    | Payload                              |
|--------|------------------|--------------|--------------------------------------|
| `0x01` | Provision        | Host → ESP32 | 32-byte root secret                  |
| `0x02` | NIP-46 request   | Host → ESP32 | NIP-46 JSON-RPC (plaintext)          |
| `0x03` | NIP-46 response  | ESP32 → Host | NIP-46 JSON-RPC (plaintext)          |
| `0x06` | ACK              | ESP32 → Host | (empty)                              |
| `0x15` | NACK             | ESP32 → Host | (empty — bad frame, parse error)     |

Provisioning (`0x01`) is a bootstrap operation before the device has an
identity. Once provisioned, the device only accepts `0x02` frames.

## NIP-46 Methods

### Phase 3 (implement now)

**`sign_event`** — the core method.

Request:
```json
{
  "id": "<request_id>",
  "method": "sign_event",
  "params": ["<unsigned_event_json>"]
}
```

The `params[0]` value is a JSON-serialised unsigned Nostr event:
```json
{
  "pubkey": "<hex>",
  "created_at": <unix_timestamp>,
  "kind": <integer>,
  "tags": [["p", "<hex>"], ...],
  "content": "<string>"
}
```

The ESP32:
1. Parses the event JSON — extracts `kind` and `content` for OLED display.
2. Computes the NIP-01 event ID: `sha256(json_serialize([0, pubkey, created_at, kind, tags, content]))`.
3. Displays the signing request on OLED with countdown.
4. Waits for button interaction (long hold = approve, short press = deny, 30s timeout).
5. If approved: derives child key from purpose + index (see Identity Resolution
   below), Schnorr signs the event ID, zeroizes child key.
6. Returns complete signed event with `id`, `pubkey`, `sig`.

Response (approved):
```json
{
  "id": "<request_id>",
  "result": "<signed_event_json>"
}
```

Response (denied/timeout):
```json
{
  "id": "<request_id>",
  "error": { "code": -1, "message": "user denied" }
}
```

**`get_public_key`** — returns the pubkey for the current identity. No approval needed.

Request:
```json
{
  "id": "<request_id>",
  "method": "get_public_key",
  "params": []
}
```

Response:
```json
{
  "id": "<request_id>",
  "result": "<hex_pubkey>"
}
```

### Phase 3 extension: identity selection

Standard NIP-46 assumes one identity per bunker. Heartwood supports multiple
derived identities. We extend the protocol with an optional context parameter
that the Pi bridge injects based on which identity the NIP-46 client is
connected to:

```json
{
  "id": "<request_id>",
  "method": "sign_event",
  "params": ["<unsigned_event_json>"],
  "heartwood": { "purpose": "persona/social", "index": 0 }
}
```

If `heartwood` is absent, the ESP32 signs with the master key (root identity).
If present, it derives the child key for that purpose + index.

This is a Heartwood-specific extension, not a NIP-46 standard field. The Pi
bridge is responsible for mapping the NIP-46 client session to the correct
purpose/index and injecting this field.

### Future phases (not implemented now)

- `nip44_encrypt` / `nip44_decrypt` — requires NIP-44 on-device (Phase 4+).
- `nip04_encrypt` / `nip04_decrypt` — deprecated, may never implement.
- `heartwood_derive` / `heartwood_switch` / `heartwood_list_identities` — identity management methods from heartwood-device. Deferred until the ESP32 needs to manage identities itself rather than being told which to use.

## Signing Flow (detailed)

1. Host sends frame type `0x02` with NIP-46 JSON-RPC.
2. ESP32 validates frame (magic, CRC, length ≤ 4096).
3. ESP32 parses JSON-RPC — extracts `method`, `id`, `params`, optional `heartwood`.
4. If method is `get_public_key`: derive pubkey (if heartwood context) or return
   master pubkey. Send response immediately, no approval needed.
5. If method is `sign_event`:
   a. Parse `params[0]` as unsigned event JSON.
   b. Extract `kind` (integer) and `content` (string, first 80 chars) for OLED.
   c. Determine identity: if `heartwood.purpose` present, show purpose on OLED.
      Otherwise show "master".
   d. Display signing request on OLED with 30s countdown.
   e. Wait for button:
      - **Long hold PRG ≥ 2s** → approve.
      - **Short press PRG < 2s** → deny.
      - **30s timeout** → deny.
   f. If approved:
      - Derive child key (HMAC-SHA256) or use master key.
      - Serialise NIP-01 commitment array from the event fields.
      - SHA-256 hash → event ID.
      - BIP-340 Schnorr sign event ID.
      - Zeroize child key material.
      - Construct signed event (add `id`, `pubkey`, `sig` to event).
      - Send frame type `0x03` with JSON-RPC result.
   g. If denied/timeout:
      - Send frame type `0x03` with JSON-RPC error.
6. Return to idle (display npub, wait for next frame).

Request-response is strictly one-at-a-time. If a new request arrives while a
signing request is pending, the ESP32 sends NACK for the new request.

## NIP-01 Event ID Computation

The ESP32 must compute the event ID exactly as specified in NIP-01. It
serialises the commitment array from the parsed event fields:

```json
[0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"]
```

This means the ESP32 needs to:
1. Parse the unsigned event JSON to extract all fields.
2. Re-serialise the commitment array in canonical form.
3. SHA-256 hash the serialised bytes.

This is more work than hashing a pre-built commitment (as in the earlier
design), but it's the correct NIP-01 approach and ensures the ESP32 verifies
what it signs — the event it displays is provably the event it hashes.

The serialisation must be canonical: no whitespace, no trailing commas, keys in
the array positional order. `serde_json::to_string` produces this by default.
The ESP32's computed event ID must match what any NIP-01 client would compute
for the same event fields.

### JSON parsing on embedded

The ESP32 needs a minimal JSON parser capable of:
- Extracting string, integer, and array values by key from an object.
- Serialising the commitment array (deterministic, no whitespace).
- Handling escaped characters in strings.

This is NOT a general-purpose parser. It handles the specific shapes of NIP-46
JSON-RPC and unsigned Nostr events. A hand-written recursive descent parser
(~200–300 lines of Rust) is appropriate. No serde, no allocator-heavy crates.

Alternatively, `serde_json` with `no_std` + `alloc` works on ESP-IDF (which
provides a global allocator). This is simpler to implement and maintain. The
ESP32-S3 has 512KB SRAM — `serde_json` is not a memory concern.

**Recommendation:** use `serde_json` with `serde` derive macros. ESP-IDF is a
`std` environment with heap allocation. Hand-rolling a JSON parser for a device
with 512KB RAM is unnecessary heroism.

## Button Handling

GPIO 0 (PRG button) on the Heltec V4.

- Configured as input with internal pull-up (active low — pressed = LOW).
- Interrupt on both edges (press and release).
- Timer measures press duration:
  - **≥ 2000ms**: long hold → **approve** (sign).
  - **< 2000ms**: short press → **deny**.
- During boot (no pending request), button presses are ignored.
- While a signing request is pending, the first completed press/hold resolves
  the request. Subsequent presses are ignored until the next request.
- OLED feedback: at the 2s threshold, the OLED flashes or changes text to
  confirm the hold has been recognised (so the user knows to release).

Note: GPIO 0 doubles as the boot-mode pin. Holding it during reset enters
download mode. This is fine — during normal operation the boot-mode window has
already passed.

## OLED Display

### Signing request screen

```
Sign as persona/social?
Kind 1
"Hello world this is
 a test post that..."
[====------] 18s
```

- Line 1: `Sign as <purpose>?` or `Sign as master?` (truncated to 25 chars).
- Line 2: `Kind <number>` — numeric kind only. No kind-name lookup on embedded.
- Lines 3–4: Content preview, first ~50 chars, wrapped. Escaped characters
  shown raw (e.g. `\n` displayed as `\n`).
- Line 5: Countdown bar + seconds remaining. Bar fills from right to left.

### Response screens

- **Approved**: `Signed!` displayed for 2 seconds, then returns to idle.
- **Denied**: `Denied` displayed for 2 seconds.
- **Timeout**: `Timed out` displayed for 2 seconds.

### Idle screen

After boot with stored identity:

```
npub1abc...xyz
(truncated across lines)
```

Same as current `show_npub` display. Shows master npub.

## File Changes

### New files

| File | Purpose |
|------|---------|
| `firmware/src/protocol.rs` | Frame parser: read magic, type, length, payload, CRC. Dispatch by frame type. |
| `firmware/src/nip46.rs` | NIP-46 JSON-RPC handler: parse method/params, dispatch to sign or get_public_key. |
| `firmware/src/sign_request.rs` | Signing flow: parse event, display on OLED, wait for button, derive, compute event ID, sign, build response. |
| `firmware/src/button.rs` | GPIO 0 interrupt handler with press-duration measurement. Exposes a channel or flag for the signing flow to poll. |

### Modified files

| File | Changes |
|------|---------|
| `firmware/src/main.rs` | Boot loop becomes: init → NVS check → provision or display npub → enter frame dispatch loop. |
| `firmware/src/provision.rs` | Refactored to handle frame type `0x01` payload only (32 bytes). Frame parsing moves to `protocol.rs`. |
| `firmware/src/oled.rs` | New functions: `show_sign_request()`, `show_countdown()`, `show_result()`. Existing functions unchanged. |
| `firmware/Cargo.toml` | Add `serde`, `serde_json` dependencies. |
| `common/src/types.rs` | Add frame type constants. Remove `PROVISION_FRAME_LEN` (now variable). |
| `provision/src/main.rs` | Updated to emit new frame format with type byte `0x01`. |

### Unchanged files

| File | Reason |
|------|--------|
| `common/src/derive.rs` | Frozen protocol — derivation logic untouched. |
| `firmware/src/nvs.rs` | NVS storage unchanged. |
| `firmware/src/sign.rs` | BIP-340 signing logic unchanged — called by `sign_request.rs`. |
| `common/src/encoding.rs` | npub encoding unchanged. |

## Constraints

- **No grant overlap**: this work is not covered by G23 (Heartwood + Bark) or
  any other submitted grant. G23 Phase 2 mentions "Hardware exploration" as
  future work. Safe to build.
- **Frozen derivation**: the nsec-tree derivation in `common/src/derive.rs` must
  not change. The test vector must continue to pass.
- **k256 alignment workaround**: signing still runs in a dedicated thread until
  k256 >=0.14.0 stable ships.
- **No WiFi**: the ESP32 never enables WiFi or any TCP/IP stack. The "LAN for
  dev" path is the Pi/test-harness sending frames to the ESP32 over serial or
  TCP, not the ESP32 connecting to anything.
- **Single request at a time**: no queuing, no pipelining. Host blocks until
  response.
- **4KB max payload**: NIP-46 requests larger than ~4KB are refused. Covers all
  common event types.

## Security Considerations

- **What you see is what you sign**: the ESP32 parses the event, displays
  kind/content, then re-serialises the commitment and hashes it. A compromised
  host cannot trick the user into signing something other than what's displayed.
- **ESP32 is the authority**: the host is untrusted. It provides transport, but
  the ESP32 makes all signing decisions. Even if the host is fully compromised,
  an attacker cannot extract keys or sign without physical button access.
- **Child key lifetime**: derived child keys exist in RAM only for the duration
  of signing (~microseconds), then are zeroized. The master secret stays in NVS.
- **No replay**: each event includes `created_at` and a unique `id`. The ESP32
  doesn't need to track nonces.
- **Timeout prevents stuck state**: if the host crashes mid-request, the ESP32
  times out after 30s and returns to idle.
- **NIP-44 gap (Phase 3 only)**: the host decrypts NIP-44 before forwarding to
  the ESP32. This means the host sees plaintext NIP-46 requests. A compromised
  host could read signing requests but still cannot forge signatures. The host
  already knows what events it's asking to be signed, so this is not a
  meaningful information leak. NIP-44 on-device closes this gap in a future
  phase.

## Development Plan

### Phase 3a: ESP32 firmware

Implement the frame parser, NIP-46 handler, signing flow, button handling, and
OLED display on the ESP32. Test with a simple Rust CLI that sends NIP-46
sign_event requests over serial.

### Phase 3b: Test harness

A Rust CLI (`sign-test/` or extend `provision/`) that:
1. Constructs an unsigned Nostr event.
2. Wraps it in NIP-46 JSON-RPC.
3. Frames it and sends over serial (or TCP for dev).
4. Reads and displays the response.

This validates the full flow without needing heartwood-device integration.

### Phase 3c: heartwood-device integration

A new serial transport in heartwood-device (or the bunker sidecar) that
forwards NIP-46 requests to the ESP32 instead of signing locally. This is a
separate PR to the heartwood repo and can happen after the ESP32 side is solid.

## Out of Scope (Future Phases)

- NIP-44 encryption/decryption on-device (ESP32 handles NIP-44 itself, Pi
  becomes fully dumb pipe)
- NVS encryption (Phase 4)
- Radio disabling in firmware (Phase 4)
- Rate limiting (Phase 4)
- BLE GATT for portable mode (Phase 5)
- Multiple in-flight requests
- Event kind allowlists on the device
- Identity management methods (heartwood_derive, heartwood_switch, etc.)
- Client session management and permissions on-device
