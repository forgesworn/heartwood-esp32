# ESP32 Full NIP-46 HSM — Design Spec

> **Goal:** Make the ESP32 a complete NIP-46 signing bunker with multi-master support, on-device transport encryption, and approval policies. The Pi is a dumb encrypted pipe — it handles networking (Tor, relays, web UI) but never sees plaintext or key material.

## Architecture

```
Internet ← Tor ← Pi (bridge) ← USB serial (ciphertext only) → ESP32 (HSM)
                   │                                              ├── NVS (multiple masters)
                   │                                              ├── secp256k1 context
                   │                                              ├── NIP-44 transport
                   │                                              ├── Identity caches (per-master)
                   │                                              ├── Approval policies
                   │                                              ├── OLED (show what's happening)
                   │                                              └── Button (approve/deny)
                   │
                   ├── Nostr relays (NIP-46 events)
                   ├── Web UI (client management, master management)
                   └── bunker:// URI generation
```

### Zero-trust Pi

The Pi never holds secret key material. The serial channel carries only:

- **Inbound:** NIP-44 ciphertext (relay → Pi → ESP32) + control frames (session setup, policy pushes)
- **Outbound:** NIP-44 ciphertext (ESP32 → Pi → relay) + status frames

The ESP32 performs NIP-44 decrypt on inbound, processes the NIP-46 request, and NIP-44 encrypts the response. If the Pi is fully compromised, an attacker sees only ciphertext and cannot sign without physical button access (for non-auto-approved requests).

---

## Multi-Master Storage

### NVS layout

Each master is stored as a numbered slot in NVS:

| NVS key | Type | Size | Content |
|---------|------|------|---------|
| `master_count` | u8 | 1 | Number of provisioned masters (max 8) |
| `master_0_secret` | blob | 32 | Raw 32-byte secret |
| `master_0_label` | string | ≤32 | Human-readable label (e.g. "primary") |
| `master_0_mode` | u8 | 1 | 0=bunker, 1=tree-mnemonic, 2=tree-nsec |
| `master_0_pubkey` | blob | 32 | Cached x-only public key (derived at provision time) |
| `master_0_connect` | blob | 32 | Connect secret for `bunker://` URI (random, generated at provision) |
| `master_1_secret` | blob | 32 | ... |
| `master_1_label` | string | ≤32 | ... |
| ... | | | |

**Capacity:** 8 masters × ~100 bytes = ~800 bytes. Well within NVS limits (~20KB usable).

### Provisioning modes (per master)

Matches heartwood-device's three modes:

| Mode | Input | What's stored |
|------|-------|---------------|
| `bunker` | Raw nsec | nsec bytes as-is — vanilla NIP-46, no tree derivation |
| `tree-mnemonic` | BIP-39 mnemonic + optional passphrase | Derived 32-byte root secret (mnemonic not stored) |
| `tree-nsec` | Existing nsec | HMAC(nsec) → tree root (nsec not stored, only derived root) |

### Provisioning protocol

Extended frame types for multi-master management:

| Frame type | Direction | Payload | Purpose |
|------------|-----------|---------|---------|
| `0x01` | host → device | `[mode_u8][label_len_u8][label...][secret_32]` | Add a master |
| `0x04` | host → device | `[slot_u8]` | Remove a master |
| `0x05` | host → device | (empty) | List masters |
| `0x06` | device → host | JSON array of `{slot, label, mode, npub}` | Masters list response |

The existing `0x01` provision frame is extended with mode and label fields. Backward-compatible: if payload is exactly 32 bytes, it's treated as legacy tree-mnemonic with label "default".

### Boot flow

```
Power on
  → Read master_count from NVS
  → If 0: show "No masters — provision me" on OLED, wait for provision frames
  → If 1: derive pubkey, show "{label}: npub1..." on OLED
  → If 2+: show all labels + npubs in rotation (3s each), or show count
  → Enter frame dispatch loop
```

No master selection at boot — all masters are available simultaneously. Per-request routing by pubkey.

---

## NIP-46 Method Set

### Standard NIP-46 (8 methods)

| Method | Behaviour | Approval |
|--------|-----------|----------|
| `connect` | Validate shared secret against per-master connect secret (stored in NVS alongside each master). Store client pubkey in session. | Auto (but OLED shows "New client: {label}") |
| `ping` | Return `"pong"` | Auto |
| `get_public_key` | Return hex pubkey for target master (or active derived identity) | Auto |
| `sign_event` | Compute event ID, sign with BIP-340 Schnorr, return signed event | Policy-dependent |
| `nip44_encrypt` | NIP-44 encrypt plaintext for a recipient pubkey | Policy-dependent |
| `nip44_decrypt` | NIP-44 decrypt ciphertext from a sender pubkey | Policy-dependent |
| `nip04_encrypt` | Legacy NIP-04 encrypt (AES-256-CBC) | Policy-dependent |
| `nip04_decrypt` | Legacy NIP-04 decrypt (AES-256-CBC) | Policy-dependent |

### Heartwood extensions (7 methods)

| Method | Behaviour | Approval |
|--------|-----------|----------|
| `heartwood_derive` | Derive child at purpose/index, add to per-master cache | Button required |
| `heartwood_derive_persona` | Derive named persona (sugar over derive) | Button required |
| `heartwood_switch` | Set active identity for subsequent requests from this client | OLED notify (auto) |
| `heartwood_list_identities` | Return cached derived identities for target master | Auto |
| `heartwood_recover` | Scan default purposes, rebuild identity cache | Button required |
| `heartwood_create_proof` | Create blind/full linkage proof between master and child | Button required |
| `heartwood_verify_proof` | Verify a supplied linkage proof | Auto |

### Master key protection

In `tree-mnemonic` and `tree-nsec` modes, the master secret is never used directly for signing. `sign_event` without a prior `heartwood_switch` (or without a `heartwood` context in the request) returns an error. This matches the heartwood security model.

In `bunker` mode, the stored nsec signs directly — there's no tree to derive from. Heartwood extension methods (`heartwood_derive`, `heartwood_switch`, `heartwood_recover`, `heartwood_create_proof`, `heartwood_derive_persona`) return error code `-5` ("not available in bunker mode") for bunker-mode masters. `heartwood_list_identities` returns an empty array. `heartwood_verify_proof` works (it's stateless).

---

## NIP-44 Transport Layer

### How it works today (bridge does crypto)

```
Relay → NIP-44 ciphertext → Bridge (decrypt) → plaintext JSON → serial → ESP32
ESP32 → plaintext JSON → serial → Bridge (encrypt) → NIP-44 ciphertext → Relay
```

### How it works with on-device transport (option A)

```
Relay → NIP-44 ciphertext → Bridge (passthrough) → serial → ESP32 (decrypt)
ESP32 (process + encrypt response) → serial → Bridge (passthrough) → Relay
```

### New frame types for transport

| Frame type | Direction | Payload | Purpose |
|------------|-----------|---------|---------|
| `0x10` | bridge → device | `[master_pubkey_32][client_pubkey_32][ciphertext...]` | Encrypted NIP-46 request |
| `0x11` | device → bridge | `[client_pubkey_32][ciphertext...]` | Encrypted NIP-46 response |

The bridge includes the master pubkey so the ESP32 knows which secret to use for NIP-44 decryption. The client pubkey is needed for both NIP-44 shared secret derivation and for looking up approval policies.

### ESP32 processing flow

```
Receive frame 0x10
  → Look up master by pubkey (or NACK if unknown)
  → NIP-44 decrypt(master_secret, client_pubkey, ciphertext) → plaintext JSON
  → Parse NIP-46 request
  → Check approval policy for (master, client, method, kind)
  → If auto-approved: process immediately
  → If button-required: show on OLED, wait for approval
  → Build NIP-46 response JSON
  → NIP-44 encrypt(master_secret, client_pubkey, response_json) → ciphertext
  → Send frame 0x11 back to bridge
```

### NIP-44 on ESP32

NIP-44 v2 requires:
- **X25519** key exchange (secp256k1 secret → Curve25519 conversion → shared secret)
- **HKDF-SHA256** key derivation
- **XChaCha20-Poly1305** AEAD encryption
- **HMAC-SHA256** for padding

Crate options for ESP32 (all no_std compatible):
- `chacha20poly1305` — XChaCha20-Poly1305 AEAD
- `hkdf` + `sha2` — HKDF-SHA256 (sha2 already in deps)
- `x25519-dalek` — X25519 key exchange

These are pure Rust with no alignment issues (unlike k256). Should work on Xtensa without problems.

**secp256k1 → Curve25519 conversion:** NIP-44 derives the shared secret via X25519, which requires converting secp256k1 private keys to Curve25519 scalar form. The conversion is: take the 32-byte secp256k1 secret, clamp it per RFC 7748 (clear bits 0-2 and 255, set bit 254), and use it as an X25519 private key. The peer's secp256k1 x-only pubkey is converted to a Curve25519 point. The `nip44` module in common will implement this conversion following the same approach as the `nostr` crate's `nip44::get_conversation_key()`.

### NIP-04 on ESP32

NIP-04 requires AES-256-CBC + PKCS7 padding + base64. Legacy but needed for compatibility.

- `aes` + `cbc` — AES-256-CBC (pure Rust, no_std)
- `base64` — encoding (already commonly available)

---

## Client Approval Policies

### Approval tiers

| Tier | When | OLED | Button |
|------|------|------|--------|
| **Auto-approve** | Pre-approved client + permitted method + permitted kind | Silent (or brief flash) | No |
| **OLED notify** | Auto-approved but notable | Show briefly (1s) | No |
| **Button required** | Unknown client, privileged method, or no policy match | Full display + countdown | Yes (long-hold 2s) |

### Policy structure

Policies are per-master, per-client:

```json
{
  "client_pubkey": "abcd1234...",
  "label": "Bark browser",
  "allowed_methods": ["sign_event", "get_public_key", "nip44_encrypt", "nip44_decrypt"],
  "allowed_kinds": [1, 6, 7, 1059, 10002, 30023],
  "auto_approve": true
}
```

### How policies reach the ESP32

The bridge sends a **session frame** at startup (and when policies change):

| Frame type | Direction | Payload | Purpose |
|------------|-----------|---------|---------|
| `0x20` | bridge → device | `[master_pubkey_32][policy_json...]` | Push client policies for a master |
| `0x21` | bridge → device | `[shared_secret_32]` | Bridge authentication (set at provision time) |
| `0x22` | device → bridge | `[status_u8]` | Session acknowledgement |

The bridge must authenticate with `0x21` before the ESP32 accepts policy pushes or encrypted request frames. Without authentication, the ESP32 operates in **button-only mode** (standalone/sign-test behaviour).

### Policy storage

Policies are held in RAM only (not NVS). They're ephemeral — the bridge re-pushes them every time it connects. This means:

- Unplugging the Pi and plugging in a laptop → button-only mode (safe)
- Pi reboots → bridge reconnects, re-authenticates, re-pushes policies
- No stale policies persisted on the device

### Rate limiting

Per-client, per-master: 60 requests per 60-second window (matching heartwood-device). Tracked in RAM. Exceeding the limit returns a NIP-46 error without OLED display.

---

## Per-Request Master Routing

### How the bridge routes

Each `bunker://` URI maps to a specific master:

```
bunker://<master1_pubkey>?relay=wss://...&secret=abc  →  master slot 0
bunker://<master2_pubkey>?relay=wss://...&secret=def  →  master slot 1
```

The bridge subscribes to NIP-46 events for all master pubkeys. When a request arrives, it includes the target master pubkey in the `0x10` frame header. The ESP32 looks up the slot by pubkey.

### OLED display

Every request shows which master is involved:

```
┌──────────────────────┐
│ ForgeSworn           │  ← master label
│ sign_event kind:1    │  ← method + kind
│ Hello world...       │  ← content preview
│ ████████░░░░ 18s     │  ← countdown (if button required)
└──────────────────────┘
```

Auto-approved requests flash briefly:

```
┌──────────────────────┐
│ CryptoDonkey ✓       │
│ sign_event kind:1    │
└──────────────────────┘
```

---

## Per-Master Identity Cache

Each master in tree mode maintains a cache of derived identities in PSRAM:

```rust
struct IdentityCache {
    /// Which master slot this cache belongs to.
    master_slot: u8,
    /// Cached derived identities.
    identities: Vec<CachedIdentity>,
    /// Currently active identity (set by heartwood_switch).
    active: Option<usize>,
}

struct CachedIdentity {
    npub: String,           // bech32 npub (63 chars)
    purpose: String,        // e.g. "persona/social"
    index: u32,
    persona_name: Option<String>,
    private_key: [u8; 32],  // zeroized on cache eviction
    public_key: [u8; 32],
}
```

**Memory budget:** Each entry is ~200 bytes. 50 identities across all masters = ~10KB. Comfortable in 2MB PSRAM.

**Active identity is per-client, per-master.** If Bark switches to "persona/social" under primary, that doesn't affect another client's active identity under the same master. This requires per-client session state:

```rust
struct ClientSession {
    client_pubkey: [u8; 32],
    master_slot: u8,
    active_identity: Option<usize>,  // index into master's identity cache
    request_count: u32,              // rate limiting
    window_start: Instant,
}
```

**Max sessions:** 32 concurrent (matching heartwood-device). ~3KB total.

---

## Serial Protocol Changes

### New frame types summary

| Type | Name | Direction | Payload |
|------|------|-----------|---------|
| `0x01` | PROVISION_ADD | host → device | `[mode][label_len][label][secret_32]` |
| `0x02` | NIP46_REQUEST | host → device | Plaintext JSON (standalone mode only) |
| `0x03` | NIP46_RESPONSE | device → host | Plaintext JSON (standalone mode only) |
| `0x04` | PROVISION_REMOVE | host → device | `[slot_u8]` |
| `0x05` | PROVISION_LIST | host → device | (empty) |
| `0x06` | ACK | device → host | (empty) |
| `0x07` | PROVISION_LIST_RESPONSE | device → host | JSON array |
| `0x10` | ENCRYPTED_REQUEST | bridge → device | `[master_pk_32][client_pk_32][ciphertext]` |
| `0x11` | ENCRYPTED_RESPONSE | device → bridge | `[client_pk_32][ciphertext]` |
| `0x15` | NACK | device → host | (empty) |
| `0x20` | POLICY_PUSH | bridge → device | `[master_pk_32][policy_json]` |
| `0x21` | SESSION_AUTH | bridge → device | `[shared_secret_32]` |
| `0x22` | SESSION_ACK | device → bridge | `[status_u8]` |

**Note:** `0x02`/`0x03` (plaintext NIP-46) are retained for standalone mode (sign-test, direct USB). They are only accepted when no bridge session is authenticated. Once `0x21` succeeds, plaintext frames are rejected (enforces zero-trust when Pi is attached).

---

## Firmware Module Layout

### New modules

| File | Responsibility |
|------|----------------|
| `firmware/src/masters.rs` | Multi-master NVS storage (add, remove, list, lookup by pubkey) |
| `firmware/src/transport.rs` | NIP-44 transport encryption/decryption (on-device) |
| `firmware/src/policy.rs` | Client approval policies, rate limiting, session state |
| `firmware/src/nip04.rs` | NIP-04 legacy encrypt/decrypt |
| `firmware/src/session.rs` | Bridge session management (auth, policy acceptance) |

### Modified modules

| File | Changes |
|------|---------|
| `firmware/src/main.rs` | Multi-master boot flow, new frame dispatch cases |
| `firmware/src/nip46_handler.rs` | Add 11 new methods, approval tier checks, per-master routing |
| `firmware/src/oled.rs` | Master label display, auto-approve flash, multi-master boot screen |
| `firmware/src/provision.rs` | Extended provision protocol (add/remove/list, mode+label) |
| `firmware/src/protocol.rs` | New frame type constants and dispatch |
| `firmware/src/nvs.rs` | Multi-slot NVS read/write |

### Common crate changes

| File | Changes |
|------|---------|
| `common/src/nip46.rs` | New method types, heartwood extension request/response types |
| `common/src/nip44.rs` | NIP-44 v2 encrypt/decrypt (shared between firmware and bridge) |
| `common/src/nip04.rs` | NIP-04 encrypt/decrypt (shared) |
| `common/src/types.rs` | New frame type constants |

### New dependencies (firmware)

| Crate | Purpose |
|-------|---------|
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD (NIP-44) |
| `hkdf` | HKDF-SHA256 key derivation (NIP-44) |
| `x25519-dalek` | X25519 key exchange (NIP-44 shared secret) |
| `aes` | AES-256 (NIP-04) |
| `cbc` | CBC mode (NIP-04) |
| `base64` | Base64 encoding (NIP-04) |

All pure Rust, no alignment issues on Xtensa. `sha2` and `hmac` are already in deps.

---

## OLED UX

### Boot (multi-master)

```
┌──────────────────────┐
│ Heartwood HSM        │
│ 3 masters loaded     │
│ Awaiting bridge...   │
└──────────────────────┘
```

### Bridge connected

```
┌──────────────────────┐
│ Bridge connected     │
│ 3 masters active     │
│ 2 clients approved   │
└──────────────────────┘
```

### Signing request (button required)

```
┌──────────────────────┐
│ ForgeSworn           │
│ sign kind:1          │
│ Hello world...       │
│ ████████░░░░ 18s     │
└──────────────────────┘
```

### Auto-approved (flash 1s)

```
┌──────────────────────┐
│ CryptoDonkey ✓       │
│ sign kind:1          │
└──────────────────────┘
```

### Identity switch

```
┌──────────────────────┐
│ ForgeSworn           │
│ → persona/social     │
│ npub1rx8u...         │
└──────────────────────┘
```

---

## Security Considerations

### What the Pi can do if compromised

- Replay old ciphertext (ESP32 should reject — NIP-44 has nonces)
- Withhold requests/responses (denial of service, not key compromise)
- Push malicious approval policies (mitigated by bridge auth secret)
- See which pubkeys are communicating (metadata, not content)

### What the Pi cannot do

- Extract any secret key material
- Sign events
- Decrypt NIP-44/NIP-04 messages
- Forge approval policies without the bridge auth secret

### Bridge authentication

The shared secret for `0x21` SESSION_AUTH is set during initial provisioning and stored in NVS. It's separate from any master secret. If the Pi is wiped, the user must re-provision the bridge secret (physical access to ESP32 required).

### Physical security

- Button required for all privileged operations regardless of policy
- OLED always shows what's happening (no silent operations in button-required tier)
- All radios disabled in HSM mode
- JTAG disabled in production firmware (future — without eFuses, this is a compile-time flag)
- Zeroize all derived key material after use

---

## Scope Boundaries

### In scope (this design)

- Multi-master NVS storage and provisioning
- Full NIP-46 method set (8 standard + 7 heartwood extensions)
- NIP-44 v2 transport encryption on-device
- NIP-04 legacy encryption on-device
- Client approval policies (RAM-only, pushed from bridge)
- Per-request master routing by pubkey
- Per-master identity caches
- Bridge session authentication
- Updated OLED UX for multi-master

### Out of scope (future phases)

- BLE portable signer mode (Phase 5)
- GPS location stamps (Phase 6)
- QR code display (Phase 6)
- Flash encryption / eFuse burning (deliberately excluded)
- Tor (Pi handles this)
- Web UI (Pi handles this)
- Relay management (Pi handles this)
