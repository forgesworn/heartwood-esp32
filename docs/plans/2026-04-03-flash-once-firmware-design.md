# Flash-Once Firmware Completion

**Date:** 2026-04-03
**Status:** Design
**Goal:** Ship a firmware that is feature-complete for production HSM use. After this flash, all management (provisioning, policy, updates) happens over serial from the Pi. No more swapping to the laptop with espflash unless something goes catastrophically wrong.

---

## 1. Connect Secret Validation

**Problem:** The `connect` handler in `nip46_handler.rs:102-104` accepts all clients unconditionally. The per-master `connect_secret` stored in NVS is generated at provision time but never checked. Any client that knows the bunker pubkey can connect.

**Fix:**

The `connect` handler must:
1. Extract `params[1]` (the optional secret) from the NIP-46 request
2. Load the per-master `connect_secret` from NVS (via `LoadedMaster`)
3. Compare in constant time
4. If no secret was sent, or it doesn't match, return error `-1` ("invalid connect secret")
5. If the secret matches, return the secret as the result (not `"ack"`) per the NIP-46 spec

**Implementation notes:**
- `handle_request` already receives `master_slot` — use it to look up the connect secret from `LoadedMaster`
- Add `connect_secret: [u8; 32]` to the `LoadedMaster` struct (it's already in NVS as `master_{N}_conn`)
- The `connect` handler needs access to the loaded masters list, or the connect secret can be passed in directly
- `build_connect_response` needs a new variant that takes the secret hex string as the result

**Files:** `firmware/src/nip46_handler.rs`, `firmware/src/masters.rs`, `common/src/nip46.rs`

---

## 2. Bridge Secret Provisioning Frame

**Problem:** `session::write_bridge_secret()` exists but is never called. The bridge secret cannot be set over serial. Without it, encrypted passthrough mode (SESSION_AUTH 0x21) cannot be bootstrapped — you'd need a flash tool to write the NVS key directly.

**Fix:**

New frame type `FRAME_TYPE_SET_BRIDGE_SECRET` = `0x23`.

| Field | Value |
|-------|-------|
| Type byte | `0x23` |
| Payload | 32 bytes (the bridge secret) |
| Response | ACK (0x06) on success, NACK (0x15) on failure |

**Constraints:**
- Only accepted when no bridge session is currently authenticated (`!policy_engine.bridge_authenticated`). This prevents a compromised bridge from rotating the secret while connected.
- Requires button confirmation (2-second hold) since this is a security-critical operation. OLED shows "Set bridge secret?" with countdown.
- Calls `session::write_bridge_secret()` on approval.

**Files:** `common/src/types.rs` (new const), `firmware/src/main.rs` (dispatch), `firmware/src/session.rs` (handler)

---

## 3. sign_event Encrypted Response

**Problem:** In passthrough mode (bridge authenticated, 0x10/0x11 encrypted channel), `sign_event` bypasses the encrypted response path. It writes a plaintext 0x03 frame directly from the button loop, while every other method returns `Some(json)` and lets the transport layer encrypt to 0x11. This means the Pi sees the plaintext signed event, breaking the zero-trust model.

**Fix:**

Refactor `handle_sign_event` to return `Some(json)` like every other handler. The interactive button loop stays in the handler, but instead of calling `write_frame(usb, 0x03, ...)` directly, it returns the response JSON string. The dispatch code in `main.rs` (plaintext path) and `transport.rs` (encrypted path) then handles framing.

**Challenge:** `handle_sign_event` currently takes `&mut usb` to write errors (timeout, deny) as well as success. After refactoring, it must return error responses as `Some(error_json)` too, never touching USB directly.

**After refactoring:**
- `handle_request` always returns `Option<String>` — `Some` for every method including sign_event
- `None` is no longer used (the "handler wrote its own frame" convention is eliminated)
- Return type could become just `String` since every path produces a response

**Files:** `firmware/src/nip46_handler.rs`, `firmware/src/transport.rs`, `firmware/src/main.rs`

---

## 4. Factory Reset Frame

**Problem:** No way to fully reset the device over serial. Currently you must either remove masters one-by-one with PROVISION_REMOVE or erase NVS via espflash.

**Fix:**

New frame type `FRAME_TYPE_FACTORY_RESET` = `0x24`.

| Field | Value |
|-------|-------|
| Type byte | `0x24` |
| Payload | Empty |
| Response | ACK (0x06) then reboot |

**Behaviour:**
1. OLED shows "FACTORY RESET?" in large text with 30-second countdown
2. Requires 2-second button hold to confirm (same as signing)
3. On approval: erase all NVS keys in the `heartwood` namespace, send ACK, reboot
4. On deny/timeout: send NACK, return to normal operation
5. This clears all masters, bridge secret, and persisted policies — device returns to "No masters -- provision me" state

**Security:** No authentication required (if someone has physical access to both the serial port AND the button, they already have the device). This is intentional — factory reset is a physical-access operation.

**Files:** `common/src/types.rs` (new const), `firmware/src/main.rs` (dispatch), `firmware/src/provision.rs` (new handler)

---

## 5. Policy Persistence (NVS)

**Problem:** `POLICY_PUSH` (0x20) stores policies in RAM only. They're lost on reboot. The bridge must re-push on every reconnect, creating a window where all requests need manual button approval.

**Fix:**

When `handle_policy_push` in `session.rs` accepts policies:
1. Store in RAM (existing behaviour)
2. Also serialise to NVS as `policy_{master_slot}` (JSON blob)

On boot (in `main.rs`):
1. After loading masters, load persisted policies from NVS
2. Populate `PolicyEngine.master_policies` with any saved policies

On `POLICY_PUSH`:
1. Overwrite both RAM and NVS
2. ACK as before

On factory reset:
1. Policies are cleared along with everything else (they're in the `heartwood` NVS namespace)

**NVS key format:** `policy_{N}` where N is the master slot (0-7). Value is the JSON-serialised `Vec<ClientPolicy>`.

**Size consideration:** Each `ClientPolicy` is ~200 bytes JSON. With 10 clients per master, that's ~2KB per slot. NVS can handle this comfortably — the `heartwood` namespace has 16KB (0x4000) allocated.

**Files:** `firmware/src/session.rs`, `firmware/src/main.rs`, `firmware/src/policy.rs`

---

## 6. Serial OTA

**Problem:** Firmware updates require espflash on the laptop via USB bootloader. No way to update firmware from the Pi.

**Fix:**

### 6a. Partition table

Replace the default single-app partition table with a custom OTA-capable one:

```csv
# Name,    Type, SubType, Offset,   Size,   Flags
nvs,       data, nvs,     ,         0x4000,
otadata,   data, ota,     ,         0x2000,
phy_init,  data, phy,     ,         0x1000,
ota_0,     app,  ota_0,   ,         0xE0000,
ota_1,     app,  ota_1,   ,         0xE0000,
```

The Heltec V4 has 8MB flash. Two 896KB OTA slots (0xE0000 each) plus NVS, otadata, and phy_init. No factory partition — the first flash via espflash writes to ota_0, and subsequent OTA updates alternate between ota_0 and ota_1. The ESP-IDF bootloader handles slot selection automatically via the `otadata` partition.

### 6b. New frame types

| Type byte | Name | Direction | Payload |
|-----------|------|-----------|---------|
| `0x30` | `FRAME_TYPE_OTA_BEGIN` | Host -> Device | `[total_size_u32_be][sha256_32]` (36 bytes) |
| `0x31` | `FRAME_TYPE_OTA_CHUNK` | Host -> Device | `[offset_u32_be][data...]` (4 + up to 4088 bytes) |
| `0x32` | `FRAME_TYPE_OTA_FINISH` | Host -> Device | Empty |
| `0x33` | `FRAME_TYPE_OTA_STATUS` | Device -> Host | `[status_u8][message...]` |

**Status codes for OTA_STATUS (0x33):**
- `0x00` = ready (OTA_BEGIN accepted)
- `0x01` = chunk received OK
- `0x02` = verification passed, rebooting
- `0x10` = error: hash mismatch
- `0x11` = error: size mismatch
- `0x12` = error: write failed
- `0x13` = error: not in OTA mode (BEGIN not sent)

### 6c. OTA flow

1. Host sends `OTA_BEGIN` with total firmware size and expected SHA-256 hash
2. Firmware shows "OTA update?" on OLED with the size, requires 2-second button hold
3. On approval: opens the inactive OTA partition for writing, replies `OTA_STATUS(0x00)`
4. Host sends `OTA_CHUNK` frames sequentially (4KB each, offset for ordering verification)
5. Firmware writes each chunk to the OTA partition, replies `OTA_STATUS(0x01)` per chunk
6. After all chunks: host sends `OTA_FINISH`
7. Firmware verifies SHA-256 of the written partition matches the expected hash
8. If valid: sets the new partition as boot target, replies `OTA_STATUS(0x02)`, reboots
9. If invalid: replies `OTA_STATUS(0x10)`, aborts OTA, existing firmware continues

**Rollback:** ESP-IDF provides automatic rollback. If the new firmware fails to boot (crashes in the first 30 seconds), the bootloader reverts to the previous partition. The firmware must call `esp_ota_mark_app_valid_cancel_rollback()` after successful boot to confirm the update. Add this call at the end of the boot sequence in `main.rs`.

### 6d. Pi-side tool

New binary: `ota/` crate in the heartwood-esp32 workspace (alongside provision, sign-test, bridge).

```
heartwood-ota --port /dev/ttyUSB0 --firmware heartwood-v1.2.bin
```

Reads the firmware binary, computes SHA-256, sends OTA_BEGIN, streams chunks with progress bar, sends OTA_FINISH, waits for status.

### 6e. sdkconfig changes

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
```

**Files:** `firmware/partitions.csv` (new), `firmware/sdkconfig.defaults`, `common/src/types.rs`, `firmware/src/main.rs`, `firmware/src/ota.rs` (new module), `ota/` (new crate)

---

## 7. Error Format Fix

**Problem:** `Nip46Error` serialises as `{"code": -3, "message": "..."}` but NIP-46 says `error` must be a plain string. Every standard client (Amber, nsec.app, Nostr Connect) will fail to parse error responses.

**Fix:**

Change `Nip46Response.error` from `Option<Nip46Error>` to `Option<String>`. The `build_error_response` function takes `(request_id, code, message)` and formats the error as the message string only (e.g. `"user denied"`, `"bad event format"`). The numeric codes are dropped from the wire format — they're useful for internal logging but NIP-46 clients just need the human-readable message.

**Migration:** This is a breaking change to the wire format. Since no standard clients are currently connecting successfully to heartwood (the connect secret bug prevents it), this is safe to ship now.

**Files:** `common/src/nip46.rs` (types + builders), tests that assert on error structure

---

## 8. Policy-Driven Auto-Approval (TOFU)

**Problem:** The `PolicyEngine::check()` method exists and is fully implemented, but `nip46_handler::handle_request` never calls it. The `policy_engine` parameter is received but suppressed with `let _ = policy_engine`. Every `sign_event` goes through the full 30-second button loop regardless of whether the client has been approved before.

**Target UX (Alby-like):** First request from a new client shows on OLED and requires button approval. After approval, that client is remembered and subsequent requests of the same type are auto-signed. The user never needs to touch the device again for routine signing from trusted clients.

**Fix:**

### 8a. Wire up PolicyEngine::check() in the handler

Before dispatching to method-specific handlers, call `policy_engine.check()`:

```rust
let method = Nip46Method::from_str(&request.method);
let event_kind = extract_event_kind_if_sign_event(&request);
let tier = policy_engine.check(master_slot, &client_pubkey_hex, &method, event_kind);

match tier {
    ApprovalTier::AutoApprove => { /* proceed without OLED or button */ }
    ApprovalTier::OledNotify => { /* flash on OLED briefly, no button wait */ }
    ApprovalTier::ButtonRequired => { /* existing interactive flow */ }
}
```

### 8b. TOFU: auto-add client policy after first approval

When a client's request goes through the button approval flow and the user approves:

1. Create a `ClientPolicy` for that client pubkey with `auto_approve: true`
2. Set `allowed_methods` to the approved method (e.g. `["sign_event", "nip44_encrypt", "nip44_decrypt", "nip04_encrypt", "nip04_decrypt", "get_public_key"]`) — all "safe" NIP-46 methods
3. Leave `allowed_kinds` empty (all kinds allowed)
4. Add to `PolicyEngine` in RAM
5. Persist to NVS (using the mechanism from item 5)

This means the user approves once per client, and the policy is remembered across reboots.

### 8c. Method approval tiers (existing, already correct)

The `Nip46Method` enum already defines sensible tiers:

| Tier | Methods | Behaviour |
|------|---------|-----------|
| `always_auto_approve` | connect, ping, get_public_key, heartwood_list_identities, heartwood_verify_proof | No button, no OLED |
| `always_requires_button` | heartwood_derive, heartwood_derive_persona, heartwood_recover, heartwood_create_proof | Always button, even with policy |
| `is_oled_notify` | heartwood_switch | Auto but flashed on OLED |
| Policy-dependent | sign_event, nip44_encrypt/decrypt, nip04_encrypt/decrypt | Button on first use, auto after TOFU |

### 8d. Client pubkey in the handler

The handler currently doesn't know the client pubkey. In plaintext mode (0x02), there is no client pubkey (it's a direct serial connection). In encrypted mode (0x10), the client pubkey is in the frame header.

**Approach:** Add `client_pubkey: Option<[u8; 32]>` parameter to `handle_request`. Transport layer passes `Some(client_pubkey)` for encrypted requests. Main loop passes `None` for plaintext requests. When `client_pubkey` is `None`, policy is always `ButtonRequired` (plaintext mode means no bridge, no trust chain).

### 8e. Revoking a client

The bridge can push an empty policy list via `POLICY_PUSH` (0x20) to revoke all auto-approvals for a master. Or push a new list that excludes the revoked client. The TOFU-added policies and bridge-pushed policies live in the same `Vec<ClientPolicy>` — the bridge can overwrite them.

Additionally, factory reset (item 4) clears everything.

**Files:** `firmware/src/nip46_handler.rs`, `firmware/src/policy.rs`, `firmware/src/transport.rs`, `firmware/src/main.rs`, `firmware/src/session.rs`

---

## Constraints

- **No eFuses.** No hardware lock-down in this release.
- **No Wi-Fi.** The ESP32 stays air-gapped. All communication is serial-only.
- **Proof methods stay stubbed.** `heartwood_create_proof` and `heartwood_verify_proof` return error -6. OTA means they can be added later.
- **No get_relays / switch_relays.** The ESP32 has no relay list — relay management is the bridge's responsibility.
- **NVS namespace stays `heartwood`.** All new keys (policies, OTA state) use the existing namespace.

---

## Implementation order

Dependencies flow downward — each item can be implemented after the items above it are complete:

1. **Error format fix** (item 7) — smallest change, unblocks all other handler changes
2. **Connect secret validation** (item 1) — needs `LoadedMaster` changes, standalone
3. **Bridge secret provisioning** (item 2) — new frame type, standalone
4. **sign_event encrypted response** (item 3) — refactors handler return convention
5. **Policy-driven auto-approval** (item 8) — depends on items 3 and 7 (handler refactor)
6. **Policy persistence** (item 5) — depends on item 8 (TOFU generates policies to persist)
7. **Factory reset** (item 4) — standalone, can be done anytime
8. **Serial OTA** (item 6) — largest change, partition table + new module + new crate

Items 1-3 and 7 are independent and can be parallelised. Items 4-6 can also be parallelised after item 8 is done.

---

## Testing strategy

- **Items 1-5, 7-8:** Unit tests in `common/` for serialisation changes. Integration tests via `sign-test` CLI against the device.
- **Item 6 (OTA):** Must be tested on hardware. Flash the OTA-capable firmware via espflash, then test the serial OTA flow with the new `heartwood-ota` tool. Verify rollback by flashing a deliberately broken firmware image.
- **TOFU flow:** Manual test via the bridge: connect a new client, approve on device, verify second request is auto-approved, reboot device, verify policy persists.
