# Flash-Once Firmware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an ESP32 firmware that is feature-complete for production HSM use — after this flash, all management happens over serial from the Pi.

**Architecture:** Eight changes to the heartwood-esp32 codebase across `common/`, `firmware/`, and a new `ota/` crate. The firmware gains connect secret validation, bridge secret provisioning, encrypted sign_event responses, factory reset, NVS-persisted policies with TOFU auto-approval, serial OTA updates, and NIP-46 error format compliance.

**Tech Stack:** Rust (ESP-IDF std), secp256k1 C FFI, ssd1306 OLED, NVS flash storage, ESP-IDF OTA APIs.

**Repo:** `~/WebstormProjects/heartwood-esp32` (private)

**Spec:** `docs/plans/2026-04-03-flash-once-firmware-design.md`

**Conventions:** British English, `type: description` commits, no `Co-Authored-By`, no `console.log`.

**Important — ESP32 firmware:** The `firmware/` crate targets `xtensa-esp32s3-espidf` and requires the ESP Rust toolchain (`espup`). You CANNOT run `cargo build` or `cargo test` in `firmware/` on a standard host. Only `common/` and host crates (`provision/`, `sign-test/`, `bridge/`, `ota/`) can be built and tested on the host. For firmware changes, verify correctness by building `common/` tests and reviewing the code — do NOT attempt `cargo build` in `firmware/`.

---

## File Map

### Modified files

| File | Responsibility | Tasks |
|------|---------------|-------|
| `common/src/nip46.rs` | NIP-46 types, response builders | 1, 2 |
| `common/src/types.rs` | Frame type constants | 3, 5, 7 |
| `common/src/policy.rs` | ClientPolicy, ApprovalTier types | 6 |
| `firmware/src/nip46_handler.rs` | NIP-46 request dispatch | 2, 4, 6 |
| `firmware/src/transport.rs` | Encrypted frame handler | 4, 6 |
| `firmware/src/main.rs` | Boot sequence, frame dispatch loop | 3, 4, 5, 6, 7, 8 |
| `firmware/src/session.rs` | Bridge auth, policy push | 3, 6 |
| `firmware/src/policy.rs` | PolicyEngine | 6 |
| `firmware/src/provision.rs` | Provision handlers | 5 |
| `firmware/sdkconfig.defaults` | ESP-IDF config | 8 |

### New files

| File | Responsibility | Tasks |
|------|---------------|-------|
| `firmware/src/ota.rs` | OTA frame handlers + ESP-IDF OTA API calls | 7 |
| `firmware/src/approval.rs` | Shared button approval loop (extracted from nip46_handler) | 4 |
| `firmware/partitions.csv` | Custom OTA partition table | 8 |
| `ota/Cargo.toml` | Pi-side OTA tool crate | 8 |
| `ota/src/main.rs` | OTA CLI tool | 8 |

---

## Task 1: Error Format Fix

**Files:**
- Modify: `common/src/nip46.rs:57-64` (Nip46Error struct, Nip46Response)
- Test: `common/src/nip46.rs` (inline tests)

This is the smallest change and unblocks the handler refactoring in later tasks. NIP-46 says `error` is a string, not an object.

- [ ] **Step 1: Update the test to expect a string error**

In `common/src/nip46.rs`, find the `test_build_error_response` test (line ~478) and change it:

```rust
#[test]
fn test_build_error_response() {
    let json = build_error_response("req99", -32600, "invalid request").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["id"], "req99");
    // NIP-46 error is a plain string, not a structured object.
    assert_eq!(parsed["error"], "invalid request");
    assert!(parsed["result"].is_null());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ./common && cargo test --features nip46 test_build_error_response`

Expected: FAIL — the test expects a string but currently gets `{"code": -32600, "message": "invalid request"}`.

- [ ] **Step 3: Change Nip46Response.error to Option\<String\>**

In `common/src/nip46.rs`, replace the `Nip46Error` struct and update `Nip46Response`:

```rust
/// A NIP-46 JSON-RPC response sent back to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip46Response {
    /// Correlation ID from the originating request.
    pub id: String,
    /// Successful result payload (present when no error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Error message (present when the request failed).
    /// NIP-46 specifies this as a plain string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
```

Remove the `Nip46Error` struct entirely (lines 57-64).

Update `build_error_response` to set `error: Some(message.to_string())` instead of `error: Some(Nip46Error { code, message: message.to_string() })`:

```rust
pub fn build_error_response(request_id: &str, code: i32, message: &str) -> Result<String, String> {
    // code is kept in the function signature for internal logging but not
    // included in the wire format — NIP-46 specifies error as a plain string.
    let _ = code;
    let response = Nip46Response {
        id: request_id.to_string(),
        result: None,
        error: Some(message.to_string()),
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise error response: {e}"))
}
```

- [ ] **Step 4: Run all NIP-46 tests**

Run: `cd ./common && cargo test --features nip46`

Expected: All tests pass. The only test that asserts on error format is `test_build_error_response`.

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/nip46.rs
git commit -m "fix(nip46): error field is a plain string per NIP-46 spec"
```

---

## Task 2: Connect Secret Validation

**Files:**
- Modify: `firmware/src/nip46_handler.rs:60-72` (handle_request signature), `firmware/src/nip46_handler.rs:102-104` (connect handler)
- Modify: `common/src/nip46.rs:338-347` (build_connect_response)
- Modify: `firmware/src/main.rs:263-276` (plaintext dispatch — pass connect_secret)
- Modify: `firmware/src/transport.rs:110-121` (encrypted dispatch — pass connect_secret)
- Test: `common/src/nip46.rs` (inline test for build_connect_response with secret)

The `LoadedMaster` struct already has `connect_secret: [u8; 32]` (loaded from NVS at `masters.rs:96-101`). The handler just needs to use it.

- [ ] **Step 1: Add a test for connect response with secret**

In `common/src/nip46.rs`, add a new test:

```rust
#[test]
fn test_build_connect_response_with_secret() {
    let secret_hex = "aabbccdd".repeat(8); // 64-char hex string
    let json = build_connect_response_with_secret("conn-2", &secret_hex).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["id"], "conn-2");
    assert_eq!(parsed["result"], secret_hex);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ./common && cargo test --features nip46 test_build_connect_response_with_secret`

Expected: FAIL — `build_connect_response_with_secret` doesn't exist yet.

- [ ] **Step 3: Add build_connect_response_with_secret**

In `common/src/nip46.rs`, add after `build_connect_response`:

```rust
/// Build a `connect` success response echoing back the validated secret.
/// Per NIP-46, the result MUST be the secret when one was provided.
pub fn build_connect_response_with_secret(request_id: &str, secret_hex: &str) -> Result<String, String> {
    let response = Nip46Response {
        id: request_id.to_string(),
        result: Some(secret_hex.to_string()),
        error: None,
    };
    serde_json::to_string(&response)
        .map_err(|e| format!("failed to serialise connect response: {e}"))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ./common && cargo test --features nip46 test_build_connect_response_with_secret`

Expected: PASS.

- [ ] **Step 5: Add connect_secret parameter to handle_request**

In `firmware/src/nip46_handler.rs`, add `connect_secret: &[u8; 32]` to `handle_request`'s parameter list (after `master_slot: u8`).

Update the `"connect"` match arm (line ~102) to validate the secret:

```rust
"connect" => {
    // NIP-46: validate connect secret from params[1].
    let client_secret = request.params.get(1).and_then(|v| v.as_str());
    let expected_hex = heartwood_common::hex::hex_encode(connect_secret);

    match client_secret {
        Some(s) if constant_time_eq(s.as_bytes(), expected_hex.as_bytes()) => {
            // Secret valid — echo it back per NIP-46 spec.
            Some(nip46::build_connect_response_with_secret(&request.id, &expected_hex)
                .unwrap_or_default())
        }
        Some(_) => {
            log::warn!("connect: invalid connect secret");
            Some(build_error_json(&request.id, -1, "invalid connect secret"))
        }
        None => {
            // No secret provided — reject. NIP-46 requires it when bunker:// URI has secret=.
            log::warn!("connect: no connect secret provided");
            Some(build_error_json(&request.id, -1, "connect secret required"))
        }
    }
}
```

Add a `constant_time_eq` helper at the bottom of the file:

```rust
/// Constant-time byte comparison to prevent timing side-channels on secrets.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

- [ ] **Step 6: Update call sites in main.rs and transport.rs**

In `firmware/src/main.rs` (line ~263), the plaintext dispatch call to `handle_request` — add `&master.connect_secret` after `master.slot`:

```rust
if let Some(response_json) = nip46_handler::handle_request(
    &mut usb,
    &frame,
    &master.secret,
    &master.label,
    master.mode,
    master.slot,
    &master.connect_secret,
    &secp,
    &mut display,
    &button_pin,
    &mut policy_engine,
    &mut identity_caches,
) {
```

In `firmware/src/transport.rs` (line ~110), the encrypted dispatch call — add `&master.connect_secret`:

```rust
if let Some(response_json) = crate::nip46_handler::handle_request(
    usb,
    &inner_frame,
    &master.secret,
    &master.label,
    master.mode,
    master.slot,
    &master.connect_secret,
    secp,
    display,
    button_pin,
    policy_engine,
    identity_caches,
) {
```

- [ ] **Step 7: Remove the `let _ = master_label;` suppression**

In `firmware/src/nip46_handler.rs` line ~90, remove `let _ = master_label;` — it will be used in later tasks for OLED display. Keep `let _ = policy_engine;` for now (wired up in Task 6).

- [ ] **Step 8: Run common tests**

Run: `cd ./common && cargo test --features nip46`

Expected: All pass.

- [ ] **Step 9: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/nip46.rs firmware/src/nip46_handler.rs firmware/src/main.rs firmware/src/transport.rs
git commit -m "fix(nip46): validate connect secret from bunker:// URI"
```

---

## Task 3: Bridge Secret Provisioning Frame

**Files:**
- Modify: `common/src/types.rs:42` (add FRAME_TYPE_SET_BRIDGE_SECRET)
- Modify: `firmware/src/session.rs` (add handle_set_bridge_secret)
- Modify: `firmware/src/main.rs` (add dispatch arm for 0x23)

- [ ] **Step 1: Add the frame type constant**

In `common/src/types.rs`, after line 41 (`FRAME_TYPE_SESSION_ACK`), add:

```rust
pub const FRAME_TYPE_SET_BRIDGE_SECRET: u8 = 0x23;
```

- [ ] **Step 2: Add the handler in session.rs**

In `firmware/src/session.rs`, add after `handle_auth`:

```rust
/// Handle a SET_BRIDGE_SECRET frame (0x23).
///
/// Sets the 32-byte bridge authentication secret in NVS. Only accepted
/// when no bridge session is currently authenticated — prevents a
/// compromised bridge from rotating the secret while connected.
///
/// Requires physical button approval (2-second hold) since this is a
/// security-critical operation.
pub fn handle_set_bridge_secret(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    policy_engine: &PolicyEngine,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    if policy_engine.bridge_authenticated {
        log::warn!("SET_BRIDGE_SECRET rejected — bridge is currently authenticated");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    if payload.len() != 32 {
        log::warn!("SET_BRIDGE_SECRET payload is {} bytes, expected 32", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    // Show confirmation on OLED and wait for button approval.
    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            let msg = format!("Set bridge\nsecret? {}s", remaining);
            crate::oled::show_error(d, &msg);
        },
    );

    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("SET_BRIDGE_SECRET denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let secret: [u8; 32] = payload.try_into().unwrap();
    match write_bridge_secret(nvs, &secret) {
        Ok(()) => {
            log::info!("Bridge secret written to NVS");
            crate::oled::show_error(display, "Bridge secret\nset!");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        }
        Err(e) => {
            log::error!("Failed to write bridge secret: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
```

- [ ] **Step 3: Create approval.rs — shared approval loop**

Create `firmware/src/approval.rs` (this module is reused by Tasks 4 and 5):

```rust
// firmware/src/approval.rs
//
// Shared button approval loop used by bridge secret provisioning,
// sign_event, factory reset, and OTA — any operation needing
// interactive confirmation.

use esp_idf_hal::gpio::{Input, PinDriver};
use std::time::{Duration, Instant};

use crate::oled::Display;

/// Result of the approval loop.
pub enum ApprovalResult {
    Approved,
    Denied,
    TimedOut,
}

/// Run the interactive button approval loop.
///
/// Shows `show_fn` on the OLED each second with the remaining countdown,
/// waits for a 2-second button hold. Returns the approval result.
pub fn run_approval_loop<F>(
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    timeout_secs: u64,
    mut show_fn: F,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32),
{
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut last_remaining = timeout_secs as u32 + 1;
    let mut pressed = false;
    let mut press_start = Instant::now();

    loop {
        let now = Instant::now();
        if now >= deadline {
            return ApprovalResult::TimedOut;
        }

        let remaining = (deadline - now).as_secs() as u32;

        if remaining != last_remaining && !pressed {
            show_fn(display, remaining);
            last_remaining = remaining;
        }

        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = now;
            crate::oled::show_error(display, "Hold 2s...");
        }
        if low && pressed {
            if now.duration_since(press_start) >= Duration::from_millis(2000) {
                crate::oled::show_error(display, "Approved!");
                esp_idf_hal::delay::FreeRtos::delay_ms(300);
                return ApprovalResult::Approved;
            }
        }
        if !low && pressed {
            crate::oled::show_error(display, "Denied (short)");
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            return ApprovalResult::Denied;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}
```

Add `mod approval;` to `firmware/src/main.rs`.

- [ ] **Step 4: Add dispatch in main.rs**

In `firmware/src/main.rs`, in the frame dispatch match block, add after the `FRAME_TYPE_SESSION_AUTH` arm (line ~333):

```rust
// 0x23 — set bridge secret
FRAME_TYPE_SET_BRIDGE_SECRET => {
    session::handle_set_bridge_secret(
        &mut usb,
        &frame.payload,
        &mut nvs,
        &policy_engine,
        &mut display,
        &button_pin,
    );
}
```

Add `FRAME_TYPE_SET_BRIDGE_SECRET` to the `use` import at the top of `main.rs` (line ~44-48).

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/types.rs firmware/src/session.rs firmware/src/approval.rs firmware/src/main.rs
git commit -m "feat: bridge secret provisioning frame (0x23) with approval module"
```

---

## Task 4: sign_event Encrypted Response + Handler Refactor

**Files:**
- Modify: `firmware/src/nip46_handler.rs` (refactor handle_sign_event to return String, extract approval loop)
- Modify: `firmware/src/transport.rs:109` (remove None handling)
- Modify: `firmware/src/main.rs:263-283` (remove None handling)
- Create: `firmware/src/approval.rs` (shared button approval loop)

This is the biggest refactoring task. `handle_sign_event` currently writes its own frame directly. After this, every method returns `String` and the caller handles framing.

- [ ] **Step 1: Refactor handle_sign_event to return String**

`approval.rs` was created in Task 3. Now use it to refactor sign_event.

In `firmware/src/nip46_handler.rs`:

1. Change `handle_sign_event` signature — remove `usb` parameter, return `String`:

```rust
fn handle_sign_event(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    request: &nip46::Nip46Request,
) -> String {
```

2. Replace the inline button loop with `approval::run_approval_loop`:

```rust
    let event = match nip46::parse_unsigned_event(&request.params) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("sign_event: bad event format: {e}");
            return build_error_json(&request.id, -3, "bad event format");
        }
    };

    let (kind, content_preview) = nip46::event_display_summary(&event, 50);
    let purpose = request
        .heartwood
        .as_ref()
        .map(|h| h.purpose.as_str())
        .unwrap_or("master");

    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        APPROVAL_TIMEOUT_SECS,
        |d, remaining| {
            crate::oled::show_sign_request(d, purpose, kind, &content_preview, remaining);
        },
    );

    match result {
        crate::approval::ApprovalResult::Approved => {
            log::info!("sign_event: approved");
            crate::oled::show_error(display, "Signing...");
            match do_sign(&event, master_secret, secp, request.heartwood.as_ref()) {
                Ok(signed) => {
                    match nip46::build_sign_response(&request.id, &signed) {
                        Ok(json) => {
                            crate::oled::show_result(display, "Signed!");
                            json
                        }
                        Err(e) => {
                            log::error!("Failed to build sign response: {e}");
                            build_error_json(&request.id, -4, "signing failed")
                        }
                    }
                }
                Err(ref e) => {
                    log::error!("Signing failed: {e}");
                    crate::oled::show_error(display, &format!("ERR:{}", &e[..e.len().min(18)]));
                    esp_idf_hal::delay::FreeRtos::delay_ms(3000);
                    crate::oled::show_result(display, "Sign error");
                    build_error_json(&request.id, -4, "signing/derivation failure")
                }
            }
        }
        crate::approval::ApprovalResult::Denied => {
            log::info!("sign_event: denied by user");
            crate::oled::show_result(display, "Denied");
            build_error_json(&request.id, -1, "user denied")
        }
        crate::approval::ApprovalResult::TimedOut => {
            log::info!("sign_event: timed out");
            crate::oled::show_result(display, "Timed out");
            build_error_json(&request.id, -1, "timeout")
        }
    }
```

3. Update the `"sign_event"` match arm in `handle_request` (line ~94) to return `Some`:

```rust
"sign_event" => {
    Some(handle_sign_event(master_secret, secp, display, button_pin, &request))
}
```

Remove `usb` from the `handle_sign_event` call — it no longer needs it.

- [ ] **Step 2: Remove the `send_error` helper**

Delete the `send_error` function at the bottom of `nip46_handler.rs` (line ~779-789). It's no longer needed since sign_event returns strings.

- [ ] **Step 3: Change handle_request return type to String**

Now that every match arm returns `Some(...)`, change the return type from `Option<String>` to `String`. Remove all `Some(...)` wrappers and the `None` return for parse failures. The parse failure at line ~73-79 should return a NACK error string:

```rust
pub fn handle_request(
    // ... same params but remove `usb: &mut UsbSerialDriver<'_>` ...
    // The handler no longer writes directly to USB.
) -> String {
    let request = match nip46::parse_request(&frame.payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse NIP-46 request: {e}");
            return nip46::build_error_response("unknown", -3, "invalid JSON-RPC request")
                .unwrap_or_default();
        }
    };
    // ... rest of match arms, removing all Some(...) wrappers ...
```

- [ ] **Step 4: Update callers in main.rs**

In `firmware/src/main.rs`, the plaintext dispatch (line ~263):

```rust
FRAME_TYPE_NIP46_REQUEST => {
    if policy_engine.bridge_authenticated {
        log::warn!("Plaintext NIP-46 rejected — bridge is authenticated; use encrypted channel");
        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
    } else if loaded_masters.is_empty() {
        log::warn!("NIP-46 request with no masters loaded");
        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
    } else {
        let master = &loaded_masters[0];
        let response_json = nip46_handler::handle_request(
            &frame,
            &master.secret,
            &master.label,
            master.mode,
            master.slot,
            &master.connect_secret,
            &secp,
            &mut display,
            &button_pin,
            &mut policy_engine,
            &mut identity_caches,
        );
        protocol::write_frame(
            &mut usb,
            FRAME_TYPE_NIP46_RESPONSE,
            response_json.as_bytes(),
        );
        oled::show_boot(&mut display, loaded_masters.len() as u8);
    }
}
```

- [ ] **Step 5: Update transport.rs**

In `firmware/src/transport.rs`, the encrypted dispatch (line ~110):

```rust
let response_json = crate::nip46_handler::handle_request(
    &inner_frame,
    &master.secret,
    &master.label,
    master.mode,
    master.slot,
    &master.connect_secret,
    secp,
    display,
    button_pin,
    policy_engine,
    identity_caches,
);

// Always encrypt the response — no more plaintext 0x03 leak.
let nonce = random_nonce_24();
match nip44::encrypt(&conversation_key, &response_json, &nonce) {
    Ok(ciphertext_b64) => {
        let mut response_payload = Vec::with_capacity(32 + ciphertext_b64.len());
        response_payload.extend_from_slice(&client_pubkey);
        response_payload.extend_from_slice(ciphertext_b64.as_bytes());
        protocol::write_frame(usb, FRAME_TYPE_ENCRYPTED_RESPONSE, &response_payload);
    }
    Err(e) => {
        log::error!("NIP-44 encrypt response failed: {e}");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    }
}
```

Remove the `if let Some(...)` wrapper — the handler always returns a String now.

- [ ] **Step 6: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/nip46_handler.rs firmware/src/transport.rs firmware/src/main.rs
git commit -m "refactor(nip46): sign_event returns encrypted response in passthrough mode"
```

---

## Task 5: Factory Reset Frame

**Files:**
- Modify: `common/src/types.rs` (add FRAME_TYPE_FACTORY_RESET)
- Modify: `firmware/src/provision.rs` (add handle_factory_reset)
- Modify: `firmware/src/main.rs` (add dispatch arm)

- [ ] **Step 1: Add frame type constant**

In `common/src/types.rs`, add after `FRAME_TYPE_SET_BRIDGE_SECRET`:

```rust
pub const FRAME_TYPE_FACTORY_RESET: u8 = 0x24;
```

- [ ] **Step 2: Add handle_factory_reset in provision.rs**

In `firmware/src/provision.rs`, add:

```rust
/// Handle a FACTORY_RESET frame (0x24).
///
/// Erases all NVS keys in the `heartwood` namespace and reboots the device.
/// Requires physical button approval (2-second hold) — this is irreversible.
pub fn handle_factory_reset(
    usb: &mut UsbSerialDriver<'_>,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            crate::oled::show_sign_request(d, "FACTORY", 0, "ERASE ALL DATA?", remaining);
        },
    );

    match result {
        crate::approval::ApprovalResult::Approved => {
            log::warn!("Factory reset approved — erasing NVS");
            crate::oled::show_error(display, "Erasing...");

            // Erase all master keys.
            let count = masters::read_master_count(nvs);
            for slot in 0..count {
                let _ = masters::remove_master(nvs, 0); // always remove slot 0 as they shift down
            }

            // Erase bridge secret and policy keys.
            let _ = nvs.remove("bridge_secret");
            for i in 0..8u8 {
                let key = format!("policy_{i}");
                let _ = nvs.remove(&key);
            }

            crate::oled::show_error(display, "Reset complete\nRebooting...");
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);

            // Reboot the device.
            unsafe { esp_idf_svc::sys::esp_restart(); }
        }
        crate::approval::ApprovalResult::Denied => {
            log::info!("Factory reset denied");
            crate::oled::show_result(display, "Reset cancelled");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
        crate::approval::ApprovalResult::TimedOut => {
            log::info!("Factory reset timed out");
            crate::oled::show_result(display, "Timed out");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
```

- [ ] **Step 3: Add dispatch in main.rs**

In the frame dispatch match block, add after `FRAME_TYPE_SET_BRIDGE_SECRET`:

```rust
// 0x24 — factory reset
FRAME_TYPE_FACTORY_RESET => {
    provision::handle_factory_reset(
        &mut usb,
        &mut nvs,
        &mut display,
        &button_pin,
    );
}
```

Add `FRAME_TYPE_FACTORY_RESET` to the import.

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/types.rs firmware/src/provision.rs firmware/src/main.rs
git commit -m "feat: factory reset frame (0x24) with button confirmation"
```

---

## Task 6: Policy-Driven Auto-Approval (TOFU) + Policy Persistence

**Files:**
- Modify: `firmware/src/nip46_handler.rs` (wire up PolicyEngine, add TOFU)
- Modify: `firmware/src/transport.rs` (pass client_pubkey to handler)
- Modify: `firmware/src/main.rs` (pass client_pubkey=None for plaintext, load policies on boot)
- Modify: `firmware/src/policy.rs` (add NVS persist/load, add TOFU method)
- Modify: `firmware/src/session.rs` (persist on POLICY_PUSH)
- Modify: `common/src/policy.rs` (add TOFU_SAFE_METHODS constant)

This task combines spec items 5 and 8 since TOFU generates the policies that need persisting.

- [ ] **Step 1: Add TOFU_SAFE_METHODS to common/src/policy.rs**

```rust
/// Methods auto-approved after first TOFU approval.
/// High-stakes methods (heartwood_derive, heartwood_recover, etc.) are
/// excluded — they always require button regardless of policy.
pub const TOFU_SAFE_METHODS: &[&str] = &[
    "sign_event",
    "nip44_encrypt",
    "nip44_decrypt",
    "nip04_encrypt",
    "nip04_decrypt",
    "get_public_key",
];
```

- [ ] **Step 2: Add client_pubkey parameter to handle_request**

In `firmware/src/nip46_handler.rs`, add `client_pubkey: Option<&[u8; 32]>` parameter to `handle_request` (after `identity_caches`).

- [ ] **Step 3: Wire up PolicyEngine::check() in the handler**

At the top of `handle_request`, after parsing the request, add the policy check:

```rust
// Remove the old suppression.
// let _ = policy_engine;  <-- DELETE THIS LINE

let method = nip46::Nip46Method::from_str(&request.method);
let event_kind = if matches!(method, nip46::Nip46Method::SignEvent) {
    nip46::parse_unsigned_event(&request.params)
        .ok()
        .map(|e| e.kind)
} else {
    None
};

// Determine approval tier from policy.
let client_hex = client_pubkey
    .map(|pk| heartwood_common::hex::hex_encode(pk))
    .unwrap_or_default();
let tier = if client_pubkey.is_some() {
    policy_engine.check(master_slot, &client_hex, &method, event_kind)
} else {
    // No client pubkey (plaintext mode) — always require button.
    heartwood_common::policy::ApprovalTier::ButtonRequired
};
```

- [ ] **Step 4: Add auto-approve and OLED-notify paths for sign_event**

Modify the `"sign_event"` match arm to check the tier:

```rust
"sign_event" => {
    match tier {
        heartwood_common::policy::ApprovalTier::AutoApprove => {
            log::info!("sign_event: auto-approved by policy");
            match handle_auto_sign(master_secret, secp, &request) {
                Ok(json) => json,
                Err(e) => build_error_json(&request.id, -4, &e),
            }
        }
        heartwood_common::policy::ApprovalTier::OledNotify => {
            crate::oled::show_auto_approved(display, master_label, "sign_event");
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);
            match handle_auto_sign(master_secret, secp, &request) {
                Ok(json) => json,
                Err(e) => build_error_json(&request.id, -4, &e),
            }
        }
        heartwood_common::policy::ApprovalTier::ButtonRequired => {
            let result = handle_sign_event(master_secret, secp, display, button_pin, &request);
            // TOFU: if approved and we have a client pubkey, remember this client.
            if client_pubkey.is_some() && !result.contains("\"error\"") {
                tofu_approve(policy_engine, master_slot, &client_hex);
            }
            result
        }
    }
}
```

Add the `handle_auto_sign` helper:

```rust
/// Sign an event without interactive approval (auto-approved by policy).
fn handle_auto_sign(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) -> Result<String, String> {
    let event = nip46::parse_unsigned_event(&request.params)
        .map_err(|e| format!("bad event format: {e}"))?;
    let signed = do_sign(&event, master_secret, secp, request.heartwood.as_ref())?;
    nip46::build_sign_response(&request.id, &signed)
}
```

- [ ] **Step 5: Add TOFU for encrypt/decrypt methods**

For the encrypt/decrypt match arms, wrap them similarly. These are simpler — they don't have an interactive approval flow, so just gate on tier:

```rust
"nip44_encrypt" => {
    match tier {
        heartwood_common::policy::ApprovalTier::ButtonRequired => {
            // For encrypt/decrypt, no interactive approval — just reject if no policy.
            // UNLESS this is the first time (TOFU) — then auto-approve and remember.
            if client_pubkey.is_some() {
                tofu_approve(policy_engine, master_slot, &client_hex);
            }
            handle_nip44_encrypt(master_secret, &request)
        }
        _ => handle_nip44_encrypt(master_secret, &request),
    }
}
```

Actually, simpler approach: encrypt/decrypt don't need button approval at all — they're safe operations. Just auto-approve them always (they're in `TOFU_SAFE_METHODS` but shouldn't need first-time button approval). The TOFU gate should only be on `sign_event`. Change the encrypt/decrypt arms to just call the handler directly — no tier check needed. The TOFU policy will ensure they're listed in the client's `allowed_methods` for future reference.

- [ ] **Step 6: Add tofu_approve helper**

```rust
/// TOFU: after first manual approval, remember this client for auto-approval.
fn tofu_approve(policy_engine: &mut PolicyEngine, master_slot: u8, client_hex: &str) {
    use heartwood_common::policy::{ClientPolicy, TOFU_SAFE_METHODS};

    // Check if client already has a policy.
    let existing = policy_engine.master_policies
        .iter()
        .any(|mp| mp.master_slot == master_slot
            && mp.policies.iter().any(|p| p.client_pubkey == client_hex));

    if existing {
        return; // Already approved.
    }

    let policy = ClientPolicy {
        client_pubkey: client_hex.to_string(),
        label: String::new(),
        allowed_methods: TOFU_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
        allowed_kinds: vec![], // All kinds allowed.
        auto_approve: true,
    };

    policy_engine.add_tofu_policy(master_slot, policy);
    log::info!("TOFU: auto-approved client {}", &client_hex[..16]);
}
```

- [ ] **Step 7: Add PolicyEngine::add_tofu_policy and NVS persistence**

In `firmware/src/policy.rs`, add:

```rust
impl PolicyEngine {
    /// Add a TOFU-generated policy for a client. Merges into existing
    /// policies for this master slot.
    pub fn add_tofu_policy(&mut self, master_slot: u8, policy: ClientPolicy) {
        match self.master_policies.iter_mut().find(|mp| mp.master_slot == master_slot) {
            Some(mp) => mp.policies.push(policy),
            None => {
                self.master_policies.push(MasterPolicies {
                    master_slot,
                    policies: vec![policy],
                });
            }
        }
    }

    /// Persist all policies for a master slot to NVS.
    pub fn persist_policies(
        &self,
        nvs: &mut EspNvs<NvsDefault>,
        master_slot: u8,
    ) {
        let policies = self.master_policies
            .iter()
            .find(|mp| mp.master_slot == master_slot);

        let key = format!("policy_{master_slot}");
        match policies {
            Some(mp) => {
                match serde_json::to_string(&mp.policies) {
                    Ok(json) => {
                        if let Err(e) = nvs.set_blob(&key, json.as_bytes()) {
                            log::error!("Failed to persist policies for slot {master_slot}: {e:?}");
                        }
                    }
                    Err(e) => log::error!("Failed to serialise policies: {e}"),
                }
            }
            None => {
                let _ = nvs.remove(&key);
            }
        }
    }

    /// Load persisted policies from NVS for all master slots.
    pub fn load_from_nvs(nvs: &EspNvs<NvsDefault>, master_count: u8) -> Self {
        let mut engine = Self::new();
        for slot in 0..master_count {
            let key = format!("policy_{slot}");
            let mut buf = [0u8; 4096]; // Max NVS blob
            if let Ok(Some(data)) = nvs.get_blob(&key, &mut buf) {
                if let Ok(policies) = serde_json::from_slice::<Vec<ClientPolicy>>(data) {
                    let count = policies.len();
                    engine.master_policies.push(MasterPolicies {
                        master_slot: slot,
                        policies,
                    });
                    log::info!("Loaded {count} persisted policies for slot {slot}");
                }
            }
        }
        engine
    }
}
```

Add required imports to `policy.rs`:

```rust
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::policy::ClientPolicy;
```

- [ ] **Step 8: Persist after TOFU and POLICY_PUSH**

In `firmware/src/nip46_handler.rs`, after `tofu_approve` is called, also persist. This requires `nvs` access — either pass `nvs` to the handler or use a different approach. The simplest is to add `nvs: &mut EspNvs<NvsDefault>` to `handle_request` and persist inside `tofu_approve`.

Alternatively, persist in `main.rs` after `handle_request` returns, by checking if policies changed. Simpler: persist after every sign_event that was ButtonRequired and succeeded.

In `firmware/src/main.rs`, after the plaintext dispatch:

```rust
// After handle_request returns, persist policies if TOFU may have added one.
// This is cheap if nothing changed (NVS write is skipped for identical data).
if !loaded_masters.is_empty() {
    policy_engine.persist_policies(&mut nvs, loaded_masters[0].slot);
}
```

Similarly in `transport.rs` after the encrypted dispatch, persist for the relevant master slot.

In `firmware/src/session.rs` `handle_policy_push`, after `policy_engine.set_policies(slot, policies)` add NVS persistence:

```rust
policy_engine.persist_policies(nvs, slot);
```

This requires `handle_policy_push` to take `&mut EspNvs<NvsDefault>` — add it to the signature and pass it from main.rs.

- [ ] **Step 9: Load policies on boot**

In `firmware/src/main.rs`, replace line ~167:

```rust
// --- Policy engine (load persisted policies from NVS) ---
let mut policy_engine = policy::PolicyEngine::load_from_nvs(&nvs, loaded_masters.len() as u8);
```

- [ ] **Step 10: Update call sites for new parameters**

Update all calls to `handle_request` in `main.rs` and `transport.rs` to pass the new `client_pubkey` parameter:

- `main.rs` plaintext dispatch: pass `None` (no client pubkey in plaintext mode)
- `transport.rs` encrypted dispatch: pass `Some(&client_pubkey)` (extracted from frame header)

Update `handle_policy_push` call in `main.rs` to pass `&mut nvs`.

- [ ] **Step 11: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add common/src/policy.rs firmware/src/nip46_handler.rs firmware/src/transport.rs firmware/src/main.rs firmware/src/policy.rs firmware/src/session.rs
git commit -m "feat: TOFU auto-approval with NVS-persisted policies"
```

---

## Task 7: Serial OTA — Partition Table + sdkconfig

**Files:**
- Create: `firmware/partitions.csv`
- Modify: `firmware/sdkconfig.defaults`
- Modify: `common/src/types.rs` (OTA frame constants)

- [ ] **Step 1: Create the partition table**

Create `firmware/partitions.csv`:

```csv
# Name,    Type, SubType, Offset,   Size,   Flags
nvs,       data, nvs,     ,         0x4000,
otadata,   data, ota,     ,         0x2000,
phy_init,  data, phy,     ,         0x1000,
ota_0,     app,  ota_0,   ,         0xE0000,
ota_1,     app,  ota_0,   ,         0xE0000,
```

Note: the second OTA slot has SubType `ota_0` because esp-idf only requires distinct partition names — the bootloader uses `otadata` to select the active slot, not the SubType. Actually, correct this — it should be `ota_1`:

```csv
# Name,    Type, SubType, Offset,   Size,   Flags
nvs,       data, nvs,     ,         0x4000,
otadata,   data, ota,     ,         0x2000,
phy_init,  data, phy,     ,         0x1000,
ota_0,     app,  ota_0,   ,         0xE0000,
ota_1,     app,  ota_1,   ,         0xE0000,
```

- [ ] **Step 2: Update sdkconfig.defaults**

Add to `firmware/sdkconfig.defaults`:

```
# OTA support
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
```

- [ ] **Step 3: Add OTA frame type constants**

In `common/src/types.rs`, add:

```rust
// --- OTA frame types ---
pub const FRAME_TYPE_OTA_BEGIN: u8 = 0x30;
pub const FRAME_TYPE_OTA_CHUNK: u8 = 0x31;
pub const FRAME_TYPE_OTA_FINISH: u8 = 0x32;
pub const FRAME_TYPE_OTA_STATUS: u8 = 0x33;

// OTA status codes (payload byte 0 of OTA_STATUS frame)
pub const OTA_STATUS_READY: u8 = 0x00;
pub const OTA_STATUS_CHUNK_OK: u8 = 0x01;
pub const OTA_STATUS_VERIFIED: u8 = 0x02;
pub const OTA_STATUS_ERR_HASH: u8 = 0x10;
pub const OTA_STATUS_ERR_SIZE: u8 = 0x11;
pub const OTA_STATUS_ERR_WRITE: u8 = 0x12;
pub const OTA_STATUS_ERR_NOT_STARTED: u8 = 0x13;
```

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/partitions.csv firmware/sdkconfig.defaults common/src/types.rs
git commit -m "feat: OTA partition table and frame type constants"
```

---

## Task 8: Serial OTA — Firmware Handler

**Files:**
- Create: `firmware/src/ota.rs`
- Modify: `firmware/src/main.rs` (dispatch OTA frames, add rollback confirmation on boot)

- [ ] **Step 1: Create firmware/src/ota.rs**

```rust
// firmware/src/ota.rs
//
// Serial OTA update handler. Receives firmware chunks over the serial
// frame protocol, writes them to the inactive OTA partition, verifies
// the SHA-256 hash, and reboots into the new firmware.

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;
use sha2::{Digest, Sha256};

use heartwood_common::types::*;
use crate::oled::Display;
use crate::protocol;

/// OTA session state. Created on OTA_BEGIN, consumed on OTA_FINISH.
pub struct OtaSession {
    /// Expected total firmware size in bytes.
    pub total_size: u32,
    /// Expected SHA-256 hash of the complete firmware image.
    pub expected_hash: [u8; 32],
    /// Bytes received so far.
    pub bytes_received: u32,
    /// Running SHA-256 hasher.
    pub hasher: Sha256,
    /// ESP-IDF OTA handle.
    pub ota_handle: esp_idf_svc::sys::esp_ota_handle_t,
    /// Target partition pointer.
    pub partition: *const esp_idf_svc::sys::esp_partition_t,
}

/// Handle OTA_BEGIN frame (0x30).
///
/// Payload: [total_size_u32_be][sha256_32] = 36 bytes.
/// Requires button approval before starting.
pub fn handle_ota_begin(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    session: &mut Option<OtaSession>,
) {
    if payload.len() != 36 {
        log::warn!("OTA_BEGIN payload is {} bytes, expected 36", payload.len());
        send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "bad payload size");
        return;
    }

    let total_size = u32::from_be_bytes(payload[0..4].try_into().unwrap());
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&payload[4..36]);

    let size_kb = total_size / 1024;
    let msg = format!("OTA update?\n{}KB firmware", size_kb);
    crate::oled::show_error(display, &msg);

    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            let prompt = format!("OTA {}KB\nHold to approve\n{}s", size_kb, remaining);
            crate::oled::show_error(d, &prompt);
        },
    );

    match result {
        crate::approval::ApprovalResult::Approved => {
            log::info!("OTA approved — opening partition for {}KB write", size_kb);
        }
        _ => {
            log::info!("OTA denied or timed out");
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "denied");
            return;
        }
    }

    // Find the next OTA partition and begin writing.
    unsafe {
        let partition = esp_idf_svc::sys::esp_ota_get_next_update_partition(std::ptr::null());
        if partition.is_null() {
            log::error!("No OTA partition found");
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "no OTA partition");
            return;
        }

        let mut handle: esp_idf_svc::sys::esp_ota_handle_t = 0;
        let err = esp_idf_svc::sys::esp_ota_begin(partition, total_size as usize, &mut handle);
        if err != esp_idf_svc::sys::ESP_OK {
            log::error!("esp_ota_begin failed: {}", err);
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "ota_begin failed");
            return;
        }

        *session = Some(OtaSession {
            total_size,
            expected_hash,
            bytes_received: 0,
            hasher: Sha256::new(),
            ota_handle: handle,
            partition,
        });
    }

    crate::oled::show_error(display, "OTA started\nReceiving...");
    send_ota_status(usb, OTA_STATUS_READY, "ready");
}

/// Handle OTA_CHUNK frame (0x31).
///
/// Payload: [offset_u32_be][data...].
pub fn handle_ota_chunk(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    display: &mut Display<'_>,
    session: &mut Option<OtaSession>,
) {
    let sess = match session.as_mut() {
        Some(s) => s,
        None => {
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "no OTA session");
            return;
        }
    };

    if payload.len() < 5 {
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "chunk too short");
        return;
    }

    let offset = u32::from_be_bytes(payload[0..4].try_into().unwrap());
    let data = &payload[4..];

    if offset != sess.bytes_received {
        log::warn!("OTA chunk offset mismatch: expected {}, got {}", sess.bytes_received, offset);
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "offset mismatch");
        return;
    }

    // Write chunk to OTA partition.
    unsafe {
        let err = esp_idf_svc::sys::esp_ota_write(
            sess.ota_handle,
            data.as_ptr() as *const core::ffi::c_void,
            data.len(),
        );
        if err != esp_idf_svc::sys::ESP_OK {
            log::error!("esp_ota_write failed: {}", err);
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "write failed");
            return;
        }
    }

    sess.hasher.update(data);
    sess.bytes_received += data.len() as u32;

    // Update OLED with progress.
    let pct = (sess.bytes_received as u64 * 100) / sess.total_size as u64;
    let msg = format!("OTA {}%\n{}KB / {}KB",
        pct,
        sess.bytes_received / 1024,
        sess.total_size / 1024,
    );
    crate::oled::show_error(display, &msg);

    send_ota_status(usb, OTA_STATUS_CHUNK_OK, "");
}

/// Handle OTA_FINISH frame (0x32).
///
/// Verifies the SHA-256 hash, sets the new partition as boot target, reboots.
pub fn handle_ota_finish(
    usb: &mut UsbSerialDriver<'_>,
    display: &mut Display<'_>,
    session: &mut Option<OtaSession>,
) {
    let sess = match session.take() {
        Some(s) => s,
        None => {
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "no OTA session");
            return;
        }
    };

    if sess.bytes_received != sess.total_size {
        log::error!(
            "OTA size mismatch: received {} bytes, expected {}",
            sess.bytes_received, sess.total_size
        );
        send_ota_status(usb, OTA_STATUS_ERR_SIZE, "size mismatch");
        return;
    }

    // Verify SHA-256 hash.
    let computed_hash: [u8; 32] = sess.hasher.finalize().into();
    if computed_hash != sess.expected_hash {
        log::error!("OTA hash mismatch");
        send_ota_status(usb, OTA_STATUS_ERR_HASH, "hash mismatch");
        unsafe {
            esp_idf_svc::sys::esp_ota_abort(sess.ota_handle);
        }
        return;
    }

    // Finalise and set as boot partition.
    unsafe {
        let err = esp_idf_svc::sys::esp_ota_end(sess.ota_handle);
        if err != esp_idf_svc::sys::ESP_OK {
            log::error!("esp_ota_end failed: {}", err);
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "ota_end failed");
            return;
        }

        let err = esp_idf_svc::sys::esp_ota_set_boot_partition(sess.partition);
        if err != esp_idf_svc::sys::ESP_OK {
            log::error!("esp_ota_set_boot_partition failed: {}", err);
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "set_boot failed");
            return;
        }
    }

    crate::oled::show_error(display, "OTA verified!\nRebooting...");
    send_ota_status(usb, OTA_STATUS_VERIFIED, "rebooting");
    esp_idf_hal::delay::FreeRtos::delay_ms(1000);

    unsafe { esp_idf_svc::sys::esp_restart(); }
}

/// Send an OTA_STATUS frame.
fn send_ota_status(usb: &mut UsbSerialDriver<'_>, code: u8, message: &str) {
    let mut payload = vec![code];
    payload.extend_from_slice(message.as_bytes());
    protocol::write_frame(usb, FRAME_TYPE_OTA_STATUS, &payload);
}
```

Add `mod ota;` to `firmware/src/main.rs`.

- [ ] **Step 2: Add OTA dispatch in main.rs**

In the frame dispatch match block, add:

```rust
// 0x30 — OTA begin
FRAME_TYPE_OTA_BEGIN => {
    ota::handle_ota_begin(
        &mut usb,
        &frame.payload,
        &mut display,
        &button_pin,
        &mut ota_session,
    );
}

// 0x31 — OTA chunk
FRAME_TYPE_OTA_CHUNK => {
    ota::handle_ota_chunk(
        &mut usb,
        &frame.payload,
        &mut display,
        &mut ota_session,
    );
}

// 0x32 — OTA finish
FRAME_TYPE_OTA_FINISH => {
    ota::handle_ota_finish(
        &mut usb,
        &mut display,
        &mut ota_session,
    );
}
```

Add `let mut ota_session: Option<ota::OtaSession> = None;` before the dispatch loop.

Add the OTA frame type imports to the `use` block at the top.

- [ ] **Step 3: Add rollback confirmation on boot**

At the end of the boot sequence in `main.rs`, before the dispatch loop (after the policy engine init):

```rust
// Confirm OTA rollback — mark the current firmware as valid.
// If this line is not reached (crash during boot), the bootloader
// will revert to the previous OTA partition on next reboot.
unsafe {
    let err = esp_idf_svc::sys::esp_ota_mark_app_valid_cancel_rollback();
    if err == esp_idf_svc::sys::ESP_OK {
        log::info!("OTA: firmware marked as valid (rollback cancelled)");
    } else if err == esp_idf_svc::sys::ESP_ERR_NOT_FOUND as i32 {
        // Not an OTA boot — first flash via espflash. Normal.
        log::info!("OTA: not an OTA boot (first flash)");
    } else {
        log::warn!("OTA: mark_valid returned {}", err);
    }
}
```

- [ ] **Step 4: Add sha2 dependency to firmware Cargo.toml**

In `firmware/Cargo.toml`, add:

```toml
sha2 = "0.10"
```

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/ota.rs firmware/src/main.rs firmware/Cargo.toml
git commit -m "feat: serial OTA update handler with SHA-256 verification and rollback"
```

---

## Task 9: Pi-side OTA Tool

**Files:**
- Create: `ota/Cargo.toml`
- Create: `ota/src/main.rs`

- [ ] **Step 1: Create ota/Cargo.toml**

```toml
[package]
name = "heartwood-ota"
version = "0.1.0"
edition = "2021"
description = "Pi-side OTA firmware update tool for heartwood-esp32"

[dependencies]
heartwood-common = { path = "../common", default-features = false }
clap = { version = "4", features = ["derive"] }
serialport = "4"
sha2 = "0.10"
indicatif = "0.17"
```

- [ ] **Step 2: Create ota/src/main.rs**

```rust
// ota/src/main.rs
//
// Pi-side OTA tool for heartwood-esp32.
//
// Usage: heartwood-ota --port /dev/ttyUSB0 --firmware heartwood.bin

use std::fs;
use std::io::{Read, Write};
use std::time::Duration;

use clap::Parser;
use sha2::{Digest, Sha256};
use indicatif::{ProgressBar, ProgressStyle};

use heartwood_common::frame;
use heartwood_common::types::*;

#[derive(Parser)]
#[command(name = "heartwood-ota")]
#[command(about = "Flash firmware to heartwood-esp32 over serial OTA")]
struct Args {
    /// Serial port path (e.g. /dev/ttyUSB0)
    #[arg(long)]
    port: String,

    /// Path to the firmware binary
    #[arg(long)]
    firmware: String,

    /// Baud rate (default 115200)
    #[arg(long, default_value = "115200")]
    baud: u32,
}

const CHUNK_SIZE: usize = 4088; // 4096 max payload - 4 bytes offset - frame overhead

fn main() {
    let args = Args::parse();

    // Read firmware binary.
    let firmware = fs::read(&args.firmware)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read firmware file: {e}");
            std::process::exit(1);
        });

    let total_size = firmware.len() as u32;
    println!("Firmware: {} ({} bytes)", args.firmware, total_size);

    // Compute SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(&firmware);
    let hash: [u8; 32] = hasher.finalize().into();
    println!("SHA-256: {}", hex_encode(&hash));

    // Open serial port.
    let mut port = serialport::new(&args.port, args.baud)
        .timeout(Duration::from_secs(60))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    // Send OTA_BEGIN.
    println!("Sending OTA_BEGIN...");
    let mut begin_payload = Vec::with_capacity(36);
    begin_payload.extend_from_slice(&total_size.to_be_bytes());
    begin_payload.extend_from_slice(&hash);
    send_frame(&mut port, FRAME_TYPE_OTA_BEGIN, &begin_payload);

    // Wait for OTA_STATUS(READY).
    let status = read_ota_status(&mut port);
    if status != OTA_STATUS_READY {
        eprintln!("Device rejected OTA (status 0x{:02x})", status);
        std::process::exit(1);
    }
    println!("Device approved OTA — streaming firmware...");

    // Stream chunks.
    let pb = ProgressBar::new(total_size as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
        .unwrap());

    let mut offset: u32 = 0;
    for chunk in firmware.chunks(CHUNK_SIZE) {
        let mut chunk_payload = Vec::with_capacity(4 + chunk.len());
        chunk_payload.extend_from_slice(&offset.to_be_bytes());
        chunk_payload.extend_from_slice(chunk);
        send_frame(&mut port, FRAME_TYPE_OTA_CHUNK, &chunk_payload);

        let status = read_ota_status(&mut port);
        if status != OTA_STATUS_CHUNK_OK {
            eprintln!("\nChunk write failed at offset {} (status 0x{:02x})", offset, status);
            std::process::exit(1);
        }

        offset += chunk.len() as u32;
        pb.set_position(offset as u64);
    }
    pb.finish_with_message("done");

    // Send OTA_FINISH.
    println!("Sending OTA_FINISH...");
    send_frame(&mut port, FRAME_TYPE_OTA_FINISH, &[]);

    let status = read_ota_status(&mut port);
    match status {
        OTA_STATUS_VERIFIED => println!("OTA verified — device is rebooting!"),
        OTA_STATUS_ERR_HASH => {
            eprintln!("OTA failed: hash mismatch");
            std::process::exit(1);
        }
        OTA_STATUS_ERR_SIZE => {
            eprintln!("OTA failed: size mismatch");
            std::process::exit(1);
        }
        other => {
            eprintln!("OTA failed with status 0x{:02x}", other);
            std::process::exit(1);
        }
    }
}

fn send_frame(port: &mut Box<dyn serialport::SerialPort>, frame_type: u8, payload: &[u8]) {
    let bytes = frame::build_frame(frame_type, payload)
        .expect("failed to build frame");
    port.write_all(&bytes).expect("serial write failed");
    port.flush().expect("serial flush failed");
}

fn read_ota_status(port: &mut Box<dyn serialport::SerialPort>) -> u8 {
    // Read frame: hunt for magic bytes, parse header, read payload.
    let mut buf = [0u8; 1];
    loop {
        port.read_exact(&mut buf).expect("serial read failed");
        if buf[0] != MAGIC_BYTES[0] { continue; }
        port.read_exact(&mut buf).expect("serial read failed");
        if buf[0] != MAGIC_BYTES[1] { continue; }

        let mut header = [0u8; 3];
        port.read_exact(&mut header).expect("serial read failed");
        let _frame_type = header[0];
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;

        let mut body = vec![0u8; length + 4]; // payload + CRC
        port.read_exact(&mut body).expect("serial read failed");

        // Reassemble and parse.
        let mut frame_buf = Vec::with_capacity(5 + length + 4);
        frame_buf.extend_from_slice(&MAGIC_BYTES);
        frame_buf.push(_frame_type);
        frame_buf.extend_from_slice(&(length as u16).to_be_bytes());
        frame_buf.extend_from_slice(&body);

        if let Ok(f) = frame::parse_frame(&frame_buf) {
            if f.frame_type == FRAME_TYPE_OTA_STATUS && !f.payload.is_empty() {
                return f.payload[0];
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
```

- [ ] **Step 3: Build and verify**

Run: `cd ./ota && cargo build`

Expected: Compiles successfully.

- [ ] **Step 4: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add ota/
git commit -m "feat: heartwood-ota Pi-side serial OTA tool"
```

---

## Task 10: Final Cleanup and Verification

**Files:**
- Modify: `firmware/src/main.rs` (remove stale comment)
- Modify: `CLAUDE.md` (update current state)

- [ ] **Step 1: Remove stale comment in main.rs**

In `firmware/src/main.rs`, find and remove the stale comment at lines ~147-148:

```
// Not yet wired into the handler — that happens in Task 5
// when the heartwood methods are implemented.
```

Replace with:

```
// Per-master identity caches — populated on demand by heartwood
// extension methods (derive, switch, list, recover).
```

- [ ] **Step 2: Update CLAUDE.md current state**

In the root `CLAUDE.md`, update the "Current state" paragraph to reflect Phase 5:

```
Phase 5 (flash-once production) complete (2026-04-0X). Five crates: `common/` (shared crypto + frame protocol + NIP-46 types + NIP-44/NIP-04 encryption + policy types), `firmware/` (ESP32), `provision/` (host CLI), `sign-test/` (signing test harness), `bridge/` (Pi-side relay bridge), `ota/` (Pi-side serial OTA tool). Multi-master NVS storage (up to 8 masters, three provisioning modes: bunker/tree-mnemonic/tree-nsec). On-device NIP-44 transport encryption — the Pi is zero-trust, only sees ciphertext (including sign_event responses). Bridge session authentication and client approval policies (NVS-persisted, TOFU auto-approval). Full NIP-46 method set (15 methods: 8 standard + 7 heartwood extensions; proof methods stubbed). Connect secret validation per NIP-46 spec. Serial OTA with SHA-256 verification and automatic rollback. Factory reset with button confirmation. Firmware uses libsecp256k1 (C FFI) for all signing.
```

Update the "Next" line:

```
Next: implement heartwood_create_proof/verify_proof (via OTA). Production hardening (JTAG disable, watchdog). Bridge management API for heartwood-device Pi web UI.
```

- [ ] **Step 3: Run all common tests**

Run: `cd ./common && cargo test --all-features`

Expected: All pass.

- [ ] **Step 4: Build the OTA tool**

Run: `cd ./ota && cargo build`

Expected: Builds cleanly.

- [ ] **Step 5: Commit**

```bash
cd ~/WebstormProjects/heartwood-esp32
git add firmware/src/main.rs CLAUDE.md
git commit -m "docs: update CLAUDE.md for phase 5 flash-once firmware"
```
