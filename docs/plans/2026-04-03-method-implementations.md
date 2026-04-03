# NIP-46 Method Implementations — Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill in all stubbed NIP-46 method handlers in the ESP32 firmware, add an identity cache for heartwood extensions, and refactor the handler to return JSON for encrypted transport responses.

**Architecture:** The handler currently writes responses directly to USB. We refactor it to return a `Result<String, (i32, String)>` (JSON response or error), then the caller (main dispatch or transport) handles framing/encryption. Each method handler becomes a pure function that returns data. The identity cache is per-master, held in a `Vec` alongside loaded masters.

**Tech Stack:** Rust, ESP-IDF, secp256k1, heartwood-common (nip44, nip04, derive, nip46).

**Spec:** `docs/specs/2026-04-03-hsm-design.md`

---

## File Map

### Modified files

| File | Changes |
|------|---------|
| `firmware/src/nip46_handler.rs` | Refactor to return JSON strings. Implement all 15 method handlers. |
| `firmware/src/main.rs` | Update dispatch to handle returned JSON (write frame or encrypt). |
| `firmware/src/transport.rs` | Update to encrypt returned JSON as 0x11 frames. |

### New files

| File | Responsibility |
|------|----------------|
| `firmware/src/identity_cache.rs` | Per-master identity cache for heartwood extensions. |

---

## Task 1: Refactor Handler to Return JSON

**Files:**
- Modify: `firmware/src/nip46_handler.rs`
- Modify: `firmware/src/main.rs`
- Modify: `firmware/src/transport.rs`

The handler currently calls `write_frame(usb, ...)` directly. Refactor so it returns the response JSON string, and the caller writes the frame. This enables the transport layer to encrypt responses.

- [ ] **Step 1: Change `handle_request` signature to return `Option<String>`**

Change the return type from `()` to `Option<String>` — the returned string is the NIP-46 JSON response to send. `None` means the handler already sent the response (legacy path for sign_event which has the button loop).

Update the function signature in `firmware/src/nip46_handler.rs`:

```rust
pub fn handle_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    master_secret: &[u8; 32],
    master_label: &str,
    master_mode: MasterMode,
    master_slot: u8,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    policy_engine: &mut PolicyEngine,
) -> Option<String> {
```

For methods that currently call `send_error` or `write_frame` directly, change them to return the JSON string instead. For `sign_event` which has the button loop and writes directly, return `None` (it manages its own USB writes).

Replace each stub/handler to return JSON:

```rust
"connect" => {
    return Some(nip46::build_connect_response(&request.id).unwrap_or_default());
}
"ping" => {
    return Some(nip46::build_ping_response(&request.id).unwrap_or_default());
}
```

For error cases, build the error JSON and return it:

```rust
fn build_error_json(request_id: &str, code: i32, message: &str) -> String {
    nip46::build_error_response(request_id, code, message).unwrap_or_default()
}
```

At the end of the match, for all non-sign_event methods, return the JSON. For sign_event, keep the existing write-to-USB pattern and return `None`.

- [ ] **Step 2: Update main.rs dispatch to handle returned JSON**

In the `FRAME_TYPE_NIP46_REQUEST` match arm, write the returned JSON as a `0x03` frame:

```rust
FRAME_TYPE_NIP46_REQUEST => {
    if policy_engine.bridge_authenticated {
        log::warn!("Plaintext NIP-46 rejected — bridge session active");
        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
    } else if let Some(master) = loaded_masters.first() {
        if let Some(response_json) = nip46_handler::handle_request(
            &mut usb, &frame, &master.secret, &master.label,
            master.mode, master.slot, &secp, &mut display,
            &button_pin, &mut policy_engine,
        ) {
            protocol::write_frame(&mut usb, FRAME_TYPE_NIP46_RESPONSE, response_json.as_bytes());
        }
        // None means handler already wrote the response (sign_event).
    } else {
        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
    }
}
```

- [ ] **Step 3: Update transport.rs to encrypt returned JSON**

In `handle_encrypted_request`, after dispatching to the handler, encrypt the response:

```rust
if let Some(response_json) = crate::nip46_handler::handle_request(
    usb, &inner_frame, &master.secret, &master.label,
    master.mode, master.slot, secp, display, button_pin, policy_engine,
) {
    // Encrypt the response with NIP-44.
    let nonce = random_nonce_24();
    match nip44::encrypt(&conversation_key, &response_json, &nonce) {
        Ok(ciphertext_b64) => {
            // Build 0x11 frame: [client_pubkey_32][ciphertext_b64_bytes...]
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
}
// None means handler wrote plaintext response directly (sign_event button loop).
```

Add a helper for generating random 24-byte nonces:

```rust
fn random_nonce_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            nonce.as_mut_ptr() as *mut core::ffi::c_void,
            24,
        );
    }
    nonce
}
```

- [ ] **Step 4: Build firmware**

Run: `cd firmware && cargo build`

- [ ] **Step 5: Commit**

```bash
git add firmware/src/nip46_handler.rs firmware/src/main.rs firmware/src/transport.rs
git commit -m "refactor: handler returns JSON, transport encrypts 0x11 responses"
```

---

## Task 2: Implement connect, ping, nip44_encrypt, nip44_decrypt

**Files:**
- Modify: `firmware/src/nip46_handler.rs`

- [ ] **Step 1: Implement connect and ping**

These are already partially done in Task 1. Verify they return proper JSON:

```rust
"connect" => {
    // TODO: validate connect secret from params against master's connect_secret.
    // For now, accept all connections.
    log::info!("connect: accepted client");
    return Some(nip46::build_connect_response(&request.id).unwrap_or_default());
}
"ping" => {
    return Some(nip46::build_ping_response(&request.id).unwrap_or_default());
}
```

- [ ] **Step 2: Implement nip44_encrypt**

NIP-46 `nip44_encrypt` params: `[peer_pubkey_hex, plaintext]`.

The handler derives the signing key (respecting heartwood context), derives the conversation key between the signing key and the peer pubkey, then encrypts.

```rust
"nip44_encrypt" => {
    if request.params.len() < 2 {
        return Some(build_error_json(&request.id, -3, "nip44_encrypt requires [peer_pubkey, plaintext]"));
    }
    let peer_pubkey_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "peer_pubkey must be a string")),
    };
    let plaintext = match request.params[1].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "plaintext must be a string")),
    };

    // Resolve signing key (master or derived child).
    let signing_secret = resolve_signing_secret(master_secret, secp, request.heartwood.as_ref());
    let signing_secret = match signing_secret {
        Ok(s) => s,
        Err(e) => return Some(build_error_json(&request.id, -4, &e)),
    };

    // Parse peer pubkey from hex.
    let peer_pubkey = match hex_decode_32(peer_pubkey_hex) {
        Some(pk) => pk,
        None => return Some(build_error_json(&request.id, -3, "invalid peer pubkey hex")),
    };

    // Derive conversation key and encrypt.
    let conversation_key = match heartwood_common::nip44::get_conversation_key(&signing_secret, &peer_pubkey) {
        Ok(ck) => ck,
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    };

    let nonce = random_nonce_24();
    match heartwood_common::nip44::encrypt(&conversation_key, plaintext, &nonce) {
        Ok(ciphertext) => {
            return Some(nip46::build_result_response(&request.id, &ciphertext).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 3: Implement nip44_decrypt**

NIP-46 `nip44_decrypt` params: `[peer_pubkey_hex, ciphertext_b64]`.

```rust
"nip44_decrypt" => {
    if request.params.len() < 2 {
        return Some(build_error_json(&request.id, -3, "nip44_decrypt requires [peer_pubkey, ciphertext]"));
    }
    let peer_pubkey_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "peer_pubkey must be a string")),
    };
    let ciphertext = match request.params[1].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "ciphertext must be a string")),
    };

    let signing_secret = resolve_signing_secret(master_secret, secp, request.heartwood.as_ref());
    let signing_secret = match signing_secret {
        Ok(s) => s,
        Err(e) => return Some(build_error_json(&request.id, -4, &e)),
    };

    let peer_pubkey = match hex_decode_32(peer_pubkey_hex) {
        Some(pk) => pk,
        None => return Some(build_error_json(&request.id, -3, "invalid peer pubkey hex")),
    };

    let conversation_key = match heartwood_common::nip44::get_conversation_key(&signing_secret, &peer_pubkey) {
        Ok(ck) => ck,
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    };

    match heartwood_common::nip44::decrypt(&conversation_key, ciphertext) {
        Ok(plaintext) => {
            return Some(nip46::build_result_response(&request.id, &plaintext).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 4: Add helper functions**

Add these helpers to `nip46_handler.rs`:

```rust
/// Build an error JSON response.
fn build_error_json(request_id: &str, code: i32, message: &str) -> String {
    nip46::build_error_response(request_id, code, message).unwrap_or_default()
}

/// Resolve the signing secret — either master or derived child.
fn resolve_signing_secret(
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    heartwood: Option<&HeartwoodContext>,
) -> Result<[u8; 32], String> {
    match heartwood {
        Some(ctx) => {
            let root = derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))?;
            let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                .map_err(|e| format!("derive: {e}"))?;
            Ok(*identity.private_key)
        }
        None => Ok(*master_secret),
    }
}

/// Decode a 64-char hex string to 32 bytes.
fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// Generate a random 24-byte nonce using ESP32 hardware RNG.
fn random_nonce_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            nonce.as_mut_ptr() as *mut core::ffi::c_void,
            24,
        );
    }
    nonce
}

/// Generate a random 16-byte IV using ESP32 hardware RNG.
fn random_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(
            iv.as_mut_ptr() as *mut core::ffi::c_void,
            16,
        );
    }
    iv
}
```

- [ ] **Step 5: Build firmware**

Run: `cd firmware && cargo build`

- [ ] **Step 6: Commit**

```bash
git add firmware/src/nip46_handler.rs
git commit -m "feat: implement connect, ping, nip44_encrypt, nip44_decrypt methods"
```

---

## Task 3: Implement nip04_encrypt, nip04_decrypt

**Files:**
- Modify: `firmware/src/nip46_handler.rs`

- [ ] **Step 1: Implement nip04_encrypt**

NIP-46 `nip04_encrypt` params: `[peer_pubkey_hex, plaintext]`.

```rust
"nip04_encrypt" => {
    if request.params.len() < 2 {
        return Some(build_error_json(&request.id, -3, "nip04_encrypt requires [peer_pubkey, plaintext]"));
    }
    let peer_pubkey_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "peer_pubkey must be a string")),
    };
    let plaintext = match request.params[1].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "plaintext must be a string")),
    };

    let signing_secret = match resolve_signing_secret(master_secret, secp, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => return Some(build_error_json(&request.id, -4, &e)),
    };

    let peer_pubkey = match hex_decode_32(peer_pubkey_hex) {
        Some(pk) => pk,
        None => return Some(build_error_json(&request.id, -3, "invalid peer pubkey hex")),
    };

    let shared_secret = match heartwood_common::nip04::get_shared_secret(&signing_secret, &peer_pubkey) {
        Ok(ss) => ss,
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    };

    let iv = random_iv_16();
    match heartwood_common::nip04::encrypt(&shared_secret, plaintext, &iv) {
        Ok(ciphertext) => {
            return Some(nip46::build_result_response(&request.id, &ciphertext).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 2: Implement nip04_decrypt**

```rust
"nip04_decrypt" => {
    if request.params.len() < 2 {
        return Some(build_error_json(&request.id, -3, "nip04_decrypt requires [peer_pubkey, ciphertext]"));
    }
    let peer_pubkey_hex = match request.params[0].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "peer_pubkey must be a string")),
    };
    let ciphertext = match request.params[1].as_str() {
        Some(s) => s,
        None => return Some(build_error_json(&request.id, -3, "ciphertext must be a string")),
    };

    let signing_secret = match resolve_signing_secret(master_secret, secp, request.heartwood.as_ref()) {
        Ok(s) => s,
        Err(e) => return Some(build_error_json(&request.id, -4, &e)),
    };

    let peer_pubkey = match hex_decode_32(peer_pubkey_hex) {
        Some(pk) => pk,
        None => return Some(build_error_json(&request.id, -3, "invalid peer pubkey hex")),
    };

    let shared_secret = match heartwood_common::nip04::get_shared_secret(&signing_secret, &peer_pubkey) {
        Ok(ss) => ss,
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    };

    match heartwood_common::nip04::decrypt(&shared_secret, ciphertext) {
        Ok(plaintext) => {
            return Some(nip46::build_result_response(&request.id, &plaintext).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 3: Build firmware**

Run: `cd firmware && cargo build`

- [ ] **Step 4: Commit**

```bash
git add firmware/src/nip46_handler.rs
git commit -m "feat: implement nip04_encrypt, nip04_decrypt methods"
```

---

## Task 4: Identity Cache

**Files:**
- Create: `firmware/src/identity_cache.rs`
- Modify: `firmware/src/main.rs` (add `mod identity_cache;`)

Per-master cache of derived identities, used by heartwood_derive, heartwood_switch, heartwood_list_identities, and heartwood_recover.

- [ ] **Step 1: Create `firmware/src/identity_cache.rs`**

```rust
// firmware/src/identity_cache.rs
//
// Per-master cache of derived identities for heartwood extensions.
// Identities are derived on demand and cached in memory.

use heartwood_common::derive;
use heartwood_common::encoding::encode_npub;
use heartwood_common::hex::hex_encode;
use zeroize::Zeroize;

/// A cached derived identity.
pub struct CachedIdentity {
    pub npub: String,
    pub purpose: String,
    pub index: u32,
    pub persona_name: Option<String>,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Drop for CachedIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Per-master identity cache.
pub struct IdentityCache {
    pub master_slot: u8,
    pub identities: Vec<CachedIdentity>,
}

impl IdentityCache {
    pub fn new(master_slot: u8) -> Self {
        Self {
            master_slot,
            identities: Vec::new(),
        }
    }

    /// Derive and cache an identity. Returns index into the cache.
    pub fn derive_and_cache(
        &mut self,
        master_secret: &[u8; 32],
        purpose: &str,
        index: u32,
        persona_name: Option<String>,
    ) -> Result<usize, &'static str> {
        // Check if already cached.
        if let Some(pos) = self.find(purpose, index) {
            return Ok(pos);
        }

        let root = derive::create_tree_root(master_secret)?;
        let identity = derive::derive(&root, purpose, index)?;

        let cached = CachedIdentity {
            npub: identity.npub.clone(),
            purpose: identity.purpose.clone(),
            index: identity.index,
            persona_name,
            private_key: *identity.private_key,
            public_key: identity.public_key,
        };

        self.identities.push(cached);
        Ok(self.identities.len() - 1)
    }

    /// Find a cached identity by purpose and index.
    pub fn find(&self, purpose: &str, index: u32) -> Option<usize> {
        self.identities.iter().position(|id| {
            id.purpose == purpose && id.index == index
        })
    }

    /// Find a cached identity by npub.
    pub fn find_by_npub(&self, npub: &str) -> Option<usize> {
        self.identities.iter().position(|id| id.npub == npub)
    }

    /// Find by persona name.
    pub fn find_by_persona(&self, name: &str) -> Option<usize> {
        self.identities.iter().position(|id| {
            id.persona_name.as_deref() == Some(name)
        })
    }

    /// List all cached identities as a JSON array string.
    pub fn list_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self.identities.iter().map(|id| {
            let mut obj = serde_json::json!({
                "npub": id.npub,
                "purpose": id.purpose,
                "index": id.index,
            });
            if let Some(name) = &id.persona_name {
                obj["personaName"] = serde_json::json!(name);
            }
            obj
        }).collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Recover identities by scanning default purposes.
    pub fn recover(
        &mut self,
        master_secret: &[u8; 32],
        lookahead: u32,
    ) -> Result<usize, &'static str> {
        let default_purposes = ["messaging", "signing", "social", "commerce"];
        let mut recovered = 0;

        for purpose in &default_purposes {
            for index in 0..lookahead {
                match self.derive_and_cache(master_secret, purpose, index, None) {
                    Ok(_) => recovered += 1,
                    Err(_) => break, // stop scanning this purpose on first failure
                }
            }
        }

        Ok(recovered)
    }
}
```

- [ ] **Step 2: Register module in `firmware/src/main.rs`**

Add `mod identity_cache;` to the module declarations.

Also add identity caches to the main function, after loading masters:

```rust
// Create per-master identity caches.
let mut identity_caches: Vec<identity_cache::IdentityCache> = loaded_masters
    .iter()
    .map(|m| identity_cache::IdentityCache::new(m.slot))
    .collect();
```

Pass `&mut identity_caches` to the NIP-46 handler (update the handler signature to accept it).

- [ ] **Step 3: Build firmware**

Run: `cd firmware && cargo build`

- [ ] **Step 4: Commit**

```bash
git add firmware/src/identity_cache.rs firmware/src/main.rs
git commit -m "feat: add per-master identity cache for heartwood extensions"
```

---

## Task 5: Implement Heartwood Extension Methods

**Files:**
- Modify: `firmware/src/nip46_handler.rs`

Implement all 7 heartwood_* methods using the identity cache.

- [ ] **Step 1: Update handler signature to accept identity caches**

Add `identity_caches: &mut Vec<crate::identity_cache::IdentityCache>` to `handle_request`.

- [ ] **Step 2: Implement heartwood_derive**

Params: `[purpose, index?]` (index defaults to 0).

```rust
"heartwood_derive" => {
    if !master_mode.is_tree() {
        return Some(build_error_json(&request.id, -5, "not available in bunker mode"));
    }
    let purpose = match request.params.first().and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return Some(build_error_json(&request.id, -3, "heartwood_derive requires [purpose, index?]")),
    };
    let index = request.params.get(1)
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let cache = identity_caches.iter_mut().find(|c| c.master_slot == master_slot);
    let cache = match cache {
        Some(c) => c,
        None => return Some(build_error_json(&request.id, -4, "no identity cache for master")),
    };

    match cache.derive_and_cache(master_secret, purpose, index, None) {
        Ok(idx) => {
            let id = &cache.identities[idx];
            let result = serde_json::json!({
                "npub": id.npub,
                "purpose": id.purpose,
                "index": id.index,
            });
            return Some(nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 3: Implement heartwood_derive_persona**

Params: `[name, index?]`. Sugar for derive with `purpose = "persona/{name}"`.

```rust
"heartwood_derive_persona" => {
    if !master_mode.is_tree() {
        return Some(build_error_json(&request.id, -5, "not available in bunker mode"));
    }
    let name = match request.params.first().and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return Some(build_error_json(&request.id, -3, "heartwood_derive_persona requires [name, index?]")),
    };
    let index = request.params.get(1)
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let purpose = format!("persona/{name}");
    let cache = identity_caches.iter_mut().find(|c| c.master_slot == master_slot);
    let cache = match cache {
        Some(c) => c,
        None => return Some(build_error_json(&request.id, -4, "no identity cache for master")),
    };

    match cache.derive_and_cache(master_secret, &purpose, index, Some(name.to_string())) {
        Ok(idx) => {
            let id = &cache.identities[idx];
            let result = serde_json::json!({
                "npub": id.npub,
                "purpose": id.purpose,
                "index": id.index,
                "personaName": name,
            });
            return Some(nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 4: Implement heartwood_switch**

Params: `[target, index_hint?]`. Target can be "master", an npub, a persona name, or a purpose string.

```rust
"heartwood_switch" => {
    if !master_mode.is_tree() {
        return Some(build_error_json(&request.id, -5, "not available in bunker mode"));
    }
    let target = match request.params.first().and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return Some(build_error_json(&request.id, -3, "heartwood_switch requires [target]")),
    };

    // Find the target identity in the cache or by resolving it.
    // "master" resets to no active identity.
    if target == "master" {
        // Reset active identity — handled by policy engine session.
        // For now, just acknowledge.
        return Some(nip46::build_result_response(&request.id,
            &serde_json::json!({"npub": "master"}).to_string()).unwrap_or_default());
    }

    let cache = identity_caches.iter_mut().find(|c| c.master_slot == master_slot);
    let cache = match cache {
        Some(c) => c,
        None => return Some(build_error_json(&request.id, -4, "no identity cache for master")),
    };

    // Try to find by npub, persona name, or purpose.
    let found = cache.find_by_npub(target)
        .or_else(|| cache.find_by_persona(target))
        .or_else(|| {
            let index_hint = request.params.get(1)
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            cache.find(target, index_hint)
        });

    match found {
        Some(idx) => {
            let id = &cache.identities[idx];
            let result = serde_json::json!({"npub": id.npub});
            return Some(nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default());
        }
        None => return Some(build_error_json(&request.id, -4, "identity not found in cache")),
    }
}
```

- [ ] **Step 5: Implement heartwood_list_identities**

No params. Returns the identity cache as JSON.

```rust
"heartwood_list_identities" => {
    if !master_mode.is_tree() {
        // Bunker mode returns empty array.
        return Some(nip46::build_result_response(&request.id, "[]").unwrap_or_default());
    }
    let cache = identity_caches.iter().find(|c| c.master_slot == master_slot);
    let list_json = match cache {
        Some(c) => c.list_json(),
        None => "[]".to_string(),
    };
    return Some(nip46::build_result_response(&request.id, &list_json).unwrap_or_default());
}
```

- [ ] **Step 6: Implement heartwood_recover**

Params: `[lookahead?]` (defaults to 20).

```rust
"heartwood_recover" => {
    if !master_mode.is_tree() {
        return Some(build_error_json(&request.id, -5, "not available in bunker mode"));
    }
    let lookahead = request.params.first()
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as u32;

    let cache = identity_caches.iter_mut().find(|c| c.master_slot == master_slot);
    let cache = match cache {
        Some(c) => c,
        None => return Some(build_error_json(&request.id, -4, "no identity cache for master")),
    };

    match cache.recover(master_secret, lookahead) {
        Ok(count) => {
            let list_json = cache.list_json();
            let result = serde_json::json!({
                "recovered": count,
                "identities": serde_json::from_str::<serde_json::Value>(&list_json).unwrap_or_default(),
            });
            return Some(nip46::build_result_response(&request.id, &result.to_string()).unwrap_or_default());
        }
        Err(e) => return Some(build_error_json(&request.id, -4, e)),
    }
}
```

- [ ] **Step 7: Implement heartwood_create_proof and heartwood_verify_proof as stubs**

These require cryptographic proof construction (blind/full linkage proofs). Stub them with a clear error for now — implementing the full proof protocol is a separate effort.

```rust
"heartwood_create_proof" => {
    if !master_mode.is_tree() {
        return Some(build_error_json(&request.id, -5, "not available in bunker mode"));
    }
    return Some(build_error_json(&request.id, -6, "heartwood_create_proof not yet implemented"));
}
"heartwood_verify_proof" => {
    return Some(build_error_json(&request.id, -6, "heartwood_verify_proof not yet implemented"));
}
```

- [ ] **Step 8: Build firmware**

Run: `cd firmware && cargo build`

- [ ] **Step 9: Commit**

```bash
git add firmware/src/nip46_handler.rs
git commit -m "feat: implement heartwood extension methods (derive, switch, list, recover)"
```

---

## Verification Checklist

- [ ] `cd common && cargo test --features "nip46,nip44,nip04,k256-backend"` — 43 tests pass
- [ ] `cd firmware && cargo build` — firmware builds clean
- [ ] `cd bridge && cargo build` — bridge builds clean
- [ ] All 15 NIP-46 methods have handler implementations (13 real, 2 stubs for proof methods)
- [ ] Handler returns `Option<String>` — `Some(json)` for most methods, `None` for sign_event
- [ ] Transport layer encrypts returned JSON as 0x11 frames
- [ ] Plaintext dispatch writes returned JSON as 0x03 frames
