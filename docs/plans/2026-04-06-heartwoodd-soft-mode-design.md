# Heartwoodd Soft Mode Design

Date: 2026-04-06

## Summary

Rename `bridge/` to `heartwoodd/` and refactor the monolithic bridge binary into
a tier-aware daemon that runs in two modes from the same codebase:

- **Hard mode** (existing) -- ESP32 attached via USB serial, all signing delegated
  to the device, Pi is zero-trust plumbing
- **Soft mode** (new) -- Pi alone, key encrypted at rest on SD card with Argon2id,
  unlocked into RAM via Sapwood, signs locally with k256

The daemon auto-detects which mode to run based on whether an ESP32 is present,
with a `--mode` CLI override. The management API, relay subscription, Sapwood
serving, and NIP-46 event loop are shared; only the signing backend differs.

## Motivation

Heartwood Soft is the normie entry point -- "flash an SD card, get a Nostr
signer" with no hardware purchase required. Users who later buy an ESP32 can
upgrade to Hard mode by plugging it in. The Pi daemon is a product in its own
right, not just plumbing for the ESP32.

## Architecture

### Module structure

```
heartwoodd/
  Cargo.toml                  (renamed from heartwood-bridge)
  src/
    main.rs                   -- CLI args, auto-detect, backend init, startup
    relay.rs                  -- Nostr client, NIP-46 subscription, event loop
    serial.rs                 -- RawSerial POSIX wrapper (extracted from current main.rs)
    api.rs                    -- Axum management API (refactored to use backend trait)
    backend/
      mod.rs                  -- SigningBackend trait, Tier enum, BackendError
      serial.rs               -- Hard mode (existing ESP32 serial code, extracted)
      soft.rs                 -- Soft mode (in-memory signing, approval queue)
      soft_store.rs           -- Encrypted keyfile read/write (Argon2id + XChaCha20-Poly1305)
```

### SigningBackend trait

```rust
pub enum Tier { Soft, Hard }

pub enum BackendError {
    NotSupported,        // e.g. OTA on Soft, unlock on Hard
    Locked,              // Soft mode, passphrase not yet entered
    DeviceBusy,          // Hard mode, serial mutex contention
    DeviceTimeout,       // Hard mode, ESP32 didn't respond
    Denied,              // user rejected (button or Sapwood)
    Internal(String),
}

pub trait SigningBackend: Send + Sync {
    fn tier(&self) -> Tier;
    fn is_locked(&self) -> bool;

    // -- Unlock/lock (Soft only, Hard returns NotSupported) --
    fn unlock(&self, passphrase: &str) -> Result<(), BackendError>;
    fn lock(&self) -> Result<(), BackendError>;

    // -- NIP-46 signing pipeline --
    fn handle_encrypted_request(
        &self, master_pubkey: &[u8; 32], client_pubkey: &[u8; 32],
        ciphertext: &str,
    ) -> Result<String, BackendError>;

    fn sign_envelope(
        &self, master_pubkey: &[u8; 32], client_pubkey: &[u8; 32],
        created_at: u64, ciphertext: &str,
    ) -> Result<String, BackendError>;

    // -- Master/slot management --
    fn list_masters(&self) -> Result<Vec<serde_json::Value>, BackendError>;
    fn list_slots(&self, master: u8) -> Result<serde_json::Value, BackendError>;
    fn create_slot(&self, master: u8, label: &str) -> Result<serde_json::Value, BackendError>;
    fn update_slot(&self, master: u8, index: u8, patch: serde_json::Value)
        -> Result<serde_json::Value, BackendError>;
    fn revoke_slot(&self, master: u8, index: u8) -> Result<serde_json::Value, BackendError>;
    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String])
        -> Result<String, BackendError>;

    // -- Device operations --
    fn factory_reset(&self) -> Result<(), BackendError>;
    fn ota_upload(&self, firmware: &[u8]) -> Result<(), BackendError>; // Hard only
}
```

The trait is object-safe (`Arc<dyn SigningBackend>`). `SerialBackend` returns
`NotSupported` for `unlock`/`lock`. `SoftBackend` returns `NotSupported` for
`ota_upload`. `SoftBackend` returns `Locked` on every signing/management call
until `unlock()` succeeds.

## Key protection at rest

### Keyfile format

A single JSON file at `<data_dir>/keystore.enc`:

```json
{
  "version": 1,
  "kdf": "argon2id",
  "argon2_m_cost": 65536,
  "argon2_t_cost": 3,
  "argon2_p_cost": 1,
  "salt": "<32 bytes, base64>",
  "nonce": "<24 bytes, base64>",
  "ciphertext": "<base64>"
}
```

Plaintext structure (inside `ciphertext` after decryption):

```json
{
  "masters": [
    {
      "slot": 0,
      "label": "personal",
      "secret_key": "<64 hex chars>",
      "mode": "soft",
      "connection_slots": [
        {
          "index": 0,
          "label": "Bark laptop",
          "keypair": "<64 hex chars>",
          "secret": "<connect secret hex>",
          "policy": {
            "auto_approve": true,
            "allowed_kinds": [1, 6, 7, 30023],
            "allowed_methods": ["sign_event", "nip44_encrypt", "nip44_decrypt", "get_public_key"]
          }
        }
      ]
    }
  ]
}
```

### Encryption scheme

- **KDF**: Argon2id with configurable parameters (default: 64MB memory, 3
  iterations, 1 lane). Takes ~1s on Pi 4, ~3s on Pi Zero 2 W.
- **Cipher**: XChaCha20-Poly1305 (authenticated encryption, 24-byte nonce)
- **Salt**: 32 bytes, randomly generated at keystore creation
- **Nonce**: 24 bytes, randomly generated on each write

### Unlock flow

1. Daemon starts, API is reachable, Sapwood loads
2. Sapwood shows "Locked -- enter passphrase to unlock"
3. User enters passphrase via Sapwood web UI (LAN only)
4. `POST /api/unlock` sends passphrase over same-origin HTTPS session
5. Backend derives key via Argon2id, decrypts keystore
6. On success: plaintext held in memory behind `RwLock`, passphrase-derived
   key cached for re-encryption on mutations
7. On failure: return error, Sapwood shows "Wrong passphrase"

No secrets in env vars or CLI args. The passphrase only travels over the
Sapwood session.

### Persistence

Any mutation (create slot, update policy, revoke, create master) re-encrypts
the full keystore and writes atomically: write to `keystore.enc.tmp`, fsync,
rename over `keystore.enc`.

## Multi-master support

Up to 8 master identity slots, matching the ESP32 model. Each master has
independent connection slots with independent policies. Sapwood already handles
the slot-based UI from Hard mode.

### Provisioning in Soft mode

Instead of the `provision` CLI tool (ESP32-specific), Sapwood gets a "Create
identity" flow:

1. Generate keypair locally (k256)
2. Add to keystore with user-provided label
3. Display npub
4. Generate and display mnemonic backup (BIP-39, shown once, user must write down)
5. Create default connection slot

## Auto-detect and startup

### CLI args

```
heartwoodd [OPTIONS]

Options:
  --mode <soft|hard|auto>     Override mode (default: auto)
  --port <path>               Serial port for ESP32 (default: /dev/ttyACM0)
  --data-dir <path>           Data directory (default: /var/lib/heartwood)
  --relays <urls>             Comma-separated relay URLs
  --api-port <port>           Management API port (default: 3100)
  --sapwood-dir <path>        Sapwood static files directory
  --api-token <token>         Bearer token for API auth (env: HEARTWOOD_API_TOKEN)
  --bunker-secret <nsec|hex>  Relay-layer signing key (env: HEARTWOOD_BUNKER_SECRET)
  --bridge-secret <hex>       ESP32 session auth (env: HEARTWOOD_BRIDGE_SECRET)
  --pin <digits>              ESP32 boot PIN
```

Hard-mode-specific args (`--bridge-secret`, `--pin`) are only required when
running in Hard mode. In Soft mode they are ignored.

In Soft mode, `--bunker-secret` is also optional. If omitted, the daemon
generates an ephemeral relay-layer keypair on each startup (used only for NIP-42
relay authentication, not for NIP-46 application-layer signing). If provided, it
uses the given key for relay auth, which gives a stable relay identity across
restarts. The NIP-46 signing identity always comes from the keystore masters.

### Startup sequence

```
1. Parse CLI args
2. If --mode=auto:
     Probe --port for ESP32 (open serial, send PROVISION_LIST, 3s timeout)
     Response received  -> Hard mode
     Timeout / no device -> check <data_dir>/keystore.enc exists
       Exists  -> Soft mode
       Missing -> Soft mode (first run, Sapwood shows provisioning wizard)
3. If --mode=hard: require serial port, fail if no device
4. If --mode=soft: skip serial entirely, use keyfile

5. Construct the appropriate SigningBackend
6. Start management API (immediate -- Sapwood needs to be reachable even while locked)
7. If Hard mode: authenticate bridge session, query masters, start relay loop
8. If Soft mode: start relay loop in "locked" state (subscribed but rejecting)
     Wait for unlock via Sapwood before signing anything
```

### Tier detection API

`GET /api/info` returns:

```json
{
  "tier": "soft",
  "locked": true,
  "relays": ["wss://relay.damus.io"],
  "uptime_secs": 42
}
```

Sapwood uses `tier` to show the correct badge and UI (unlock form vs device
status, OTA section vs not, approval queue vs not).

### No hot-switching

Plugging in an ESP32 while running in Soft mode does nothing. Restart the daemon
(or let systemd restart it) with `--mode auto` to pick up the device. The
upgrade to Hard mode is a deliberate flow through Sapwood, not a surprise.

## Signing ceremony (Soft mode)

### Policy evaluation

Same order as ESP32 firmware:

1. `allowed_methods` -- is the method in the list? No -> deny immediately
2. `allowed_kinds` -- is this event kind in the list? No -> queue for approval
3. `auto_approve` -- if true and kind is allowed, sign immediately
4. Otherwise -> queue for approval

### Approval queue

When a request falls outside policy, it enters an in-memory approval queue:

- Each pending request gets a UUID and a 60-second TTL
- The NIP-46 response is deferred (relay event loop parks and moves on)
- If approved via Sapwood, signing happens and the response publishes
- If denied or expired, a NIP-46 error response publishes
- Queue is not persisted (daemon restart clears it, relay subscription
  picks up from `since: now`)

### API endpoints

```
GET  /api/approvals          -- list pending (method, kind, summary, age, slot label)
POST /api/approvals/:id      -- approve or deny: { "action": "approve" | "deny" }
```

Both behind existing bearer token auth.

### What Sapwood shows

Notification badge on approval tab. Each pending request displays: client label
(from connection slot), NIP-46 method, event kind, content preview (first 100
chars), tags summary. Enough to make an informed decision.

## Soft-to-Hard upgrade path

When a user plugs in an ESP32 and restarts in Hard mode, Sapwood presents two
options:

1. **Start fresh on device** -- provision the ESP32 with new keys (existing flow).
   Old Soft-mode identities remain in the keystore as a backup.
2. **Migrate existing identities** -- transfer master secrets from keyfile to
   ESP32 NVS, then wipe the local keyfile. Same npubs, clients don't notice.

**Only option 1 is built now.** Option 2 (key migration) is reserved for the
Heartwood Phase 2 grant (`identity-migrate` flow). Sapwood shows it as greyed
out with a "Coming soon" label.

## New dependencies

| Crate | Purpose |
|-------|---------|
| `argon2` | Argon2id KDF for keyfile encryption |
| `chacha20poly1305` | XChaCha20-Poly1305 authenticated encryption |
| `uuid` | Approval queue request IDs |

All other dependencies (`k256`, `nostr-sdk`, `axum`, etc.) are already present
in `common/` or `bridge/`.

## Out of scope

- Sapwood UI changes (separate repo, separate design)
- Soft-to-Hard key migration (reserved for Phase 2 grant)
- `.deb` packaging (G23 M2)
- Pi flashable image (G23 M3)
- HTTPS/TLS for Sapwood (reverse proxy concern)
- Mnemonic import from existing nsec
- Hot-switching between modes without restart
