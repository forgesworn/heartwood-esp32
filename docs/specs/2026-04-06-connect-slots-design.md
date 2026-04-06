# Per-Client Connection Slots

**Date:** 2026-04-06
**Status:** Approved
**Scope:** common, firmware, bridge, sapwood

## Problem

NIP-46 clients generate ephemeral keypairs per session. Each time nostrudel.ninja is opened or Bark reconnects, a new random pubkey appears. The current system TOFU-approves each one and persists it to NVS forever. Result: dozens of stale "approved clients" from 3-4 real apps.

## Solution

Replace the single connect secret per master with up to 16 **named connection slots** per master. Each slot has its own secret, producing a unique bunker URI. The slot -- not the ephemeral pubkey -- becomes the stable client identity. When a client reconnects with a new ephemeral key, the slot's pubkey is swapped and all permissions carry over.

## Data Model

`ConnectSlot` in `common/src/policy.rs`:

```rust
pub struct ConnectSlot {
    pub slot_index: u8,              // 0-15
    pub label: String,               // "nostrudel desktop", "Bark laptop"
    pub secret: String,              // hex-encoded 32 bytes (64 chars), ESP32 hardware RNG
    pub current_pubkey: Option<String>, // hex, set on first connect
    pub allowed_methods: Vec<String>,
    pub allowed_kinds: Vec<u64>,
    pub auto_approve: bool,
    pub signing_approved: bool,      // true once button-pressed for sign_event
}
```

- Replaces `ClientPolicy` entirely
- Identity is the slot (stable), not the pubkey (ephemeral)
- `signing_approved` drives silent-replace vs OLED-flash on pubkey change
- Secret stored in the slot, not separately

**Storage:** One NVS blob per master: `connslots_{master_slot}`, JSON array of up to 16 slots. Secret bytes hex-encoded in JSON.

**Limits:** 16 slots per master, 8 masters max = 128 slots maximum.

## Connect Flow

```
connect(client_pubkey, secret, metadata)
  |
  +-- no secret?
  |     -> ACK (spec compliance), no slot assigned
  |     -> every subsequent request hits ButtonRequired ("stranger" path)
  |
  +-- iterate slots, constant-time compare secret
        |
        +-- no match -> reject with error
        |
        +-- match found:
              |
              +-- slot.current_pubkey is None (first use)
              |     -> set current_pubkey
              |     -> grant connect-safe methods
              |     -> update label from client metadata if slot label is "default"
              |     -> persist
              |
              +-- slot.current_pubkey == client_pubkey (same client)
              |     -> refresh session, no-op
              |
              +-- slot.current_pubkey != client_pubkey (new ephemeral key)
                    |
                    +-- signing_approved == false
                    |     -> silent swap current_pubkey, persist
                    |
                    +-- signing_approved == true
                          -> OLED flash "{label} reconnected"
                          -> swap current_pubkey
                          -> keep all existing methods/kinds
                          -> persist
```

## Policy Engine Refactor

**Current:** `PolicyEngine` holds `Vec<MasterPolicies>` with `Vec<ClientPolicy>` keyed by pubkey.

**New:** `PolicyEngine` holds `Vec<MasterSlots>` with `Vec<ConnectSlot>` keyed by slot index.

**`check()` signature unchanged:** Receives pubkey from NIP-46 event, internally does pubkey -> slot lookup, evaluates the slot's permissions. No match = `ButtonRequired`.

**Replaced methods:**
- `add_tofu_policy` -> removed (slot creation via `create_slot`, pubkey assignment in connect handler)
- `upsert_policy` -> `update_slot` (update methods/kinds/auto_approve by slot index)
- `revoke_client` -> `revoke_slot` (delete a slot by index)
- `set_policies` -> `set_slots` (bridge bulk-push)

**Session tracking (`ClientSession`):** Still keys on pubkey -- tracks the current connection for rate limiting, not the stable identity. Unchanged.

**sign_event approval:** If `signing_approved == false`, OLED shows request, button press required. On approval, set `signing_approved = true` and add `sign_event` to `allowed_methods`.

## Serial Frame Protocol

| Frame type | Code | Direction | Payload | Purpose |
|------------|------|-----------|---------|---------|
| `CONNSLOT_CREATE` | 0x40 | Bridge -> FW | `[master_slot, label_json]` | Create slot; FW generates secret via hardware RNG |
| `CONNSLOT_CREATE_RESP` | 0x41 | FW -> Bridge | `[slot_index, secret_hex, bunker_uri]` | New slot with generated secret and full URI |
| `CONNSLOT_LIST` | 0x42 | Bridge -> FW | `[master_slot]` | List all slots for a master |
| `CONNSLOT_LIST_RESP` | 0x43 | FW -> Bridge | `[json_array]` | All slots, secrets redacted |
| `CONNSLOT_UPDATE` | 0x44 | Bridge -> FW | `[master_slot, slot_json]` | Update label, methods, kinds, auto_approve |
| `CONNSLOT_UPDATE_RESP` | 0x45 | FW -> Bridge | `[ok/err]` | Confirmation |
| `CONNSLOT_REVOKE` | 0x46 | Bridge -> FW | `[master_slot, slot_index]` | Delete a slot |
| `CONNSLOT_REVOKE_RESP` | 0x47 | FW -> Bridge | `[ok/err]` | Confirmation |
| `CONNSLOT_URI` | 0x48 | Bridge -> FW | `[master_slot, slot_index, relay_json]` | Get bunker URI for a slot |
| `CONNSLOT_URI_RESP` | 0x49 | FW -> Bridge | `[bunker_uri]` | Full URI including secret |

**Secrets only leave the device inside a bunker URI** (via `CONNSLOT_CREATE_RESP` or `CONNSLOT_URI_RESP`). List responses redact secrets.

## Bridge API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/slots/{master}` | GET | List all connection slots (secrets redacted) |
| `/api/slots/{master}` | POST | Create slot (body: `{"label": "..."}`) -- returns slot with bunker URI |
| `/api/slots/{master}/{index}` | PUT | Update label/methods/kinds/auto_approve |
| `/api/slots/{master}/{index}` | DELETE | Revoke a slot |
| `/api/slots/{master}/{index}/uri` | GET | Get bunker URI (with secret) for a slot |

Each endpoint is a thin proxy to the corresponding `CONNSLOT_*` serial frame.

`/api/bridge/info` continues to return a `bunker_uri` field using slot 0 for backwards compatibility.

## Migration

Not live yet, so migration is minimal:

1. Firmware detects old-format `policy_{slot}` and `master_{slot}_conn` in NVS
2. Creates one `ConnectSlot` at index 0: label "default", old secret, no current pubkey, connect-safe methods only, `signing_approved = false`
3. Deletes old NVS keys
4. Old clients reconnect, hit the existing secret, get assigned to the "default" slot
5. First `sign_event` needs a button press again

Old `/api/clients/*` bridge endpoints can be removed (not live, no backwards compat needed).

## Heartwood Soft

This design is for ESP32 first. Heartwood Soft will follow. The `ConnectSlot` type lives in `common/` so Soft can reuse the data model with its own storage backend (file-based instead of NVS) and management interface.

## Testing

**Unit tests (common/):**
- `ConnectSlot` serialisation round-trip
- `check()` with slot-based lookup: same pubkey, different pubkey, no slot
- Secret comparison (constant-time)
- Migration: old format -> new format

**Integration tests (firmware/, sign-test/):**
- Create slot via serial frame, verify response
- Connect with correct secret -> slot assigned
- Connect with wrong secret -> rejected
- Reconnect with new pubkey, `signing_approved == false` -> silent swap
- Reconnect with new pubkey, `signing_approved == true` -> OLED flash
- 16 slots full -> create returns error
- Revoke slot -> client pubkey no longer resolves

**Bridge API tests:**
- CRUD endpoints proxy correctly to serial frames
- List endpoint redacts secrets
- URI endpoint returns full bunker URI

## Edge Cases

**Two slots, same pubkey:** Shouldn't happen (one client can't know two secrets). If it does, first match wins. Old slot's pubkey goes stale, replaced next time that slot's real client reconnects.

**No secret provided on connect:** ACK returned (NIP-46 spec compliance), no slot assigned. Every subsequent request hits `ButtonRequired`. This is the "stranger" path.

**Slot 0 "default" after migration:** Works like any other slot. User can rename it, revoke it, or leave it. No special treatment beyond being the one that migrates the old secret.
