# NIP-46 Client Compatibility Hardening

**Date:** 2026-04-04
**Status:** Complete (2026-04-04)
**Context:** First real-world testing of Heartwood bunker with Nostr clients (Nostur, Coracle, Nostrudel) revealed several issues. Crash bugs fixed in fc60c4e1. Remaining work below.

## Background

Tested bunker:// URI with three clients:
- **Nostrudel** (web) -- works correctly, clean NIP-46 implementation
- **Coracle** (web) -- connects but triggers AUTH storms (kind 22242), sends `switch_relays` unknown method, may not delegate likes through bunker
- **Nostur** (iOS) -- broken for tree-mode bunkers where signer pubkey != user pubkey (doesn't call `get_public_key` properly)

Bridge fixes already shipped: serial buffer drain on restart (71af1568), crash fixes (fc60c4e1).

## Task 1: Handle `switch_relays` gracefully

**Type:** Bug fix (foundation)
**Files:** `firmware/src/nip46_handler.rs`
**Effort:** Small

Coracle sends `switch_relays` as part of its NIP-46 handshake. The ESP32 returns `{"error":"unknown method"}` which may cause Coracle to enter a degraded state.

**Fix:** Add a match arm for `"switch_relays"` that returns an empty success response. It's not in the NIP-46 spec but returning success is harmless and unblocks clients that expect it.

```rust
"switch_relays" => {
    // Non-standard method sent by some clients (e.g. Coracle).
    // Return success to avoid blocking the handshake.
    nip46::build_result_response(&request.id, "{}").unwrap_or_default()
}
```

Add this before the `other =>` catch-all in the match block around line 344.

**Test:** Rebuild firmware, flash, connect Coracle -- verify no "unknown method" in bridge logs.

## Task 2: TOFU policy management interface

**Type:** Feature (foundation -- exposing existing shipped functionality)
**Files:** `common/src/types.rs`, `firmware/src/policy.rs`, `firmware/src/main.rs`, `provision/src/main.rs`
**Effort:** Medium

Currently there is no way to view or manage TOFU-approved clients. The policy engine exists and persists to NVS, but there's no read/revoke interface.

### 2a: New frame types in `common/src/types.rs`

```
FRAME_TYPE_POLICY_LIST_REQUEST  = 0x27  // host -> device: payload = master_slot (1 byte)
FRAME_TYPE_POLICY_LIST_RESPONSE = 0x28  // device -> host: payload = JSON Vec<ClientPolicy>
FRAME_TYPE_POLICY_REVOKE        = 0x29  // host -> device: payload = master_slot (1) + client_pubkey_hex (64 bytes ASCII)
FRAME_TYPE_POLICY_UPDATE        = 0x2A  // host -> device: payload = master_slot (1) + JSON ClientPolicy
```

### 2b: Firmware dispatch in `firmware/src/main.rs`

Add match arms in the frame dispatch loop for the new frame types. All should be gated on bridge authentication (`policy_engine.bridge_authenticated`) OR allowed unconditionally in bridge-decrypts mode (since the provision tool connects directly).

**POLICY_LIST_REQUEST:** Find `MasterPolicies` for the slot, serialise to JSON, return as POLICY_LIST_RESPONSE.

**POLICY_REVOKE:** Find and remove the `ClientPolicy` matching the client pubkey hex. Set `policies_dirty = true`. Persist. Return ACK/NACK.

**POLICY_UPDATE:** Parse the JSON `ClientPolicy` from payload. Upsert (replace if client_pubkey matches, else add). Set `policies_dirty = true`. Persist. Return ACK/NACK.

### 2c: Provision tool commands

Add subcommands to `provision/src/main.rs`:

```
provision list-clients --port /dev/cu.usbmodem1101 --master-slot 0
provision revoke-client --port /dev/cu.usbmodem1101 --master-slot 0 --client <hex-pubkey>
provision update-client --port /dev/cu.usbmodem1101 --master-slot 0 --client <hex-pubkey> --label "Nostrudel" [--no-auto-approve] [--allowed-kinds 7,1,0]
```

### 2d: Known issue -- 4096 byte NVS buffer

`load_from_nvs` in `firmware/src/policy.rs` reads into a 4096-byte stack buffer. If many TOFU clients accumulate, the JSON blob could exceed this. Consider increasing to 8192 or switching to per-client NVS keys.

### Data model reference

```rust
// common/src/policy.rs
pub struct ClientPolicy {
    pub client_pubkey: String,      // 64-char hex
    pub label: String,              // human-readable
    pub allowed_methods: Vec<String>,
    pub allowed_kinds: Vec<u64>,    // empty = all kinds
    pub auto_approve: bool,
}
```

TOFU-generated policies have: `auto_approve: true`, `label: ""`, all `TOFU_SAFE_METHODS`, empty `allowed_kinds`.

## Task 3: File Nostur issue

**Type:** Community engagement
**Repo:** https://github.com/nostur-com/nostur-ios-public/issues

**Title:** bunker:// login fails to load profile when signer pubkey differs from user pubkey

**Body:**

When logging in via `bunker://` URI where the remote signer's pubkey (in the URI) is different from the user's pubkey (returned by `get_public_key`), Nostur fails to find the user's profile.

This happens with hardware signers and nsecBunker setups that use key derivation (tree mode), where the signer key is a root/transport key and the actual signing identity is a derived child.

Per the NIP-46 spec update (Feb 2025, https://github.com/nostr-protocol/nips/commit/c6cd655c), clients must differentiate between `remote-signer-pubkey` and `user-pubkey`, calling `get_public_key` after `connect` to discover the actual user identity for profile lookup.

**To reproduce:**
1. Set up a NIP-46 bunker where signer pubkey != user pubkey (e.g. tree-derived key)
2. Paste `bunker://<signer-pubkey>?relay=...` into Nostur login
3. Nostur attempts to look up a profile for `<signer-pubkey>` instead of the pubkey returned by `get_public_key`
4. No profile found

**Expected:** Nostur calls `get_public_key` after the NIP-46 handshake, then uses the returned pubkey for profile/metadata lookup.

**Confirmed working:** Same bunker URI works correctly with Nostrudel (web) -- profile loads as expected.

## Task 4: Investigate serial round-trip latency

**Type:** Performance investigation (foundation)
**Effort:** Small investigation, potentially medium fix

Each sign_event takes ~6 seconds round-trip through the serial port despite the actual signing being sub-millisecond. The bottleneck is likely:

1. **Baud rate** -- currently 115200. Could increase to 230400 or higher.
2. **VTIME setting** -- bridge serial has `VTIME=1` (100ms poll interval). Each read returns after 100ms even if data is available sooner.
3. **Frame parsing** -- byte-by-byte magic hunting in `read_any_response` is slow over serial.

**Investigation steps:**
- Add timing logs to bridge: time from "request sent" to "first response byte" to "full response parsed"
- Check if firmware has any delays in the response path (show_auto_approved draws to OLED)
- Try increasing baud rate to 230400

## Grant guardrails

All four tasks are **foundation work** (bug fixes, management of existing features, community engagement, performance investigation). None are G23 milestones. Safe to proceed.

G23 reserved milestones (DO NOT implement):
- NIP standardisation (nsec-tree + multi-identity signing)
- Start9 + Umbrel packaging
- Pi Zero 2 W flashable image
- Hardening (relay failover, watchdog, Shamir)
- Bark browser extension (Firefox port, store submissions)
- Documentation + adoption
- Ongoing maintenance

## Suggested execution order

Tasks 1 and 3 are independent and quick -- parallelise them.
Task 2 is the meatiest -- do after 1 and 3.
Task 4 is investigative -- do last or in parallel with Task 2.

## New roadmap items discovered this session

- Bark should appear as a remote signer on nostrapps.com
- NWC wallet integration for hardware-signed zaps (bray's NWC stack + ESP32 sign_event kind 9734)
- Sapwood management daemon on Pi -- always-running systemd service that controls the bridge (start/stop/restart), proxies management frames when bridge has the port, exposes HTTP API for Sapwood. Enables Sapwood to work in both modes: direct Web Serial (bridge off) or HTTP proxy (bridge on).
- Sapwood social preview image
- Add Heartwood + Sapwood to awesome-nostr
- Register sapwood.dev domain, point to GitHub Pages
- Sapwood BLE connectivity for portable mode (requires: management frame rate limiting in firmware, BLE pairing button press, CSP headers)
