# Phase 2 — Provisioning Design

**Date:** 2026-04-03
**Status:** Approved
**Scope:** Workspace restructure, provisioning CLI, NVS storage, first-boot flow

## Overview

Phase 2 adds secure provisioning: getting a real BIP-39-derived root secret onto the ESP32 over USB serial and storing it in encrypted NVS. The codebase is restructured into a Cargo workspace so the derivation logic is shared between the ESP32 firmware and a host-side CLI tool.

## Crate Structure

Three independent crates with path dependencies (not a Cargo workspace — firmware targets xtensa via the ESP toolchain, provision and common target the host via standard Rust). Each is built from its own directory.

```
heartwood-esp32/
  common/                     shared crate — pure Rust, no ESP deps
    Cargo.toml
    src/
      lib.rs
      derive.rs               HMAC-SHA256 child derivation (moved from firmware)
      encoding.rs             bech32 npub encoding (moved from firmware)
      types.rs                TreeRoot, Identity, constants (moved from firmware)
  firmware/                   ESP32 crate
    Cargo.toml
    build.rs
    sdkconfig.defaults
    rust-toolchain.toml
    .cargo/config.toml
    src/
      main.rs                 boot flow: NVS check → provision or run
      sign.rs                 BIP-340 Schnorr signing/verification
      nvs.rs                  NVS read/write for root secret
      provision.rs            serial provisioning protocol (ESP32 side)
      oled.rs                 OLED display helpers
  provision/                  host CLI tool
    Cargo.toml
    src/
      main.rs                 mnemonic → secret → serial push
```

The `common` crate compiles on both host (x86_64) and xtensa (ESP32-S3). It contains no platform-specific code.

## Derivation Path

Matches heartwood-core exactly:

1. BIP-39 mnemonic + optional passphrase → 64-byte seed (PBKDF2)
2. BIP-32 master key from seed
3. Derive at path `m/44'/1237'/727'/0'/0'`
4. Extract 32-byte private key — this is the tree root secret
5. `create_tree_root(secret)` — no HMAC intermediate, raw secret → SigningKey

The BIP-32 path constant `MNEMONIC_PATH` lives in `common/src/types.rs`. Note: `common` does NOT depend on `bip39` or `bip32` — those are provision-only dependencies. The ESP32 never sees a mnemonic; it receives raw 32-byte secrets. `common` provides the HMAC child derivation, encoding, types, and the path constant.

## Provision CLI (`heartwood-provision`)

### Dependencies

| Crate | Purpose |
|-------|---------|
| `common` (path dep) | Shared derivation, encoding, types |
| `bip39` (v2) | Mnemonic validation + PBKDF2 seed generation |
| `bip32` (v0.5) | BIP-32 HD key derivation |
| `serialport` | USB serial communication |
| `rpassword` | Hidden stdin input (mnemonic + passphrase) |
| `crc32fast` | CRC32 checksum for serial framing |
| `zeroize` | Deterministic secret cleanup |

### User Flow

```
$ heartwood-provision --port /dev/ttyUSB0

Enter mnemonic: ************************************
Enter passphrase (empty for none): ********

Derived master npub: npub1abc...xyz
Send to device? [y/N]: y

Sending... ACK received.
Root secret provisioned. Device will now boot with this identity.
```

1. Prompt for mnemonic (hidden input, no echo)
2. Prompt for passphrase (hidden input, optional)
3. Derive root secret via BIP-39 → BIP-32 → 32 bytes
4. Display master npub for user confirmation
5. Send 38-byte frame over serial
6. Wait for ACK/NACK (timeout 30s)
7. Zeroise all secrets and exit

### Serial Protocol

```
PC → ESP32:  [0x48 0x57] [32 bytes secret] [4 bytes CRC32]  = 38 bytes total
ESP32 → PC:  [0x06] ACK   or   [0x15] NACK
```

- **Magic bytes:** `0x48 0x57` ("HW") — sync marker
- **CRC32:** computed over the 32-byte secret only (not magic bytes)
- **Baud rate:** 115200 (ESP-IDF default)
- **Timeout:** 30 seconds on both sides
- **NACK reasons:** CRC mismatch, NVS write failure

No encryption on the wire. USB serial is point-to-point. For now the heartwood server (Pi) and dev PC are on the same local LAN, so provisioning runs directly from the PC over USB. The air-gapped provisioning workflow and USB-only lockdown come later when moving to a production setup.

## ESP32 Firmware — Boot Flow

```
Boot
  │
  ├─ Initialise ESP-IDF, OLED
  │
  ├─ Read NVS "root_secret" key
  │
  ├─ Found?
  │    │
  │    yes ──► Derive master npub
  │            Display npub on OLED
  │            Log "Booted with stored identity"
  │            Enter idle loop
  │
  └─ Not found?
       │
       ──► OLED shows "Awaiting secret..."
           Listen on USB serial for 38-byte frame
           Validate magic bytes
           Validate CRC32
           │
           ├─ Invalid → send NACK, keep waiting
           │
           └─ Valid → store secret in encrypted NVS
                      Send ACK
                      Derive master npub
                      Display npub on OLED
                      Log "Provisioned — identity stored"
                      Enter idle loop
```

### NVS Storage

- **Namespace:** `heartwood`
- **Key:** `root_secret`
- **Value:** 32 bytes (blob)
- **Encryption:** plaintext NVS for Phase 2. NVS encryption (AES-XTS with eFuse key) deferred to Phase 4 (hardening) — flash encryption burns eFuses irreversibly and risks bricking the device if anything goes wrong during first boot. The secret is protected by physical security until JTAG-disable and NVS encryption are added together in Phase 4.

### Test Vector Handling

Two separate test vectors:

1. **Phase 1 vector (raw bytes):** The `0x01..0x20` → expected npub assertion stays in `common` as a unit test for the HMAC child derivation. It does not appear in the firmware boot path.

2. **Phase 2 vector (full mnemonic path):** A known test mnemonic is derived through the full BIP-39 → BIP-32 → `create_tree_root` path. The expected master npub is recorded. This becomes the end-to-end provisioning test — run the CLI with the test mnemonic, confirm the device displays the expected npub. The test mnemonic and expected npub are defined in `common/src/types.rs` as test constants (behind `#[cfg(test)]`).

## OLED Display States

| State | Display |
|-------|---------|
| First boot (no secret) | `Awaiting secret...` |
| Provisioning success | Master npub (same layout as Phase 1) |
| Normal boot (secret in NVS) | Master npub |
| Provisioning error | `CRC error — retry` or `NVS write failed` |

## sdkconfig Changes

No sdkconfig changes needed for Phase 2. NVS works with the default partition table in plaintext mode. NVS encryption and custom partition table are deferred to Phase 4.

## Security Considerations

- **Secrets never logged:** only npub (public key) appears in serial output or OLED
- **Zeroisation:** all private key material wrapped in `Zeroizing<[u8; 32]>`, zeroised after use
- **No echo:** mnemonic and passphrase input hidden from terminal
- **Air-gap assumed:** provisioning PC should be offline; the CLI does no networking
- **NVS plaintext:** flash encryption and NVS encryption are permanently deferred (see "Deliberately excluded" in README). eFuse burning risks bricking the device and prevents reuse for other firmware. Physical security is the protection model.
- **Single write:** once provisioned, the CLI could warn if NVS already has a secret (future enhancement, not Phase 2 scope)

## Out of Scope

- Re-provisioning / secret rotation (Phase 4 hardening territory)
- Mnemonic generation (user brings their own, generated offline)
- Backup/export of the secret from the device (by design — secrets never leave the ESP32)
- Child key provisioning for portable mode (Phase 5)
