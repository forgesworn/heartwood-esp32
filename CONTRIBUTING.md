# Contributing

## Prerequisites

- Rust stable (for host crates: `common`, `provision`, `sign-test`, `bridge`, `ota`)
- ESP Rust toolchain (for `firmware` only):
  ```bash
  cargo install espup ldproxy espflash
  espup install
  source ~/export-esp.sh
  ```
- Heltec WiFi LoRa 32 V4 board (for firmware development)

## Setup

```bash
git clone git@github.com:forgesworn/heartwood-esp32.git
cd heartwood-esp32
```

Each crate is independent — build from its own directory.

## Development

| Crate | Build | Test |
|-------|-------|------|
| `common` | `cd common && cargo build` | `cargo test` (k256 backend) |
| `common` (NIP-46 + event ID) | — | `cargo test --features nip46` |
| `provision` | `cd provision && cargo build` | manual: flash device, run CLI |
| `sign-test` | `cd sign-test && cargo build` | manual: requires flashed device |
| `bridge` | `cd bridge && cargo build` | manual: requires flashed device + relay |
| `ota` | `cd ota && cargo build` | manual: requires flashed device |
| `firmware` | `cd firmware && cargo build` | manual: flash and inspect OLED |

**CI runs `common` tests only** (no hardware required). All other crates require a physical device.

### Running common tests

```bash
cd common
cargo test                      # default k256 backend
cargo test --features nip46     # includes NIP-46 types and event ID tests
```

The frozen test vector in `common/src/derive.rs` MUST pass. Do not change expected values — the derivation output must match `heartwood-core` byte-for-byte.

### Flashing for manual testing

```bash
cd firmware
cargo build
espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

After flash, use `sign-test` to exercise the signing flow:

```bash
cd sign-test
cargo run -- --port /dev/cu.usbserial-*
```

## Making Changes

1. Branch: `git checkout -b type/short-description`
2. Make changes. Ensure `cargo test` passes in `common/`.
3. For firmware changes: flash to hardware, verify OLED output and button behaviour.
4. Commit using conventional commits:
   - `feat:` — new feature
   - `fix:` — bug fix
   - `docs:` — documentation only
   - `refactor:` — no behaviour change
   - `test:` — test additions or fixes
   - `chore:` — build or tooling changes
5. Open a pull request against `main`.

## Code Conventions

- British English in all prose and comments
- No secrets in log output, serial frames, or OLED display — npub only, never nsec
- Zeroize all private key material after use (use the `zeroize` crate)
- Firmware: use `secp256k1-backend` feature; host tools use `k256-backend` (default)
- Do not use the `k256` crate in firmware — it causes alignment faults on Xtensa LX7 (see `CLAUDE.md` § Known issues)

## Frozen Protocol

The nsec-tree derivation context string and the mnemonic derivation path (`m/44'/1237'/727'/0'/0'`) are frozen. Any change must be coordinated with `heartwood-core` and both test vectors updated simultaneously.

## Project Structure

```
common/       Shared crypto — derivation, NIP-44/04, NIP-46 types, frame protocol, policy types
firmware/     ESP32 firmware — flash to the Heltec V4 device
provision/    Host CLI — push mnemonic or nsec to a freshly-flashed device
sign-test/    End-to-end test harness — send NIP-46 requests over serial
bridge/       Pi-side relay bridge — Nostr relays ↔ NIP-44 ↔ serial ↔ ESP32
ota/          Pi-side serial OTA tool — push firmware updates with SHA-256 verification
docs/specs/   Design specifications (HSM, provisioning, signing oracle)
docs/plans/   Implementation plans and hardening roadmap
```
