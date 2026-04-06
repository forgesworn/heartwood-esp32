# Heartwood ESP32

Hardware signing device for Nostr on a Heltec WiFi LoRa 32 V4 (ESP32-S3). Two modes from the same codebase:

- **HSM mode** (default) — USB-attached to Pi, holds master secret, all radios disabled
- **Portable mode** — battery-powered, holds child key, BLE enabled for phone signing

## Security model

- **Physical approval required** — OLED shows the request, button press to sign. No silent signing.
- **HSM mode:** all radios disabled, USB serial only. Pi compromise is survivable — keys live on the ESP32.
- **Portable mode:** only BLE enabled (short range). Holds a child key, never the master. If compromised, burn that branch and re-provision.
- **WiFi is never enabled** in either mode — TCP/IP stack is too large an attack surface for a key-holding device.
- **JTAG disabled** in production firmware to prevent debug-port key extraction.

## Feature flags

The two modes will be cargo features (not yet implemented):

```toml
[features]
default = ["hsm"]
hsm = []        # USB serial, all radios off, master secret
portable = []   # BLE GATT, battery management, child key only
```

## Current state

Phase 5 (flash-once production) complete (2026-04-03). Seven crates: `common/` (shared crypto + frame protocol + NIP-46 types + NIP-44/NIP-04 encryption + policy types), `firmware/` (ESP32), `provision/` (host CLI), `sign-test/` (signing test harness), `heartwoodd/` (Pi-side daemon -- Soft and Hard modes), `ota/` (Pi-side serial OTA tool), `sapwood/` (web management UI, separate repo). Multi-master NVS storage (up to 8 masters, three provisioning modes: bunker/tree-mnemonic/tree-nsec). On-device NIP-44 transport encryption -- the Pi is zero-trust in Hard mode, only sees ciphertext (including sign_event responses). Connection slot policies (NVS-persisted on ESP32, Argon2id keyfile on Pi). Full NIP-46 method set (15 methods: 8 standard + 7 heartwood extensions; proof methods stubbed). Connect secret validation per NIP-46 spec. Serial OTA with SHA-256 verification and automatic rollback. Factory reset with button confirmation. Firmware uses libsecp256k1 (C FFI) for all signing.

Heartwood Soft mode: `heartwoodd` runs standalone on a Pi with no ESP32. Keys encrypted at rest with Argon2id + XChaCha20-Poly1305, unlocked via Sapwood. Policy-based auto-approve with Sapwood approval queue for out-of-policy requests. Same management API, same Sapwood UI, same NIP-46 signing -- just software-backed instead of hardware-backed.

Next: end-to-end Soft mode testing (unlock, create master, pair Bark, sign). Production hardening (JTAG disable, watchdog). Sapwood UI for tier badge, unlock form, approval queue.

## Session memory

Cross-session design thinking, grant reservations, and feedback lessons are in `docs/memory/` (mirrored from each machine's `~/.claude/projects/.../memory/` auto-memory store). **At the start of any session on this repo, read `docs/memory/MEMORY.md` and the files it references.** These capture context that isn't in the code or git history, including:

- **Heartwood tier ladder** (Soft/Hard/Portable/Pocket): product reframe and naming decisions
- **Coercion-resistance stack**: canary + spoken-token + ring-sig + button composition, **as post-grant roadmap, NOT current work**
- **Grant milestone reservations**: explicit do-not-build list for work reserved under G01 NLnet CANARY, G12 NLnet Privacy, G23 OpenSats Heartwood, and Heartwood Phase 2
- **Grant-safe design feedback**: rule to check existing libraries and `prometheus/grants/TRACKER.md` before designing cross-repo crypto integration

On machines where Claude Code's auto-memory should also load them, sync or symlink `~/.claude/projects/-Users-darren-WebstormProjects-heartwood-esp32/memory/` with `docs/memory/`. The repo copy is the portable canonical; auto-memory on each machine is a local working copy.

## Build & flash

Five crates — build each from its own directory:

```bash
cd common && cargo test                    # shared crypto tests
cd common && cargo test --features nip46   # NIP-46 + event ID tests
cd provision && cargo build                # host CLI tool
cd sign-test && cargo build                # signing test harness
cd heartwoodd && cargo build               # Pi-side daemon (Soft or Hard mode)
cd ota && cargo build                      # Pi-side serial OTA tool
cd firmware && cargo build                 # ESP32 firmware (needs ESP toolchain)
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Requires the ESP Rust toolchain for firmware: `espup install`, then `source ~/export-esp.sh`.

## Conventions

- British English in all prose and comments
- No secrets in logs, serial output, or display — npub only
- Zeroize all private key material after use
- Git commits: `type: description` (feat:, fix:, docs:, refactor:, test:, chore:)
- No `Co-Authored-By` lines in commits
- This is a PRIVATE repo — docs and plans can live here

## Frozen protocol

The nsec-tree derivation MUST match heartwood-core byte-for-byte. The test vector in `common/src/derive.rs` asserts this. The mnemonic derivation path (`m/44'/1237'/727'/0'/0'`) is tested in `provision/src/main.rs`. If derivation logic changes, update both repos.

## GPIO pin assignments (Heltec V4)

| Function | GPIO | Verified |
|----------|------|----------|
| OLED SDA | 17 | Yes — Heltec factory test, Meshtastic |
| OLED SCL | 18 | Yes — Heltec factory test, Meshtastic |
| OLED RST | 21 | Yes — must stay HIGH after init or display blanks |
| Vext (OLED power) | 36 | Yes — active LOW, must be set before I2C init |
| White LED | 35 | Yes — active HIGH |
| GNSS TX | 34 | Not yet used |
| GNSS RX | 33 | Not yet used |
| LoRa NSS | 8 | Not yet used |
| LoRa RST | 12 | Not yet used |
| LoRa DIO1 | 14 | Not yet used |

**PSRAM uses GPIO 26–32.** Never drive those pins.

## Known issues

### k256 LoadStoreAlignment on Xtensa (RESOLVED)

k256's field arithmetic does unaligned memory accesses that hang on Xtensa LX7.
No amount of thread/alignment tricks fixes it reliably — `SigningKey::from_bytes()`
hangs deterministically, with one-off successes depending on exact binary layout.

**Resolution:** Firmware now uses the `secp256k1` crate (C FFI wrapping Bitcoin
Core's libsecp256k1) which is alignment-safe on all architectures. The `common`
crate has a feature flag: `k256-backend` (default, for host tools/tests) and
`secp256k1-backend` (for firmware). Both backends produce identical outputs —
verified by the frozen test vector in `common/src/derive.rs`.

## Dependencies

All crypto crates are no_std-compatible but we use the ESP-IDF std framework:

| Crate | Why |
|-------|-----|
| secp256k1 | libsecp256k1 C FFI — BIP-340 Schnorr (firmware) |
| k256 | secp256k1 pure Rust — BIP-340 Schnorr (host tools/tests) |
| hmac + sha2 | HMAC-SHA256 child key derivation |
| zeroize | Deterministic secret cleanup |
| bech32 | npub encoding |
| bip39 + bip32 | Mnemonic derivation (provision CLI only) |
| crc32fast | Serial protocol integrity |
| esp-idf-svc + esp-idf-hal | ESP-IDF std framework (I2C, GPIO, NVS, logging) |
| ssd1306 + embedded-graphics | OLED driver and text rendering |
