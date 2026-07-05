# Heartwood ESP32

Hardware signing device for Nostr on a Heltec WiFi LoRa 32 (ESP32-S3). Both the V3 (CP2102 UART bridge) and V4 (native USB-Serial-JTAG) boards are supported from the same codebase via the `heltec-v3` / `heltec-v4` cargo features. See `firmware/src/serial.rs` for the transport abstraction. The operating mode is selected at runtime from the NVS network config (`NetConfig.mode`), not a build flag:

- **USB-bridged mode** (default) — USB-attached to a Pi, holds master secrets, all radios disabled; the Pi handles networking.
- **WiFi-standalone mode** (opt-in) — the ESP32 joins WiFi and talks to Nostr relays directly, running the full NIP-46 signing loop on-chip with no Pi. Enabled only when provisioned with an SSID + relay list; the USB cable stays fully live in parallel. See `firmware/src/relay.rs`.
- **Portable mode** (roadmap, not built) — battery-powered, holds a child key, BLE for phone signing.

## Security model

- **Physical approval required** — OLED shows the request, button press to sign. No silent signing. Applies in every mode, including WiFi-standalone.
- **USB-bridged mode (high-assurance default):** all radios disabled, USB serial only. Pi compromise is survivable — keys live on the ESP32, and in device-decrypts mode the Pi only ever sees ciphertext.
- **WiFi-standalone mode (opt-in convenience tier):** WiFi *is* enabled and the device reaches relays directly — a deliberately larger attack surface, accepted in exchange for dropping the Pi. Keys still never leave the chip, NIP-44 is still decrypted on-device, and every signature is still button-gated. Relay-side device management (kind 24134) is authenticated to a provisioned operator pubkey and replay-protected. Don't enable this tier where the USB high-assurance model is required.
- **Portable mode** (roadmap, not built) — would enable only BLE (short range) and hold a child key, never the master.
- **JTAG disabled** in production firmware to prevent debug-port key extraction.

## Feature flags & mode selection

Operating mode (USB-bridged vs WiFi-standalone) is selected **at runtime** from `NetConfig.mode` in NVS (`common/src/net_config.rs`: `"usb"` default, `"wifi"` opt-in) — it is **not** a cargo feature. Cargo features select the board (`heltec-v3` / `heltec-v4`) and the crypto backend (`k256-backend` for host tools/tests, `secp256k1-backend` for firmware — see Known issues below). The future `portable` (BLE) tier is not built.

## Current state

Phase 5 (flash-once production) complete (2026-04-03). Seven crates: `common/` (shared crypto + frame protocol + NIP-46 types + NIP-44/NIP-04 encryption + policy types), `firmware/` (ESP32), `provision/` (host CLI), `sign-test/` (signing test harness), `heartwoodd/` (Pi-side daemon -- Soft and Hard modes), `ota/` (Pi-side serial OTA tool), `sapwood/` (web management UI, separate repo). Multi-master NVS storage (up to 8 masters, three provisioning modes: bunker/tree-mnemonic/tree-nsec). On-device NIP-44 transport encryption -- the Pi is zero-trust in Hard mode, only sees ciphertext (including sign_event responses). Connection slot policies (NVS-persisted on ESP32, Argon2id keyfile on Pi). Full NIP-46 method set (15 methods: 8 standard + 7 heartwood extensions; proof methods stubbed). Connect secret validation per NIP-46 spec. Serial OTA with SHA-256 verification and automatic rollback. Factory reset with button confirmation. Firmware uses libsecp256k1 (C FFI) for all signing.

Heartwood Soft mode: `heartwoodd` runs standalone on a Pi with no ESP32. Keys encrypted at rest with Argon2id + XChaCha20-Poly1305, unlocked via Sapwood. Policy-based auto-approve with Sapwood approval queue for out-of-policy requests. Same management API, same Sapwood UI, same NIP-46 signing -- just software-backed instead of hardware-backed.

Encrypted backup/restore of connection slots and policies via Sapwood -- auto-snapshots after slot changes, manual export/import, Argon2id + XChaCha20-Poly1305 encrypted backup file, physical button confirmation on restore. Dedicated backup passphrase (default "heartwood", changeable via Sapwood). Works in both Hard and Soft modes.

Next: end-to-end Soft mode testing (unlock, create master, pair Bark, sign). Production hardening (JTAG disable, watchdog). Sapwood UI for tier badge, unlock form, approval queue, backup export/import.

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
- Private docs (plans, session memory) live in gitignored directories

## Frozen protocol

The nsec-tree derivation MUST match heartwood-core byte-for-byte. The test vector in `common/src/derive.rs` asserts this. The mnemonic derivation path (`m/44'/1237'/727'/0'/0'`) is tested in `provision/src/main.rs`. If derivation logic changes, update both repos.

## GPIO pin assignments (Heltec V3 and V4)

Common to both boards:

| Function | GPIO | Verified |
|----------|------|----------|
| OLED SDA | 17 | Yes -- Heltec factory test, Meshtastic |
| OLED SCL | 18 | Yes -- Heltec factory test, Meshtastic |
| OLED RST | 21 | Yes -- must stay HIGH after init or display blanks |
| Vext (OLED power) | 36 | Yes -- active LOW, must be set before I2C init |
| White LED | 35 | Yes -- active HIGH |
| PRG button | 0 | Active LOW, internal pull-up |
| LoRa NSS | 8 | Not yet used |
| LoRa RST | 12 | Not yet used |
| LoRa DIO1 | 14 | Not yet used |

Board-specific (host transport):

| Board | Mechanism | GPIO |
|-------|-----------|------|
| V4 | Native USB-Serial-JTAG | 19 (D-), 20 (D+) |
| V3 | UART0 via CP2102 bridge | 43 (TX), 44 (RX) |

V4-only (not present on V3):

| Function | GPIO | Verified |
|----------|------|----------|
| GNSS TX | 34 | Not yet used |
| GNSS RX | 33 | Not yet used |

**PSRAM uses GPIO 26-32 on the V4 (S3R2).** V3 (S3FN8) has no PSRAM. Never drive those pins on V4.

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
