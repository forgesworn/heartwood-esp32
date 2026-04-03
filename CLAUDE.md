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

Phase 2 (provisioning) complete. Three independent crates: `common/` (shared crypto), `firmware/` (ESP32), `provision/` (host CLI). The firmware has not been flashed yet — needs ESP toolchain installed.

Next: install ESP toolchain, flash, and test the provisioning flow end-to-end.

## Build & flash

Three independent crates — build each from its own directory:

```bash
cd common && cargo test                    # shared crypto tests
cd provision && cargo build                # host CLI tool
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
| OLED RST | 21 | Yes — Heltec factory test, Meshtastic |
| GNSS TX | 34 | Not yet used |
| GNSS RX | 33 | Not yet used |
| LoRa NSS | 8 | Not yet used |
| LoRa RST | 12 | Not yet used |
| LoRa DIO1 | 14 | Not yet used |

**PSRAM uses GPIO 26–32.** Never drive those pins.

## Dependencies

All crypto crates are no_std-compatible but we use the ESP-IDF std framework:

| Crate | Why |
|-------|-----|
| k256 | secp256k1 (BIP-340 Schnorr) |
| hmac + sha2 | HMAC-SHA256 child key derivation |
| zeroize | Deterministic secret cleanup |
| bech32 | npub encoding |
| bip39 + bip32 | Mnemonic derivation (provision CLI only) |
| crc32fast | Serial protocol integrity |
| esp-idf-svc + esp-idf-hal | ESP-IDF std framework (I2C, GPIO, NVS, logging) |
| ssd1306 + embedded-graphics | OLED driver and text rendering |
