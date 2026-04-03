# Heartwood ESP32

Hardware signing module (HSM) for Nostr on a Heltec WiFi LoRa 32 V4 (ESP32-S3). USB-attached to a Raspberry Pi running heartwood-device. The Pi handles networking, the ESP32 handles cryptography. Private keys never leave the chip.

## Security model

- **All wireless radios disabled** — WiFi, BLE, LoRa are attack surfaces. The device communicates only over USB serial.
- **Physical approval required** — OLED shows the request, button press to sign. No silent signing.
- **Pi compromise is survivable** — keys live on the ESP32, not in Pi memory. An attacker with root on the Pi still cannot extract keys or sign without physical button access.
- **JTAG disabled** in production firmware to prevent debug-port key extraction.

## Build & flash

```bash
cargo build                                                          # debug build
espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32  # flash + serial
```

Requires the ESP Rust toolchain: `espup install`, then `source ~/export-esp.sh`.

## Conventions

- British English in all prose and comments
- No secrets in logs, serial output, or display — npub only
- Zeroize all private key material after use
- Git commits: `type: description` (feat:, fix:, docs:, refactor:, test:, chore:)
- No `Co-Authored-By` lines in commits
- This is a PRIVATE repo — docs and plans can live here

## Frozen protocol

The nsec-tree derivation MUST match heartwood-core byte-for-byte. The test vector in `main.rs` asserts this at runtime. If derivation logic changes, update both repos.

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
| esp-idf-svc + esp-idf-hal | ESP-IDF std framework (I2C, GPIO, logging) |
| ssd1306 + embedded-graphics | OLED driver and text rendering |
