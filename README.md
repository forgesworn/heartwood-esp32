# Heartwood ESP32

nsec-tree signing token spike for the **Heltec WiFi LoRa 32 V4** (ESP32-S3R2, 2MB PSRAM, 16MB flash, built-in SSD1306 OLED, L76K GNSS).

Derives a child identity from a hardcoded test seed using HMAC-SHA256 (the nsec-tree protocol) and displays the npub on the built-in OLED. The derived npub is asserted against heartwood-core output at runtime — if the protocol doesn't match, it panics before touching the display.

## Hardware

| Component | Detail |
|-----------|--------|
| Board | Heltec WiFi LoRa 32 V4 |
| Chip | ESP32-S3R2 (Xtensa LX7 dual-core, 240 MHz) |
| PSRAM | 2MB quad-SPI |
| Flash | 16MB |
| OLED | 128x64 SSD1306 (I2C: SDA=GPIO17, SCL=GPIO18, RST=GPIO21, addr 0x3C) |
| GNSS | L76K (not used in this spike) |
| LoRa | SX1262 (not used in this spike) |

## Setup

Install the ESP Rust toolchain:

```bash
cargo install espup ldproxy espflash
espup install
source ~/export-esp.sh
```

## Build

```bash
cargo build
```

## Flash & monitor

```bash
espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Serial output will show:
```
Heartwood ESP32 — nsec-tree signing token spike
Root npub: npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m
Child npub: npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t
Protocol vector verified — npub matches heartwood-core
npub displayed on OLED
```

## Test vector

| Parameter | Value |
|-----------|-------|
| Root secret | `[0x01, 0x02, ..., 0x20]` (32 bytes, sequential) |
| Root path | Raw secret → SigningKey (no HMAC intermediate) |
| Purpose | `persona/test` |
| Index | `0` |
| Expected child npub | `npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t` |

This must match heartwood-core's output for the same inputs. The nsec-tree derivation is:

```
context = b"nsec-tree\0" || b"persona/test" || 0x00 || 0x00000000
child_secret = HMAC-SHA256(key=root_secret, msg=context)
child_pubkey = SigningKey(child_secret).verifying_key()
npub = bech32_encode("npub", child_pubkey)
```

## GPIO safety

Verified against Heltec factory test code, Meshtastic firmware, and ESPHome configs:

- **GPIO 17, 18, 21** — confirmed correct for the V4 OLED. No conflict with PSRAM/flash.
- **PSRAM pins** on ESP32-S3R2 are GPIO 26–32 (quad-SPI). Nowhere near our I2C pins.
- **GPIO 33–37** are free on this board (only reserved on octal PSRAM variants like S3R8).

## Structure

```
Cargo.toml              ESP-IDF std project
build.rs                embuild sysenv
sdkconfig.defaults      ESP32-S3, PSRAM, 16KB stack
rust-toolchain.toml     esp channel
.cargo/config.toml      xtensa-esp32s3-espidf target
src/
  main.rs               Entry point: init OLED, derive, display
  derive.rs             HMAC-SHA256 child derivation (matches heartwood-core)
  encoding.rs           bech32 npub encoding
  types.rs              TreeRoot, Identity structs
```

## Stretch goals

- [ ] Sign a dummy 32-byte hash and display the signature
- [ ] Accept a signing request over BLE
- [ ] Show a QR code of the npub on the OLED
- [ ] LoRa ping (prove the radio works alongside the crypto)
- [ ] Read GPS coordinates from L76K GNSS module
