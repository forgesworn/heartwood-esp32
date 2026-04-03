# Heartwood ESP32

A hardware signing module (HSM) for Nostr, built on the **Heltec WiFi LoRa 32 V4** (ESP32-S3R2). Holds an nsec-tree master secret, derives child identities, and signs on request — private keys never leave the chip.

Designed to be **USB-attached to a Raspberry Pi** running [heartwood-device](https://github.com/forgesworn/heartwood). The Pi handles all networking (Tor, NIP-46 WebSocket, relay connections). The ESP32 handles all cryptography (key storage, derivation, signing). Communication between them is serial over USB — no wireless attack surface.

```
Internet ← Tor ← Pi (networking) ← USB serial → ESP32 (keys + signing)
                                                    ├── OLED (show request)
                                                    └── Button (approve/deny)
```

**Security model:** even if the Pi is fully compromised, an attacker cannot extract keys (they live on the ESP32) or sign without a physical button press on the device. This is the same architecture as Ledger/Trezor but for Nostr identities.

All wireless radios (WiFi, BLE, LoRa) are **disabled in firmware**. The board has them, but a signing device should be deaf.

## Hardware

| Component | Detail |
|-----------|--------|
| Board | Heltec WiFi LoRa 32 V4 |
| Chip | ESP32-S3R2 (Xtensa LX7 dual-core, 240 MHz) |
| PSRAM | 2MB quad-SPI |
| Flash | 16MB |
| OLED | 128x64 SSD1306 (I2C: SDA=GPIO17, SCL=GPIO18, RST=GPIO21, addr 0x3C) |
| GNSS | L76K (disabled — not used for signing) |
| LoRa | SX1262 (disabled — attack surface) |
| WiFi | ESP32-S3 built-in (disabled — attack surface) |
| BLE | ESP32-S3 built-in (disabled — attack surface) |
| USB | USB-C (power + serial communication with Pi) |
| Button | PRG button (signing approval) |

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

## Roadmap

### Phase 1 — Prove the crypto (current spike)

- [x] nsec-tree HMAC-SHA256 derivation on ESP32-S3
- [x] bech32 npub encoding
- [x] Runtime assertion against heartwood-core test vectors
- [x] Display npub on OLED
- [ ] Sign a dummy 32-byte hash and display the signature

### Phase 2 — Provisioning

- [ ] CLI tool to derive 32-byte root secret from mnemonic + passphrase (offline PC)
- [ ] NVS storage for root secret (encrypted flash partition)
- [ ] First-boot provisioning mode: accept root secret over USB serial
- [ ] Subsequent boots read from NVS, skip provisioning
- [ ] Show master npub on OLED after boot

### Phase 3 — USB signing oracle

- [ ] Serial protocol: Pi sends signing requests, ESP32 responds with signatures
- [ ] OLED shows what you're signing (event kind, content preview, target pubkey)
- [ ] Physical button to approve/deny each request
- [ ] Integration with heartwood-device on the Pi (new serial transport for NIP-46)
- [ ] Timeout: unsigned requests expire after N seconds

### Phase 4 — Hardening

- [ ] Disable all wireless radios in firmware (WiFi, BLE, LoRa)
- [ ] Disable JTAG debugging
- [ ] Rate limiting (max signs per minute)
- [ ] Audit log on OLED (last N signing events)
- [ ] Tamper detection (voltage glitch monitoring if feasible)
- [ ] Zeroize on repeated failed auth attempts

### Not planned (attack surface)

These are deliberately excluded. The board has the hardware, but a signing device should be deaf:

- ~~BLE signing~~ — BLE stack has had CVEs, unnecessary attack surface
- ~~WiFi signing~~ — full TCP/IP stack is a liability for a key-holding device
- ~~LoRa signing~~ — any radio reception is a fuzzing target
- ~~GPS attestations~~ — interesting concept but not worth the attack surface on an HSM
