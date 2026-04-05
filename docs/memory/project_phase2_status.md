---
name: Phase 3 signing oracle — complete
description: Phase 3 fully verified end-to-end on hardware (2026-04-03) — signing, OLED, button, serial all working
type: project
---

Phase 3 signing oracle **complete and verified end-to-end** on hardware (2026-04-03).

**Full stack verified:**
sign-test CLI → USB serial → ESP32 frame parser → NIP-46 dispatch → OLED sign request → button approval (long hold 2s) → libsecp256k1 Schnorr sign (~4s) → USB serial response → sign-test receives signed event

**Key implementation details:**
- `common/` has dual crypto backend: `k256-backend` (default, host) and `secp256k1-backend` (firmware)
- Firmware creates ONE `Secp256k1::signing_only()` context at boot via `Arc`, shared everywhere
- OLED font is FONT_6X10 (21 chars/line), upgraded from FONT_5X8
- USB serial TX buffer must be 1024 bytes (default 256 was too small for signed event response ~500 bytes)
- Cross-compiler for secp256k1-sys: `CC_xtensa_esp32s3_espidf = "xtensa-esp32s3-elf-gcc"` in `.cargo/config.toml`
- Boot derives npub and displays on OLED (~2s for context creation + keypair)

**Gotcha resolved:** "Signing hangs" was actually `write_frame()` blocking on a too-small TX buffer, not a crypto issue. OLED-based diagnostics (showing step labels before each operation) was the technique that pinpointed this instantly.

**Next steps:**
1. Integrate with heartwood-device (Pi-side bridge daemon)
2. Test child key derivation (heartwood context with purpose/index)
3. Production hardening: JTAG disable, error recovery, watchdog

**Why:** Phase 3 was the last blocking milestone for the signing device. With end-to-end signing verified, the device is ready for Pi integration.

**How to apply:** The firmware is ready to flash and use. Next work is on the Pi side (bridge crate) and child key derivation testing.
