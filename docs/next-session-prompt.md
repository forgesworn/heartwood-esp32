# Next session prompt

Paste this to pick up where we left off:

---

## GitHub issue #2: get_public_key and sign_event use different active identities

Confirmed the firmware is NOT the bug -- both `handle_get_public_key` and `do_sign` in `firmware/src/nip46_handler.rs` derive pubkeys identically from the same `master_secret` parameter. The identity mismatch can only happen if the bridge sends different `master_pubkey` bytes in the encrypted frame header for different NIP-46 methods.

The bridge code is on mypi.local at `~/heartwood/crates/heartwood-device/`. SSH as usual. Need to trace how the bridge resolves which master pubkey to put in the ENCRYPTED_REQUEST frame header for `get_public_key` vs `sign_event`. The bridge startup log shows it queries the device for its master list and routes to slot 0 -- so the routing logic is the place to look.

## Context

- Device is a Heltec WiFi LoRa 32 V4 (ESP32-S3) connected to a Raspberry Pi at mypi.local via USB serial (/dev/ttyACM0)
- Bridge service: `heartwood-esp32-bridge.service`
- esptool.py is installed on the Pi at `~/.local/bin/esptool`
- OTA works end-to-end (use `espflash save-image` to convert ELF to app binary first!)
- After esptool flash to ota_0, always erase otadata: `esptool erase_region 0xd000 0x2000`
- Always build with `--release` (debug builds are 2.2MB, exceed the 1.5MB ota_0 partition)
- All OLED screens have been upgraded to graphical design system (Rectangle primitives, tracked headers, graphical bars) -- don't touch those, they're good
- Boot animation: procedural 16-frame walk cycle with diagonal gait, Bezier tail, paw pads, haunch fill -- done and working
- Grant guardrails: check `docs/memory/project_heartwood_grant_timing.md` before building anything that might overlap with G01/G12/G23/Phase 2
