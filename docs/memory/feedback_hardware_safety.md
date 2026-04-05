---
name: Hardware safety — never brick the Heltec V4
description: Critical constraint — all firmware changes must be safe to flash on the Heltec WiFi LoRa 32 V4
type: feedback
---

Never brick the Heltec WiFi LoRa 32 V4. Before flashing, verify the build compiles cleanly and does not touch unsafe GPIO pins (PSRAM uses GPIO 26–32).

**Why:** The user has one physical device and bricking it would halt the entire project.

**How to apply:** Always verify compilation before recommending a flash. Never drive PSRAM pins (GPIO 26–32). Never disable the USB bootloader. Be cautious with flash partition changes. When in doubt, test with `cargo build` before `espflash flash`.
