---
name: No eFuse burning
description: Never burn eFuses or enable flash encryption on the Heltec V4 — permanently locks the chip
type: feedback
---

Do NOT burn eFuses, enable flash encryption, or do any permanent chip-locking operations on the Heltec WiFi LoRa 32 V4.

**Why:** eFuse burning is irreversible — it permanently locks the chip to one firmware, prevents reuse (e.g. for Meshtastic), and risks bricking. Physical security is the protection model instead. This is also documented in CLAUDE.md under "Deliberately excluded".

**How to apply:** If any task, plan, or hardening step mentions eFuses, JTAG disable via eFuse, flash encryption, or secure boot — skip it entirely. Warn the user if it comes up.
