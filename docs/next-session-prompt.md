# Next session prompt

Paste this to pick up where we left off:

---

## Current state

Heartwoodd Soft mode implemented. The `bridge/` crate has been renamed to `heartwoodd/` with a `SigningBackend` trait and two implementations:

- **SerialBackend** (Hard mode) -- existing ESP32 serial code wrapped behind the trait
- **SoftBackend** (Soft mode) -- Argon2id-encrypted keyfile, local k256 signing, NIP-44/NIP-46 processing, policy-based approval queue

The daemon auto-detects mode at startup (probes for ESP32, falls back to Soft) with `--mode` CLI override. Management API, relay event loop, and Sapwood serving are shared across both modes.

Branch: `feat/heartwoodd-soft-mode` (not yet merged to main)

Design spec: `docs/plans/2026-04-06-heartwoodd-soft-mode-design.md`
Implementation plan: `docs/plans/2026-04-06-heartwoodd-soft-mode-plan.md`

19 tests pass (trait object safety, keystore crypto, SoftBackend lifecycle).

## What's next

- End-to-end Soft mode testing (unlock, create master, pair Bark, sign event)
- Sapwood UI changes for tier badge, unlock form, approval queue (separate repo)
- Merge feat branch to main after testing
- Production hardening (JTAG disable, watchdog) -- separate from Soft work
- Grant guardrails: check `docs/memory/project_heartwood_grant_timing.md` before building anything that overlaps G01/G12/G23/Phase 2

## Context

- Device is a Heltec WiFi LoRa 32 V4 (ESP32-S3) connected to Pi at mypi.local via USB serial (/dev/ttyACM0)
- heartwoodd replaces heartwood-bridge (same binary, two modes)
- Soft mode: Pi alone, Argon2id keyfile at <data-dir>/keystore.enc, Sapwood unlock
- Hard mode: ESP32 attached, serial frame protocol, button press signing
- OTA works end-to-end (use `espflash save-image` to convert ELF to app binary first!)
- Always build with `--release` for ESP32 (debug builds exceed 1.5MB ota_0 partition)
- All OLED screens have been upgraded to graphical design system -- don't touch those
- Boot animation: procedural 16-frame walk cycle -- done and working
