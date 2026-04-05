---
name: Sapwood -- Heartwood device management web UI
description: Sapwood (sapwood.dev) is the Meshtastic-style web UI for managing the Heartwood ESP32. Public repo at forgesworn/sapwood. Brand finalised 2026-04-04.
type: project
---

**Sapwood** is the web-based management interface for the Heartwood ESP32 signing device. Named after the living, active layer between bark and heartwood in tree anatomy. Public repo at forgesworn/sapwood.

- **Tagline:** Shape your signer
- **Domain:** sapwood.dev (primary), sapwood.app + sapwood.org (defensive)
- **Tone:** Sovereign, precise, calm
- **Brand artifacts:** ~/WebstormProjects/sapwood/brand.json + docs/brand-identity.md

**Why:** The provision CLI works but is developer-facing. A web UI on the Pi would let users manage the device -- view status, manage TOFU-approved clients, trigger factory reset, run provisioning, flash firmware via OTA.

**How to apply:** The policy management frames (0x27-0x2A) added on 2026-04-04 are UI-agnostic. The bridge needs a small HTTP/WebSocket API that Sapwood calls, which then sends serial frames. Not a G23 grant milestone -- it's foundation work.
