---
name: Heartwood is a ladder of tiers, not a single device
description: Reframe of the heartwood-esp32 project -- same daemon runs on Pi with ESP32 as an optional hardware upgrade; "bridge" should be dropped from the vocabulary
type: project
---

Heartwood is an ecosystem with tiers, not "an ESP32 with a Pi-side bridge". The same daemon (`heartwoodd`) runs on the Pi regardless of whether an ESP32 is attached. When an ESP32 is plugged in, the daemon delegates signing and holds no secret. When it isn't, the daemon signs locally with a key encrypted at rest.

Tiers (each defends against a specific threat; together they form the ladder):
- **Heartwood Pocket** -- phone holds its *own* scoped child key derived by the upstream Pi/ESP32. Signs locally, biometric-gated, no round-trip. Scope baked in at provisioning: allowed kinds, amount ceilings, expiry, relay allowlist, optional geofence/time windows. Lose the phone → revoke that branch from Sapwood, reissue. Defends against browser-extension theft and casual device loss.
- **Heartwood Soft** -- Pi alone. Key encrypted on SD, unlocked into RAM. Normie entry point, no hardware purchase required. Defends against phone compromise (root survives; reissue child).
- **Heartwood Hard** -- Pi + ESP32. Pi becomes zero-trust plumbing. Button press on device required to sign. Defends against Pi compromise.
- **Heartwood Portable** -- ESP32 + battery + BLE. Child key, phone-paired. Hard-tier security away from home.

Critical design rule: **the phone is never a remote for the ESP32.** It does not auto-forward signing requests upstream on the basis of "biometric = physical presence" -- that would turn a button-press HSM into a remote oracle and let a compromised phone drain the root key. Instead, the phone is a leaf with its own key, same shape as Portable mode, just software-backed. The ESP32 button stays the ceremony for things that warrant ceremony; scoped child keys make the button press rare, not constant.

Duress handling lives at the Pocket tier: duress PIN unlocks a decoy child, heartbeat revocation expires keys if phone stops checking in with the Pi, tiered scopes route high-value signs (e.g. >10k sats, specific kinds) back to the Pi/ESP32 for button-press confirmation while low-value signs (likes, reposts, kind 1) stay on the phone.

**Canary/spoken/ring integration is a post-grant roadmap, not current work.** See `project_coercion_stack_roadmap.md` for the full composition story and `project_heartwood_grant_timing.md` for which pieces are reserved for which grant. Short version: canary-kit v2.7.0 already ships the duress/liveness/group primitives in TypeScript, but the Rust port needed for heartwood's `common/` crate is G01 NLnet CANARY M3 (submitted, not yet approved). Ring-sig Rust port is G12 NLnet Privacy (not yet submitted). `heartwood_create_proof`/`verify_proof` beyond the current stubs is reserved for Heartwood Phase 2 (future NLnet). Until those land, the Pocket tier should use canary-kit as a TypeScript library consumer in the app layer -- NOT a Rust integration inside common/ or firmware/.

Naming implications: drop the word "bridge" from user-facing vocabulary. The `bridge/` crate becomes `heartwoodd` (or just `heartwood`). Sapwood stays the UI across all tiers and shows a Soft/Hard/Portable badge. ESP32 firmware is `heartwood-device` or `heartwood-hsm`.

**Why:** Darren framed this on 2026-04-05 -- "on the Pi you can manage your keys on that machine, or go one step further and manage your ESP32 -- it's an ecosystem". Reframes the product story from "weird dev board required" to "flash an SD card, get a Nostr signer; add hardware later for button-press security".

**How to apply:** When scoping `.deb` / Pi image / Sapwood work, treat Heartwood Soft as a product in its own right, not plumbing. Upgrade path (plug in ESP32 → Sapwood detects → walks through key migration) is a first-class flow. Be honest in Sapwood's UI about the security tradeoff: Soft = "as safe as your Pi"; Hard = "as safe as your button finger". Avoid the word "bridge" in docs, commit messages, and UI copy going forward.
