# Heartwood security model

What the device protects, against whom, and where the current limits are. This
is deliberately honest: a signer is only as trustworthy as the threats it
actually resists, so the gaps are stated as plainly as the strengths.

Status: 2026-06-22. Applies to the firmware in this repo and the Sapwood web
manager.

## Assets

| Asset | What it is | If stolen |
|-------|-----------|-----------|
| **Master seed** | 32-byte root (the 12-word phrase) | Full impersonation — the attacker *is* the identity |
| **Operator key** | kind-24134 management authority (Sapwood) | Can manage clients + approve signing (see below) |
| **Bridge secret** | USB management session auth | Can manage clients over USB |
| **Slot secrets** | per-client bunker connection credentials | Can connect as that client (subject to its policy) |

The master seed is the crown jewel. **It is generated on-device from hardware
entropy and is never transmitted off the device by any code path** — not over
USB, not over the relay, not in a backup. The only place it is ever displayed is
the OLED, once, at creation.

## Components and trust boundaries

```
[ Nostr app ] --bunker--> [ relay (untrusted) ] <--wss--> [ ESP32 signer ]
                                                  ^
[ browser: Sapwood ] --kind 24134 (operator) ----+   (holds the master seed)
[ browser: Sapwood ] --USB frames (bridge auth) ----------> (USB only)
```

- **ESP32 firmware** — trusted; holds the seed. Its integrity is the root of the
  whole system.
- **Relay / network** — untrusted. Sees only NIP-44 ciphertext.
- **Browser / Sapwood** — semi-trusted. Holds the *operator* key, not the seed.
- **Physical device** — see "Physical access" below; this is the weak boundary.

## Threat: remote / network attacker — **resisted**

An attacker on the network (or running a malicious relay) can observe and inject
relay traffic. They cannot:

- **Read messages** — NIP-44 encrypted master⇄counterparty; the relay sees only
  ciphertext.
- **Forge management** — kind-24134 commands are accepted only if authored by the
  baked **operator key** (`mgmt::is_operator`), and each request id is checked
  against a replay seen-set persisted across reboots (`mgmt::classify_replay`).
- **Reach the seed or firmware** — no relay method exposes the seed, and OTA is
  not reachable over the relay (the relay loop NACKs it).
- **Get a signature for free** — `sign_event` is gated by per-client policy;
  a fresh client's first signature needs either a physical button hold (USB) or
  an explicit operator `approve_signing` (relay). Connect/get_public_key/ping are
  the only unauthenticated-stranger operations.

**Residual:** a malicious relay can drop/delay traffic (availability) and replay
within the bounded window after a reboot (see "Known limits").

## Threat: compromised operator key or browser — **bounded, recoverable**

If the operator key leaks (or the browser is compromised), the attacker can do
what the operator can: create/revoke/relabel clients, change client policy, and
**approve signing** for a client they control — i.e. get the device to sign as
the master for messages they choose, for as long as the operator key is trusted.

They **cannot** extract the master seed, read it, or push firmware. Recovery:
the operator can revoke the rogue client; rotating the operator key requires a
re-flash (it is baked into the config partition).

Mitigations in place: the operator key lives in browser `localStorage` behind a
strict **Content-Security-Policy** (`script-src 'self'`, no `eval`, no
third-party origins — see `sapwood/vite.config.ts`), which closes the usual XSS
exfiltration routes. Sapwood renders no user-supplied HTML (the one `{@html}` is
a locally-generated QR SVG, not reflected input).

## Threat: malicious firmware (OTA or the web flasher) — **physical / trust-on-first-use**

OTA verifies a **SHA-256 of the image against a hash supplied by the host** —
this is *integrity* (the image arrived intact), not *authenticity* (the image is
from a trusted author). OTA is **USB-only** and gated by a **physical 2-second
button hold**. So a remote attacker cannot push firmware; a local one needs the
cable and the button.

The real exposure is trust in the **firmware source**: a user who flashes from a
compromised origin and approves the update installs whatever they're given — the
approval screen shows only the size, not provenance. Today this is mitigated by
operationally (HTTPS + CSP on the flasher, committed bins) rather than
cryptographically. See the secure-boot roadmap below.

## Threat: physical access (device lost / seized) — **NOT resisted (current gap)**

This is the headline limitation. With flash encryption, NVS encryption and
secure boot **all disabled** (see `sdkconfig.defaults`):

- The **master seed is stored in plaintext** in NVS. Anyone with the device and
  a USB cable can `esptool.py read_flash` and recover the 32-byte seed.
- **No secure boot** → arbitrary firmware can be flashed over the ROM bootloader,
  bypassing the OTA button approval entirely.
- The **boot PIN gates only the application's frame loop**, not the ROM
  bootloader or a raw flash read — it does not protect the seed at rest.

**So in the current configuration, physical possession of the device equals full
compromise of every key on it.** For a shelf/server signer behind physical
security this may be acceptable; for a device that travels, it is the gap between
"a neat signer" and "a hardware wallet."

### Roadmap to physical-access resistance

The ESP32-S3 supports the fix, and it is the single highest-value security
investment:

- `CONFIG_SECURE_BOOT=y` (Secure Boot v2) — the device only runs firmware signed
  by a key you hold; closes the malicious-firmware path cryptographically.
- `CONFIG_FLASH_ENCRYPTION_ENABLED=y` + `CONFIG_NVS_ENCRYPTION=y` — the seed is
  encrypted at rest with a per-device eFuse key; a flash dump yields ciphertext.

**Trade-offs (why it is a deliberate decision, not a flag flip):** burning the
eFuses is **irreversible**; it complicates the flash/OTA/recovery workflow;
release signing keys must be managed; and a mistake can brick a device. It should
be rolled out carefully on a sacrificial unit first, with the flasher and OTA
paths updated to match.

## What the design already gets right

- Seed generated on-device from a **guaranteed hardware entropy source**
  (`fill_random_strong` brackets the draw with `bootloader_random_enable`), never
  leaves the device, shown once on the OLED.
- Remote management is **operator-authenticated** with **replay protection
  persisted across reboots**.
- Signing is **policy-gated**, with first-use approval requiring physical presence
  or explicit operator authority.
- OTA is **USB-only + physical-button**, never remote.
- The web manager makes **no third-party requests**, ships a strict **CSP**, and
  holds only the operator key — never the seed.

## Known limits (accepted)

- **Replay window after reboot:** the seen-set is bounded (`SEEN_MAX = 64`); a
  management command older than the window *could* be replayed after a reboot.
  Accepted because the method set is low-stakes (no seed/trust-root operations)
  and the device has no wall-clock to enforce a freshness window.
- **`BACKUP_EXPORT` over USB** returns slot + bridge secrets (not the seed) and is
  not separately bridge-auth-gated; this is defence-in-depth only, since USB
  physical access already implies a flash read. Worth gating regardless.
