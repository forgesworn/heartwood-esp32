# Heartwood security model

What the device protects, against whom, and where the current limits are. This
is deliberately honest: a signer is only as trustworthy as the threats it
actually resists, so the gaps are stated as plainly as the strengths.

Status: 2026-07-12. Applies to the firmware in this repo and the Sapwood web
manager.

## Assets

| Asset | What it is | If stolen |
|-------|-----------|-----------|
| **Master seed** | 32-byte root (the 12-word phrase) | Full impersonation — the attacker *is* the identity |
| **Operator key** | kind-24134 management authority (Sapwood) | Can manage clients, scoped signing policy, and WiFi configuration (see below) |
| **Bridge secret** | USB management session auth | Can manage clients over USB |
| **Slot secrets** | per-client bunker connection credentials | Bearer credential — first connect binds the presenter's pubkey with no confirmation (TOFU); a rebind on a signing-capable slot needs the physical hold. See "Slot-secret custody" below |
| **Bearer notes** | LUD-25 (LNURLcash) note secrets held by the note locker | Spendable cash — whoever reads the secrets can redeem the notes first |

The master seed is the crown jewel. For an identity **generated on-device**
(frame 0x57), the seed comes from hardware entropy and **is never transmitted
off the device by any code path** — not over USB, not over the relay, not in a
backup; the only place it is ever displayed is the OLED, once, at creation.
Restored or imported identities are the exception: a mnemonic or nsec pushed
over USB provisioning, or a seed derived browser-side in a Sapwood restore
flow, necessarily transits the host, which must then be trusted with it. Where
the threat model requires that no host ever sees the seed, prefer on-device
generation.

Bearer notes ride the seeds' at-rest posture: **plaintext in NVS when no PIN
or vault key is set** — the same physical-custody model — and they are
deliberately **excluded from backups**: a note restored onto two boards is a
double-spend, so bearer value is unrecoverable by design (see
`docs/plans/2026-08-18-note-locker-goal.md`).

### Slot-secret custody

A slot secret is a **bearer credential**, and it is deliberately widely held:
served to any heartwoodd API-token holder, carried in `BACKUP_EXPORT`, and
stored in every paired client app. Treat any copy as compromised together:

- **First bind is trust-on-first-use.** The first connect presenting a valid
  secret binds that pubkey with no device confirmation — a captured bunker URI
  lets an attacker pair *first* and become the slot's client. Mitigation is
  procedural: pair over a channel you control, and treat a "slot already
  bound" surprise as a leak.
- **A rebind on a signing-capable slot needs the physical hold.** If the
  slot's current policy includes `sign_event`, swapping to a different client
  pubkey stops for the same button approval as any other authority grant — a
  stolen secret no longer silently inherits signing authority. (Non-signing
  slots — encrypt/decrypt only — still swap with just an OLED flash: there is
  no signing authority to inherit, and the flash keeps the event visible.)
- **There is no rotation frame.** The leak response is revoke + recreate the
  slot (fresh secret) — either operator can do it remotely. A backup restore
  never re-imports signing: grants are stripped on import and each slot
  re-earns them physically (legacy) or from operator policy (strict v2).

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
- **heartwoodd (bridge daemon)** — semi-trusted host courier. Holds the bridge
  secret and, when the vault is enabled, the vault key — never the seeds. Its
  management API is cleartext HTTP and binds to **loopback only** by default;
  `--bind 0.0.0.0` is an explicit opt-in (with a loud startup warning) that
  exposes the API token, unlock passphrase, vault key and connect secrets to
  every host on the LAN. TLS is not implemented — treat any non-loopback bind
  as a trusted-network decision, not a safe default.
- **ESP8266 tethered signer** (`esp8266-firmware/`) — the second, bare-metal
  signer tier: USB-tethered only (no radio), with NIP-46 couriered by the
  bridge daemon, which never sees plaintext or keys. Seeds are host-supplied
  at provisioning behind a button hold (no OLED phrase flow exists on that
  hardware), signing is OLED-plus-hold approved, and a boot self-test halts a
  silently corrupting chip. Its flash key store is unsealed — no PIN/vault
  path — so physical possession equals key recovery, the same posture as an
  unsealed ESP32.
- **Physical device** — see "Physical access" below; this is the weak boundary.

### Authority boundary

The operator is intentionally powerful enough to run an unattended signer, but
it is not the device trust root:

| Authority | May do remotely | May not do remotely |
|-----------|-----------------|---------------------|
| **Operator key** | List/create/update/revoke clients; install exact v2 method/kind policy; approve legacy signing; read redacted network state; stage/activate/commit/abort WiFi changes | Read/replace the seed; change the operator key or other trust roots; switch to USB-only mode; change the boot PIN; invoke OTA |
| **Client slot** | Use only its NIP-46 methods and event kinds, under that slot's approval mode | Manage the device or widen its own policy |
| **USB + physical approval** | Seed lifecycle, trust-root changes, PIN, USB-only mode, signed OTA | Nothing remotely merely because the operator key is present |

There is deliberately **no remote OTA implementation**. Firmware updates remain
USB-only, release-signed, and physically approved.

**Board caveat: the physical-approval anchor is only as strong as the USB
wiring.** On the UART-transport boards (Heltec V3, T-Display) the approval
button is GPIO0, which sits behind the CP2102/CH9102 auto-download circuit — a
host with serial control can hold that line low and satisfy a button hold
remotely, collapsing the "USB + physical approval" tier into plain "USB". The
native-USB boards (V4, C6) have no such bridge and are unaffected; prefer them
for high-value keys.

### USB frame authority

The USB host is untrusted; what a frame may do depends on session state, not
on the cable. Two independent gates apply:

- **Session gate (bridge auth).** Once a bridge secret is provisioned, an
  authenticated `SESSION_AUTH` session is required for: connection-slot
  management (`CONNSLOT_*`), backup export **and** import, identity-meta
  writes (0x5B), vault unlock delivery (0x63), and the plaintext-USB NIP-46
  decrypt methods and persona-registry mutations (frames 0x02/0x03 with no
  bound client). With **no** bridge secret provisioned the device is in the
  open tier: a cabled host is the whole trust anchor and those paths stay
  open — the tethered first-run flows (provisioning, avatar sync before
  pairing) rely on it. A failed `SESSION_AUTH` never drops an established
  session, and repeated failures are refused under a short cooldown.
- **Physical hold (independent of session).** Every frame that creates,
  destroys, or re-roots authority stops for the button: PROVISION / GENERATE /
  RESTORE / DERIVE / REMOVE (0x01/0x57/0x58/0x60/0x04), SET_BRIDGE_SECRET
  (0x23 — also refused while a session is authenticated, so replacement is a
  deliberate physical act), SET_PIN, VAULT_SET (0x62 — also bridge-auth),
  SET/PATCH_NET_CONFIG, SET_OPERATOR (also revision-bound), backup import,
  and OTA (additionally release-signed). A relay-side client rebind on a
  signing-capable slot takes the same hold via the deferred-approval
  machinery.

Read-only probes (firmware info, identity list, redacted network state) are
open on every tier: they disclose nothing secret-bearing. There is no frame
that exports a seed, on any tier.

## Threat: remote / network attacker — **resisted**

An attacker on the network (or running a malicious relay) can observe and inject
relay traffic. They cannot:

- **Read messages** — NIP-44 encrypted master⇄counterparty; the relay sees only
  ciphertext.
- **Forge or replay management** — kind-24134 commands are accepted only if
  authored by the operator key authorised for the addressed identity — the
  baked **device operator**, or that identity's per-identity **delegate**
  (`mgmt::is_authorised_operator`). Every mutation
  must also carry the current device-issued 256-bit challenge. Firmware persists
  and reads back a fresh challenge before dispatch, so a captured command stays
  stale across reboot and after its id leaves the bounded duplicate-delivery
  set. Challenge discovery and responses remain inside the authenticated NIP-44
  channel. (The full method catalogue, error codes and stale-retry semantics
  live in the dispatch code — `relay.rs` and the `mgmt` module; there is no
  standalone kind-24134 spec document, so this model states the
  security-relevant invariants.)
- **Reach the seed or firmware** — no relay method exposes or replaces the seed,
  and remote OTA is not implemented.
- **Get a signature for free or monopolise the approval loop** — `sign_event`
  is gated by per-client policy. An unbound relay peer is rejected before the
  30-second button wait; direct USB and a provisioned, slot-bound legacy client
  can use physical approval, or the operator can use `approve_signing`, while a strict v2 client
  gets signing only when the authenticated exact policy names `sign_event`.
  `ping`/`get_public_key` remain global protocol operations; `connect` must
  present a valid slot secret.

**Residual:** a malicious relay can drop or delay traffic (availability). Two
legitimate managers can race for the same one-time challenge; one succeeds and
the other receives an explicit stale-state error, refreshes, and asks the user
to retry instead of applying an index-sensitive change to newer state.

### Exact v2 client policies

Authenticated `create_client_v2` and `nostrconnect_v2` install the requested
policy as one validated mutation. The method name is versioned so old firmware
rejects the request before creating a broader legacy slot. Heartwood derives
`signing_approved` from the presence of `sign_event`; a separate boolean cannot
drift out of sync with the method ceiling.

New v2 slots set `strict_permissions=true`:

- a method not in `allowed_methods` is denied;
- a `sign_event` kind outside a non-empty `allowed_kinds` list is denied;
- an empty `allowed_kinds` list with `sign_event` means all event kinds;
- `auto_approve=true` makes matching requests suitable for unattended signing;
  `false` still requires the device button;
- caller-supplied top-level `heartwood` identity context is rejected, so an
  allowed method cannot be redirected to an arbitrary derived child;
- protocol-wide `ping`/`get_public_key` behavior and operations that always
  require the button remain firmware invariants, not policy-expansion hooks.

This strict denial boundary matters: an out-of-policy request cannot be turned
into broader authority by pressing the button later. Existing legacy slots keep
`strict_permissions=false` for compatibility, so their historical out-of-policy
behavior remains a button prompt. Approving signing on a legacy slot adds
`sign_event` without silently broadening its existing encryption-method or
event-kind ceiling.

## Threat: compromised operator key or browser — **bounded, recoverable**

If the operator key leaks (or the browser is compromised), the attacker can do
what the operator can: create/revoke/relabel clients, install a strict method and
kind policy, approve legacy signing, and change the WiFi SSID/password/relay set.
They can therefore create a client they control and get master signatures inside
the policy they authorised, for as long as the operator key remains trusted.

They **cannot** extract or replace the master seed, rotate the management trust
root, disable the radio into USB-only mode, change the boot PIN, or push
firmware. Recovery: revoke the rogue client and restore a known-good network
configuration; if the attacker has removed every route the owner knows, that
recovery is necessarily over trusted USB. Rotating the operator key likewise
requires a trusted USB re-flash (it is baked into the config partition).

Mitigations in place: the operator key lives in browser `localStorage` behind a
strict **Content-Security-Policy** (`script-src 'self'`, no `eval`, no
third-party origins — see `sapwood/vite.config.ts`), which closes the usual XSS
exfiltration routes. Sapwood renders no user-supplied HTML (the one `{@html}` is
a locally-generated QR SVG, not reflected input).

### Staged remote network management

Remote WiFi changes use an authenticated, revision-bound transaction rather
than overwriting the live configuration:

1. `get_network_config` returns the monotonic revision plus redacted active,
   pending-trial, and last-terminal state. It exposes only `password_set`, never
   the password.
2. Sapwood generates a fresh 32-hex transaction id and stages a patch against
   the exact base revision. The accepted candidate consumes revision `N+1` but
   remains inert; an identical retry is idempotent, and a conflicting or stale
   request is rejected.
3. A separate transaction-id + revision-bound activation schedules reboot only
   after its reply. Boot persists `attempted=1` *before* selecting candidate B,
   so B is a one-shot boot. A reset or power loss before commit returns to A.
4. Commit is accepted only on that attempted candidate boot and only through a
   configured candidate **primary** relay. An old relay or client-pinned relay
   is not proof that B is reachable.
5. Commit first persists `phase=committed` in the single transaction blob; that
   marker is the atomic decision after which every boot selects B. Promotion to
   the compact active/terminal records is retryable cleanup. Abort and automatic
   rollback leave their own durable terminal outcomes, so Sapwood can recover
   the truth after a lost reply instead of guessing which configuration won. A
   staged-but-never-activated change is safe on A and can be explicitly discarded.

Before activation, Sapwood durably reads back a password-free handoff journal
containing only device pubkey, transaction/revision, and the old + candidate
relay routes. If that journal cannot be saved, activation is refused. A killed
or reloaded mobile tab reconnects over both routes, reads authenticated terminal
state, persists the winning route, and only then clears the journal. SSID and
WiFi password are never journalled.

The remote patch may keep/set/clear the password and replace SSID/primary relays,
but accepts only WiFi mode and `wss://` relays. Changing SSID requires an explicit
password set or clear. The patch cannot carry `op_mgmt`, so it cannot rotate its
own authority, and it cannot switch the signer to USB-only mode.

Local operator recovery is a separate protocol boundary. USB exposes only
password-redacted network state (`password_set`, never the password). Replacing
`op_mgmt` requires the caller's exact observed network revision, a valid x-only
secp256k1 pubkey, and a physical hold on the signer. The device durably rotates
the management mutation challenge before writing and read-back verifying the
new operator, then reboots so no stale in-memory authority remains. Local
network patching has its own frame and cannot name `op_mgmt`.

The entire management request, including a newly supplied WiFi password, is
NIP-44 ciphertext in transit. That is a transport guarantee only: flash and NVS
encryption are disabled, so the active or staged WiFi password is stored as
plaintext in NVS. Sapwood does not read it back or persist it; physical flash
access can recover it.

## Threat: malicious firmware (OTA or the web flasher) — **signed USB OTA; flasher is trust-on-first-use**

USB OTA verifies **two things**: a SHA-256 of the image (*integrity* — the image
arrived intact) and an **ed25519 release signature** over that digest
(*authenticity* — the image was signed by our release key). The public key is
baked into the firmware at build time (`firmware/ota-release-pubkey.hex` →
`release_key.rs`); the signature is made in CI by `release.yml` and checked
on-device twice — at `OTA_BEGIN` over the claimed digest (an unsigned image is
refused before the owner is even asked to approve) and at `OTA_FINISH` over
the digest recomputed from the bytes actually written to flash. The signed
message is domain-separated by **board id** (see `common/src/ota_sign.rs`), so
one board's image cannot be replayed onto another. Older releases remain
verifiable deliberately: with no update health-check, an owner must be able to
roll back a bad release. OTA also stays **USB-only** and gated by a **physical
2-second button hold** — so a remote attacker cannot push firmware, a local one
needs the cable, the button *and* the release key. No eFuses involved; the
scheme is plain software and fully reversible. Key custody and rotation:
`docs/ota-signing.md`.

**Remote OTA is not implemented.** Operator management has no firmware-update
method; a remote manager cannot turn possession of `op_mgmt` into code execution.

The remaining exposure is the **first flash**: the web flasher writes to a
blank (or ROM-bootloader-accessible) device, where no baked-in key exists yet
to check against — trust-on-first-use, mitigated operationally (HTTPS + CSP on
the flasher, CI-built committed bins with SHA-256 verification at sync and
fetch time). Cryptographically closing *that* would require secure boot, which
is out of scope (below).

## Threat: physical access (device lost / seized) — **resisted only when sealed at rest**

This is the headline limitation of the default (unsealed) configuration. With
flash encryption, NVS encryption and secure boot **all disabled** (see
`sdkconfig.defaults`):

- The **master seed is stored in plaintext** in NVS — unless the PIN or vault
  key seal below is enabled, in which case flash yields only ciphertext.
  Anyone with an *unsealed* device and a USB cable can `esptool.py read_flash`
  and recover the 32-byte seed.
- The **WiFi password and network transaction candidate are plaintext** in NVS.
  NIP-44 protects remote delivery, not storage on the ESP32.
- **No secure boot** → arbitrary firmware can be flashed over the ROM bootloader,
  bypassing the OTA button approval entirely.
- The **boot PIN gates only the application's frame loop**, not the ROM
  bootloader or a raw flash read — it does not protect the seed at rest.

**So with an unsealed device, physical possession equals full
compromise of every key on it.** For a shelf/server signer behind physical
security this may be acceptable; otherwise enable the PIN or the vault key —
both below — so possession yields only ciphertext.

### Decision: eFuse-based hardening is out of scope

The ESP32-S3 *can* close this gap cryptographically with
`CONFIG_SECURE_BOOT=y` (Secure Boot v2) and
`CONFIG_FLASH_ENCRYPTION_ENABLED=y` + `CONFIG_NVS_ENCRYPTION=y` (seed encrypted at
rest with a per-device eFuse key). **We have deliberately decided not to do
this.** Burning those eFuses is **irreversible**, carries a real brick risk, and
would complicate the flash / OTA / recovery workflow this project depends on. The
physical-access gap is therefore an **accepted limitation**, mitigated
operationally (keep the device in your possession; treat a lost device as a
compromised key and rotate by re-flashing a new identity).

### PIN-derived seed encryption — the eFuse-free at-rest mitigation (P5, BUILT)

The one hardening lever that does **not** touch eFuses is **PIN-derived seed
encryption**, and it is now built (opt-in). When a PIN is set, each master seed
is stored as ciphertext — `PBKDF2-HMAC-SHA256(pin, salt)` derives the key,
ChaCha20 + HMAC-SHA256 encrypt-then-MAC it (`common/src/seed_cipher.rs`), and
the plaintext is removed. A raw `esptool read_flash` now yields ciphertext, not
the seed. On boot the device is locked until a PIN decrypts the seeds into RAM;
5 wrong attempts erase and verify both the flash-time `config` source and the
complete NVS partition, so old WiFi/operator state cannot re-seed itself after
the wipe. Physical factory reset uses the same complete path. See
[`PERSISTENT-STATE.md`](PERSISTENT-STATE.md) for the key inventory, failure
semantics, and power-safe per-master removal journal. There is **no stored PIN hash** — a fast hash
would let a flash-dump attacker brute-force the PIN cheaply and skip the slow
KDF, so the AEAD tag is the sole PIN check and every guess pays the PBKDF2 cost.

**Honest limitation:** with no secure element and no eFuses, the key is derived
**entirely from the PIN**. An attacker who owns the flash can brute-force the
PIN offline; the slow KDF raises the per-guess cost but a short PIN is an
enumerable space. So this is a real uplift — a stolen device is no longer
instant game-over — but it is **not** hardware-wallet-grade at-rest security.

Trade-offs: it costs unattended reboot. A PIN-protected signer needs the PIN
entered after every boot (over USB today), and operator relay management cannot
unlock it. Firmware rejects remote network activation when encrypted seed blobs
mean the following reboot would need that local unlock. A shelf signer expected
to recover unattended after a power cut is therefore incompatible with enabling
the boot PIN; the PIN mode suits a "carried, manually unlocked" device instead.
Losing the PIN means the on-device seed is
unrecoverable **by design** — the escape hatch is re-restoring the 12-word
phrase on a wiped device, so a verified phrase backup is the prerequisite for
enabling it. Full design + build notes:
`docs/2026-07-02-pin-seed-encryption-design.md`.

### Host-held vault key — encrypted at rest WITH unattended reboot (BUILT)

The PIN's availability cost — "the device reboots while I am in another
country and I cannot type the PIN" — is closed by splitting trust instead of
deriving from a human secret. A **vault key** (32 random bytes, 256 bits) is
generated and held by the host side — heartwoodd's data directory, or
Sapwood's browser storage — and **never stored on the device**. The seeds are
wrapped with exactly the same AEAD as the PIN path; only the wrapping secret
changes hands:

- **USB-bridged:** after bridge authentication, heartwoodd (or Sapwood over
  WebSerial) sends a `VAULT_UNLOCK` frame (0x63) with the vault key. The
  device unwraps into RAM and runs. A locked device answers `PROVISION_LIST`
  with `locked: true` so hosts can show the state. Reboots self-serve.
- **WiFi-standalone:** a locked device generates a **one-time unlock keypair
  in RAM**, announces it over its relays (ephemeral kind 24135, p-tagged to
  the operator) every 60 s, and Sapwood pushes the vault key back live
  (ephemeral kind 24136, NIP-44 operator→unlock pubkey). Ephemeral kinds are
  never stored by relays, so there is no standing ciphertext to scrape.
- `VAULT_SET` (0x62) enables/disables the wrapping; it requires bridge
  authentication **and** physical button confirmation, so a remote party can
  never change the at-rest posture.

Security properties and honest residuals:

- Flash dump alone: ciphertext under a 256-bit key — unbruteforceable, unlike
  a short PIN.
- Pi/browser compromise alone: a vault key that decrypts nothing the host
  possesses.
- A wrong vault key is a plain NACK and deliberately does **not** feed the
  PIN wipe counter (a buggy host must not be able to wipe the device).
- The relay announcement is **not** device-authenticated (every attesting key
  is locked). A fake announcement could phish a vault key from an inattentive
  operator — but exploiting it still requires the physical flash. Sapwood
  therefore never auto-sends; the operator taps, and only for a signer they
  know rebooted.
- Theft of device **and** host together is full compromise, and the host side
  is weaker than the design spec intended: heartwoodd stores the vault key as
  **plaintext hex** in `<data-dir>/vault.key` (mode 0600) and delivers it
  automatically at boot — the spec's Argon2id-encrypted keyfile with a
  Sapwood-typed passphrase is **not implemented**. So a Pi compromise alone
  already hands over one of the two halves; with flash access as well, the
  seeds collapse to nothing. The other host store is Sapwood's browser
  storage — same plaintext-at-rest posture. Until the keyfile design is
  built, protect the Pi's filesystem accordingly.
- Host RAM hygiene is best-effort, not guaranteed: heartwoodd scrubs master
  secrets and keystore buffers on drop/lock (`Zeroizing`), but vault-key
  handling is documented as callers' duty and one residual (`ConnectSlot.secret`,
  a plain `String` whose type is shared with the firmware in `common/`) is not
  scrubbed.
- Escrow: Sapwood offers the vault key for export at setup (password manager,
  safe), the analogue of writing down the recovery phrase. Losing every copy
  of the vault key with no PIN set means the seeds are unrecoverable by
  design — restore from the phrase.

Design spec: `docs/specs/2026-08-08-encrypted-at-rest-unlock-design.md`.

## What the design already gets right

- Seed generated on-device from a **guaranteed hardware entropy source**
  (`fill_random_strong` brackets the draw with `bootloader_random_enable`), never
  leaves the device, shown once on the OLED.
- Remote management is **operator-authenticated** with a **one-time mutation
  challenge rotated durably before dispatch** and a bounded RAM request-id set
  for duplicate delivery across live relays.
- Reusable client indices are bound to a non-secret credential fingerprint for
  every approve/update/revoke/URI action. Slot authority writes use exact
  read-back plus durable compensation of the complete prior snapshot. This
  recovery model explicitly assumes one ESP-IDF NVS key is atomically old or
  new after power loss, never a torn mixture.
- New v2 clients have an **atomic, strict method + event-kind ceiling**; legacy
  slots retain their button-fallback behavior for compatibility.
- Remote WiFi changes are **staged, revision-bound, one-shot, and rollback-safe**;
  commit must arrive through a candidate primary relay.
- Signing is **policy-gated**, with authority coming from physical presence or
  an explicit operator-installed policy.
- OTA is **USB-only + physical-button**; remote OTA is not implemented.
- The web manager makes **no third-party requests**, ships a strict **CSP**, and
  holds only the operator key — never the seed.

## Known limits (accepted)

- **One device operator; per-identity delegates:** the device-wide `op_mgmt`
  pubkey is the management root. Any identity can additionally be delegated to
  its own operator via `set_identity_operator` — device-operator only,
  challenge-protected like every mutation, applied at restart. A delegate is
  confined to its one identity: it manages that identity's clients, policies
  and metadata, but cannot add identities, delegate further, read device-wide
  state (network configuration, audit ring, relay topology, storage
  inventory), or even enumerate the owner's other identities. The delegation
  is stored per slot and travels/clears with the slot bundle on removal, so a
  slot shift can never bind a stale delegate to a different identity. Two
  residuals: Sapwood's phone handoff still copies the device-operator
  credential rather than enrolling an independently revocable delegate, and
  browsers may reuse one operator across several signers, increasing its
  compromise blast radius. Replacing the device operator itself remains a
  trusted-USB, physical-hold operation.
- **Bounded duplicate history; no freshness window:** the RAM-only request-id
  set is bounded (`SEEN_MAX = 64`) and resets on reboot. An old `mgmt_seen`
  NVS blob from earlier firmware is ignored. An evicted read may be processed
  again, but reads cannot consume or mutate authority. An evicted or
  post-reboot mutation still carries its already-used NVS challenge and is
  rejected. Keeping polled read ids out of NVS avoids roughly 43,200
  writes/day from a manager open at a four-second poll interval. NIP-46 client
  requests ride a separate 64-entry RAM ring with the same eviction/reset
  properties, and **no `created_at` freshness window is enforced on any
  inbound path** (firmware relay side, or heartwoodd, which likewise ignores
  `created_at` and will re-process a redelivered request). What a replayed,
  previously valid request can therefore achieve, per method class:
  **mutations** (slot, policy, network, operator writes) — nothing; they carry
  the durable one-time challenge and are rejected as stale after first use,
  across reboots and evictions. **`sign_event`** — a fresh signature on the
  identical, already-public event (relays dedupe the shared id); the owner
  authorised that exact event once already. **encrypt/decrypt** — the response
  re-seals to the original client's pubkey, so a replaying attacker without
  that client's key reads nothing new. **Button-gated methods** — one captured
  request can re-arm a 30 s prompt: an availability nuisance bounded by the
  physical button, never an approval. **Management reads** — redacted state
  only, and only inside the authenticated operator channel. This is accepted
  deliberately: a `created_at` window would break legitimate clients with
  skewed clocks, while the durable challenge already anchors every mutation.
- **No wired rate limiting:** the April design's 60 req/60 s per-client
  counter exists (`policy.rs`) but is not consulted in dispatch. Abuse is
  bounded instead by policy gating (unknown clients are button-only), the
  unbound-peer denial set, and the bounded approval machinery. Wiring the
  counter in is future hardening, documented here so the gap is honest.
- **PIN KDF cost scales per identity:** unlocking pays the PBKDF2-HMAC-SHA256
  cost (100k rounds) once per sealed master — about 26 s for three identities
  on current hardware (HARDWARE-TEST-CHECKLIST), so boot unlock allows 60 s.
  The per-guess cost is the point (every offline brute-force attempt pays it),
  but it bounds how many identities a PIN user will tolerate; the vault-key
  path pays no per-identity human-secret cost for the same at-rest protection.
- **Bridge-secret rotation is physical:** the USB pairing secret can only be
  set or replaced while no session is authenticated, under the physical hold
  (Sapwood surfaces this as "replace pairing"). There is no remote rotation —
  the bridge secret never transits the relay path — so a leaked pairing is
  revoked on the device, not over the wire.
- **Backups carry slot + bridge secrets (never seeds).** `BACKUP_EXPORT` and
  `BACKUP_IMPORT` both require an authenticated bridge session and a physical
  hold. Import never restores authority as-is: every slot is re-validated
  against the management policy validator, `signing_approved`/`sign_event` and
  kind ceilings are stripped (each slot re-earns signing physically or from
  operator policy), and a carried bridge secret installs only under its own
  distinct hold. The export file remains a plaintext secrets dump by design —
  protect it accordingly.
- **Legacy NIP-04 is a decryption oracle for weak crypto.** Permitting the
  legacy `nip04_decrypt` method in a slot policy makes the device a decryption
  oracle for AES-256-CBC — unauthenticated legacy encryption — so prefer the
  NIP-44 methods in policies wherever the client supports them.
- **No Anti-Exfil-style nonce commitment.** A *weak or dead* RNG cannot weaken
  signatures: BIP-340 derives the nonce from the secret key and message, and
  `aux_rand` (drawn via `fill_random`, `firmware/src/sign.rs`) can only add
  entropy, never replace it. What synthetic nonces do NOT stop is *malicious
  signed firmware* grinding its `aux_rand` choice to leak seed bits through the
  signatures themselves — the covert channel Blockstream Jade closes with its
  sign-to-contract Anti-Exfil protocol. Closing it needs the host to commit
  randomness into the nonce, which NIP-46 has no method for; today the defence
  is the signed, CI-built release chain plus deliberate rollback capability.
  The protocol to close it is specified in
  [`docs/nip-nonce-commitment.md`](nip-nonce-commitment.md) (published as a
  draft community NIP, kind 30817, identifier `nip-nonce-commitment`);
  the firmware implementation is future work.
