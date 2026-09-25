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
deliberately **excluded from backups as spendable secrets**: a note restored
onto two boards is a double-spend, so bearer value is unrecoverable by design
(see `docs/plans/2026-08-18-note-locker-goal.md`).

That is sound, and its consequence has to be said out loud rather than left
for an owner to discover: **a board that dies takes its notes with it, and no
seed, share set or export brings them back.** Every other secret here is
recoverable, so this is the one an owner will wrongly assume is handled. The
locker is a till, not a vault. Collect promptly (since #129 a whole batch
costs one hold) and keep little on it.

What a backup does carry (#86) is the INVENTORY, so the loss is at least
legible: an optional top-level `note_inventory` array, at most sixteen
entries, each holding one note's `id`, `commitment`, `state`, `amount_msat`,
`host`, `key_index`, `created_at` and `updated_at`. The commitment is the
identifier the issuing mint already files the note under: `sha256(k1)` for a
note behind a hash, the note's own x-only public key for one paid to a device
key, which is what the mint recovers from a `ck1`. It carries no spending
authority and is something an owner can actually show a mint. It is
deliberately not called `secret_hash`, because for half the notes here it is
not a hash of anything and a name that says otherwise invites a reader to
check it the wrong way; `key_index` being non-null is what tells the two
apart. Nothing derived from a preimage or a note key ever enters the file, a
log line, the display or an error string. The approval card names what leaves
(`+amt/mint`): the inventory carries amounts and mint hosts, not only
commitments.

A second optional top-level field, `note_inventory_unreadable`, counts the
notes the exporting board held but could NOT read: records still sealed under
an at-rest key that boot was never given, or a locker whose index would not
load. It travels in the file and not only in a log, because otherwise an
export taken on a locked board carries an empty inventory that is
byte-identical to one taken on an empty locker. "I cannot see four of them" is
a different statement from "there were none", and a backup that quietly
rounds the first down to the second is the precise false comfort this feature
exists to remove. Zero is omitted, so the ordinary case costs nothing.

The restore side is the other half, and it is a refusal: `BACKUP_IMPORT`
shape-checks a carried inventory, logs what it saw and drops it
(`common/src/backup.rs::inspect_imported_inventory`, which is handed no store,
no storage and no secret). No code path from an import reaches the note
locker, so a backup cannot create, resurrect or alter a note, which is the
point, because the alternative is a second board believing in money the first
one already spent.

The inventory is also the one part of a backup that is read LENIENTLY. A
record of money that is already gone must never be able to stop an owner
getting their identities and pairings back, so `note_inventory` deserialises
as `Entries` or, for any shape this firmware does not understand, as
`Unreadable`: the field is reported as ignored and the restore carries on.
Masters and connection slots keep exactly the strictness they had, including
`sanitise_imported_slot`. The field is optional in both directions, so pre-#86
backups import unchanged and new backups import on pre-#86 firmware.

Notes can also move as **NIP-59 gift wraps** (`common/src/note_wrap.rs`).
Sending seals the secret to the recipient's pubkey inside the signing
boundary: the client that asked gets an opaque kind-1059 back and never sees
the plaintext, which no other path out of the locker (export, QR, browser)
can say. Two consequences are deliberate. A wrap is a permanent copy of the
secret under the recipient's key on every relay that carried it, so a
received note is held only until a wallet rotates it (the device has no mint
client and cannot), under a low cap (`MAX_RECEIVED`), and is never forwarded
by wrap again. And sending does not burn: the note stays CONFIRMED with
`sent_to` recorded so the owner can rotate it back if unclaimed, but it can
never be sealed a second time.

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
| **Operator key** | List/create/update/revoke clients; install exact v2 method/kind policy; approve legacy signing; read redacted network state; stage/activate/commit/abort WiFi changes; list and revoke unlock phones; ask to add one (a press on the board's card) | Read/replace the seed; change the operator key or other trust roots; switch to USB-only mode; change the boot PIN; invoke OTA |
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

The exact-policy method catalogue includes the normal legacy-safe operations
plus `heartwood_derive_persona`, `heartwood_remove_persona`, and
`heartwood_rename_persona`. This lets one authenticated, persona-addressed
manager pairing administer the personas of its owning master when the operator
has explicitly installed that narrow list. Those operations are not added to
the legacy TOFU catalogue, and a strict slot that omits any one of them still
denies it. Identity switching and caller-selected identity context remain
outside this grant.

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
firmware. They can list and revoke unlock phones, but adding one, which would
be a persistent way to release the data key after a restart, still takes the
owner's press on the board's card. The card leads with five words derived from
the enrolment key, and the owner compares them with the phone that made that
key, not with the browser: an attacker holding the operator key (or the
browser itself) can swap in a key of their own, and could show matching words
in the browser, but not on the owner's phone. Recovery: revoke the rogue client and restore a known-good network
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

Encrypted-seed records made by current firmware also carry an authenticated
format/version and PBKDF2 round count. The original 92-byte records remain
valid and keep their original 100,000-round cost, so updating the firmware
never turns a previously sealed seed into an absent or undecryptable one. A
later cost retune must still be measured on the slowest supported board; the
stored count makes that a deliberate new-record policy rather than an unsafe
global constant change.

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
- `FIRMWARE_INFO` and the relay `get_status` reply also carry `at_rest`
  (`none`/`pin`/`vault`/`encrypted`) and `unlock_phone_count`, so a manager
  stops inferring the mode from side effects it happened to witness. Resolved
  in one pure, host-tested function — `heartwood_common::at_rest_status::
  resolve` — behind a single firmware read (`pin::at_rest_status`) that all
  three call sites share, rather than each composing it separately.
  `FIRMWARE_INFO` answers this to any USB host, in any mode, including while
  locked (the same trust level as its other operational fields — uptime, RNG
  state, crash context); `relay` `get_status` only once genuinely unlocked,
  and only to the device operator, never a per-identity delegate — including
  its low-heap `minimal_status_json` fallback, which used to leak
  `master_count`, `relay` and `crashed_during` to a delegate too (now fixed
  alongside this). Both delegate reply shapes (normal and low-heap fallback)
  are built from `at_rest_status::DELEGATE_STATUS_KEYS`/
  `DELEGATE_STATUS_FALLBACK_KEYS` in `relay.rs`, with a host test asserting
  the fallback's keys are a subset of the normal reply's (`truncated`
  excepted — a structural marker naming no device data), so the closed leak
  cannot silently return. Neither reply ever names a phone. `unlock_phone_count`
  is `null`, never `0`, over a damaged phone blob — an oversized blob, a
  length mismatch against what was actually read, and a zero-length blob are
  all treated as damage, host-tested — except once `at_rest` is `none`, which
  always reports `0` (a leftover `dk_ph` from removing the last identity, or
  from disabling encryption on older firmware, is moot once there is no data
  key left for it to wrap).
- The wrapped data key (`dk_sec`) does not itself record which secret wrapped
  it — same shape for a PIN and a vault key — so telling `pin` from `vault`
  needed a marker (`common/src/data_key.rs`: kind byte + the first 8 bytes of
  SHA-256(dk_sec), read/written over `BlobStore` so the module's own
  power-cut model tests cover it). The digest binds the marker to the
  wrapper it describes: a marker that no longer matches — a cut between the
  wrap write and the marker write, a failed marker write, a secret changed on
  firmware that predates this marker, or any other re-wrap the marker missed
  — reports `encrypted` (sealed, kind unknown) rather than a guess.
  Deliberately never a `pin` fallback: only a `PIN_UNLOCK` guess counts
  towards the 5-failure wipe, so mislabelling an unattended vault board as
  PIN-protected would invite typed guesses into a counter it was never meant
  to arm. The board's own next successful unlock self-repairs a missing or
  wrong marker via `data_key::repair_secret_kind`: `PIN_UNLOCK`, `VAULT_UNLOCK`
  and the relay's 24136 operator vault delivery all resolve through
  `pin::try_unlock`, and the secret's length settles which kind it is (4-8
  digits vs 32 bytes) — at most one write, since an already-correct marker is
  left alone. `repair_secret_kind` takes the `Unlocked` proof only a
  successful unlock produces, so it cannot run ahead of one; a phone-slot
  unlock produces no such proof from a secret and never touches the marker.
  `try_unlock` also clears the PIN wipe counter as soon as the secret is
  proven correct, before migration or the marker repair (the two writes that
  can follow): a power cut during either can no longer catch the counter
  mid-way stale and leave an owner who just typed the right PIN one guess
  from a wipe.

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

### Adding an unlock phone

An enrolled phone holds a slot secret that, with the board's flash, releases
the data key after any restart, so adding one adds a persistent unlocker. It
is always a press on the board, whichever way the request arrives:

- **Cable:** `PHONE_UNLOCK_CMD` (0x64) `{"op":"enrol"}`, bridge-authenticated,
  with a blocking card (45 s, like the relay's).
- **Relay:** `enrol_unlock_phone` on the kind-24134 management channel. Device
  operator only: a per-identity delegate is refused before anything else is
  looked at, and a NIP-46 client has no route to management at all. The
  request spends the durable one-time mutation challenge before the card goes
  up, so a replay (live, or after a restart) raises no card. The card is held
  on the deferred-approval queue (#64): 45 s on screen (every other card
  has 30 s; the words need time to be read and compared), at most 90 s
  waiting behind other cards, one enrolment at a time, RAM only. The relay
  card does not block the relay loop. The cable card does, for up to about
  55 s with its wait for the approving button to come up, which passes the
  loop's 50 s silence limit, so a cable frame that holds the loop credits
  every relay session's silence clock (`silence_from`) without pretending
  anything was heard: the liveness judged at a relay enrolment's press is
  still what was really heard.
- **What the owner checks:** both cards lead with the request code, five
  words of spoken-token's 2048-word list from the phone's one-off enrolment
  key P (`deriveToken(P, 'heartwood-unlock:enrol-request', 0, {format:
  'words', count: 5})`, 55 bits), and the owner holds only if the PHONE, which
  made P, shows the same five words (Cambium support pending). A browser may
  show them too, but only as a convenience: whoever relays the request can
  replace P, and the words in the browser with it. So that the comparison is
  actually made, the card shows the words large enough to read at arm's
  length on the 128x64 OLED: two a page with their place numbers and a
  "1-2 of 5" marker, stepping every 4 s on its own (bench, 2026-09-25: the
  old card's five words, two to a line in 6 px letters, could only be read
  from a photograph, by which time the card had gone). Paging brings its own
  risk, an owner holding after page 1 having seen two words, 22 bits, which a
  compromised browser grinds in moments. So neither card can be approved
  until every page has actually been on screen for its full 4 s dwell and
  12 s have passed: the pages turn on what the firmware drew, not on the
  clock, so a loop held up by a stalling relay (a redial, a rejoin) cannot
  let the gate open with words 3 to 5 never shown; the page on screen simply
  stays up longer. Time under another screen does not count either: every
  panel flush moves a draw counter on, and when the card finds it has been
  drawn over (a signing confirmation, an OTA chunk) it draws itself again at
  once and the page starts its dwell afresh, so a stream of overdraws only
  makes the card expire. What the counter cannot see is the panel itself:
  the dwell assumes the glass shows what was last flushed. Until then the hint reads "compare all 5 words" and no hold that
  STARTS then ever counts, however long it runs; a short press does
  nothing, so it cannot decline and spend the phone's code (B/NO on a
  T-Display still cancels). The cable and relay cards share the rule
  (`phone_unlock::EnrolGate`, host-tested). A card whose pages could not all
  be shown in its 45 s expires and adds nothing; the window is not extended,
  since expiry is the safe failure and the owner starts again.
- **One button, one decision:** in WiFi mode, while a relay card (or a result
  younger than 20 s) is up, every cable frame that may raise a card of its
  own is refused "approval on screen" (`phone_unlock::cable_frame_claim`,
  checked by ui-preview against every cable arm that can reach the button).
  Otherwise a compromised host could send one while the owner hesitates over
  a relay enrolment, and the hold that answers the cable card, latched by
  the button sampler with its full length, would then read as the relay
  card's approval. As a second line, a cable frame that held the loop 2 s or
  more disarms the front relay card and clears the latched press, and every
  card, relay or cable (the enrol card after its gate too), arms only once
  the button has been seen up with it on screen.
- **Recovery is never locked out:** anyone can keep a relay card up (a
  RECEIVE card returns for every wrap published to the board), so the
  owner's recovery commands over the cable, `PATCH_NET_CONFIG`,
  `OTA_BEGIN`, `FACTORY_RESET`, and `SET_NET_CONFIG` while it keeps the
  stored operator, take the screen over instead of being refused. Only a
  frame that will actually raise its card does so: the takeover runs
  straight before the card, after the handler's own checks (the config
  parses and validates, the patch's revision is current, the image's
  release signature verifies and it fits a spare slot), so a garbage or
  refused frame, however often a host sends one, cancels nothing. Every
  relay card is then answered Expired (with the reply an expiry always
  sends) and the latched press is cleared; a held result stays, and is
  drawn again after the recovery card, so a "revoke id N" is not lost to
  one. The cable card arms only after the button has been seen up, so a
  hold begun for a relay card cannot answer it. What remains: the checks
  stop garbage, not a host. Any USB host, with no bridge secret, can pass
  them with all four frames: `FACTORY_RESET` (checks nothing), an
  `OTA_BEGIN` carrying any published release's signature, and, since
  `GET_NET_CONFIG` answers any USB host in WiFi mode with the revision and
  `op_mgmt`, a `PATCH_NET_CONFIG` restating the config at the current
  `base_revision` and a `SET_NET_CONFIG` that copies `op_mgmt`. Each
  expires every relay card and raises a card the owner must deny or let
  run out; a hostile charger or hub re-sending one every 45 s blocks relay
  approvals for as long as it is plugged in. That is within the model: USB
  is physical access, the same access that can already factory-reset the
  board, and unplugging it ends it. It cannot approve anything. A
  `SET_NET_CONFIG` whose `op_mgmt` differs from the stored one hands relay
  management to another key (or to none), which is no recovery: it is an
  ordinary card, refused under a relay card, and its card says so in every
  mode ("Replace operator?" with the new key's first 8 hex digits, as the
  `SET_OPERATOR` card says it, "New operator?" where there was none, or
  "Remove operator?", where a plain network change reads "Set network
  config?"). One whose `op_mgmt` is not empty and not 64 hex digits is
  refused "invalid config" before any card. The other card-raising frames
  (identity, PIN, vault, operator, slots, backups, NIP-46) stay refused:
  none is needed to get a board back. And a relay card no longer outlives
  a WiFi outage: the loop's WiFi-down waits tick it with no session, so it
  still expires on time. An approval made then waits in the #82 outbox for
  only 60 s (`held_reply::HELD_REPLY_TTL_SECS`) and is dropped if no
  session takes it by then; a dependant persona's action is not done at
  all with no session (its C5 audit rail must leave down a live socket),
  and the card says "Offline / Nothing was done" rather than APPROVED. A
  card whose window has passed never keeps the cable refused.
- **The real bound:** a compromised browser holds P from the moment the owner
  pastes the phone's code, before it sends anything, so it can grind a key of
  its own whose five words match for as long as the owner is willing to wait
  for a card. Each try is a key generation and an HMAC: 55 bits is about
  3.6e16 tries, weeks on one GPU and hours on a large rented rack, against an
  owner who waits minutes. (Four words, 44 bits, was about half an hour on one
  GPU.) A table built in advance does not help, since P is fresh each time.
  The label is printable ASCII only, quoted, and drawn on a line of its own
  (`ADD "<label>"?`), never beside a word; every line of the card keeps clear
  of the button tags.
- **What the check code does, and does not do:** after the press the board
  shows PHONE ADDED with the check code (from its one-off hand-off key E) and
  "else revoke N", until a press (at most 5 minutes). For its first 20 s it
  holds the screen: a relay card waits behind it, and in WiFi mode a cable
  command that would put up its own card is refused "approval on screen"
  (refused, not queued; the host retries). The USB-bridged loop refuses
  nothing: its host waits on every frame, and the result is drawn again
  after each. After that a queued relay card takes over and
  the result is gone, while a cable command runs over the top of it and the
  result is drawn again afterwards. The phone and Sapwood show the same
  code. It confirms
  delivery and catches mix-ups (a stale or crossed hand-off, a phone that
  never received one); it does NOT prove the board sent the hand-off the
  phone holds. The hand-off is sealed from an unauthenticated one-off key, so
  whoever has already swapped P for a key of their own can grind 24 bits for
  an E' whose check code matches. The five words are the only defence
  against a swap. "Else revoke N" stays: a phone that never shows the check
  code never got its hand-off, and record N is revoked.
- **Parked follow-up (not built): an authenticated hand-off.** The board
  would sign (E, P) with its paired identity, so the phone could verify the
  hand-off came from the board it paired with, and a swap after the words
  would be caught on the phone too.
- **Only while unlocked:** a locked board serves no management at all, and
  the board is checked again at the press (the operator is still the device
  operator, a configured relay has been heard from within the ping interval
  plus 10 s, a data key, relays, fewer than 16 phones), and the record is
  written only
  once the answer carrying the hand-off is known to fit the heap. Nothing is
  written before the press, so a card that is declined, expires or is lost to
  a restart leaves no record; the phone's enrolment key is spent either way
  and the phone starts again.
- **Nothing new on the wire:** the request and answer are the existing
  operator ⇄ identity 24134 exchange (NIP-44, the label and P only inside
  it); the hand-off Sapwood passes to the phone is byte-for-byte the cable's.
  Residual: a relay that sees both the operator's traffic and the phone's
  one-off rendezvous subscription can link that enrolment to the phone's IP
  address at that moment, which is weaker than the stable link Cambium's own
  NIP-46 pairing already makes.
- **Rollout:** this firmware must ship only together with the Cambium
  release that shows the five words (and keeps its labels to printable ASCII,
  which the board now requires on the cable too) and the Sapwood release that
  tells the owner to compare the board with the phone. Shipped alone, owners
  have nothing trustworthy to compare the card with.
- **Residual: a lost answer.** The record is written before the answer is
  published (a phone is never handed a secret the board did not keep). The
  answer is offered to every configured relay session; if none that counted
  as live at the press (heard from within the ping interval plus 10 s) takes
  it, the board says "Not sent / revoke id N" instead of PHONE ADDED and logs
  the id.
  Such a record's secret left nowhere: it unlocks nothing and is removed with
  a revoke. A relay can still accept the answer and lose it, which only the
  phone never receiving a hand-off shows.

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
