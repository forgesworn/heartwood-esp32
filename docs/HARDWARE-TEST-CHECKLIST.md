# Hardware-in-the-loop test checklist

Things that can only be confirmed on a real board — the on-device gestures, the
OLED, OTA, and the USB/WiFi mode transitions. CI covers the host logic and that
the firmware builds and fits; this covers everything CI can't reach.

Run this on every supported target before release and record the board under
test. Have Sapwood open (Chrome/Edge for Web Serial). Where a step says
"approve on the device", use that board's local confirmation control; on the
Heltec boards this is a 2-second hold of **PRG**.

Sections 1–5 and 7 are the ESP32 WiFi signer; **§6 is the USB-tethered ESP8266**
(NodeMCU+OLED) — a different device and flow, with its own board and gestures.

**Reading the device log.** A standard build prints no log at all. The console
is compiled out on every board (`CONFIG_ESP_CONSOLE_NONE`; the V4 also needs
`CONFIG_ESP_CONSOLE_SECONDARY_NONE`, since #113 on 2026-09-06), because log
bytes on the USB port corrupt the frame protocol. `scripts/serial-log.mjs`
therefore shows nothing on a standard build. Where a step below quotes a log
line, it is extra detail visible only on a bench build with the console routed
to a UART probe on spare GPIOs (`CONFIG_ESP_CONSOLE_UART_DEFAULT=y` in the
board's `sdkconfig.defaults.*`; never USB-Serial-JTAG, which carries the
frames). Each step also names what you can observe without one: the panel,
FIRMWARE_INFO, `heartwood_note_list`, or relay traffic via
`scripts/fetch-events.mjs`. Bench records dated before 2026-09-06 quote log
lines that did reach USB at the time; they are accurate for their date.

## Bench record — 2026-07-12 T-Display

Non-destructive checks completed on a provisioned classic ESP32-D0WDQ6
T-Display. Public identity and credential values are deliberately omitted.

- [x] Read and validated the pre-flash factory application image. SHA-256:
      `2266d4fe43239397edfe6ca4df108dd1383605d71db227eef1566f6fd6d39279`. <!-- pragma: allow-secret — public SHA-256 -->
- [x] Built the `tdisplay` release image; it targets classic ESP32, validates as
      an ESP32 application with embedded version `0.12.0`, and fits the 3 MiB
      factory partition with 134,720 bytes spare. Final bench SHA-256:
      `f9c9492b17eaeab8b8e6577a5a3868afd66226cb6f7f74acfa88ef78b8a10274`. <!-- pragma: allow-secret — public SHA-256 -->
- [x] Flashed only the factory application at `0x10000`; the programmer's
      written-data hash verification passed. NVS and the separate config
      partition were not erased or written.
- [x] Post-flash protocol read-back reports firmware `0.12.0`, board
      `tdisplay`, one master named `test` in mode `0`, and one connection slot.
      This proves the existing provisioned inventory survived the application
      update without publishing its npub or client material.
- [x] New USB redacted-state read-back reports WiFi mode, four relays, a stored
      password boolean, a configured operator, no pending trial, and healthy
      recovery. The decoded response contains no `password` field or value.
- [x] A stale-revision network patch and a 32-byte non-curve operator key were
      NACKed before approval. Revision and operator remained byte-for-byte
      unchanged on the next read-back.
- [ ] Confirm the display is visually normal after reboot.
- [ ] Run the authenticated relay, unattended-policy, phone handoff, network
      transaction, replay, and power-cut checks in §7. These require the matching
      operator credential and disposable test network/identity state; the safe
      application-only flash is not evidence for them.

## 1. Flash + first identity (generate)

- [ ] Flash from Sapwood (Flash tab). Board reboots into the boot animation.
- [ ] Setup shows **Create a fresh identity** and **Restore from my 12 words**.
- [ ] Create → name → "Create it on my device". OLED shows **NEW IDENTITY / Working**.
- [ ] OLED walks the 12 words one at a time (**WORD n/12**, big font). Tap advances.
- [ ] After word 12, **ALL 12 SHOWN** — a short tap re-shows the words; a 2-second
      hold saves (**SAVED**).
- [ ] Sapwood shows the npub and moves to "write it down". npub matches the device.

## 2. On-device restore (the new path)

Pick a **known test phrase** with a known npub (e.g. the all-zero vector
`abandon …× 11 … about`). Do **not** use a real key for the first run.

Gestures (firmware v0.9.4+): **single tap = next, double-tap = pick, hold = go
back.** (Hold steps the highlight back one choice; the only *other* hold is the
deliberate 2-second save at the very end.) Once a word fully resolves (the sole
choice), a **single tap accepts it**.

- [ ] Setup → **Restore from my 12 words** → name → **Restore on my device**.
- [ ] OLED shows the intro (1 tap = next / 2 taps = pick / hold = go back) then **WORD 1/12**.
- [ ] Entering a word:
  - [ ] A **single tap** moves forward through the choices: valid next letters, then the
        whole word (underlined) once it resolves.
  - [ ] **Hold = back (the headline fix):** overshoot a letter (tap a→b), then **hold**
        — the highlight steps back (b→a) in one gesture, NOT a full lap and NOT a jump
        to the previous word.
  - [ ] A **double-tap** picks the highlight — a letter extends the prefix; the
        underlined word accepts it. Typing `a` `b` `a` offers **abandon** within ≤4 letters.
  - [ ] **Single-tap accept:** once the prefix resolves to one word (shown alone,
        underlined, legend reads **tap=pick**), a **single tap** accepts it directly —
        no double-tap needed. (A double-tap still works too.)
  - [ ] **Delete a letter:** with the highlight on the first choice, a **hold** removes
        the last committed letter; on an empty word it steps back to the previous word.
- [ ] After word 12, OLED shows the **REVIEW** screen:
  - [ ] A **single tap** pages forward through all 12 words, then **SAVE**, then **CANCEL**;
        a **hold** pages back one item.
  - [ ] A **double-tap** on a word re-enters *just that word* in place, returning to review.
  - [ ] A **double-tap** on **SAVE** validates the phrase.
- [ ] Valid phrase → **THIS ACCOUNT?** with the derived npub:
  - [ ] The npub matches the expected one for the test phrase.
  - [ ] A **tap** returns to review; a 2-second **hold** saves (**RESTORED**).
- [ ] Sapwood shows the same npub and completes.

### Restore edge cases

- [ ] **Wrong word recovery (the headline fix):** deliberately accept a wrong word,
      finish the 12, hit SAVE → on the REVIEW screen, page to the wrong word, double-tap
      to re-enter it correctly, SAVE again → succeeds.
- [ ] **Bad checksum:** 12 valid words with a wrong checksum → SAVE returns to
      **REVIEW** with a **"! phrase invalid - fix a word"** banner (not a dead-end);
      fixing the bad word and SAVE then succeeds.
- [ ] **Cancel:** REVIEW → **CANCEL** (double-tap), or during entry **hold** to step
      back past word 1 → restore cancels cleanly, device returns to normal, no master stored
      (Sapwood reports "cancelled / didn't check out").
- [ ] **Real phrase round-trip:** restore a phrase generated in step 1 on a
      factory-reset board → the npub matches the original identity.

## 3. OTA over USB (fresh / USB device)

- [ ] Update firmware shows **"On your signer vX / Bundled vY"** and an **Update to vY**
      button (hand-picking a `.bin` is under **Advanced**).
- [ ] **Update to vY** → OLED shows **FIRMWARE UPDATE** + size + countdown.
- [ ] Approve on the device (2-second hold) → Sapwood streams (progress to 100%).
- [ ] OLED shows **VERIFYING** then **VERIFIED / Rebooting**; device boots the new
      version (check the boot-screen version string).
- [ ] **Tamper check:** corrupt one byte of the `.bin` first → device reports a
      checksum failure and keeps the current firmware (rolls back).

## 4. OTA on a deployed WiFi signer (no re-flash)

- [ ] Start from a provisioned WiFi signer running its relay loop (manages over WiFi).
- [ ] In Sapwood, Update firmware on a relay connection shows the **USB-only**
      guidance (no upload button).
- [ ] Power-cycle / RESET the board; while it shows **"Hold PRG = USB"** (3s window),
      hold PRG until **"USB mode"** appears.
- [ ] Connect over USB in Sapwood, then run the OTA as in §3.
- [ ] After reboot, the signer rejoins WiFi on the new firmware.

## 5. Two-phrases sanity

- [ ] The **operator phrase** (shown in Sapwood at flash time) and the **device
      recovery phrase** (shown on the device's screen) are different 12-word sets.
      Confirm the Flash screen calls this out so they aren't conflated.

## 6. ESP8266 tethered signer (first-flash bench pass)

A different device and flow from §1–5: the ESP8266 has no WiFi and no on-device
key generation. It is flashed with public firmware, provisioned **offline** over
USB (`heartwood-provision`, or the Sapwood tethered wizard), and reaches Nostr
only through a `heartwood-bridge` daemon. Use the NodeMCU+OLED (CH340) board.

The boot **POST is the critical gate** — it recomputes a frozen pubkey/sig/persona
vector on the real lx106 and refuses to run if k256 is byte-wrong. If §6.2 passes,
the bare-metal crypto is proven and everything after is plumbing.

### 6.1 Flash (online OK — public firmware)

- [ ] Sapwood `/flash` → **USB-tethered ESP8266** → Flash (pick the CH340 port;
      install the CH340 driver if no port appears). Progress to 100%, then RESET.

### 6.2 Boot POST — the critical gate

- [ ] Press RESET. The OLED flickers **self-test...** then settles.
- [ ] **PASS:** `Heartwood signer / unprovisioned / provision over USB` (no key yet).
- [ ] **FAIL = the k256-on-lx106 risk is real — stop and capture the exact text:**
  - `SELF-TEST FAILED / pubkey mismatch` or `sign mismatch` → k256 returns wrong
    bytes (unaligned-access corruption).
  - Stuck on `self-test...` forever → k256 hard-faulted.
  - `nip44 roundtrip` / `persona mismatch` → a narrower AEAD/derivation drift.
- [ ] (Blank/garbled OLED → check SDA=GPIO14/D6, SCL=GPIO12/D5. Garbled serial →
      the 80 MHz→115200 divisor assumption is wrong for this board.)

### 6.3 Provision offline (the key)

Take the host offline (Wi-Fi off, cable out), device plugged in:

- [ ] `heartwood-provision --port <PORT> generate --gen-bridge-secret` — writes 12
      words (write them on paper), type `yes`; prints `Pubkey: npub1…` and a bridge
      secret hex (keep it for §6.4).
- [ ] OLED: `PROVISION SEED? / hold FLASH = approve` → **hold the FLASH button (GPIO0)**.
- [ ] CLI: `✓ Seed provisioned` → `✓ Bridge secret paired` → `✓ Device confirms
      identity: npub1…` — the readback npub matches `Pubkey` above.
- [ ] (Restore instead: `provision --mode tree-mnemonic` / `--mode tree-nsec`; for the
      `abandon …× 11 … about` vector the master npub is
      `npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx`.)
- [ ] Reboot → the OLED now shows the **npub**, not "unprovisioned".

### 6.4 Bridge bring-up (online host)

- [ ] Move the board to the always-on host; find its port there.
- [ ] In `HEARTWOOD_DATA_DIR`: `master.payload` = `hsm:<port>`, `bridge.secret` = the
      hex, `config.json` = `{"relays":["wss://…"]}` (Sapwood's bridge step renders these).
- [ ] `HEARTWOOD_DATA_DIR=<dir> heartwood-bridge` → it `SESSION_AUTH`s and advertises a
      `bunker://` URI.

### 6.5 Sign once (end-to-end)

- [ ] Point a NIP-46 client (Nostrudel / nak) at the `bunker://` URI → `get_public_key`
      returns the npub; `sign_event` (kind 1) returns a signed event the client posts.
- [ ] (A `heartwood_*` persona request derives a child identity — the boot POST already
      proved that path with the social vector
      `npub1qdztfxg9z46k8qg4707n747y9rt7kl3f954lju2pneesmc3ypf2q83gm0e`.)

### Known risks to watch

- [ ] **k256 unaligned access on lx106** (§6.2) — the headline Phase-0 risk; the POST is the canary.
- [ ] **UART 115200 divisor** assumes an 80 MHz CPU — garbled serial means the clock/divisor is off.
- [ ] **NIP-44 nonce entropy** on bare-metal (`sign_path::random_nonce`) — flagged for review;
      affects signing safety, not the POST.

## 7. Remote policy + network transaction bench pass

These are required real-board checks for the operator-management changes. They
are intentionally unchecked here; this document update is not evidence that the
hardware tests ran. Use throwaway identities, WiFi credentials, and relays.

### 7.1 Exact strict v2 policy

- [ ] Over authenticated relay management, create a v2 client with
      `auto_approve=true`, `allowed_methods=[get_public_key,sign_event]`, and one
      test event kind. `list_clients` reports `strict_permissions=true` and the
      exact echoed method/kind lists.
- [ ] That client signs the allowed kind unattended. A different event kind and
      an unlisted encryption method are denied without a PRG fallback.
- [ ] A pre-v2/legacy slot still uses its historical button fallback; approving
      signing does not broaden its existing encryption-method or kind ceiling.
- [ ] Attempts over operator management to replace/export the seed, change
      `op_mgmt`, switch to USB-only mode, change the PIN, or start OTA fail and
      leave state unchanged. The firmware UI continues to describe OTA as USB-only.

### 7.2 Good staged network commit

- [ ] Record active A, revision N, operator pubkey, and remembered relays. A
      `get_network_config` response contains SSID/relays/`password_set`, but no
      password field or password value.
- [ ] Stage candidate B with a fresh transaction id and `base_revision=N`.
      Response is revision N+1; the device does not reboot and remains on A.
- [ ] Drop or corrupt the stage reply after persistence. Sapwood resolves the
      exact staged transaction from `get_network_config`; it does not resend the
      mutation under a fresh management challenge.
- [ ] Activate the same transaction + revision. The response arrives before
      reboot; on candidate boot, trial state is `trying` with `attempted=true`.
- [ ] Commit through one of B's configured primary relays. A request delivered
      only through an old or client-pinned relay does not commit.
- [ ] Final read-back is active B, no trial, and `last_result` is the same
      transaction/revision with `outcome=committed`. Sapwood remembers only B's
      relays after this point; the operator pubkey is unchanged.
- [ ] Drop the commit reply after the device has persisted it. Sapwood reads the
      exact terminal transaction/revision on B and completes without attempting
      to abort an already-committed change.

### 7.2a Durable management replay challenge

- [ ] Capture a valid encrypted `revoke_client` request, execute it once, then
      send at least 65 newer management requests and reboot. Replaying the
      capture returns a stale-challenge error and does not touch the current
      occupant of that numeric slot.
- [ ] Fetch one challenge on two trusted managers. After manager A mutates the
      device, manager B's pending mutation is rejected without dispatch; Sapwood
      reports the conflict and refreshes state before the user retries.
- [ ] Cut power after the next challenge is persisted but before the requested
      slot mutation dispatches. After reboot the old request remains stale, no
      partial slot change exists, and a newly discovered challenge works.
- [ ] Against pre-challenge firmware, current Sapwood reports that a USB firmware
      update is required and never falls back to sending an unprotected mutation.

### 7.3 Bad candidate + power-loss recovery

- [ ] Stage and activate an unreachable SSID, wrong password, or unusable relay.
      Sapwood never reports success or replaces the remembered A relays; the
      signer returns to A and reports the transaction as rolled back.
- [ ] Power-cycle after **stage but before activate**: it boots A and preserves an
      inert staged transaction. Sapwood offers **Discard pending change**; abort
      removes it without changing A.
- [ ] Power-cycle on candidate B **before commit**: the next boot selects A, not B,
      and terminal state records `rolled_back`.
- [ ] Interrupt power during commit/cleanup and reconnect on both routes. Durable
      active/trial/terminal state resolves to exactly one outcome: committed B if
      the committed marker became authoritative, otherwise rolled-back A; no
      endless retry of B and no ambiguous UI success.
- [ ] Kill/reload the mobile browser after activation and again just after commit
      publish. Recovery retains enough non-secret transaction + old/candidate
      relay state to find the signer, read its terminal outcome, and remember the
      winning route; the WiFi password is never journalled.

### 7.4 Password handling + unattended reboot

- [ ] Blank password means **keep** only when SSID is unchanged; changing SSID
      requires an explicit new password or **clear/open** choice. Password values
      never appear in read-back, Sapwood storage, or relay plaintext captures.
- [ ] Confirm a relay capture contains NIP-44 ciphertext, then (using only the
      throwaway test password) confirm a raw flash/NVS inspection can recover the
      plaintext network credential while NVS encryption is disabled. Record this
      as the accepted at-rest limitation, not an encryption pass.
- [ ] With a boot PIN enabled, reboot leaves relay signing/management unavailable
      until the PIN is entered over USB. Remote network activation is rejected
      before mutation/reboot. Do not describe that configuration as capable of
      unattended power-loss recovery.

### 7.4b Vault key (host-held encrypted at rest)

- [x] Flash v0.14.0 (vault build) on Heltec V4: boot healthy, FIRMWARE_INFO
      and PROVISION_LIST respond, `locked:false` present on every master row,
      SESSION_AUTH with a zero secret rejected (0x01), VAULT_SET without bridge
      auth NACKs "bridge auth required", VAULT_UNLOCK while unlocked NACKs
      "already unlocked". (2026-08-08, automated frame harness.)
- [ ] **Enable over USB**: Sapwood Device > Security > Encrypt at rest (or
      `heartwoodd --vault-enable` with the bridge secret). OLED shows
      "Enable vault? (host-held key)"; confirm with the hold. ACK, Sapwood
      shows the escrow prompt. Reboot: OLED shows "Locked — Await unlock…",
      PROVISION_LIST rows report `locked:true`, signing frames NACK.
- [x] **Auto-unlock (USB-bridged)**: with `vault.key` in heartwoodd's data
      dir, start the daemon; the device unlocks after SESSION_AUTH and serves
      signing normally. Verified on a three-master Heltec V4 through a local
      relay and Bark: get public key, relay discovery, event signing, and
      signature verification all passed after a real locked reboot. The
      multi-master KDF took about 26 seconds, so startup allows 60 seconds and
      re-authenticates the normal policy session after leaving the locked boot
      loop. (2026-08-13.)
- [ ] **Vault status reporting**: after auto-unlock,
      `GET /api/vault/status` reports `key_present:true`.
- [ ] **Wrong vault key**: corrupt a copy of `vault.key` and attempt unlock
      (Sapwood paste flow). NACK "wrong vault key", NO wipe-counter increment,
      device stays locked, correct key still unlocks afterwards.
- [ ] **WiFi-standalone remote unlock**: with a wifi-mode locked signer, open
      Sapwood from another network; the kind-24135 announcement appears as
      "Signer is locked" within ~60 s; tap unlock; the device unwraps and the
      banner clears. A relay capture shows only ephemeral kind-24135/24136
      events, never a standing ciphertext.
- [ ] **Escrow restore**: clear the browser's vault store, unlock with the
      exported hex via the paste flow; Sapwood remembers it afterwards.
- [ ] **Disable**: Sapwood "Disable encryption" → OLED confirm → reboot boots
      straight through unlocked and `locked:false` everywhere.
- [ ] **PIN coexistence**: set a boot PIN while vault-enabled (or vice versa);
      both unlock paths work; five wrong PINs still wipes (use a test device).
- [ ] Repeat 7.5's power-cut matrix against a vault-locked device: a power cut
      mid-VAULT_SET leaves either fully-plaintext or fully-encrypted blobs,
      never a torn mixture that refuses both keys.

### 7.5 Destructive persistence and master-removal recovery
- [ ] Put a recognisable SSID/operator key in the raw `config` partition and a
      different runtime config plus identities/clients/personas in NVS. Approve
      physical factory reset; verify `config` is blank before NVS, both regions
      read back entirely as `0xff`, ACK arrives only after verification, and the
      reboot cannot re-seed either old configuration.
- [ ] Repeat through the fifth wrong PIN. Verify the same two-region erase and
      that a reset/power cut at the threshold never grants another PIN guess.
- [ ] Fault-inject config erase, NVS erase, and verification-read failures.
      Confirm the display says erase failed, USB receives NACK where applicable,
      no completion is claimed, and no signing loop resumes while retrying.
- [ ] With three masters, distinct client slots/legacy policy/display metadata,
      personas on every master, and client-pinned relays, remove slot 0, then a
      middle slot, then the last slot in separate fixtures. After each reboot,
      surviving keys retain exactly their own policy/metadata; target personas
      and pinned entries are gone; higher persona/pinned owner slots decrement.
- [ ] Cut power before/after every `rm_journal` cursor transition and repeat cuts
      within slot copy, persona rewrite, terminal cleanup, and count commit.
      Boot must finish idempotently before loading a signer and must never bind
      stale authority to a survivor or newly added master.
- [ ] Corrupt `rm_journal` or a required persona record. Boot remains
      fail-closed and offers a clearly-labelled two-second PRG hold for a full
      persistent wipe; it never auto-wipes. Corrupt only `pinned_rly`; removal
      succeeds by discarding that non-authoritative reachability cache.

## Bench record — 2026-08-14 Heltec V4 (16 MB variant), v0.16.0

Run on a provisioned V4 (3 identities, 2 app pairings, WiFi mode, encrypted at
rest with a host-held vault key).

- [x] **Root-caused a fleet-relevant OTA failure**: the device carried an
      early bring-up partition table (one 16000K `factory` slot, no
      `otadata`/`ota_0`/`ota_1`), so `esp_ota_get_next_update_partition`
      returned null and every OTA died at OTA_BEGIN with ERR_WRITE ("couldn't
      prepare its update slot"). Any other early-flashed V4 will behave the
      same. Its NVS also used the legacy 24K size — the standard table's 16K
      nvs would truncate live page 4, so **do not** blind-reflash such units
      with the fleet layout.
- [x] Repaired via `firmware/partitions-v4-16mb-legacy-nvs.csv`: keeps the
      24K NVS at 0x9000, real 2MB A/B slots, config at the standard 0x410000,
      otadata relocated to 0x414000. Wrote table + signed v0.16.0 app with
      espflash after taking a raw NVS backup (deleted after verification).
- [x] v0.16.0 boots from the new table; all 3 identities and both app
      pairings survived; vault unlock via Sapwood works.
- [x] Sapwood shows signer v0.16.0 = bundled v0.16.0, no update banner
      (correct no-op case for the new update check).
- [x] Idle carousel confirmed in WiFi mode: press wakes to the identity card,
      further presses page NETWORK (SSID + status) and DEVICE (version,
      board, uptime).
- [ ] Known rough edge: a wake press during WiFi (re)association or a
      degraded relay session waits for the blocking connect/read — poll the
      button in the retry-wait loops (follow-up).
- [ ] OTA into ota_1 on this repaired unit (Re-install button) — exercise
      when the next release lands.

## 8. Field-test feedback fixes + multi-network (added 2026-08-14, not yet bench-run)

Covers the 2026-08-14 approval/wake fixes and the new features. Run on a
T-Display (two buttons) and one Heltec (single button).

Approval flow (both boards):
- [ ] Trigger a network change from Sapwood and let the prompt expire
      untouched. The screen must show "Request expired / no change made" — not
      a stale countdown — and after display sleep, waking must show the idle
      card, never the dead prompt.
- [ ] T-Display: the prompt names the buttons ("hold lower 2s = yes / tap
      upper = no"). Holding the lower (GPIO 0) button 2 s approves with the
      progress bar; tapping the upper (GPIO 35) button shows CANCELLED and
      Sapwood reports the denial.
- [ ] T-Display clone check: on a board whose GPIO 35 floats (no external
      pull-up), approvals behave single-button — B must never self-cancel
      prompts. (A console build also logs "leaving it unregistered" at boot.)
- [ ] After a Sapwood web flash, without replugging: the display wakes on a
      button PRESS (not release) and the device never looks dead while the
      serial bridge holds GPIO 0.

Idle carousel (both boards, USB and WiFi modes):
- [ ] Short presses cycle identity/status → NETWORK → DEVICE → back. NETWORK
      shows mode + SSID + live stage (WiFi mode) or "radio off" (USB mode);
      DEVICE shows version, board, uptime. Sleep resets to the first page.
- [ ] A short press never triggers or interferes with a signing approval.

Multi-network WiFi (T-Display or Heltec in WiFi mode):
- [ ] Over USB, add two fallback networks in Sapwood (e.g. phone hotspot +
      second AP), reorder them, save, and read back: the list survives the
      reboot and the redacted state shows ssid + password_set only.
- [ ] Power the primary AP off. The signer rotates to the hotspot within a few
      retry cycles (~10 s/candidate) and comes online — Sapwood and paired apps
      reach it again. (A console build also names each candidate as "wifi
      network N/M".)
- [ ] Promote a fallback to primary in Sapwood using its saved password (no
      password typed). The device joins it after reboot.
- [ ] Encrypted-at-rest + WiFi: with the vault locked, the device now joins
      WiFi during the locked phase (previously the station never associated)
      and publishes its kind-24135 unlock announcement.

Quick USB update (T-Display / C6):
- [ ] Sapwood's Firmware section offers "Update to vX over USB" for the
      factory-layout board; the flow writes app-only, and after reset the
      device keeps identity, Wi-Fi settings and slots (verify via read-back).
- [ ] The device panel shows the update banner when the bundle is newer, and
      after the update + reconnect Sapwood prints the confirmed version line.

Demo game (spare T-Display):
- [ ] `scripts/build-firmware.sh demo --release`, flash `heartwood-demo.elf`
      at 0x10000. Title screen brands Heartwood, names the flash URL, and the
      button-check labels light while held. A jumps, B ducks, collisions end
      the run, score/best display. It must never expose signer frames on USB.

Signing confirmation hold (#60, both boards, USB and WiFi modes):
- [x] Button-approved sign: after the hold, the SIGNED card names the
      requester and event kind and stays up ~5 s before the idle card
      returns on its own. The client must receive the response immediately
      (no heartwoodd timeout — the hold must never delay the response).
- [x] NIP-17 DM send (the recipient seal and the self-copy seal auto-sign
      back-to-back; the gift wraps sign client-side with ephemeral keys):
      two AUTO-SIGNED cards show ~5 s each in order, then the idle card
      returns. Neither flashes past unread.
- [x] A short press during a held card dismisses straight to the idle card;
      the next press pages the carousel as normal.

      Bench 2026-08-14, Heltec V4, WiFi-standalone, hold tuned 3 s → 5 s:
      client was bray in true bunker mode (BUNKER_URI only, no local key)
      over the relay path. First DM send: seal 1 button-approved mid-window
      and the signed response was published 0.28 s after the press (hold
      never delayed it); seal 2 auto-signed 1.2 s later and queued behind
      the held SIGNED card. Second send on the upgraded slot: both seals
      auto-approved 1.25 s apart (serial-log timed), two AUTO-SIGNED cards
      queued in order. Both DMs delivered and decrypted back through the
      device (`dm-read` exercises on-device nip44_decrypt of the wraps).

      Follow-up bench same day (#61/#62 fixes, commits 7f12385 + b1468fc):
      an expired request's outcome card measured 32.2 s on screen before
      burn-in blanking (`sign_event: timed out` → `display blanked after
      inactivity` on the serial tap) — pre-fix it blanked within moments.
      The dismiss-tap item now self-reports over serial (`confirm: card
      run dismissed by press`), so closing it needs one short press while
      a card is held, with the tap running — no OLED observation needed.
      Note the semantics: a short press is only "dismiss" while a card is
      held; during an approval prompt it remains deny.

      Dismiss-tap confirmed same day: two held-card runs (relay-path DM
      auto-signs), two taps, two `dismissed by press` lines 2.9 s and
      2.4 s after each run's first card — pre-fix the tap usually did
      nothing in WiFi mode (#61 closed).

## 9. Packed persona registry + storage gauge (added 2026-08-14, not yet bench-run)

Family-bunker Phase 1 (see signet-plans
`2026-08-14-heartwood-family-bunker-migration-design.md` §11.2/§11.3). Run on
a Heltec (cap 32) AND a T-Display (cap 64); the migration case needs a board
carrying personas created by pre-packed firmware.

- [x] **Boot migration.** Flash a board that already holds `p{n}_*` personas.
      First boot logs "Migrating N persona(s) to the packed registry layout"
      then "migration complete"; PROVISION_LIST shows the same personas with
      the same npubs; a paired app addressed to a persona still signs.
      (2026-08-14, T-Display 0.13.7 → 0.16.0 app-only reflash: legacy
      persona `bark-check`, 3 masters and 4 pairings all carried across
      with identical npubs; packed round-trips on the migrated registry
      passed 8/8, and slot-0 derives matched the Heltec V4's byte-for-byte
      — cross-device parity confirmed live. Signing re-check pending the
      UI click-through.)
- [ ] **Migration power-cut.** Repeat on a board with several personas, but
      cut power mid-boot (first boot after flashing). Every subsequent boot
      resumes the journal; the registry ends identical to the uncut run.
- [ ] **Sapwood pairing ceremony.** Identity panel → Add a persona. First use
      creates the "Sapwood manager" slot: the device shows the policy-update
      confirm; one press. Persona appears in the identity list with its own
      npub; reboot; still there.
- [ ] **Create / rename / remove round-trip.** Create `bench-a`, rename its
      label, remove it. PROVISION_LIST reflects each step; after remove, a
      NIP-46 request addressed to `bench-a`'s pubkey is NACKed; re-deriving
      `bench-a` reproduces the SAME npub as before removal.
- [ ] **Remove mid-power-cut.** With 3+ personas, remove the middle one and
      cut power between the OLED activity and the Sapwood confirmation.
      Boot resumes the removal journal; exactly one persona is gone, the
      others' npubs are unchanged (compare a pre-cut PROVISION_LIST dump).
- [ ] **Registry cap.** Script `heartwood_derive_persona` to the board cap
      (32 Heltec / 64 T-Display). The cap-plus-one derive returns the
      "identity storage full" error, not a timeout, and the device stays up.
- [ ] **Storage gauge.** Device panel shows "Identity & app storage" over USB
      and (WiFi tier) over the relay; the percentage moves as personas are
      added/removed; warn copy appears past 80%.
- [ ] **Master removal still clean.** With personas owned by two masters,
      remove a master (existing §journal flow): its personas disappear, the
      other master's personas survive with owners remapped, and a cut during
      the removal still resumes to the same end state.
- [ ] **Regression sweep.** Section 1–3 basics still pass on the same build:
      provision, pairing, sign, backup export/import, OTA.

`scripts/bench-personas.mjs` semi-automates the non-physical items over the
cable (round-trip, post-reboot persistence, cap): run its three phases in
order with an `espflash reset` between round-trip and post-reboot. It drives
the plaintext NIP-46 path, so a vault-locked signer NACKs it — unlock first.

Bench record — 2026-08-14 Heltec V4 (16 MB variant), packed-registry build:

- Flashed over USB with NVS preserved (3 masters, 6 app pairings carried
  across). Boot completed cleanly through `migrate_if_needed` on an empty
  legacy registry (no-op path) into the vault-locked boot loop.
- FIRMWARE_INFO now reports the storage stats on real hardware:
  `nvs_used_entries 520 / total 756, free 236, max_personas 32` — the gauge's
  wire format confirmed end-to-end.
- PROVISION_LIST serves correctly on the new registry module (3 masters,
  0 personas, locked flags accurate).
- Remaining phases (derive/rename/remove round-trips, post-reboot
  persistence, cap refusal) blocked on this board's vault unlock: slot 0 is
  encrypted at rest and the plaintext path correctly NACKs while locked.
  Run the script's three phases after unlocking. Migration-with-data and
  the power-cut items additionally need a board carrying `p{n}_*` personas
  from pre-packed firmware.

Bench record — 2026-08-14 (same board, later, encrypted path): full pass
via `scripts/bench-personas-nip46.mjs` (0x10/0x35 — the transport the
Sapwood manager pairing uses; vault-unlocks itself, needs a sibling
sapwood checkout for deps):

- ✔ Pairing ceremony live: CONNSLOT_CREATE, button-confirmed manager
  ceiling, NIP-46 connect with the slot secret.
- ✔ Derive / rename / list / idempotent re-derive; packed growth measured
  at ~5 NVS entries per persona (536 → 546 for two).
- ✔ Reboot: personas and the rename survive; re-derive returns the same
  key; removal is registry-only (same npub back on re-derive).
- ✔ Cap: 32/32 created, the 33rd refused with the "identity storage full"
  text, device healthy at cap (nvs 609/756), full cleanup to zero.
- ✔ All of the above SILENT after the pairing press — this run caught and
  then verified the fix for `policy.rs check()` returning ButtonRequired
  for slot-listed extensions (a listed method + auto_approve now defers to
  `evaluate_slot_policy`; consent is the button-confirmed ceiling install).
  First attempt burned a thumb on ~35 per-request prompts.
- Chaos power-cut runs, same day (T-Display, live cable yanks during
  registry churn — derive/remove bursts at ~5 ops/s): two cuts at distinct
  points (mid-derive-burst; at the removal boundary), and after each the
  board booted to a CONSISTENT registry — 3 masters, the migrated persona,
  no duplicate pubkeys, mid-flight personas landing atomically on one side
  of the cut. A cut-adjacent removal resumed invisibly from its journal at
  boot. Honest scope: hand-timed pulls sample arbitrary cut points; the
  per-step cut coverage lives in the host models
  (`persona_pack` cut-after-every-step tests), which these runs corroborate.
- Sapwood store-path click-through equivalent, same day: 5/5 on the Heltec
  via a vitest harness driving the EXACT store functions the Identity/Device
  panels call (real SerialTransport over node-serialport; only the Web
  Serial chooser and DOM clicks bypassed): pairing recognition without a
  fresh ceremony, create, rename, remove with same-key re-derive, and the
  gauge from live firmware stats. The harness caught a real bug on the way:
  an existing pairing skipped session auth, refusing the first persona
  action of any fresh browser session (fixed, sapwood 4a660bc).
- **CP1: SIGNED OFF.** Every §9 behaviour is hardware-verified on both
  board classes. The only untested residue: literal DOM clicks/Chrome Web
  Serial (thin, type-checked), and a hand-timed cut during a first-boot
  MIGRATION (host cut-models cover it; revisit if another legacy-persona
  board appears).

## 10. Path B family recovery — words-only enrolment (bench-run 2026-08-14)

Sapwood-side Phase 2 of the family-bunker plan: rebuild a family onto the
signer from the guardian's recovery words plus the encrypted roster on the
sync relay. Zero firmware changes — the run exercises the existing 0x10
NIP-46 path (`heartwood_derive_persona`, `heartwood_rename_persona`,
`nip44_decrypt`) behind the Sapwood manager slot policy.

Bench record — 2026-08-14 evening, Heltec V4 v0.16.0 (wifi-standalone,
vault-encrypted at rest), harness `sapwood/hardware-recovery.test.ts`
(vitest over node-serialport driving the exact wizard store functions):
**6/6 PASSED**, one button press total (the manager-pairing ceiling).

- Throwaway guardian: fresh 12 words each run; the host derives the whole
  family (same maths as My Signet), publishes a real `signet:dependants`
  kind-30078 roster to the relay, self-encrypted to the natural person, and
  verifies it by fetch-back before touching the device.
- Provision rode the wifi-standalone REBOOT semantics (master-set changes
  reboot the signer to re-subscribe): port reopen, SESSION_AUTH +
  VAULT_UNLOCK (slow unseal), then a CONNSLOT_LIST poll until the relay
  loop serves USB again. Same ride after each cleanup removal.
- Natural-person parity: the on-chip derive matched the host derivation
  from the words byte-for-byte, then the signer decrypted the fetched
  roster itself (target = peer = NP; the key never left the chip). The
  widened manager ceiling (now including `nip44_decrypt`) upgraded and
  enforced as designed.
- Enrolment: 7 identities (guardian persona + professional blind, two
  dependants' np/persona, one extra) all derived on-chip and verified
  against the roster's expected pubkeys; display-name renames applied and
  visible in the registry; 1 view-only record correctly reported as
  unrecoverable. Cleanup removed personas, revoked the pairing, and removed
  the bench master — board back on its original master set.
- Bench-infrastructure gotchas (not firmware): sapwood's unit-test
  `InertWebSocket` stub must be swapped for a real `ws` client in the
  hardware config (vite's browser resolve condition serves ws's throwing
  shim unless aliased to `ws/index.js`); nostr-tools `publish` can resolve
  with a "connection failure:" string, so the roster publish is only
  trusted after a fetch-back.
- Noted for a later firmware cycle: some button-approval windows (e.g. the
  CONNSLOT_UPDATE ceiling confirm) run their timeout without the usual
  countdown graphics.

### CP2: SIGNED OFF (joint gate closed 2026-08-15)

Both halves of the spec §12 CP2 checkpoint have now run on real hardware:

- **Path B (words-only, this repo's half):** 6/6 above (2026-08-14).
- **Path A (live phone, app side):** passed 2026-08-15 on the orange
  T-Display (0.16.0, last-green c064029) — full family enrolled 6/6 with
  the one-way strip, every derived npub matching the manifest, venue-entry
  NP signing on-device, persona kind-0 publish/retract on the persona
  slot, and a child app re-paired straight to the device via a
  persona-addressed bunker URI and signing (five child-authored events
  verified on the relay, no guardian phone in the loop). Full record: the
  CP2 sign-off note in the signet-app branch doc.

Firmware findings from the Path A run tracked as #64 (approval window
blocks the transports; unapproved sign_events serialise), #65
(unprovisioned board watchdog reboot on idle serial) and #66 (first-boot
setup screen rejects SET_NET_CONFIG). The persona-addressed pairing mint
(D2) is recorded in the signet-plans design doc.

## 11. C4 escalation + C5 audit rail (v0.17.0; button-free half bench-run 2026-08-15)

Firmware under test: `heartwood-esp32` 0.17.0 (C4 park/notify/resolve,
C5 gift-wrapped audit rail, countdown bar on every approval window).
Driver: `sapwood/hardware-escalation.test.ts` (committed), run with
`npx vitest run --config vitest.hardware.config.ts hardware-escalation.test.ts`.

### 11a. Autonomous half — PASSED 5/5, twice, desk Heltec V4 (2026-08-15, no button presses)

- App-only reflash to 0.17.0 over USB-JTAG (`espflash save-image` +
  `write-bin 0x10000`; this board carries the single-factory table, so no
  otadata dance), vault re-unlock, relay loop re-served — FIRMWARE_INFO
  confirms the running version.
- Bench-manager pairing (slot 6, CP1) still drives the registry silently:
  `natural-person` and `dependant-9-np` derived over NIP-46-USB.
- A fresh `CONNECT_SAFE` slot (bridge-session create, no button) paired
  over the live relay (`connect` echoes the secret) and a `nip44_encrypt`
  addressed to the dependant persona auto-approved — the policy-decided
  outcome the C5 rail exists to record.
- The C5 kind-1059 wrap arrived on the same relay addressed to the
  guardian NP, was decrypted BY the signer (NP persona as its own
  oracle over the same client slot: wrap layer peer = ephemeral author,
  seal layer NP⇄NP), and matched the ratified §2 shape exactly: rumor
  kind 31000, author NP, empty content, computed id, no sig; tags
  `t:audit`, `d:<dep>:<created_at*1000+seq>`, `method:nip44_encrypt`,
  `outcome:auto-approved`, `p:<peer>`; seal kind 13 SIGNED by the real
  guardian NP key (verifies), wrap by an ephemeral key (verifies), no
  expiration on an audit wrap, request-derived stamp, seal/wrap jitter
  only backwards.
- Cleanup: slot revoked, bench personas removed, registry byte-identical
  to the pre-run state.
- Quirk found (minor, tracked): PROVISION_LIST can serve one stale
  persona row immediately after `heartwood_remove_persona`; the next
  list corrects itself. The bench sweeps until stable.
- Harness gotchas: kind 24133 is ephemeral (forward-only — poll-based
  fetch impossible); the pinned nostr-tools `subscribeMany` takes ONE
  filter, not an array (an array becomes a REQ the relay NACKs with
  "could not parse command"); the bench subscribes with raw WebSocket
  REQs and publishes via SimplePool.
- **Countdown bar visually confirmed 2026-08-15 on the T-Display**
  (0.17.0, two-button board): the SET_BRIDGE_SECRET approval drew the
  draining bar with the `hold lower=yes up=no` hint, and the hold
  progress ran to an approve. Same pass surfaced the next polish item —
  change SUCCESS messages were rendered on the red `show_error` fault
  screen ("Bridge secret set!", "PIN set!", "Unlocked!" etc.); all now
  use the styled green `show_change_done` card (DONE header + title +
  hint, network-card framing), verified live on the T-Display.
  Bench access note: the T-Display's bridge secret was re-keyed under
  physical approval to `~/heartwood-bench/tdisplay-bridge.secret`, so
  future benches can open a session on this board. The desk Heltec still
  runs the pre-success-card 0.17.0 build — reflash it at the §11b
  session.

### 11b. Interactive half — PASSED 2026-08-16 (steps 2–9 + 11, machine-driven; T-Display pass owed for CP5)

Escalation flags can only be installed by an operator (`create_client_v2`
/ `update_client` / `resolve_approval` policy writes) or a button-confirmed
USB `CONNSLOT_UPDATE` (0x17.0 carries `escalate`, `petition_on_deny`,
`audit_child_wrap`, `bound_identity`), so this half cannot run unattended:

1. **Flag a slot**: CONNSLOT_UPDATE with `{"escalate": true}` on a
   dependant-bound client slot — button-confirm; check the prompt now
   draws the countdown bar (the §10 gap this cycle fixed) and says
   "family" in its change list.
2. **Fast path**: client sends an interactive request → device parks
   (no button window, loop stays live), kind-31001 `t:approval` notice
   arrives at the guardian NP (24 h expiration on the wrap, `park`,
   `client`, `identity`, `method`, `k`, `park-ttl` tags); operator sends
   `resolve_approval {park, action: approve-once}` within the client's
   wait → original request completes, response `{"park":"live",
   "applied":"completed"}`, C5 records `approved`.
3. **Slow path**: park again, let the client time out, resolve after →
   `{"park":"live","applied":"completed"}` still publishes the (ignored)
   response; the client's RETRY sails through on the transient allow.
4. **Expired park**: resolve after the 600 s TTL →
   `{"park":"expired","applied":"window"}`; retry sails through.
5. **Reboot with parked requests**: power-cycle mid-park; the verdict
   after reboot resolves cleanly `{"park":"expired","applied":"none"}`.
6. **approve-remember**: verdict carries `policy` → slot policy replaced
   durably (verify via `list_clients`: flags echo back), retry silent.
7. **deny**: parked request NACKed `user denied`; C5 records `denied`.
8. **Petitions**: strict-deny slot with `petition_on_deny` → repeated
   asks coalesce (`count` climbs), 7-day expiration, deny stays enforced.
9. **Child wrap**: slot with `audit_child_wrap` + `bound_identity` set to
   the dependant → the same rumor arrives wrapped to that slot's client
   pubkey as well.
10. Run the pass on the T-Display too before calling CP5.
11. **D2 persona-addressed mint** (operator channel, no button):
    `create_client_v2` with `params.identity` = a dependant persona →
    returned `bunker_uri`/`npub_hex` addressed to the persona and
    `bound_identity` defaulted to it; a client pairing on that URI gets
    `get_public_key` = the persona. `client_uri` with `params.identity`
    re-issues an existing slot's URI persona-addressed. `nostrconnect_v2`
    with `params.identity` publishes its connect ACK authored BY the
    persona (the app pins the persona as its signer). A persona of a
    different master, or junk hex, is rejected without touching the slot
    table. Gate on `pairing_identity_v1` in `get_status.capabilities`.

### Bench record — 2026-08-16, desk Heltec V4, machine-driven over the operator channel

One button press total (SET_OPERATOR install of a fresh bench operator key —
`scripts/set-operator.mjs`, key files in the bench folder). Everything else ran
headless over kind 24134 (`~/heartwood-bench/mgmt-request.mjs`) plus a bench
NIP-46 relay client (`nip46-client.mjs`), with the serial tap as the
machine-verifiable witness. Steps 2–9 and 11 PASSED:

- **Step 1 (flags install)**: via operator `create_client_v2`/`update_client`
  rather than the button-confirmed CONNSLOT_UPDATE (that variant and its
  countdown bar were already confirmed on the T-Display, §11a). Semantics
  pinned on hardware: a strict slot's out-of-ceiling kind is a strict DENY
  (petition territory), the parking tier is an in-ceiling kind with
  `auto_approve: false`; the exact envelope accepts only TOFU-safe methods,
  so a manager slot (heartwood_* extensions) is minted v1 + legacy
  `update_client` widen.
- **Step 2 (fast path)**: parked (serial: "parked interactive sign_event …
  awaiting guardian verdict"), loop stayed live (operator `get_status`
  answered mid-park), notice published; verdict `approve-once` at ~8 s →
  client received the persona-signed event at 13.6 s, well inside its wait.
  Notice unwrapped via the NP oracle: rumor kind 31001, unsigned, tags
  exactly `t:approval / d:<client>:<seq> / park / client / identity /
  method / k / park-ttl:600`; wrap expiration 24 h.
- **Step 3 (slow path)**: client timed out at 110 s, late verdict →
  `{"park":"live","applied":"completed"}`, retry sailed through silently
  (881 ms) on the transient allow. Measured semantics: the approve-once
  allow is 600 s per (client, kind) — a second same-kind ask inside the
  window auto-signs rather than re-parking.
- **Step 4 (expired park)**: park left unresolved; sweep logged "park for
  sign_event expired unresolved" at TTL; verdict after →
  `{"park":"expired","applied":"window"}`; retry sailed (1.1 s).
- **Step 5 (reboot mid-park)**: app-only reflash as the power-cycle; park
  cleared; post-reboot verdict → `{"park":"expired","applied":"none"}`.
- **Step 6 (approve-remember)**: verdict carried a full v2 policy → parked
  client completed at 13.3 s, policy replaced durably (list_clients echoes
  kinds/auto/escalate/petition/bound_identity exactly), follow-up sign
  silent at 828 ms.
- **Step 7 (deny)**: parked client received "user denied" at 11.2 s;
  verdict answered `{"park":"live","applied":"none"}`.
- **Step 8 (petitions)**: three out-of-ceiling asks → three `unauthorised`
  (~1.1 s each, deny enforced), three petition notices coalescing on one
  replaceable `d` (`<client>:<kind>`) with `count` climbing 1 → 2 → 3;
  wrap expiration ~7 days.
- **Step 9 (child wrap)**: `audit_child_wrap` + `bound_identity` → one
  silent in-policy sign fanned the same rumor to BOTH the guardian NP and
  the child slot's client pubkey. The child copy was decrypted host-side
  (client key held): seal kind 13 signed by the real NP (verifies), rumor
  kind 31000, unsigned, `t:audit / d:<dep>:<stamp> / k:30078 /
  outcome:auto-approved`.
- **Step 11 (D2 mint)**: all assertions above ran verbatim — mint addressed
  to the persona, `bound_identity` defaulted, `get_public_key` = persona
  over the minted pairing, junk hex / cross-master persona / v1-with-identity
  all rejected cleanly.
- Step 10 (T-Display pass) still owed before CP5.

**Findings:** (a) #67 — a dependant persona whose registry chunk write
failed at derive time was served all session then evaporated at reboot
(the derive had answered success); the free-entry count looked healthy, so
suspect blob-page pressure on this board's legacy 24K NVS. (b) Fixed on
main same day: a persona persisted by the management path's retry hook
(park completion) never joined the live `#p` filters until reboot — the
NP oracle was unreachable mid-session because of it. (c) Creating an 11th
connection slot failed cleanly at NVS persist ("could not persist client
creation; request was not applied") with a held rollback — the practical
slot ceiling on the legacy table sits below MAX_CONNECT_SLOTS. Cleanup:
bench slots revoked (NVS 548/756 used, better than found);
`natural-person` deliberately left registered — C4 notices wrap to it, so
the guardian NP should stay addressable.

## 12. Non-blocking approval cards (#64; added 2026-08-16, not yet bench-run)

Firmware under test: the WiFi-standalone signer after #64 — an interactive
ask no longer blocks the relay loop. The card is held and serviced from the
loop, the hold is measured by the button sampler thread, and same-client asks
for the same identity collapse onto one card. Bench this on the desk V4 in
WiFi-standalone mode, vault unlocked.

**Most of this is machine-driven.** `scripts/bench-approval-cards.mjs` runs
steps 1, 2, 6, 8, 9, 10, 11, 14 and 16 over the operator channel with no
button presses at all — it mints a disposable TOFU slot, raises cards, probes
the cable and the relay while they are up, and revokes the slot afterwards:

```bash
node scripts/bench-approval-cards.mjs --master <npub>          # everything
node scripts/bench-approval-cards.mjs --master <npub> --only usb
```

Note it mints with legacy `create_client`, deliberately. Naming `sign_event`
in an operator-installed v2 exact policy IS the operator approving it, so a v2
slot answers "signing pre-approved by operator" and auto-signs — no card ever
appears, and every liveness probe would pass against a signer that never
stopped. The script asserts `signing_approved: false` at mint for that reason.

Only the button steps (3-5, 7, 12, 13) and the T-Display pass (15) need a
person at the desk. The individual tools are `scripts/nip46-client.mjs`,
`scripts/mgmt-request.mjs`, `scripts/fetch-events.mjs` and
`scripts/device-status.mjs` if a step needs driving by hand.

### Baseline before the fix — 2026-08-16, desk Heltec V4 on 0.17.0

Run against the pre-#64 firmware to prove the harness measures the right
thing. All three of the issue's bullets reproduced:

| Step | Result | Measured |
|------|--------|----------|
| 1 cable under a card | FAIL | 4 probes, worst 10090 ms (want < 6000) |
| 2 relay under a card | FAIL | 2 probes, neither answered within 12 s |
| 6 card expires | PASS | `timeout` after ~32 s — the control |
| 8 batch shares a card | FAIL | three same-kind asks answered **64 s apart** — a window each |
| 9 one expiry answers all | FAIL | three separate `timeout`s, not one decision |
| 10 second client waits | PASS | A answered, then B 32 s later — ordering already holds |
| 11 caps refuse | FAIL | 0 of 10 answered busy; all ten queued and ran a window each |
| 14 late reply stamp | FAIL | reply `created_at` 0 s after a request answered 32 s later |

Step 8's 64 s is issue #64's second bullet on hardware: two full serialised
windows for what the operator sees as one decision. Every FAIL above must
flip on the fixed firmware, with 6 and 10 staying green.

Step 11 is slow to run against pre-#64 firmware for the same reason — ten
queued asks take a window each, so the phase spends five minutes draining
before it can clean up. That is expected, not a hang.

### Bench note — run the machine-driven phases unattended

Part-way through the same session the desk V4 began answering button-required
requests ~5 s after each arrived, where earlier ones had sat out their full
window. The serial tap:

```
15:54:12.985 NIP-46 request: method=sign_event id=2bb067e3 master_slot=0
15:54:18.492 sign_event: approved
```

**It was the operator pressing the button.** They were at the desk and
approved each card as it appeared — the device was working exactly as
designed. The first reading of this log was that GPIO 0 must be stuck low,
because `sign_event: approved` needs two continuous seconds of it and no
press, wake or carousel line appears nearby. That reasoning was wrong: a
person pressing the button produces the same log, and the absent lines only
mean the panel was already awake. The same mistake was made earlier in the
session over SET_OPERATOR ("timeouts NACK as denied"), and it has the same
root — inferring a fault from timing when the real variable is whether
somebody is standing there.

The lesson that survives is about the harness, not the hardware:

- **Run the machine-driven phases unattended.** Every one of them measures
  what the signer does with a card *nobody answers*. A helpful press turns a
  batch-collapse check green whatever the firmware does.
- On pre-#64 firmware a press is doubly misleading: the first approved
  `sign_event` upgrades the slot to signing (TOFU), so the rest of a burst
  auto-signs and lands together — which looks exactly like the batch collapse
  being tested. Only an unpressed run tells collapse from that upgrade.
- `bench-approval-cards.mjs` raises one card at the start and aborts if
  anything answers it, naming both possible causes. If that fires because you
  pressed, just let the next run alone.

The point of every step is that **the rest of the device keeps working while
the card is up** — that is the whole fix, and it cannot be seen from the card
itself.

1. **Cable stays live under a card.** Send a `sign_event` on a slot that needs
   the button. While the card is on screen, run `device-status.mjs` over USB:
   it must answer within a second or two. Before #64 it answered nothing until
   the card resolved.
2. **Relay stays live under a card.** With the card still up, watch the relay
   with `fetch-events.mjs --live`: the signer must keep answering other
   traffic (a `get_public_key` from a second, auto-approved client returns
   while the card waits).
3. **Approve.** Hold the button 2 s. Card shows the fill bar, then APPROVED,
   then the SIGNED confirmation card; the response publishes and the event
   verifies on the relay.
4. **Deny by early release.** New ask, press and release inside 2 s: answers
   `user denied` promptly.
5. **Deny by B (two-button boards).** New ask, press B: answers `user denied`.
6. **Expiry.** New ask, touch nothing for 30 s: the terminal "request expired"
   card appears and the client gets `timeout`.
7. **Fast hold between passes.** Press and hold for ~2.5 s in one motion,
   releasing quickly. The relay loop only samples once a second, so this is
   the case the sampler thread exists for: it must approve, not be missed.
8. **Batch collapse.** Fire 3 `sign_event`s of the **same kind** back to back
   from one client on a slot that needs the button. One card appears, showing
   the count (`app x3`) and that kind; one hold answers all three, and three
   signed responses publish. Then repeat with **mixed kinds**: those must NOT
   collapse — each kind gets its own card, because the card can only name one.
9. **Batch fast-deny.** Repeat step 8 and deny once: all three answer
   `user denied` — not three separate windows.
10. **Second client queues.** With a card up from client A, have client B ask.
    B waits; when A's card resolves, B's card appears with a full window.
11. **Busy refusal.** Push past the caps (9+ asks from one client, or more
    than 4 other clients waiting): the extra asks answer "signer is busy with
    another approval; retry shortly" rather than the device growing RAM.
12. **Press during a card is not a carousel page.** With a card up, a short
    press must not page the idle carousel — it belongs to the decision (and,
    being under 2 s, denies).
13. **Card wins the screen.** With a SIGNED confirmation card still held from
    an earlier sign, a new ask must take the screen immediately.
14. **Reply timestamps.** After a 25-second-held approval, check the response
    event's `created_at` on the relay: it must be within a second or two of
    when the button was pressed, not of when the request arrived.
15. **T-Display pass** of steps 3-7 before CP5 (B-button path is board-specific).

16. **USB signing does not steal the screen.** With a relay card up, send a
    NIP-46 sign request over the cable: it must be refused with
    `approval on screen` rather than painting over the card. The card then
    resolves normally, and the same USB request succeeds once it is gone.

Regression watch, all still on the USB-bridged tier, which deliberately keeps
the blocking loop (the host is waiting on the reply frame): a USB `sign_event`
approval, a `SET_NET_CONFIG` confirmation and a factory-reset confirmation must
behave exactly as before.

## 13. Bearer-note locker (added 2026-08-18; relay-path half bench-run same day)

**Bench record — 2026-08-18, Heltec V4 (16 MB, bench unit), firmware
0.17.0+note-locker (main + IDLE0-yield fix), app-only flash into the new
`partitions-v4-16mb-legacy-nvs-bigapp.csv` layout (4 MB single app slot —
the release app outgrew the 2 MB OTA slot, see that CSV's header; table +
otadata-erase + app written 0x8000/0x414000/0x10000, all live NVS/config
preserved, verified by masters and pairings surviving).**

Bench-found bug, fixed and verified in-session: the nk mint's PBKDF2 runs
starved the IDLE0 task watchdog (two task-wdt reboots, backtrace into
`seed_cipher::derive_km ← sync_sealed`); `wdt::feed` alone was insufficient
— the fix yields (`FreeRtos::delay_ms(20)`) beside every KDF feed in
`notes::sync_sealed` and `pin.rs`'s per-slot loop. After the fix: unlock →
`[notes] sealed state in sync` → relay subscribed, no watchdog. The nk blob
persisted (NVS 550 → 555 entries). Neither crash tore any state — verify-
before-write held both times. Also observed (pre-existing, not ours):
"Persona chunk 0 short (1 of 2 entries)" on this board's registry.

- [x] Item 13 PASS: 0x70 in wifi mode → NACK `use heartwood_note_* over
      the relay` (exact string).
- [x] Item 14 PASS (notes-held half): SET_PIN → NACK `at-rest changes need
      USB mode while notes are held`, no card, no state change. No-notes
      half not run.
- [x] Item 15 PASS: bound client (fresh legacy slot) round-tripped
      heartwood_note_new (701 ms, hash-only), _confirm, _list (one
      CONFIRMED note, no secrets in any response), _export; an unbound
      fresh client got `unauthorised` for _list. Not exercised: _import,
      _new_pair, _spent, _discard.
- [x] Item 16 PASS, both halves: unattended export card timed out (~30 s)
      with `timeout` and the note untouched — twice; a measured ~5 s hold
      released `k1` — twice (serial log: card raised, "dispatching on a
      hold already completed"). EXTRA, worth keeping: the approve-once
      transient window from a completed export hold did NOT silently
      release a repeat export — the next ask raised its own card. The
      CRITICAL auto-approve-slot variant is NOT yet run (needs an
      operator-installed exact policy naming the method).
- [x] Item 17 PASS: two parallel exports collapsed onto one card ("joins
      the open approval card (2 asks)" in the log); a single hold answered
      both; an unanswered collapsed pair timed out as one card.
- Item 7 PARTIAL: nk minted, wrapped, verified and persisted on real
  flash; the note created after key-set is sealed-on-write, but the
  flash-dump HWNS/no-plaintext check is not yet run.
- Item 8 second half PASS (incidental, same evening): after a reflash +
  power cycle the sealed note survived, the unlock unwrapped the nk and
  `[notes] sealed state in sync (1 note(s) under the note key)` reported
  it; heartwood_note_list over the relay then returned it intact. Locked
  get_info / NACK-"locked" checks still not run.
- Size diet verified on this board same evening: common cert bundle +
  no-SoftAP + no-IPv6 (sdkconfig.defaults) took the release app from
  2,105 KB to 1,990 KB — back inside the 2 MB OTA slot with ~107 KB
  headroom. "Certificate validated" + TLS + subscribe + a relay note_list
  all confirmed on the trimmed bundle against relay.trotters.cc.
- Items 1–6, 8–12 and the no-notes half of 14: NOT YET BENCH-RUN (USB-mode
  items need the board switched to usb mode; sealing round-trip items need
  a reboot/unlock cycle with notes held).

Firmware under test: the note locker — LUD-25 bearer-note custody over the
`FRAME_TYPE_NOTE_CMD` (0x70) USB frame, lnurl-vault JSON command set, notes
sealed at rest under a note key wrapped by the same PIN/vault secret as the
seeds. Design and decisions: docs/plans/2026-08-18-note-locker-goal.md.
Drive every step with `scripts/note-cmd.mjs` (node-serialport, no
reset-on-open); gated commands wait on a 30 s approval card.

All items NOT YET BENCH-RUN.

USB tier, unlocked, no at-rest:

1. `get_info` answers version/board/storage/counts; `new_secret` then
   `confirm` then `list_notes` shows one CONFIRMED note. NOT YET BENCH-RUN.
1a. Cable identity, including while PIN-locked: send
    `{"cmd":"identify","nonce":"0123456789abcdef0123456789abcdef"}` and
    verify the returned 64-hex-character `pubkey` and 128-hex-character `sig`
    over `lnurlvault-id-v1 || 0x00 || nonce`. A fresh nonce must yield a
    verifiable proof from the same pubkey; a different test board must have a
    different pubkey. After a full factory/PIN wipe and reprovisioning, the
    old pubkey must no longer verify a new proof. Do this only on a
    non-production USB board: it is a trust-on-first-use board identity, not a
    Nostr identity, note key, or firmware-signing key. NOT YET BENCH-RUN.
1b. `{"cmd":"get_info","tag":"a1"}` comes back carrying `"tag":"a1"`, and the
   same `get_info` with no tag comes back with no `tag` field at all. Then
   `{"cmd":"get_info","tag":""}` is refused `bad_request` and that refusal
   carries no tag. The point of the check on real hardware rather than in the
   native suite: the tag has to survive the framing, which is where a lost or
   torn reply happens in the first place. **PASSED 2026-09-06** (Heltec V4,
   USB mode): `bench-zulu` echoed verbatim; no tag leaves the reply with no
   `tag` field; empty and 33-byte tags both refused `bad_request` with no tag
   on the refusal; and the tag is echoed on error replies too (a card that
   timed out came back carrying its tag). The straggler case turned up for
   real in passing: a client with no tag filtering picked up the previous
   request's late reply, which is precisely what the field prevents.

1d. Idle locker summary: on a non-production board, short-press through the
   four idle pages in both USB and WiFi-standalone modes. The fourth page is
   `NOTES`, with only `held`, `received` and `pending` counts plus `4/4`.
   Create one test secret and confirm it: before confirmation the card must
   agree with `get_info` that one note is held and one is pending; afterwards
   it must show one held and zero pending. Receive one disposable test wrap
   and confirm that `received` advances. The card must show no amount, mint,
   sender, note id or secret, and a sealed-at-rest record must remain included
   in `held` before unlock. NOT YET BENCH-RUN.

1c. LUD-25 seed-recoverable note secrets, end to end. **PASSED 2026-09-06**
   (Heltec V4, USB mode, after the `Storage` delegation fix in #109 — before
   it, `provision_cash_node` failed `storage_full` on a board with 156 free
   NVS entries, because the write never reached NVS at all):
   `provision_cash_node` with `lnurlcash-conformance` 0.7.0's own domain node
   for `mint.example` raised a held-button card and persisted;
   `new_secret --host mint.example` derived index 0 to
   `h=7db9da2845cd45c1c3c2e302d6135da46823e245f756b830ef59ac324b769e02`,
   byte-identical to that vector's published value, from 64 bytes the device
   treats as opaque; the counter advanced 0 to 1 and survived a reboot; and a
   refusal raised before an index is taken (`admit_creation`, locker at
   `MAX_NOTES`) burnt no index.

   Index 1 followed on the same board once `MAX_SPENT` and the mint-path
   eviction landed: `h=99b98cb845940e0d6401e176aaca1446365aa315201803861e17f3c530ed1dcf`,
   again byte-identical to the published vector, with the ladder at
   `next_index: 2`. The mint that produced it is itself the proof of the
   eviction fix — the locker was at `MAX_NOTES` and the same call had returned
   `storage_full` minutes earlier.
2. `export_secret` raises a card headed `RELEASE NOTE` whose title is the
   money — `<amount> @ <host>`, the action having moved into the header so
   both title lines are available to the amount and the mint — hold
   approves and returns 64-hex `k1`; short press denies (`user_declined`);
   unattended card times out (`timeout`) with the note untouched. NOT YET
   BENCH-RUN.
2b. Amount rendering, on the panel, against dni's rules
    (`common/src/note_fmt.rs`, mirroring lnurl-vault's
    `src/proto/note_display.h`). Confirm a note at each of these and read
    the RELEASE card: 1 000 msat shows `1 sat` (singular), 21 000 shows
    `21 sats`, 2 100 000 shows `2 100 sats` (grouped, so it cannot be
    misread as 21 000), 999 shows `999 msat` and NOT `0 sats`, 1 999 shows
    `1 999 msat`. Then confirm one against a long host
    (`mint.forgesworn.example.com/u/alice/w`): the amount must be complete
    and unclipped; the host shortened out of the MIDDLE with a leading `..`
    so that both the registrable domain with its TLD and the whole withdraw
    path survive (PR #77 — two tenants of one mint must never draw the same
    card); and on the 128 px Heltec the amount and the host must fall on
    separate lines rather than one centred line running off both edges.
    Confirm a second note at `.../u/bob/w` and check the two cards differ.
    NOT YET BENCH-RUN.
3. Destructive gating: `mark_spent` / `discard` / `rename` / `delete` each
   raise a card; wrong-state commands answer `invalid_state` with NO card
   (watch the OLED; the serial answer alone does not prove it). Run the
   `mark_spent` here on a note this session has NOT just exported, or it
   rides that export's hold and shows no card by design (#129, section 17).
   NOT YET BENCH-RUN.
4. Full spend shape: `import_secret` (mint preimage) → `new_secret` rotate →
   confirm → mark_spent → `new_secret_pair` split → confirm both →
   mark_spent → delete housekeeping; counts and states correct throughout.
   NOT YET BENCH-RUN.
5. Cap refusal at 16 notes (`storage_full`), and a re-import of a held
   secret returning the existing id with nothing restated. NOT YET
   BENCH-RUN.
6. Backup exclusion: BACKUP_EXPORT with notes held, restore onto the same
   board after a wipe — pairings return, notes do NOT, and nothing in the
   backup file contains a note secret. NOT YET BENCH-RUN.

Sealing (enable at-rest with notes held):

7. SET_PIN (or VAULT_SET) with notes held seals them: power-cycle, dump the
   `hw_notes` namespace — every note blob starts `HWNS`, an `nk` blob
   exists, no plaintext `HWNB` remains. NOT YET BENCH-RUN.
8. Locked boot: `get_info` answers with `note_count` including sealed notes;
   every other note command NACKs with reason `locked`. After PIN_UNLOCK /
   VAULT_UNLOCK (expect one extra PBKDF2 run in the unlock time), the same
   notes list and export correctly — the seal round-tripped real money.
   NOT YET BENCH-RUN.
9. PIN change with sealed notes: notes remain readable after unlock with the
   NEW pin (the note key was re-wrapped, not regenerated). NOT YET
   BENCH-RUN.
10. Disable at-rest: notes return to plaintext `HWNB`, `nk` removed,
    everything still spends. NOT YET BENCH-RUN.
11. Torn-enable self-heal: cut power between the seed-seal and note-seal
    passes (or flash a state with sealed seeds + plaintext notes + no
    `nk`); the next unlock seals the stragglers without losing any. NOT
    YET BENCH-RUN.
12. Power-cut during a split (between `new_secret_pair` and `confirm`):
    reboot, unlock — the PENDING pair is still there, never auto-discarded,
    and the wallet-side confirm/discard converges. NOT YET BENCH-RUN.

WiFi-standalone tier:

13. Every 0x70 frame NACKs with reason `use heartwood_note_* over the
    relay` (the frame surface is USB-mode; the locker itself is served as
    NIP-46 extensions there — items 15–17). NOT YET BENCH-RUN.
14. With notes held, SET_PIN and VAULT_SET over the cable NACK with reason
    `at-rest changes need USB mode while notes are held`; with no notes
    they behave as before. NOT YET BENCH-RUN.

Relay path (`heartwood_note_*`, advertised as `note_locker_v1` in
get_status and in heartwood_capabilities; drive with the
scripts/nip46-client.mjs conventions):

15. From a bound slot: `heartwood_note_list` / `_new` / `_confirm` /
    `_import` round-trip over the relay with no button; an unbound client
    gets `unauthorised` for every note method. NOT YET BENCH-RUN.
16. `heartwood_note_export` raises a card and waits (deferred — the relay
    loop stays live underneath, same as a #64 sign ask); hold approves and
    the result carries `k1`; deny and timeout answer as errors. CRITICAL:
    repeat on a slot whose policy names the method with auto-approve — the
    card MUST still appear (pinned always-ask; a silent export here is a
    security regression, stop and file). NOT YET BENCH-RUN.
17. Same-method batch collapse: several `heartwood_note_export` asks from
    the same client collapse onto one card whose single hold answers the
    batch; a concurrent `sign_event` ask gets its OWN card — one hold must
    never cover both a signature and a disclosure. BENCH-RUN 2026-08-21
    (web wallet collecting three notes) and it exposed a lie: the card
    read `RELEASE NOTE / 12 sats` while the hold released three notes
    worth 1,110 sats. Now: a batched note card reads `RELEASE 3 NOTES /
    1 110 sats @ <host>` (or `@ 2 mints`), the count and total re-drawn as
    each ask joins, and a join DISARMS the card so a press already under
    way is discarded and the operator presses again on the card that names
    the batch. Sends to different recipients never share a card. Verify:
    collect three notes from the web wallet; the card must name `3 NOTES`
    and the sum before you hold, then `SPEND 3 NOTES` the same way. The
    firmware logs the wording each join produced, but since #113 that log
    reaches only a console build, so on a standard build this needs eyes on
    the panel. Seen on the v4 board 2026-08-21
    21:27 UTC, and the hold that followed answered both asks:
    `joins the open approval card (2 asks); card reads 'RELEASE 2 NOTES'
    / '24 sats @ mint.forgesworn.dev/w'`.

Regression watch: a USB `sign_event` approval and a factory reset must behave
exactly as before; FIRMWARE_INFO's nvs entry stats now include the
`hw_notes` namespace's usage.

### Locker capacity, measured 2026-09-06

The bench V4 sits AT `MAX_NOTES` (16). Fifteen of those slots held SPENT
records — `mint.forgesworn.dev` (sunset 27 Aug) and `moneyer.dev` — against a
single live CONFIRMED note of 994,000 msat. `admit_creation` then refuses every
new mint with `storage_full`, which is correct behaviour but means the device
had been one note away from refusing all along, in ordinary use, with nothing
saying so.

This was issue #96 (spent records prunable only over a cable, and not at all in
WiFi mode) biting in practice rather than in principle. Freeing a slot cost one
held-button `delete` card per record, which is a poor answer for fifteen of them.

**Addressed the same day.** `MAX_SPENT` caps spent records at the spend
transition, and `evict_spent_for_room` now runs on the mint paths as well as
`receive` — the asymmetry was that a full locker accepted a note someone sent
it and refused to mint one of its own. Verified on this board: a mint that had
returned `storage_full` succeeded, `note_count` held at `MAX_NOTES`, and a
spent record gave way. The backlog drains one slot per mint rather than all at
once, which is deliberate: nothing removes a record the owner has not caused a
state change to.

**One path was missed, fixed 2026-09-12 (NOT YET BENCH-RUN).** `import_secret`
was the last creation path without the eviction, and it is the ordinary one:
the browser wallet pays the mint and hands the preimage over with
`heartwood_note_import`. So a locker that would happily mint still refused the
note the owner had just paid for. Verify on the board:

1. Get the locker to `MAX_NOTES` with at least one SPENT record in it. Four
   is the most it will hold now, so mint, `confirm` and `heartwood_note_spent`
   four notes, then fill the rest with live ones.
2. Note the id and `updated_at` of the oldest spent record from
   `heartwood_note_list`.
3. Pay a small note at the mint from the web wallet and let it import. The
   import must SUCCEED, not answer `storage_full`.
4. `heartwood_note_list` again: `note_count` still `MAX_NOTES`, the new note
   present, and the record from step 2 gone. No CONFIRMED or PENDING note may
   have moved.
5. Replay the same import (the wallet re-sending it, or `note-cmd.mjs` run
   twice). It must return the SAME id, `created: false`, and `note_count`
   must not drop: the dedupe sits ahead of the eviction, so a replay never
   costs a record.
6. With sixteen LIVE notes and no spent record, an import must still be
   refused `storage_full`. Nothing here may evict money.

## 14. Bearer notes over Nostr (added 2026-08-21; NOT YET BENCH-RUN)

`note_wrap_v1` in get_status. A kind-1059 gift wrap addressed to a master
npub, carrying a kind-2525 rumor whose content is a LUD-25 note URL
(`common/src/note_wrap.rs`), puts a RECEIVE card up; `heartwood_note_send`
seals one of the locker's own notes to a recipient on-device and hands the
client an opaque wrap to relay. Drive the receive half with
`scripts/send-note-wrap.mjs` (or notecase `send <sats> --to <device npub>`);
the send half with `scripts/nip46-client.mjs --method heartwood_note_send
--params '[{"id":"<note id>","to":"<64hex>"}]'` from a bound slot, or
notecase `heartwood send`.

1. Wrap a test-mint note to the device's master npub while it sits on the
   relays with no host attached. Expect: panel wakes, amber card headed
   RECEIVE NOTE, first line `<amount> @ <host>`, second `from
   <npub8>..<npub8>`; no NIP-46 response is published to anyone. Hold:
   green "<amount> received / wallet collects it", back to idle after ~3 s;
   `heartwood_note_list` shows the note CONFIRMED with `from` set and
   `get_info.received_count` 1. Tap (B) or let it expire: nothing stored,
   count unchanged.
2. Replay: publish the SAME wrap again (relay replay, or two sessions).
   Expect no second card (`wrap_seen`). After a reboot it must NOT come
   back either: the hold went to the persisted ledger (`wrap_ledger`), and
   the connect-time catch-up REQ skips it before any decrypt. Same for a
   wrap the owner declined with (B). A wrap that merely lapsed DOES come
   back: at the next connect, and ten minutes after each lapse while the
   device stays up, until it is held or declined.
2a. Catch-up: power the device OFF, wrap a note to its master npub, wait
   for the relay to confirm, power ON. Expect the RECEIVE card within a few
   seconds of `subscribed on`, with no sender action. Then: with ONE held
   decision in the ledger, wrap a note, power-cycle, and confirm the REQ on
   the wire carries `"since":<mark - 172800>,"limit":16` and the card still
   comes up; with an empty ledger the REQ carries `"limit":16` and no
   `since`. The keepalive re-REQ 40 s later must be back to `"limit":0`.
3. Not for us: a wrap to a persona pubkey, a kind-14 DM whose text has no
   note (or two), a wrap whose rumor claims a different author than the
   seal signer, and a rumor whose URL has no amount. Expect: silent drop —
   no card, no wake, and nothing new in `heartwood_note_list`. (A console build
   also logs one `[relay] gift wrap ... not for us / is not a note` line.)
2b. Trusted sender: `notecase heartwood trust <mint npub>` puts up a
   TRUST SENDER card (npub, both ends visible); hold. `heartwood trusted`
   lists it; it survives a reboot. A wrap sealed by that key now stores
   on arrival with NO card: a three-second "N sats received / from
   <host>" toast, and
   the ledger has it — `heartwood_note_list` shows it (reboot: no re-offer). A
   console build also logs `note ... received from trusted sender`. A wrap from anyone else still
   gets the card. A trusted sender is not bound by the 4-note letterbox,
   only by the locker's 16, and a spent record is not a note: with the
   locker full of spent notes, the next received note evicts the oldest
   spent one (seen live: sixteen collected zaps filled it and every zap
   after was deferred). With four received notes held, a fifth from
   the trusted mint stores; a fifth from a stranger is deferred (`dropped
   until there is room`), never silently lost, and arrives by itself once
   a collect frees a slot (seen on the bench: two deferred zaps landed
   380 ms apart the moment the collect finished). `heartwood untrust` needs no hold and the next wrap from
   that key gets a card again.
2c. Pair from a wallet: from a bound wallet (`notecase heartwood pair
   phone`, or the web wallet's Settings → Hardware signer → Pair another
   device). Expect a PAIR NEW WALLET card ("for 'phone' / it will see your
   notes"); hold. The response is a bunker URI whose relays match
   GET_NET_CONFIG and whose secret is fresh; a second wallet links with it
   and `heartwood notes` works there. An unbound client, or a USB NIP-46
   session with no client, gets `unauthorised`: there is still no way onto
   the device without a binding or the cable.
3a. From a stranger's client: on a phone running any NIP-17 client
   (0xchat, Amethyst), resolve the device's NIP-05, and DM it a note as
   plain text, once as `lnurlw://...`, once as bech32 `LNURL1...`, once
   with a `lightning:` prefix, once wrapped in a sentence. Expect the same
   RECEIVE card each time, with the sender's npub on it. A DM carrying two
   notes is dropped (`more than one note in the message`).
4. Letterbox cap: with MAX_RECEIVED (4) received notes held, a fifth wrap
   raises no card and `heartwood_note_list` still shows four received notes. (A
   console build also logs `letterbox full; dropped until there is room`.)
   Mark one spent over the relay: WITHOUT sending again, the catch-up
   re-runs and the fifth wrap's card comes up on its own. Also: two wraps
   in quick succession raise ONE card (`a note is already waiting on the
   button; wrap deferred`); settle it, and the second's card follows
   without anyone resending. A `sign_event` ask arriving behind a RECEIVE
   card still queues and gets its own card after it.
5. Collect: from notecase, `heartwood link <bunker>` then `heartwood
   collect`. Expect RELEASE NOTE card (amount @ host), hold; notecase
   claims it at the mint (the wrapped secret is now burned); SPEND NOTE
   card, hold; `heartwood_note_list` shows it SPENT.
6. Send: `heartwood_note_send` on a CONFIRMED note of the device's own.
   Expect SEND NOTE card, `<amount> @ <host>` / `to <hex8>..<hex8>`; hold
   returns `{"ok":true,"event":{...kind 1059...}}` and NO `k1` anywhere in
   the response; the note lists as CONFIRMED with `sent_to`. Repeat on the
   same note: `invalid_state` with no card. `heartwood_note_export` on it
   still raises a card (unsend path). A received note (`from` set) answers
   `invalid_state` to send with no card.
7. The wrap from 6, published to the recipient's inbox relays, opens in
   notecase (`inbox`) and on a second heartwood (RECEIVE card) — the same
   bytes, both ends.
8. Over USB, `{"cmd":"send",...}` on the 0x70 frame answers `bad_request`
   "send is not available on this surface" without a card.
9. Regression: a `sign_event` card, a non-note extension card and a C4 park
   all behave exactly as in §12; the REQ now carries a fourth filter and the
   40 s re-REQ still lands (watch for the kind-0 profile refresh).

## 15. Notes paid to the device's own keys (LUD-25 Part 2; added 2026-09-11, items 1, 2, 3 and 6's scan bench-run the same day)

Bench record, 2026-09-11, Heltec V4 (e8:f6:0a:c9:e7:b4), app-only flash of this
branch's release build, unlocked over WiFi, on real sats at moneyer.dev:
two operator names owned by the master npub pointed at its keys (one
kind-27235 hold each; the mint echoed the cx1, and both names share it). 21
sats to the first was minted to key 0 and stored with no card as `(its own
key #0)` from the trusted mint key. `heartwood address scan` found key 0 live and already held.
`heartwood collect <id>` released a ck1 on one hold, the mint burned the note
(`notes.state = burned`), SPEND NOTE on a second hold. Seen on the way: a
spent record stamped just after a reboot sorted as the OLDEST (the clock is
seconds since boot) and was the first trimmed; the store's stamps now never
go backwards (`NoteStore::stamp`).

`heartwood_note_address` and `heartwood_note_claim` in `heartwood_capabilities`.
A lightning address whose owner is a master npub can be paid to keys the
device derives from that identity key (`common/src/cash_key.rs`): seed =
HMAC-SHA256(identity key, `LNURLcash/nostr-seed`), then lnurl-wallet's
`m/139'/1'/d1..d4` for the mint. The mint holds only the watch-only `cx1`,
mints each payment to the next key, and wraps `https://<mint>/w?p=<cp1>&
amount=&sig=<cs1>&i=<index>`: no secret on any relay. Drive it with notecase
from a bound slot and a mint that pays names to keys (moneyer >= 0.13.1).

1. `notecase heartwood address keys <name> --mint <host>`, for a name the
   master npub owns. Expect NO card for the address (it spends nothing), then
   a HOLD TO SIGN card for kind 27235 (the NIP-98 request); hold within a
   minute. The mint now pays the name to that `cx1` (moneyer: the
   `zap_names.cx1` column), and a second `heartwood_note_address` for the same
   host returns the same `cx1` (deterministic).
2. Pay the name a few sats (a zap or `<name>@<host>` from any wallet). With
   the mint's zap key trusted: a "N sats received / from <host>" toast, no
   card, `note ... received from trusted sender (new: true, paid to a key)` in
   the log. Untrusted: the RECEIVE card as in 14.1. `heartwood notes` lists it
   CONFIRMED with `(its own key #0)`; the list JSON carries `p` (the `cp1` the
   wrap named) and `index` 0, and the note's `sig` is a `cs1`.
3. `heartwood collect`: RELEASE NOTE card, hold; the k1 notecase receives is a
   `ck1` (starts `ck1`), never 64 hex, and the mint accepts it; SPEND NOTE
   card, hold; the note lists SPENT. The mint's `/stats` outstanding count is
   unchanged by the collect (one note burned, one minted to notecase).
4. Replay and reboot: the same wrap again raises nothing, and after a reboot
   the note is still listed with its `p` and `index` (a v3 blob; a plain note
   written before this is still v2 and still reads).
5. Not ours: a wrap whose `p` is some other key (edit the index, or wrap a
   note paid to another npub's branch) raises no card, does not appear in
   `heartwood_note_list`, and is not offered again. (A console build also logs
   `is not a note: that note is paid to a key this device does not hold`.)
6. Lost wrap: pay the name while the device is powered off, then delete the
   wrap from the relays (or pay a second name pointed at the same `cx1` with
   no relay reachable). `heartwood address scan --mint <host>` reports the
   device kept it at key #N; no card (a claim discloses nothing). A second
   scan keeps nothing twice. `heartwood_note_claim` with a `p` the device
   would not derive answers `bad_request`.
7. `heartwood_note_send` on a key note answers `invalid_state` with no card:
   its secret is a key, not a k1, and a wallet rotates it first.
8. Over USB, `cash_address` and `claim_key_note` on the 0x70 frame answer
   `bad_request` ("not available on this surface"): there is no identity on
   the cable.
9. `heartwood address custodial <name>`: one HOLD TO SIGN card; the next
   payment arrives as a plain note sealed to the npub, as in 14.

## 16. A second configured relay (#92; added 2026-09-11, items 1-3 bench-run)

Bench record, 2026-09-11, Heltec V4 (e8:f6:0a:c9:e7:b4), app-only flash of this
branch's release build: online on relay 0 with `secondary_index` 1 within 40 s
of the WiFi unlock; heap with both sessions free 188,024 B, largest block
92,160 B (one session: 209,480 B and 143,360 B), so a second TLS session costs
about 21 KB. A `ping` sent to ONE relay at a time from an unbound client was
answered on relay 0 and relay 1 and not on relay 3, and the note locker
listed intact over the relay. Items 4 (pairing) and 5 (T-Display) not yet run.

Failover bench record, 2026-09-12, same board, firmware v0.18.0-beta.4. A
relay the bench could kill was needed, so a throwaway in-memory relay was put
behind TLS at `wss://relaybench.forgesworn.dev` and patched in as relay 0 with
`scripts/net-relays.mjs`; the other three were left alone. After the reboot
and unlock the device was `stage=online`, `relay_index` 0, `secondary_index`
1. Killing the relay PROCESS (so the live socket closed, rather than a relay
that merely cannot be dialled) promoted the secondary: at the next reading
`relay_index` was 1 with a new `secondary_index` 2, `stage` never left
`online`, and `heartwood_note_list` over the relay answered immediately
after, so the signer was serving on the promoted session. The relay list was
patched back afterwards and the device came up on its usual relays.

Two honest limits on that record: the cable was polled every few seconds, so
"promoted at once" is bounded by a 15 s reading rather than measured, and the
"about 3 s later" figure for the replacement secondary was not timed. A
tighter run wants the device's own log, not `net-config` polling.

The signer used to serve one configured relay at a time, so a relay that
silently stopped delivering hid every wrap and request sent there, while
clients and senders publish to all of them. It now keeps a SECOND configured
relay live when the slot is free and the heap can spare it (at least 120 KB
free and a 48 KB block; shed below a 32 KB block). A pinned relay (a client's,
from pairing) always takes precedence. `scripts/net-config.mjs` reports
`runtime.secondary_index` next to `relay_index`.

1. Boot and unlock with four configured relays. About 15 s after the primary
   comes up, `net-config` shows `secondary_index` set to another relay, and
   the heap log reads `2 session(s)` with free heap still well above 120 KB.
2. Deafness: from a client, publish a NIP-46 request ONLY to the secondary's
   relay (a one-relay bunker URI for it). The signer answers. Then only to the
   primary's. It answers. The same request published to both is answered
   once (dedupe), and a wrap published to both raises one card or toast.
3. Failover (bench-run 2026-09-12, see the record above; a relay you can stop
   the process of beats blocking at the router, and beats a WAF rule, which
   does not close a WebSocket that is already open): make the primary's relay
   unreachable (block it at the router,
   or pick a relay you can take down). The secondary is promoted at once:
   `relay_index` becomes the old `secondary_index` with no offline gap, and a
   new secondary is dialled on the next relay about 3 s later.
4. Pairing: with a secondary live, pair a client whose relay is none of the
   configured four (`nostrconnect://` with its own relay). The pairing
   succeeds; the secondary gives up its slot to the pin, and `secondary_index`
   is null while the pin holds it. Revoke the client: the secondary returns.
5. Heap pressure: on the T-Display (no PSRAM), confirm no secondary is ever
   dialled (`secondary_index` stays null) and nothing else regresses.

## 17. One hold per collect (#129; added 2026-09-11, NOT YET BENCH-RUN)

A collect is `heartwood_note_export` then `heartwood_note_spent`, and both are
pinned ButtonRequired, so the owner held the button twice for one note. The
second hold bought nothing: the mint has already burned the note by the time
it runs, and the card guarded only against a paired client lying "that one is
spent". An approved export now leaves a single-use grant in RAM, and the spend
mark for THAT note, from THAT client, within two minutes, runs with no card.

Drive it with notecase from a bound slot (`heartwood collect <id>`), or over
the cable with `scripts/note-cmd.mjs`. Nothing in the wallet changed: the
grant is entirely device-side.

1. One note, one hold: `heartwood collect <id>` on a CONFIRMED note. Expect
   exactly ONE card (RELEASE NOTE), one hold, and the note listed SPENT
   afterwards with NO SPEND NOTE card at any point. Watch the OLED, not only
   the CLI: the serial answer alone does not prove a card was skipped.
2. Reboot in between: export a note (`heartwood_note_export`, hold), RESET the
   board, let it come back up and unlock, then `heartwood_note_spent` the same
   note. The SPEND NOTE card is back and the hold is required: grants live in
   RAM only and never in NVS.
3. Never exported: `heartwood_note_spent` on a CONFIRMED note this boot has
   not exported. SPEND NOTE card, as before.
4. Expiry: export a note, hold, then wait more than two minutes before the
   spend mark. The card is back.
5. Another client: pair a second wallet, export from wallet A (hold), then
   spend-mark the same note from wallet B. The card is back. (Wallet A's grant
   is untouched by B's attempt.)
6. Never widens: with a note just exported and its grant live,
   `heartwood_note_send` for that same note still raises a SEND NOTE card, and
   so does a rename of it (`heartwood_note_rename` over the relay, `rename`
   over the cable): RENAME NOTE, every time. (`discard` and `delete` need a
   PENDING and a SPENT note respectively, so they cannot share an export's
   grant at all; neither is ever covered by one.)
7. Batch: `heartwood collect` with several notes held (up to eight, which is
   `approval_queue::MAX_BATCH` and already the cap on one card). Expect ONE
   hold for the release of all of them and NO second card for the write-offs,
   where it used to be two holds. The grant table holds exactly one card's
   worth, so it is never the binding limit; a ninth ask is refused `busy` at
   the release stage as it always was.

## 18. Renaming a note over the relay (#96; added 2026-09-12, NOT YET BENCH-RUN)

`rename` was cable-only, and a WiFi-standalone board NACKs the whole 0x70
surface, so on that tier a label typed wrong could not be corrected by any
route. `heartwood_note_rename` maps onto the same wire command the cable runs,
so this is checking the relay wrapper, not the rename.

Drive it with `notecase heartwood rename <id> <label>` from a bound slot, or
with the scripts/nip46-client.mjs conventions.

1. Rename a CONFIRMED note. Expect a RENAME NOTE card showing that note's
   amount and mint (the new label is deliberately not on the card: the device
   never draws a label, and the decision is that this note's label changes),
   one hold, `{"ok":true}`, and the new label in the next
   `heartwood_note_list`. Watch the OLED, not only the CLI.
2. Decline it, and let one time out. Both answer as errors and the label is
   unchanged in the next list.
3. A label the device refuses (33 bytes or more) must answer `bad_request`
   with NO card at any point. This is the one that matters: the validation
   runs before the prompt so a hold is never spent on a command that could
   never land.
4. Any state: repeat item 1 on a PENDING note (the card names it by id, since
   a pending note has no confirmed amount yet) and on a SPENT record. Both
   rename.
5. Pinned always-ask: repeat item 1 on a slot whose policy names
   `heartwood_note_rename` with auto-approve. The card MUST still appear.
6. Never on a grant: see section 17 item 6. A rename inside a live export
   grant still raises its own card, and the grant survives for the spend mark.
7. Unbound client: `heartwood_note_rename` from a client with no slot gets
   `unauthorised`, like every other note method.
8. USB tier unchanged: on a USB-bridged board, `node scripts/note-cmd.mjs
   --port ... '{"cmd":"rename","id":"...","label":"..."}'` behaves exactly as
   before, and a direct-USB NIP-46 `heartwood_note_rename` (no bound client)
   answers `unauthorised`: the relay methods serve bound clients, the cable
   has the frame.

## 19. An approved reply survives a reconnect (#82; added 2026-09-12, NOT YET BENCH-RUN)

This reproduces the §14 bench failure of 2026-08-21: the owner held the
button, the card resolved, the relay session went away, and the wallet was
told `heartwood_note_export` "did not answer in time" for a release the
device had already performed. An approved reply is now sealed to its client
and kept in RAM for up to 60 s, so the next session carries it.

Two boards are not needed; one bound wallet and a way to break the socket
are. Easiest reconnect trigger with no second machine: `scripts/patch-relay-list.mjs`
to point the device at a relay that is not there, or pull the AP, and let the
join loop come back. `scripts/nip46-client.mjs` drives the calls.

1. **The original failure.** Ask for `heartwood_note_export` on a CONFIRMED
   note, hold the button, and force the reconnect within a second or two of
   the card resolving (drop the AP as the "approved" screen appears). Expect
   the reply to arrive once the device is back on a relay, inside the 60 s
   window, and the wallet to report the `ck1` rather than a timeout. On a
   standard build the wallet reporting the `ck1` after the reconnect is the
   evidence; a console build also logs `held for the next session` then
   `delivered on a later session`.
2. **Delivered once.** Same run: watch for exactly one reply event. A second
   flush pass must not republish it, and `heartwood_note_list` must show one
   note, still CONFIRMED (an export mutates nothing).
3. **No session at all.** Take the relays away entirely (bad relay list), then
   raise a card over the cable's paired client, or simply let a queued card
   resolve while the device is between sessions. The work now happens and the
   answer waits; before this change the card resolved, the OLED said
   approved, and nothing at all was dispatched.
4. **It expires.** Repeat item 1 but keep the device off the air for more
   than 60 s. The reply is dropped (a console build logs `expired undelivered`),
   the wallet times out, and the note is still CONFIRMED, so asking again works.
   Nothing must be published after the window.
5. **A reboot loses it.** Approve an export, force the reconnect, and RESET
   the board before it comes back. Nothing is published after boot and no
   `ck1` appears anywhere. This is the one that matters: a held export reply
   is spending authority and must never reach flash.
6. **Only its own client.** With two wallets bound, approve an export for
   wallet A and force the reconnect. Wallet B must see nothing: no event
   addressed to it, and nothing it can decrypt. (It could not read A's reply
   in any case; the ciphertext is sealed to A's conversation key.)
7. **Nothing held for a refusal.** Decline a card, and let another time out,
   each with the session breaking as it resolves. Both are errors and neither
   is retried on the next session; the log must show no `held for the next
   session` line.
8. **Revoked in between.** Approve an export, force the reconnect, and revoke
   that client's slot over the cable before the device reconnects. The held
   reply is dropped (`that client is no longer bound`), not delivered.
9. **The grant still lines up.** After a successful item 1, the wallet melts
   the `ck1` and calls `heartwood_note_spent` for that note. With the reply
   delivered inside the 60 s window there is still grant left (#129's window
   is 120 s from the approval), so the write-off takes no second card. Past
   that, the SPEND NOTE card is back, which is the safe direction.
10. **The secondary carries it.** With two relays live (§16), break only the
    primary as a card resolves. The reply should go straight out on the
    secondary with no hold at all. Watch it with `node scripts/fetch-events.mjs
    --live --relay <secondary> --filter '{"kinds":[24133]}'` (NIP-46 replies
    are ephemeral, so only a live subscription sees them): the reply lands as
    the card resolves, not after a reconnect. A console build also logs
    `would not take the reply` for the dead relay, and no `held` line.

## 20. The spend grant starts at the handover (#137; added 2026-09-12, NOT YET BENCH-RUN)

Section 17 pinned what the #129 grant may and may not cover. This pins *when*
it starts: the moment the reply carrying the `ck1` is handed to the caller,
not the moment the secret is generated. A released secret that never arrives
now grants nothing, so the following `heartwood_note_spent` raises its own
card the way it did before #129.

Same drivers as section 17 and section 19: notecase from a bound slot, or
`scripts/nip46-client.mjs`, with `scripts/patch-relay-list.mjs` or pulling the
AP to break the session.

1. **Unchanged in the normal case.** `heartwood collect <id>` on a healthy
   link. Still exactly ONE card, still SPENT afterwards with no SPEND NOTE
   card. Section 17 item 1 must still read exactly the same on the OLED.
2. **A lost reply grants nothing.** Export a note and force the reconnect so
   the reply is held (section 19 item 1), then, before the flush lands, send
   `heartwood_note_spent` for that note. Expect a SPEND NOTE card. This is the
   one this section exists for: before #137 that write-off ran silently.
3. **An expired reply grants nothing.** Export, force the reconnect, and keep
   the device off the air past the 60 s held-reply window. When it comes back,
   `heartwood_note_spent` for that note raises a card, and the note is still
   CONFIRMED and still exportable.
4. **A delivered held reply does grant.** Export, force a reconnect short
   enough that the flush lands (section 19 item 1), then mark spent within two
   minutes of the *delivery*. No card. Evidence on a standard build: the wallet
   reports the `ck1` after the reconnect, and only then is the spend mark sent
   (a console build also logs `delivered on a later session` first).
5. **The window runs from the handover.** Repeat item 4 but let the reply sit
   held for most of a minute before the flush. The write-off must still be
   free for a full two minutes after it arrives, not two minutes after the
   hold. Time it from the `delivered on a later session` line.
6. **A revoked client grants nothing.** Section 19 item 8: approve an export,
   force the reconnect, revoke that slot over the cable, let the device
   reconnect. Re-pair and confirm the note is still CONFIRMED, and that a
   spend mark for it raises a card.
7. **Cable unchanged.** On a USB-bridged board, `node scripts/note-cmd.mjs
   --port ... '{"cmd":"export_secret","id":"..."}'` then the matching
   `mark_spent`: one card for the export, none for the write-off, exactly as
   section 17 item 1 records it. The cable writes its frame synchronously, so
   nothing about its timing changed.
8. **Reboot still clears it.** Section 17 item 2 unchanged: export, hold,
   RESET, unlock, spend mark. The card is back.

## 21. The entropy game is playable (#141; added 2026-09-12, not bench-run)

The game asked for 64 presses inside a 90 s cap while spawning about one
obstacle every three seconds, so an owner who played as the intro tells them
to ("tap: jump the blocks") could never finish, and it felt endless. It also
blitted the whole 1 KiB buffer over 400 kHz I2C on every physics step, about
25 ms of a 33 ms frame, and the button is only polled between steps, so taps
landed late and short ones could be missed. Obstacles now spawn about every
0.8 s and the panel redraws at 15 fps while physics stays at 30.

1. Provision a board and take the game at the intro. Jumping only at
   obstacles, reach 64 presses well inside the 90 s cap, and time how long it
   actually takes.
2. Every tap registers: the counter rises on each press, including quick
   double taps 30 ms or more apart. Nothing is dropped mid-blit.
3. The world does not visibly stutter at the lower redraw rate, and a
   collision still flashes.
4. Hold to skip still aborts to hardware-only stacking, and the 30 s intro
   timeout still defaults to skip.
5. The seed the board then generates is still accepted, and the log still
   reports the press count it collected.

## 22. The RNG gate and the recovery-word labels (added 2026-09-12, NOT YET BENCH-RUN)

Two findings from a field report where a fresh key looked like a repeat of the
last one.

The boot RNG self-test compares this boot's draw against a hash stored in NVS
from the previous boot, but a factory reset erases that proof along with
everything else — and the boot straight after a reset is exactly the boot an
owner provisions on. A post-wipe boot now seeds the proof and stays
UNVERIFIED: signing continues, minting refuses until one more boot proves the
draw changed.

Separately, every ForgeSworn recovery sequence opens "edge obtain" because
magic and version fill the first two words entirely. Walking a fresh phrase
therefore starts identically to every phrase the board has ever shown, which
reads as a stuck RNG. The walk now names what each word is, after a one-off
screen that says so before the words start.

Build first (release ELFs, ready to flash):

```
bash scripts/build-firmware.sh v4 --release   # -> firmware/target/heartwood-v4.elf
bash scripts/build-firmware.sh v3 --release   # -> firmware/target/heartwood-v3.elf
```

1. **A wipe costs one power-cycle.** Factory reset a board. When it comes back,
   ask for a new identity over the cable. It must refuse with `Power-cycle
   once / then generate` on the screen and a NACK naming the same reason —
   NOT `RNG CHECK FAILED / refusing new keys`, which means a fault.
2. **The second boot clears it.** Power-cycle, then `node scripts/device-status.mjs
   --port ...` must show `"rng":"verified","rng_cause":"draw_moved"`. Generate.
   It proceeds. (Not the serial log: the console is compiled out on every board,
   so `RNG self-test passed` is never emitted where you can read it.)
3. **Signing never stopped.** Between items 1 and 2, an existing master still
   signs. The gate covers new key material only.
4. **A genuinely stuck RNG is still caught.** Run this FIRST, before trusting
   any key the board has made:

   ```
   node scripts/rng-check.mjs
   ```

   It reads `rng` and `rng_cause` from FIRMWARE_INFO, never writes DTR/RTS
   (so it cannot reset a signer), and prints a verdict. A boot that followed
   another boot is already a comparison, so usually no reset is needed; on the
   first boot after a flash or a wipe it asks for one RST press. Exit 0 = the
   draw moved. Exit 1 on `draw_repeated` or `constant_draw` means stop, and
   treat every key the board generated as reproducible. Exit 2 = no verdict;
   `proof_unreadable`/`proof_write_failed` are storage faults, not evidence
   against the RNG.

   A boot straight after a firmware change compares against a proof the OLD
   firmware stored. A boot-seeded PRNG can pass that comparison if the two
   versions consume randomness in a different order before the self-test, so
   treat it as provisional: press RST once more and confirm `draw_moved` again
   on the same version. (Done on the one-off legacy V4 on 2026-09-13: beta.5 ->
   beta.8 read `draw_moved`, then beta.8 -> beta.8 across an RST read
   `draw_moved` again.)

   Firmware up to 0.18.0-beta.7 cannot be checked at all: its only report was
   a log line, and the log console is compiled out. The first version of this
   script waited for that line and could never have seen it (found on a real
   V4, 2026-09-13). Flash first. The proof key, namespace and hash are unchanged
   since beta.5 and so is the partition table, so an app flash keeps the masters
   and the first boot compares against the last proof the old firmware stored.
5. **Slot secrets are gated too.** On the post-wipe boot, `CONNSLOT_CREATE`
   and the relay's `create_client` both refuse with the power-cycle reason.
6. **The prefix notice appears once.** Generate an identity: before word 1
   the screen reads `BEFORE YOU WRITE / Words 1-7 are format, not key. / Same
   start every time`, and a tap moves on. Restarting the review from the
   final confirm shows it again.
7. **Each word is captioned.** Words 1-2 read `SAME ON EVERY KEY`, words 3-7
   `HEADER, NOT SECRET`, words 8+ `SECRET`. Words 1 and 2 really are `edge`
   and `obtain`; word 3 is a `d`-word.
8. **The caption never touches the word.** Check on whichever panel the board
   has. `ui-preview` renders all three, but confirm on glass.
8b. **The shortened error cards are not clipped.** The five cards that were
   over the 18-glyph budget now fit; `ui-preview`'s scan enforces it, but read
   the RNG ones on the actual panel — they are the cards that tell you whether
   to trust the board.
9. **The word is bigger on a colour panel.** On a T-Display or C6, the word in
   both the write-down walk and the restore picker is drawn at 2x (3x on a
   landscape C6). On the 128x64 OLED it must look exactly as it did before.
   Check the longest case: restore a phrase containing an 8-letter word such
   as `announce` and confirm it neither overflows nor is clipped.
10. **The picker legend fits.** On a two-button board, the legend under the
    subtitle reads in full with nothing cut off at the right edge or the
    bottom row. On a narrow panel it reads `A/B move  holdA back` and the
    pick gesture appears in the subtitle instead.

## 23. A pairing acts only as the identities it was approved for (added 2026-09-17; core path bench-run 2026-09-17, desk Heltec V4)

**Bench run 2026-09-17** (V4, 16 MB legacy-NVS bigapp layout, app-only flash at
0x10000, vault re-unlocked, fresh legacy slot 11 "idscope-bench" over the relay,
revoked afterwards):

- Items 1, 2: first sign as the master raised its card and one hold approved it;
  later kind-1 signs answered in ~1.8 s with no card.
- Item 3: `sign_event` with a context for `nostr:persona:natural-person` raised a
  card, signed as `2ed46ab2..` (not the master), and the next one was silent
  (~2.3 s).
- Item 4: an unregistered child's context raised a card and was approved.
- Items 15: a card left to expire answered `timeout`, and the slot recorded
  nothing (`approved_identities` unchanged).
- Item 17: `revoke_client_identity` with the 16-hex tag answered
  `changed: true` and dropped the tag; the same call again answered
  `changed: false`; the master still signed silently; the revoked identity's
  next sign raised its card again. `revoke_client` then removed the bench slot.
- Not yet bench-run: items 5 to 14, 11b, 11c, 16.

The whole decision is one pure function, `heartwood_common::policy::gate_request`,
host-tested as a full matrix; the relay's pre-dispatch plan and the handler both
call it. Card labels and headings are host-tested in `common/src/encoding.rs`.
Approved identities are stored per slot as 16-hex-char tags in the slot JSON's
`ids` field (up to 16) and listed read-only as `approved_identities` in
`list_clients`. Needs a board with at least one persona and an app paired to the
master on a legacy slot that already signs silently.

1. **Upgrade prompts once.** After flashing, the app's first sign as the master
   raises a sign card headed `ALLOW AS <master label>?`, with the app, the kind
   line (`k<kind> <name>`) and `<label> npub1xxxxxxxx..`. One hold signs and
   approves the identity; the next sign is silent. An approved identity whose
   sign still needs a hold by policy reads `HOLD TO SIGN` as before.
2. **Approval covers every method.** After step 1, `nip44_decrypt` as the master
   is silent (policy permitting).
3. **Another identity prompts.** `sign_event` with a top-level `heartwood`
   context for `nostr:persona:natural-person` reads `ALLOW AS natural-p?`. Tap to
   deny: `user denied`, a retry prompts again. Hold on the retry: further signs,
   encrypts and decrypts as it are silent.
4. **Unregistered child.** A context for a purpose not in the registry reads
   `ALLOW AS ?<tail>#<index>?` (index shown when not 0).
5. **Relay addressing.** `#p` to a persona's own pubkey from the master-paired
   app: same card, same one-time approval. Non-identity cards on that connection
   (for example `heartwood_derive`) read `SIGN AS <persona label>?`, never the
   master's label.
6. **Contextual pubkey.** `get_public_key` with a context for an unapproved
   identity reads `NPUB AS <label>?` with the app and short npub; after the hold
   it is answered and nothing is recorded (it prompts again next time).
   Without a context it stays silent.
7. **Crypto card.** `nip44_decrypt` with a context for an unapproved identity
   reads `ALLOW AS <label>? / <app> / npub1xxxxxxxx..`.
8. **Note methods.** `heartwood_note_address` as an unapproved identity raises
   `ALLOW AS`; after the hold it answers. `heartwood_note_send` as an unapproved
   identity raises `ALLOW AS`, then the `SEND NOTE` card over USB; over the relay
   the first request answers `identity approved; send the request again`, and
   the retry raises `SEND NOTE` alone.
9. **heartwood_list_identities.** On a legacy pairing that does not list it:
   `LIST IDS FOR <app>?`. After the hold the method is in the slot's
   `allowed_methods` and answers silently. On a strict slot it stays
   `unauthorised` unless listed. Bark: see the note on its 5 s connect probe.
10. **heartwood_switch.** Switching reads `SWITCH TO <label>?` with the short
    npub below. The hold switches and approves the target, so the app's
    following `get_public_key` and first sign as it raise no card (Bark: one
    press per switch, as before). A switch a slot policy lets through silently,
    or a guardian verdict, records nothing.
11. **Rebind seeds; wallet pairing does not.** A signing slot's rebind hold (a
    new client key with the slot secret) clears the old approvals and seeds the
    served identity. `heartwood_pair_wallet` records nothing: the new wallet's
    first note method raises `ALLOW AS`. A never-seen key binding to a slot
    whose previous key was removed also clears its approvals.
11b. **A card acts only as it said.** Put up a `HOLD TO SIGN` or `ALLOW AS` card
    over the relay for the master, then (before holding) switch the same app to
    a persona silently (a slot that lists `heartwood_switch` with auto-approve).
    Hold: the request answers `unauthorised`, nothing is signed or recorded.
    A deferred `SWITCH TO` whose persona is removed before the hold answers
    `identity not found in cache`; otherwise it switches to exactly the pubkey
    the card showed, even if another persona now shares the name.
11c. **Backups keep grants.** Export a legacy slot holding the LIST IDS grant
    and approved identities, restore it: both survive (signing is stripped as
    before).
12. **Binding change clears.** Change a slot's `bound_identity` (USB
    CONNSLOT_UPDATE or `update_client`): `approved_identities` is empty and the
    new binding signs without a card.
13. **Strict slots.** On a D2 persona-addressed pairing, the bound persona is
    silent; another identity prompts once (or parks for the guardian on an
    `escalate` slot, with the notice's `identity` tag naming it). An explicit
    `heartwood` context is still `unauthorised` with no card.
14. **Seventeenth identity.** With 16 approved on one slot, a seventeenth
    prompts on every request and is never recorded.
15. **Timeout leaves nothing behind.** Let any of these cards expire: the slot is
    unchanged and a retry prompts.
16. **USB unchanged.** Direct USB requests (no client pubkey) behave as before.
17. **Revoke one identity, or all.** With the master and a persona approved on
    a legacy slot, `revoke_client_identity` (`slot_index`,
    `expected_secret_fingerprint`, `identity` as the persona's npub, fresh
    `mutation_challenge`, no button): the result has `changed: true` and
    `list_clients` no longer lists its tag; the master still signs silently and
    the persona's next sign reads `ALLOW AS` again. The same call again answers
    `changed: false`. An approval by its `list_clients` tag (16 hex, either
    case) revokes the same way. Revoking a strict slot's `bound_identity`, by
    pubkey or by its tag, answers
    `bound_identity: identity is the slot's binding; change the binding
    instead` and changes nothing. `clear_client_identities` empties the list,
    the binding still signs silently, and the slot's methods, kinds and client
    keys are unchanged. Put a `HOLD TO SIGN` card up for an approved identity,
    revoke it before holding: the hold answers `approval changed while waiting;
    send the request again`. On an `escalate` slot, approve-once a parked sign
    as the persona, revoke the persona inside the verdict's window: the result
    shows `verdicts_dropped: 1` and the next sign of that kind parks again
    instead of riding the verdict.

### Retained-client reconnect regression (added 2026-09-21, NOT YET BENCH-RUN)

Use a disposable signing slot with two already-authorised client keys, A and B.
Pair both first, then approve the test identity: adding an unknown client still
clears the slot-wide identity grants in this firmware. Record the slot's
authorised keys and approved identities without exporting its secret.

1. Reconnect A, then B, then A using their existing credentials. No rebind card
   appears. Each becomes the displayed current client and the other remains
   authorised. The approved identity list stays unchanged. Make three requests
   within the installed method/kind policy after each reconnect: all succeed
   without a new approval card.
2. Reconnect the current client again. It remains silent. Reboot/unlock the
   signer and repeat A → B → A: the retained keys and identity grants survive.
3. Connect an unknown C to the used signing slot. A physical rebind card is
   still required. Deny it, then separately let it time out: neither outcome
   adds C or changes the existing keys/grants. Repeat with a revoked or
   FIFO-evicted key; it must not be treated as a retained client.
4. With a bench fixture for a previously-used signing slot whose current key
   is absent, an unknown key still needs the rebind hold. A retained authorised
   key is silent. A genuinely unused operator-issued slot retains its existing
   first-connect behaviour. Do not edit a live user's NVS to create a fixture.
5. Use a controlled slot-write failure/rollback bench fixture on a retained-key
   reconnect: no successful connect acknowledgement is sent unless the updated
   slot state is durable. Preparing that fixture is part of bench acceptance;
   do not corrupt a live user's storage. Also check a deferred rebind after
   slot removal or policy change; it must use the live slot state.
6. Separately verify an ordinary app update and relay reconnect on the user's
   actual routes: Kithmoot → Bark, Kithmoot → Cambium on Android, and the other
   consumer → My Signet. Record installed versions, the credential fingerprint,
   persona, policy, prompt heading and observed result. Distinct app pairings
   need not share a slot; the two-client bench case above is separate evidence.

Host classifier tests and a firmware build do not establish these outcomes.

## 24. A guardian verdict answers a note card too (#160; added 2026-09-17, NOT YET BENCH-RUN)

Escalation exists so the family's guardian can answer when nobody is at the
board. A bearer-note disclosure or destruction owes its own card whatever the
slot policy says, and that card used to go up on the board even after the
guardian had approved the park: the request completed through the interactive
handler, sat on a 30 s `SEND NOTE` card nobody was there to press, blocked the
relay loop for the whole window and then answered `timeout`. The verdict is now
what answers that card, for the one request the notice named and nothing else.

Needs an `escalate` legacy slot on a board holding at least one CONFIRMED note,
the guardian channel of section 11 (`scripts/guardian.mjs` or the operator
channel driver used there), and a note client (notecase, or
`scripts/nip46-client.mjs`).

1. **A parked note send completes with no press.** From the escalate slot, send
   `heartwood_note_send`. The board shows no card; the guardian receives the
   approval-needed notice naming the client, `heartwood_note_send` and the
   identity, **and carrying the card the device would have shown**: a `card`
   tag reading `SEND NOTE` and a `detail` tag with the amount, the mint and
   `to <recipient>`, the same text as the OLED card in section 13. Check the
   amount and recipient match the request before answering. Answer
   `approve-once`. The note is wrapped and sent, the client gets its reply,
   and **no card ever appears on the OLED**. The verdict answers
   `applied: "completed"`, `park: "live"`.
1b. **No preview, no verdict.** A pinned note request the device cannot build a
   preview for (for example `heartwood_note_send` naming a note id the locker
   does not hold) must NOT park: it raises the card on the board as it always
   did, and the guardian is not asked to approve a method name. The log line
   reads `no card preview to show the guardian`.
2. **The loop stayed live throughout.** While the park waits, and again while
   the verdict is being applied, a second app on another slot signs a kind 1
   and is answered normally. Before this fix the second app timed out for the
   30 s the dead card held the loop.
3. **The verdict covers that request only.** Immediately after item 1, inside
   the verdict's window, send a second `heartwood_note_send` from the same
   client for the same identity. It must NOT go silently: it parks again and
   the guardian is notified again. (A non-pinned method, a `sign_event` of the
   same kind, does ride the window, which is unchanged.)
4. **An unapproved identity still needs its own approval.** With the identity
   absent from the slot's `approved_identities`, repeat item 1. The notice's
   `identity` tag names it, the verdict completes the send, and afterwards
   `list_clients` shows `approved_identities` UNCHANGED: the verdict released
   one request, it did not enrol the identity.
5. **Denial and expiry.** Answer `deny`: the client gets `user denied`, no card,
   nothing sent. Let another park expire unanswered (10 min) and then answer
   `approve-once`: `applied: "window"`, nothing is sent, and the client's own
   retry parks again rather than riding the late verdict.
6. **Export and the destructive methods.** Repeat item 1 for
   `heartwood_note_export` (the `ck1` reaches the client, no card) and for
   `heartwood_note_spent` inside the export's grant window (still no second
   card, section 17 unchanged). `heartwood_note_discard` and
   `heartwood_note_rename` park and complete the same way.
7. **A slot policy still cannot silence a note method.** On the same escalate
   slot, add `heartwood_note_send` to `allowed_methods` with `auto_approve`.
   The next send must still park for the guardian, never run silently, and
   never fall through to a card on the board.
8. **No regression off the escalate path.** On a normal legacy slot (no
   `escalate`), `heartwood_note_send` still raises `SEND NOTE` on the board and
   still needs the physical hold; section 13 and section 23 item 8 read exactly
   as they did.
9. **USB unchanged.** `node scripts/note-cmd.mjs --port ...
   '{"cmd":"send", ...}'` still shows its card and waits for the hold. The
   cable has no guardian and is not escalated.
10. **A verdict cannot answer for the device.** On the same escalate slot,
   send `heartwood_provision_rendezvous` and then `heartwood_pair_wallet`.
   Each must be refused IMMEDIATELY, with `this request must be approved at
   the device; a guardian verdict cannot answer it`, no card on the OLED, no
   notice to the guardian, and no park (`get_status` shows none pending).
   Time the reply: it comes back in the usual second or two, not after 30 s,
   and another app signing on a second slot is answered throughout.
11. **The same two still work at the device.** Clear the slot's `escalate`
   flag and repeat item 10: `PROVISION RENDEZVOUS` and `PAIR NEW WALLET`
   raise their cards on the board and one hold completes each, exactly as
   section 11b and the note-locker sections record them. Nothing about the
   cabled or non-escalated path changed.
12. **A sign still needs its own approval.** On the escalate slot, park a
   `sign_event` of a kind the slot does not auto-approve and answer
   `approve-once`: it completes as it did before this change (the approve-once
   window is what lifts it, no card is owed). Revoke the identity inside the
   window first and the retry parks again, as section 23 item 17 records.

## 25. The sealed-seed KDF on the SHA accelerator (#121; added 2026-09-18, NOT YET BENCH-RUN)

`derive_km` now runs on the chip's SHA peripheral on the ESP32-S3 Heltecs and
the C6, instead of the pure-Rust `sha2` software path. The iteration count is
unchanged at 100,000 and the on-disk blob format is untouched, so this is a
speed change and nothing else, which is exactly what has to be proved. See
`docs/2026-09-18-pbkdf2-cost-and-sha-acceleration.md` and
`firmware/src/sha_accel.rs`.

Two items are gates. Item 1 is the **concurrency** gate: the accelerator is
exclusive only because every other user of it, TLS included, takes
`esp_sha_acquire_hardware` first, and that assumption is only testable with a
live TLS session passing traffic while a derivation runs. Item 6 is the
**correctness** gate: an old sealed blob still opening, because a hardware path
that derives a *different* key is the one genuinely dangerous failure here. Do
not sign off this section without both, and do not run any of it on a board
whose seed you cannot re-provision.

1. **Unseal while a relay session is live on WiFi.** FIRST, because everything
   else assumes it. This is the contention case the shared SHA/AES lock
   creates, and it only exists in the WiFi-standalone tier. Provision a board
   for WiFi-standalone with a vault key, reboot it locked, and let it come up
   and announce its ephemeral unlock pubkey (kind 24135): the TLS session to
   the relay is live at that moment. Deliver the vault key with `node
   scripts/vault-unlock-wifi.mjs` and confirm the device unlocks, the relay
   session does NOT drop or error, a `sign_event` sent immediately afterwards
   is answered normally, and the next boot reports no crash crumb.

   Then do it with TLS actually busy rather than merely open: with the board
   unlocked and an app signing through the relay in a loop (`node
   scripts/nip46-sign.mjs` repeatedly, or `scripts/bench-personas-nip46.mjs`),
   trigger a fresh `derive_km` by changing the at-rest secret (`VAULT_SET` or a
   PIN change, which reseals every slot). Neither side may stall for more than
   a second or two, no relay frame may be dropped, no signature may be wrong,
   and the board must not reboot. A log line `SHA accelerator contended -
   finishing this derivation in software` is the retreat working, not a
   failure; note how often it fires. Repeat on a board with the note locker
   enabled, which adds the `nk` re-wrap to the same window.
2. **Timed unseal, per slot, before and after.** Flash the previous release,
   set a PIN on a single-master board, power-cycle, and time the unlock from
   the `PIN_UNLOCK` frame to the ACK (`scripts/device-status.mjs`, or the
   Sapwood unlock spinner, or a stopwatch on the OLED's `Unsealing 1/1`
   card). Record it: the figure on record is ~29 s a slot on a V4. Flash this
   release and repeat with the SAME PIN on the SAME board. Expect roughly
   0.7-2 s a slot; anything above about 5 s means the accelerator is not in
   the path and item 3's log line will say so. Record both numbers for the V4,
   the V3 and the T-Display. The T-Display has no accelerated path by design
   (its SHA cannot resume from a saved digest state), so its number should be
   unchanged: that is a pass, not a failure.
3. **The self-check ran and passed.** On a bench build with the console on a
   UART probe, the first unlock after boot logs `SHA accelerator self-check
   passed - sealed-seed KDF is hardware-backed`. On the T-Display the boot line
   instead reads `accelerator not available on this board - software path`.
   Without a console, item 2's timing is the observable.
4. **A three-master unlock.** On a board with three sealed masters, unlock once
   and confirm: all three slots open on one PIN entry, the OLED progress card
   counts `1/3`, `2/3`, `3/3`, the total is roughly three times item 2's
   per-slot figure, and there is NO watchdog reboot (`FIRMWARE_INFO` reports no
   `task-watchdog` crash crumb on the next boot). Repeat with the bearer-note
   locker enabled: that is a fourth `derive_km` for the `nk` wrap, so four
   stretches, not three.
5. **The seal path still verifies in software.** Enabling at-rest encryption
   re-derives each blob through the REFERENCE KDF to check its own work, so a
   `SET_PIN` or `VAULT_SET` on a sealed board is fast-then-slow per slot: about
   a second of hardware sealing followed by the old ~29 s software verify.
   That is expected and is what guarantees a committed blob opens without the
   accelerator. Time it on a three-master board and confirm no watchdog reboot.
6. **An old sealed blob still opens.** THE CORRECTNESS GATE. Take a board
   sealed by a PREVIOUS release: ideally one sealed months ago, and at minimum
   one sealed
   by the release under test in item 2's "before" half, which must not be
   re-sealed in between. Flash this release WITHOUT wiping NVS and unlock with
   the original PIN. The seed must come back byte-identical: confirm by npub,
   not by "it unlocked". `get_status` must report the same master npubs it
   reported before the flash, and a `sign_event` must verify against them. Do
   this for both blob lengths if you have them: a 92-byte legacy record and a
   101-byte current one (a board provisioned before #155 has the former).
7. **The self-check mismatch path.** Build with the bench-only feature that
   deliberately corrupts the hardware answer:

   ```
   cd firmware
   export MCU=esp32s3
   export ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.heltec-v4"
   cargo build --target xtensa-esp32s3-espidf --release --no-default-features \
     --features heltec-v4,sha-selfcheck-fail --bin heartwood-esp32
   ```

   Flash it to a SCRATCH board (not one holding keys) that has a sealed seed,
   and unlock. It must: log `SHA accelerator self-check FAILED - known-answer
   mismatch`, fall back to software for the rest of the session, take the OLD
   ~29 s per slot, and still unlock correctly to the right npub. It must never
   report a wrong PIN and must never produce a different key. Reboot and
   confirm the message repeats: the fallback is per session, not sticky
   across boots. Then reflash the normal image and confirm item 2's timing
   comes back.
8. **The iteration ceiling.** `MAX_PBKDF2_ITERATIONS` is now 150,000 rather
   than 1,000,000. With a hex editor on an NVS dump from a scratch board, set
   the `rounds` field of a 101-byte blob to 200,000 and put it back. The
   unlock must fail FAST, within the usual frame timeout rather than after
   minutes, with the blob refused before any KDF work, and the board must not reboot.
   The failed-attempt counter behaviour is unchanged (this is a malformed
   blob, and it still burns an attempt, as it did before).
9. **Nothing else moved.** Sanity-sweep the paths that share the KDF: enable
   at-rest encryption from scratch (`SET_PIN`), disable it, enable the
   bearer-note locker on a PIN-locked board and confirm its `nk` wrap unwraps,
   and run one Sapwood backup export/import round trip. All of these call
   `encrypt_seed`/`decrypt_seed` and all must behave exactly as sections 7 and
   13 record them.
## 26. A backup carries the note inventory and restores none of it (#86; added 2026-09-18, NOT YET BENCH-RUN)

A bearer note IS its secret, so a restored copy of one is a double spend and
notes will never be in a backup as money. But a board that dies silently
taking value with it is the worst kind of loss: unbounded and unprovable. So a
backup now carries a non-spendable INVENTORY - per readable note, the public
commitment its mint already files it under, plus amount, mint, state and
timestamps - and nothing that can move a satoshi. This section checks both
halves on real hardware: that the inventory is there and honest, and that a
restore cannot bring a note back.

Needs a board holding at least two notes in different states (mint one and
confirm it, receive or import a second, mark a third spent if convenient),
Sapwood's Backup panel, and a text editor for the decrypted file.

1. **The export card says what is leaving.** Sapwood -> Backup -> Export.
   The board's CONFIRM CHANGE card reads `Export backup?` over
   `<n>m <n>sl <n>nt+amt/mint` when the locker holds notes - the `+amt/mint`
   clause is there because the inventory carries amounts and mint hosts as
   well as commitments - and the familiar `<n> masters/<n> slots` when the
   locker is empty. Hold to approve; the done card repeats the same line.
   Sapwood's success message ends "plus a non-spendable inventory of N notes".

2. **The file says the same thing.** Decrypt the downloaded backup with its
   passphrase (Sapwood's import preview is enough) and read `note_inventory`.
   One entry per note the card counted, each with exactly these eight fields:
   `id`, `commitment`, `state`, `amount_msat`, `host`, `key_index`,
   `created_at`, `updated_at`. There is no `secret_hash` (the field is called
   `commitment` because for a key note it is a public key, not a hash of
   anything). The ids and amounts match `heartwood_note_list` /
   `scripts/note-cmd.mjs '{"cmd":"list"}'` exactly. With every note readable,
   there is no `note_inventory_unreadable` key at all.

3. **The commitment is the mint's own handle.** For an ordinary note, compare
   `commitment` with the `h` the wallet registered when the note was minted
   (`note-cmd.mjs` prints it at `new`; the mint's ledger calls it the note id).
   They are the same 64 hex characters. For a note paid to one of the device's
   own keys (section 15), `key_index` is non-null and `commitment` is the
   note's PUBLIC key, not a hash - check it against the `p` the mint holds for
   that index.

4. **No secret is anywhere in the file.** Export a note's secret over the
   cable (`{"cmd":"export_secret","id":"<id>"}`, one hold) and search the
   DECRYPTED backup text for that `k1`, for it uppercased, and for the first
   eight characters of it. Zero hits. Do the same for a key note's key.
   Nothing but commitments leaves the board.

5. **A locked board is honest about what it cannot see, IN THE FILE.** With
   at-rest encryption enabled and at least two notes held, reboot and export
   BEFORE unlocking. Every record is sealed, so:
   - the card reads `<n>m <n>sl 0nt <u> UNREAD` with `<u>` the sealed count,
     not the plain `masters/slots` line;
   - the serial log carries `note record(s) unreadable this boot`;
   - and, the point of this item, the DECRYPTED file carries
     `"note_inventory": []` **together with** `"note_inventory_unreadable": <u>`.
   Without that second key the file would be byte-identical to one taken on
   an empty locker, and an owner would read a nil loss where the truth is an
   unknown one. Unlock, export again: the inventory is complete and the
   `note_inventory_unreadable` key is gone. A sealed record is never invented
   into the file, and never silently omitted from it either.

6. **A restore creates no note.** On a SECOND board (or the same board after
   a factory reset and re-provision), import the backup from step 2. The slots
   restore as section 5 records. `heartwood_note_list` on that board returns
   exactly what it held before the import - nothing added, nothing changed,
   no id from the inventory present. The serial log shows
   `ignoring a <n>-entry note inventory ... notes are never restored`.

7. **A doctored inventory changes nothing either.** Edit the decrypted payload
   before re-encrypting: change an `amount_msat`, corrupt a `commitment` to
   `not-a-hash`, and add an entry with an id the board has never seen. Import
   it. The slot restore still succeeds, the log reports the malformed count,
   and `heartwood_note_list` is unchanged. There is no path from a backup file
   to a note, and this is what that looks like from outside.

7b. **A broken inventory cannot cost an owner their pairings.** Repeat item 7
   but replace the whole `note_inventory` value with junk a parser cannot
   read: first `"note_inventory": 42`, then `"note_inventory": {"not":"a
   list"}`, then an entry using the pre-release name `secret_hash` instead of
   `commitment`. Each import must still restore the app slots, and the log
   must say `the note inventory is in no shape this firmware reads; ignoring
   it. Identities and app slots are unaffected.` A record of money that is
   already gone must never be able to block the recovery of the things that
   are not.

8. **Old and new meet in both directions.** Import a backup taken before this
   firmware (no `note_inventory` at all): it restores exactly as it always
   did. Then take a NEW backup and import it on a board running pre-#86
   firmware: the unknown field is ignored and the slots restore. Neither
   direction needs a flag.

9. **A locker with no notes still exports.** Spend or discard everything, then
   export on an UNLOCKED board. The card reads `<n> masters/<n> slots` again
   and the file carries `"note_inventory": []` with no
   `note_inventory_unreadable` key - an empty inventory, which is a
   statement, not an absence. Compare the file with the one from item 5: same
   empty array, different second key, different meaning.

## 27. Unlock phones follow a relay change (added 2026-09-25, NOT YET BENCH-RUN)

A phone listens on the relays it has been told about. A board that moves to
relays its phones never heard of would, at its next locked restart, announce
where no phone listens. The board now records the relays the phones were last
told (`ph_relays`) and, while its live list has a relay missing from that
record, tells them on the OLD relays (logic and host tests:
`common/src/phone_relays.rs`):

- locked, it repeats each phone's lock announcement on one old relay per
  announce interval, in the pass straight after the live announcement (a
  dial blocks for at most about 35 s, so it ends before the next
  announcement); each relay rests 5 minutes after a dial, and a failing one
  backs off (10, 20, 40, then 60 minutes);
- unlocked, it posts a relay update (a 24135 like any other, sealed `t` =
  `relays`) on each old relay in six rounds: the first a random 2 to 20
  minutes after the board comes online, then after gaps of about 2 min,
  13 min, 45 min, 5 h and 18 h, each randomised by a quarter either way. Every
  update goes out on a publish-only connection of its own, never on a session
  carrying the signer's subscription. The secondary relay stays closed for
  the round; with the primary and a pinned relay both live the round waits,
  and after 10 minutes the pinned relay steps aside for one dial and
  redials 15 s later, once it has been quiet for 5 s with nothing buffered.
  The round count is saved after each round, so a restart resumes. A round in
  which the heap was too tight for every dial does not count and comes back
  later. After the sixth round the live list is recorded and the drift ends,
  but only if some round had an event accepted by an old relay; until then
  the sixth round repeats about every 18 h. A revoke of the last phone, or an
  enrolment after that, ends the update at once without touching the new
  record.

**Release note (next beta):** phones enrolled on beta.17 before a relay
change also made on beta.17 are not told about it (beta.17 kept no record,
and the first boot on this firmware records the live list as what they know):
re-enrol them.

Needs a WiFi board with a vault key and one phone enrolled with
`scripts/phone-unlock.mjs enrol` while the board used relay set A, a second
relay set C sharing no relay with A, and a relay capture on A (any client
subscribed to `{"kinds":[24135]}`).

1. **In step, nothing extra.** Reset the board. The serial log has no
   "relays changed" line and no "old relay" line; A carries only the usual
   announcements.

2. **Change to C, restart locked.** Point the board at C (Sapwood's network
   editor or `SET_NET_CONFIG`). After the restart the log reads "relays changed
   since the phones were told; telling them on N old relay(s), 0 of 6 update
   rounds already sent", then, straight after an announcement on C,
   "announced on old relay ..." for one A relay (the next A relay a minute
   later). The capture on A shows a 24135 per phone with one `h` tag and no
   `p` tag, from the same one-time author as the board's announcements on C.

3. **The phone hears it on A and unlocks over C.** Run `phone-unlock.mjs
   listen` with the state file still listing only A. It prompts once (the
   repeat on C, if it listens there, is a duplicate), prints "following the
   board to" the C relays, and delivers; the board shows "Unlocked by"
   typically within 5 s of the delivery, and within 40 s at most (the outer
   bound, when an old-relay dial to a slow or dead relay started just before
   the delivery), and never announces again after it.

4. **A dead old relay decays.** Add an unreachable `wss://` URL to A before
   the change (or stop one of A's relays). Its "old relay ... failed" lines
   come 10, 20, 40 and then 60 minutes apart, and a heartwoodd or Sapwood PIN
   unlock over USB still succeeds between them.

5. **Unlocked, the rounds go out on their own connections.** With the board
   unlocked on C, "relay update round 1 of 6" appears 2 to 20 minutes after
   the board came online, with one "relay update on old relay" line per A
   relay ("(n accepted)"); round 2 follows 90 to 150 s later. The capture on A
   shows each round's 24135s from a new author, each the same length as the
   lock announcements of step 2, arriving on a connection that sent no `REQ`.
   A second `listen` run against a copy of the state file that lists only A
   prints "relay update: ..." and does NOT prompt.

6. **A restart resumes.** Reset after round 2 and unlock. The boot log says
   "2 of 6 update rounds already sent" and round 3 goes out 2 to 20 minutes
   after the board comes online.

7. **Ceiling.** With a pinned relay live beside the primary (a nostrconnect
   pairing on a relay outside C), the log says "relay update waiting: the
   primary and a pinned relay fill the session ceiling" once; about 10
   minutes later, at a moment the pinned relay has been quiet for 5 s,
   "pinned ... steps aside for one relay update dial", the dial, and the
   pinned relay rejoining about 15 s later. At no point are three
   relay sessions open (heap log: "2 session(s)" at most).

8. **Revoked and zero-phone boards say nothing.** Revoke the phone
   (`phone-unlock.mjs revoke`) while an update is pending, then reset. The
   boot log has no "relays changed" line (the record went with the last
   phone), and A sees no further 24135 from the board. Enrol again on C and
   reset: still no "relays changed" line.

   8b. **The same in one unlocked boot, no reset.** With an update pending
   (after step 5's round 1, before round 6), revoke every phone, then enrol
   a new one on C (`phone-unlock.mjs enrol`, one press). Within a second of
   the last revoke the log says "phones' relay record changed (revoke or
   enrolment); relay update ended", and the enrolment after it starts no
   update. Keep the capture on A running for at
   least 20 minutes (past the next round's latest time): A sees no further
   24135 from the board. A reset afterwards has no "relays changed" line.

9. **The record ends the drift.** Optional, about 24 h: leave the board
   unlocked through round 6. The log says "phones told about the relay
   change; recorded", and a reset afterwards has no "relays changed" line.

## 28. Deleted NVS entries are zeroed (added 2026-09-25, NOT YET BENCH-RUN)

ESP-IDF marks a deleted or replaced NVS value erased and leaves its bytes
until the sector is collected. The firmware now zeroes every erased entry at
boot, after a phone or pairing revoke, an identity removal and every at-rest
change (SECURITY-MODEL.md, *Leftover bytes in NVS*; logic and host tests:
`common/src/nvs_scrub.rs`). Nothing here has run on hardware.

Needs a sacrificial V4 on the previous firmware, sealed with a vault key, with
two phones enrolled, two or three pairings and a few changes behind it (a
network edit, a revoked pairing), so the partition has residue; ESP-IDF's
`nvs_tool.py` (in the build tree:
`firmware/.embuild/espressif/esp-idf/v5.3.2/components/nvs_flash/nvs_partition_tool/nvs_tool.py`,
run with the IDF Python env); a way to read the NVS partition (`espflash
read-flash` or `esptool.py read_flash`, offset `0x9000`, length `0x4000` on
the release table, `0x6000` on the legacy V4 tables); and, for step 6, a
switched USB power supply or hub.

1. **Residue exists today.** On the previous firmware, dump NVS to
   `before.bin` and run `nvs_tool.py -d all -i before.bin`. Expect entries in
   state `Erased` that still show a key and readable data (old `dk_ph`,
   `connslots_N`, `net_config`, and `master_N_secret` if an identity was
   added before sealing). Record how many; this measures the residual the
   scrub closes. Keep `before.bin` for step 6.

2. **The boot pass.** App-only flash the scrub build (NVS untouched) and let
   it boot. `FIRMWARE_INFO` shows
   `"nvs_scrub":{"zeroed":N,"pages_skipped":0,"complete":true}` with N > 0.
   Dump to `after.bin`: in `nvs_tool.py -d all -i after.bin` every `Erased`
   entry shows an empty key and all-zero data; `-i` reports every page's
   CRC32 OK and nothing `before.bin` did not already report. `nvs_tool.py -d
   written` of both dumps differs only in keys a boot rewrites (`rng_proof`,
   `lk_boots` on a locked boot). Unlock with the vault key, then restart and
   unlock with each phone: both work. A second restart shows a small
   `zeroed` (the boot's own rewrites) and `complete: true`.

3. **A phone revoke answers with the scrub.** Revoke one phone
   (`scripts/phone-unlock.mjs revoke`, or Sapwood). The answer is
   `{"revoked":<id>,"scrub":{"zeroed":n,"pages_skipped":0,"complete":true}}`
   with n > 0 (the old `dk_ph` copy at least). Dump: no `Erased` entry holds
   a non-zero byte. Restart: the revoked phone's unlock answers are ignored;
   the other phone still unlocks the board.

4. **A pairing revoke.** Over the relay as the device operator,
   `revoke_client` answers with the same `scrub` object; as a per-identity
   delegate, the answer has no `scrub` key. Over USB, `CONNSLOT_REVOKE` still
   answers `ok`, and `FIRMWARE_INFO`'s `nvs_scrub` changes afterwards.
   `get_status.capabilities` includes `nvs_scrub_v1`.

5. **At-rest changes and removal.** Change the vault key (`VAULT_SET`, hold),
   clear it, set a PIN, then remove an identity (`PROVISION_REMOVE`, hold):
   after each, a dump shows no `Erased` entry with non-zero data, and the
   board unlocks with whatever secret is now current. After sealing, no
   32-byte run of any identity's plaintext seed appears anywhere in the dump.

6. **Pull power during a boot-time pass, repeatedly.** Write `before.bin`
   back to the NVS partition (the dirty image), power on, and cut power at a
   varied delay after power-on (sweep about 100 ms to 1.5 s in 50 ms steps;
   the pass runs after the boot animation and the journal recoveries). Power
   on again and let it boot fully. Each time: the board boots and unlocks
   with the vault key and with each phone; `FIRMWARE_INFO` shows `complete:
   true`; a dump's `nvs_tool.py -d written` matches step 2's `after.bin`
   except the boot-rewritten keys, and `-i` adds no complaint. Note roughly
   how much longer a dirty boot takes than a clean one.

7. **PHY calibration is off NVS.** This firmware builds with
   `CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE=n`. On a WiFi board, compare
   time from reset to "relay connected" with the previous firmware (expect
   about 100 ms more, a full calibration each boot) and check WiFi joins and
   holds as before. On a board that had stored calibration, `nvs_tool.py -d
   all` still lists the `phy` namespace (`cal_data`, `cal_mac`,
   `cal_version`) as written entries, unchanged across several boots with
   WiFi: nothing writes them any more. On a freshly wiped board no `phy`
   namespace appears at all.

8. **Size.** Record the release `app.bin` size against the #197 build.

## Notes

- Restore and OTA are **USB-only** by design; remote OTA is not implemented.
- The recovery phrase only ever appears on the device's OLED — never in the browser.
- If a step wedges, RESET the board; an unsaved phrase staying on screen is the
  safe failure (nothing is stored until the final hold).
