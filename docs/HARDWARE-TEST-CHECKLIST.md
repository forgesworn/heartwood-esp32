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
      pull-up), boot logs "leaving it unregistered" and approvals behave
      single-button — B must never self-cancel prompts.
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
      retry cycles (~10 s/candidate) and comes online; logs name each
      candidate as "wifi network N/M".
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
2. `export_secret` raises "Release note? N sats @ host" — hold approves and
   returns 64-hex `k1`; short press denies (`user_declined`); unattended
   card times out (`timeout`) with the note untouched. NOT YET BENCH-RUN.
3. Destructive gating: `mark_spent` / `discard` / `rename` / `delete` each
   raise a card; wrong-state commands answer `invalid_state` with NO card
   (watch the OLED — the serial answer alone does not prove it). NOT YET
   BENCH-RUN.
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
    never cover both a signature and a disclosure. NOT YET BENCH-RUN.

Regression watch: a USB `sign_event` approval and a factory reset must behave
exactly as before; FIRMWARE_INFO's nvs entry stats now include the
`hw_notes` namespace's usage.

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
   RECEIVE NOTE, first line `<sats> sats @ <host>`, second `from
   <npub8>..<npub8>`; no NIP-46 response is published to anyone. Hold:
   green "N sats received / wallet collects it", back to idle after ~3 s;
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
   seal signer, and a rumor whose URL has no amount. Expect: silent drop
   with one `[relay] gift wrap ... not for us / is not a note` log line,
   no card, no wake.
3a. From a stranger's client: on a phone running any NIP-17 client
   (0xchat, Amethyst), resolve the device's NIP-05, and DM it a note as
   plain text, once as `lnurlw://...`, once as bech32 `LNURL1...`, once
   with a `lightning:` prefix, once wrapped in a sentence. Expect the same
   RECEIVE card each time, with the sender's npub on it. A DM carrying two
   notes is dropped (`more than one note in the message`).
4. Letterbox cap: with MAX_RECEIVED (4) received notes held, a fifth wrap
   logs `letterbox full; dropped until there is room` and raises no card.
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
   Expect SEND NOTE card, `<sats> sats @ <host>` / `to <hex8>..<hex8>`; hold
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

## Notes

- Restore and OTA are **USB-only** by design; remote OTA is not implemented.
- The recovery phrase only ever appears on the device's OLED — never in the browser.
- If a step wedges, RESET the board; an unsaved phrase staying on screen is the
  safe failure (nothing is stored until the final hold).
