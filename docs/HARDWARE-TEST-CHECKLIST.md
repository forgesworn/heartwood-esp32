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
- Still open: the power-cut runs (a hand on the plug mid-migration and
  mid-removal), and a Sapwood-UI click-through for CP1. Migration-with-data
  passed same day on the T-Display (see the ticked item above).

## Notes

- Restore and OTA are **USB-only** by design; remote OTA is not implemented.
- The recovery phrase only ever appears on the device's OLED — never in the browser.
- If a step wedges, RESET the board; an unsaved phrase staying on screen is the
  safe failure (nothing is stored until the final hold).
