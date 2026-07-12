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

## Notes

- Restore and OTA are **USB-only** by design; remote OTA is not implemented.
- The recovery phrase only ever appears on the device's OLED — never in the browser.
- If a step wedges, RESET the board; an unsaved phrase staying on screen is the
  safe failure (nothing is stored until the final hold).
