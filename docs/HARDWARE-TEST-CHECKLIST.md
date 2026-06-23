# Hardware-in-the-loop test checklist

Things that can only be confirmed on a real board — the on-device gestures, the
OLED, OTA, and the USB/WiFi mode transitions. CI covers the host logic and that
the firmware builds and fits; this covers everything CI can't reach.

Use a Heltec WiFi LoRa 32 V4. Have Sapwood open (Chrome/Edge for Web Serial).
Where a step says "approve on the device", that's a 2-second hold of **PRG**.

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

Gestures (firmware v0.9.1+): **single tap = next choice, double-tap = pick.** A
single press of *any* length counts as one tap, so lingering on the button can
never select by accident — and there is no hold-to-pick to time. (The only hold
is the deliberate 2-second save at the very end.)

- [ ] Setup → **Restore from my 12 words** → name → **Restore on my device**.
- [ ] OLED shows the intro (1 tap = next / 2 taps = pick) then **WORD 1/12**.
- [ ] Entering a word:
  - [ ] A **single tap** cycles the highlighted choice: valid next letters, then the
        whole word (underlined) once it resolves, then a **DELETE** item.
  - [ ] A **double-tap** picks the highlight — a letter extends the prefix; the
        underlined word accepts it. Typing `a` `b` `a` offers **abandon** within ≤4 letters.
  - [ ] **Lingering check:** press and hold a letter for a second, then release —
        it should just advance (one tap), NOT select. No accidental picks.
  - [ ] Cycle to **DELETE** and double-tap to remove a letter; on an empty word,
        DELETE steps back to the previous word.
- [ ] After word 12, OLED shows the **REVIEW** screen:
  - [ ] A **single tap** pages through all 12 words (one big word each), then **SAVE**, then **CANCEL**.
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
- [ ] **Cancel:** REVIEW → **CANCEL** (double-tap), or during entry double-tap **DELETE**
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

## Notes

- Restore and OTA are **USB-only** by design; the WiFi relay loop NACKs them.
- The recovery phrase only ever appears on the device's OLED — never in the browser.
- If a step wedges, RESET the board; an unsaved phrase staying on screen is the
  safe failure (nothing is stored until the final hold).
