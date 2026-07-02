# Bench verification — v0.10.1 (2026-07-02)

One hardware pass clears everything that's been built + committed but can only
be proven on real boards. Nothing below has touched hardware yet; each item is
compile-verified and (where possible) host-tested only. Work top to bottom; the
firmware items all ride the same T-Display / Heltec flash, so it's one sitting.

## Prep

- [ ] `firmware/ota-release-pubkey.hex` holds the real release key (it does —
      `3cdfa635…39b7`); `OTA_SIGNING_SEED` secret is set. So a `v0.10.1` tag
      will produce a signed release.
- [ ] Build fresh from `main`: `source ~/export-esp.sh && bash scripts/build-firmware.sh tdisplay --release` and `… v4 --release`.

## 1. Two-button restore picker (T-Display) — the new UX

Flash the T-Display, trigger a restore (frame `0x58`, or via Sapwood's restore
flow), and enter a known 12-word phrase.

- [ ] Intro screen teaches **A = next choice / B = pick it / pick ← to delete**
      (not the "1 tap / 2 taps / hold" single-button vocabulary).
- [ ] **A** moves the highlight through letters; **B** picks one and extends the
      prefix. No double-tap, no hold anywhere.
- [ ] Prefix autocomplete still narrows to the word; **B** on the whole word
      accepts it.
- [ ] The **← / "back"** item is reachable by A and, on B, deletes the last
      letter; on an empty prefix it steps back to the previous word.
- [ ] Review screen: **A** pages words + SAVE + CANCEL, **B** acts (edit / save
      / discard). Editing a word re-enters just that slot.
- [ ] Final confirm shows the npub with **B = save / A = back**; B stores, the
      derived npub matches the phrase's real npub.
- [ ] Overshooting a choice costs **one press of A** to come back around (or the
      ← item) — no timed hold. This is the whole point; confirm it feels right
      for the impatient-kid bar.
- [ ] Sanity: a Heltec (single-button) restore is UNCHANGED — tap / double-tap /
      hold still work exactly as before.

## 2. Signed OTA (Heltec, has the A/B OTA slots)

- [ ] Flash a Heltec with the **pre-signature 0.9.x** release, then OTA to
      **0.10.1** via Sapwood. This exercises the host's legacy-fallback (old
      firmware rejects the 100-byte signed BEGIN as ERR_SIZE → host retries the
      36-byte form). The update should complete and the device report 0.10.1.
- [ ] From **0.10.1**, OTA to the *next* signed release (or re-flash 0.10.1's
      own signed image). This exercises **enforcement**: the device verifies the
      ed25519 signature at BEGIN and FINISH. A correct signature installs.
- [ ] Negative: feed `heartwood-ota` a tampered image with the real `.sig` (or
      the wrong `.sig`). Device rejects with `ERR_SIG (0x14)` and keeps its
      current firmware.

## 3. Relay decryption-oracle + derive-gate fixes (WiFi board)

On a Wi-Fi-relay board, from an **unbound** relay client (a throwaway key that
never ran `connect` with a slot secret):

- [ ] `nip44_decrypt([somekey, ciphertext])` → **"unauthorised"** (was: returned
      plaintext — the oracle). A *bound* client (connected with a slot secret)
      still decrypts normally.
- [ ] `heartwood_derive` / `heartwood_derive_persona` from an unbound client →
      **"unauthorised"**; no new persona is written to NVS. A bound client still
      derives.
- [ ] Direct-USB (no relay client) encrypt/decrypt/derive still work — physical
      presence is unaffected.

## 4. ESP8266 first-flash POST (the long-standing gate)

- [ ] Flash the ESP8266 and watch the boot POST — `HARDWARE-TEST-CHECKLIST.md`
      §6. It recomputes the frozen crypto vectors on the real lx106 in the first
      second. If POST passes, the tethered signer tier is just plumbing.

## 4b. PIN-derived seed encryption (P5, opt-in — set only on a bench device)

**Have the 12-word phrase to hand first** — a forgotten PIN means wipe +
re-restore. On a device with a master already provisioned + unlocked:

- [ ] Set a PIN (SET_PIN frame / Sapwood PIN UI); approve with the button.
      Device reports "PIN set!".
- [ ] `esptool read_flash` the NVS region (or dump flash) and confirm the seed
      is NOT present in the clear — you should see the 92-byte encrypted blob
      (`master_0_secret_enc`), not the 32-byte plaintext seed.
- [ ] Power-cycle. Device boots to "PIN locked — await unlock" and refuses
      signing.
- [ ] Wrong PIN → "Wrong PIN, N left"; the counter persists across a reboot
      (power-cycle mid-attempts and confirm it doesn't reset). 5 wrong → wipe.
- [ ] Correct PIN → "Unlocked!", seeds decrypt into RAM, signing works, and the
      derived npub is unchanged (same account as before the PIN).
- [ ] Remove the PIN (empty SET_PIN, button-approved) → seed stored plaintext
      again, boots without a lock. (Confirms the opt-out path.)
- [ ] Note the availability trade-off: a PIN-protected Wi-Fi signer needs the
      PIN entered over USB to boot — it won't auto-rejoin relays after a power
      cut until unlocked (on-device PIN entry is the planned follow-on).

## 5. heartwood-bridge on a Pi/Linux box + USB signer

The `heartwood` repo retired the soft signer; the bridge is now the keyless
daemon. Prove it end to end:

- [ ] Provision a USB signer + its `bridge.secret` (Sapwood or the `provision`
      CLI). Install `heartwood-bridge` (release install.sh or Docker with
      `--device=/dev/ttyUSB0`).
- [ ] Set `HEARTWOOD_SERIAL_PORT` (+ relays); `bridge.secret` in the data dir.
      Start the service; it connects to relays and logs the master npub read
      over serial.
- [ ] Pair a Nostr app via its bunker URI and sign an event — the request routes
      relay → bridge → USB device → signature, with the key never leaving the
      device.

## On green

Tag `v0.10.1` (bump `firmware/Cargo.toml` first) → the release pipeline builds +
signs all boards. Then `npm run sync:firmware v0.10.1` in Sapwood.
