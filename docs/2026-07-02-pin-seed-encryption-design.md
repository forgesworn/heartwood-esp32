# PIN-derived seed encryption — design (P5)

The eFuse-free answer to device theft. This is a design + decisions doc, written
*after* the security audit (as the roadmap requires) so it targets the real
threat model. It proposes an approach and surfaces the choices that are yours to
make before I build it — because a couple of them change the product's feel and
one of them is a hard, honest limitation that has to be stated plainly, not
engineered away.

## Current state

- The master seed is stored **in plaintext** in NVS: `masters.rs` writes
  `master_<slot>_secret` as a raw blob. A flash dump (`esptool read_flash`)
  yields the 32-byte seed directly.
- The existing PIN (`pin.rs`) is **authentication only**: it's a SHA-256 hash
  compared at unlock, gating the application frame loop, with a 5-attempt
  persisted counter → NVS wipe. It does **not** protect the seed at rest — the
  ROM bootloader and a raw flash read bypass it entirely.
- `SECURITY-MODEL.md` already states this: "physical possession of the device
  equals full compromise of every key on it", accepted because eFuses are off
  the table.

P5 closes the *at-rest* half of that gap in software: encrypt the seed so a
flash dump yields ciphertext, and the PIN is what decrypts it.

## The honest limitation (read this first)

There is **no secure element** and (by your standing decision) **no eFuses**.
That means:

- The encryption key must be derived entirely from the PIN — the device has no
  hardware secret an attacker who owns the flash can't also read.
- So an attacker with a flash dump can **brute-force the PIN offline**. A
  4-digit PIN is 10⁴ candidates; even a 6-digit is 10⁶. A slow KDF raises the
  per-guess cost but cannot make an enumerable space safe.

**Conclusion:** PIN-seed-encryption raises the bar from "read the seed straight
off the flash" to "brute-force the PIN against a KDF." That is a real,
worthwhile uplift (a stolen device is no longer instant game-over), but it is
**not** hardware-wallet-grade at-rest security, and the doc/UX must say so. This
is consistent with the accepted no-eFuse posture — it's a mitigation, not a
guarantee.

## Proposed design

1. **KDF** — derive a 32-byte key from `PIN || per-device salt` with a
   deliberately slow function. Options: PBKDF2-HMAC-SHA256 with a high iteration
   count (simple, already have `hmac`+`sha2`), or Argon2id (memory-hard, best,
   but the ESP32's RAM budget caps the memory parameter — needs measuring). The
   salt is random, stored in NVS (it's not secret; it stops rainbow tables and
   makes each device's brute-force independent).
2. **Cipher** — encrypt the seed with ChaCha20-Poly1305 or AES-256-GCM (both
   already pullable via the `nip44`/`nip04` feature deps). AEAD so a wrong PIN
   fails the tag check cleanly (no ambiguous "is this the right seed?").
3. **NVS layout** — replace the plaintext `master_<slot>_secret` with
   `master_<slot>_secret_enc` = `salt || nonce || ciphertext || tag`. Migration:
   an existing plaintext seed is re-encrypted on first PIN set (or left as-is if
   the user never sets a PIN — see the opt-in decision).
4. **Boot flow** — on boot, if an encrypted seed exists, prompt for the PIN
   **on-device**, derive the key, decrypt into RAM (zeroised on lock/idle).
   Wrong PIN → AEAD failure → increment the existing attempt counter → wipe
   after N. The seed never exists in plaintext at rest again.
5. **On-device PIN entry** — reuse the button UX. On the **T-Display** this is
   the natural home for the new two-button picker: a digit picker (A = next
   digit, B = pick), which we just built the primitives for. Single-button
   boards enter the PIN with the gesture picker. Entering the PIN on-device (not
   from the host) is what makes it a theft mitigation rather than a host-trust
   one.

## Decisions for you

1. **PIN strength vs the audience bar.** A 4-digit PIN is kid-friendly but only
   ~10⁴ offline guesses. A 6-digit, or a short word-based passcode, is stronger
   but more to enter on buttons. My lean: **6-digit default, on-device entry**,
   with the doc stating the offline-brute-force reality. Your call on the length.
2. **Mandatory or opt-in.** Mandatory at-rest encryption is safest but changes
   the out-of-box flow (every device needs a PIN, and a forgotten PIN needs a
   phrase re-restore). Opt-in keeps the frictionless path for people who accept
   the physical-access gap. My lean: **opt-in**, prominently offered at setup
   (matches "the device is a shelf-HSM by default, carryable if you PIN it").
3. **KDF choice + cost.** PBKDF2 (simple, iteration-count tunable) vs Argon2id
   (memory-hard, better, RAM-limited on ESP32). Needs a boot-time measurement —
   how many seconds of KDF is acceptable at unlock? My lean: **PBKDF2 tuned to
   ~1–2 s on the slowest board**, revisit Argon2id if the RAM fits.
4. **Lost-PIN policy.** With the seed encrypted, a forgotten PIN = the keys are
   unrecoverable *from the device* — by design. The escape hatch is the 12-word
   phrase: re-restore on a wiped device. So the UX must **force a verified
   phrase backup before enabling the PIN** (you already have the restore path).
   Agree?
5. **Wrong-PIN policy.** Keep the existing 5-attempt → wipe? Against an *online*
   attacker that's good; against the *offline* flash-dump attacker the wipe is
   irrelevant (they brute-force the dump, not the device). So the counter is
   really an anti-shoulder-surf/anti-grab measure. Keep at 5, or make it
   configurable?

## Build plan (once the decisions land)

- `common/`: a host-testable `seed_cipher` module (KDF + AEAD wrap/unwrap) with
  vectors — same pattern as `ota_sign`, so the crypto is unit-tested off-device.
- `firmware/pin.rs` + `masters.rs`: store/read the encrypted blob; re-encrypt on
  PIN set; decrypt at boot.
- On-device PIN entry screens (digit picker, two-button on T-Display).
- `SECURITY-MODEL.md`: document the uplift **and** the offline-brute-force
  limitation honestly.
- Bench: set a PIN, power-cycle, confirm wrong PIN fails and right PIN unlocks;
  confirm a flash dump shows ciphertext, not the seed.

Tell me your calls on the five decisions (or just "your leans are fine") and I'll
build it.
