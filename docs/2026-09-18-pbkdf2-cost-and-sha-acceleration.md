# Sealed-seed KDF: is the SHA accelerated, and what should the cost be?

Investigation for #121, 2026-09-18. Branch `investigate/pbkdf2-cost`.
Follows on from `docs/2026-07-02-pin-seed-encryption-design.md`.
No device was flashed or contacted. No firmware behaviour was changed.

Everything below is read off the code, the pinned ESP-IDF v5.3.2 tree that
`firmware/.embuild` already holds, and host benchmarks of the exact pinned
crate versions. Where a number is an estimate rather than a measurement it
says so.

---

## 0. The short answer

**No. Nothing on the sealed-seed KDF path touches the ESP32-S3 SHA
accelerator.** It is pure-Rust `sha2` software, compiled for size, executing
from flash through a 16 KB instruction cache. mbedTLS is linked into the
image for TLS, and its hardware SHA is enabled, but the KDF never calls it.

The accelerator exists, is idle, and is between one and two orders of
magnitude faster than what the KDF is currently getting. Wiring it up plausibly
puts a 100,000-round unseal at roughly **1 s per slot instead of 29 s**, which
is the figure the constant's own doc comment asks for, **at the iteration count
we already ship**. If that holds on the bench, #121 closes with no protocol
change, no migration, and no security given up.

Separately, and more importantly for the threat model: the iteration count is
close to irrelevant against a numeric PIN once the flash is dumped. That is
argued with measured numbers in §4.

---

## 1. What the measurement says

### 1.1 Which implementation is compiled in

`common/src/seed_cipher.rs` line 81 is the whole story:

```rust
pbkdf2::pbkdf2_hmac::<Sha256>(pin, salt, iterations, &mut km);
```

Resolved from the lockfiles (`common/Cargo.lock`, `firmware/Cargo.lock`, both
agree):

| crate | version | features as built |
|---|---|---|
| `pbkdf2` | 0.12.2 | `default-features = false`, `hmac` |
| `hmac` | 0.12.1 | `default-features = false` |
| `sha2` | 0.10.9 | `default-features = false` |

`sha2` 0.10.9 picks its backend in `src/sha256.rs` with a `cfg_if` chain. The
arms are `force-soft-compact`, `force-soft`, `x86`/`x86_64`, `aarch64 + asm`,
`loongarch64 + asm`, else `soft`. There is no `target_arch = "xtensa"` arm and
no `riscv` arm, so **every board falls through to `soft`** - the portable Rust
compression function. No `asm` feature is requested anywhere in the tree, and
it would not help if it were: `sha2-asm` has no Xtensa or RISC-V backend.

There is no `esp-idf-sys` / mbedTLS call anywhere on this path. `grep` for
`pbkdf2` across the repo returns exactly one hit, the line above.

### 1.2 Optimisation level

`firmware/Cargo.toml` sets a workspace-wide release profile:

```toml
[profile.release]
opt-level = "z"
codegen-units = 1
```

There is no `[profile.release.package.sha2]` override, so the compression
function is built for size like everything else. That is deliberate and it is
also, on this chip, the *faster* choice - see §1.5.

### 1.3 Does esp-idf have SHA acceleration enabled

Yes, and it is irrelevant to this path.

`CONFIG_MBEDTLS_HARDWARE_SHA` is `default y` in
`components/mbedtls/Kconfig` and depends only on `SOC_SHA_SUPPORTED`, which
the S3 sets. None of the five `sdkconfig.defaults*` fragments mentions SHA at
all, so the default stands and mbedTLS on this image hashes in hardware.

`components/soc/esp32s3/include/soc/soc_caps.h` sets `SOC_SHA_SUPPORT_DMA`,
so the S3 compiles `components/mbedtls/port/sha/dma/`. That is the port TLS
uses for certificate chains and record MACs. The Rust KDF never enters it.

So the accelerator is powered, configured and used by the TLS half of the
firmware, while the seed unseal grinds beside it in software.

### 1.4 The arithmetic

`derive_km` asks for 64 bytes of output, which is **two** PBKDF2 output
blocks. Each PBKDF2 iteration is one HMAC-SHA256, which with precomputed
ipad/opad states is **two** SHA-256 compressions. So:

```
compressions per derive_km = iterations x 2 output blocks x 2 compressions
                           = 4 x iterations
at 100,000 iterations      = 400,000 compressions
                           = 400,000 x 64 B = 25.6 MB of SHA-256 input
```

Against the recorded bench figure of ~29 s per slot on a V4 at 240 MHz
(#121 comment, post-#122, `ACK in 86.9s` for three masters):

```
29 s / 400,000 compressions = 72.5 us per 64-byte compression
72.5 us x 240e6 Hz          = 17,400 CPU cycles per compression
25.6 MB / 29 s              = 0.88 MB/s effective SHA-256 rate
```

**17,400 cycles to hash 64 bytes.** SHA-256 is 64 rounds of roughly 20 to 30
32-bit instructions plus the message schedule - call it 2,000 to 3,000 cycles
on an in-order 32-bit core executing from cache. The measured figure is
**six to nine times** that. The gap is not instruction selection. It is stall.

Espressif's own CI floor for the same chip, hashing in hardware, is in
`components/idf_test/include/esp32s3/idf_performance_target.h`:

```c
// SHA256 hardware throughput at 240MHz, threshold set lower than worst case
#define IDF_PERFORMANCE_MIN_SHA256_THROUGHPUT_MBSEC   90
```

90 MB/s versus our 0.88 MB/s is **102x**. Read that as a bound on the
peripheral, not a promise: `components/mbedtls/test_apps/main/test_sha_perf.c`
measures it over 256 calls of 16 KB from DMA-capable internal RAM - one lock
acquisition, 256 blocks per DMA burst, no per-block state save. Our pattern is
the opposite (§2.2). 90 MB/s works out to 171 cycles per 64-byte block, which
is the floor the realistic estimate below sits above.

### 1.5 The opt-level result, and why it redirects everything

Already on the issue, and it is the load-bearing measurement. Forcing
`opt-level = 3` on `sha2`/`hmac`/`pbkdf2` added 34,672 bytes and made a single
slot exceed the 60 s task watchdog, i.e. **more than twice as slow**, from
byte-identical source. The only mechanism that explains code getting slower by
being unrolled is that it stopped fitting the instruction cache.

The S3's instruction cache default is confirmed in
`components/esp_system/port/soc/esp32s3/Kconfig.cache`:

```
choice ESP32S3_INSTRUCTION_CACHE_SIZE
    default ESP32S3_INSTRUCTION_CACHE_16KB
```

**16 KB**, 8-way, 32-byte lines. The repo sets none of these, so 16 KB stands.
Everything the KDF loop touches is fetched from external flash through that
16 KB.

A second, quieter corroboration: #122 raised the V4 from 160 to 240 MHz, a
1.5x clock increase, and the per-slot figure went from ~25 s to ~29 s - it did
not improve. A compute-bound loop cannot ignore a 50% clock rise. A loop
waiting on flash through a cache can, because the SPI flash clock did not move.

### 1.6 Host benchmark, same crate versions

`pbkdf2` 0.12.2 / `hmac` 0.12.1 / `sha2` 0.10.9, on an 8-core arm64 laptop,
`derive_km` shape (64-byte output, 100,000 iterations):

| build | time for 100k iterations | per compression |
|---|---|---|
| `opt-level = 3`, `force-soft` | 189 ms | 0.47 us |
| `opt-level = "z"`, `codegen-units = 1`, `force-soft` | 243 ms | 0.61 us |
| `opt-level = 3`, arm64 SHA2 instructions | 111 ms | 0.28 us |

The device is **119x** slower than the third-row-equivalent software build.
Clock alone accounts for roughly 19x and a wide out-of-order core maybe 3-4x
more, so perhaps 60-75x is "expected". The rest is the stall §1.5 identified.
Treat this row as corroboration, not proof; §1.5 is the proof.

---

## 2. The hardware path: does one exist, and what would it take

### 2.1 It exists and it is reachable from Rust

`components/mbedtls/port/include/sha/sha_dma.h` is a **public** port header.
It declares, among others:

```c
void esp_sha_acquire_hardware(void);
void esp_sha_release_hardware(void);
void esp_sha_write_digest_state(esp_sha_type sha_type, void *digest_state);
void esp_sha_read_digest_state(esp_sha_type sha_type, void *digest_state);
int  esp_sha_dma(esp_sha_type, const void *input, uint32_t ilen,
                 const void *buf, uint32_t buf_len, bool is_first_block);
```

That write/read digest-state pair is exactly what PBKDF2 needs: it lets you
load a saved SHA-256 midstate (the precomputed ipad or opad state) into the
peripheral, hash one block, and read the state back out. Without it the
accelerator would be useless here, because every HMAC starts from a keyed
midstate rather than from the IV.

### 2.2 The shape that would be wrong

The obvious wiring - call `mbedtls_internal_sha256_process` once per
compression - would very likely be **slower than the software we have**.
`components/mbedtls/port/sha/dma/esp_sha256.c` does this *per 64-byte block*:

```c
esp_sha_acquire_hardware();          /* takes a FreeRTOS mutex,
                                        enables the crypto bus clock,
                                        resets the SHA register block */
esp_internal_sha_update_state(ctx);  /* 8 word writes (digest state) */
esp_sha_dma(ctx->mode, data, 64, 0, 0, ctx->first_block);
esp_sha_read_digest_state(ctx->mode, ctx->state);   /* 8 word reads */
esp_sha_release_hardware();          /* gates the bus clock, gives the mutex */
```

A mutex take/give plus a peripheral clock gate and register-block reset,
400,000 times, is a lot of ceremony around 64 cycles of hashing. (Note also
that for a 64-byte input `esp_sha_dma` does not use DMA at all: it checks
`s_check_dma_capable(input)` and falls through to `esp_sha_block_mode`, which
calls `sha_hal_hash_block` directly. So the "DMA port" hashes our blocks
CPU-fed anyway.)

### 2.3 The shape that would be right

Acquire once per work unit, then drive `sha_hal_hash_block`-equivalent calls
in a tight loop, carrying the two midstates in registers/stack:

```
esp_sha_acquire_hardware()
for each PBKDF2 iteration:
    write ipad midstate (8 words)
    fill text block     (16 words)
    continue_block; wait idle          # ~64 accelerator cycles
    read digest state   (8 words)      # = inner hash
    write opad midstate (8 words)
    fill text block     (16 words)
    continue_block; wait idle
    read digest state   (8 words)      # = outer hash = next U
    XOR into the accumulator
esp_sha_release_hardware()
```

Per compression: ~25 register writes, ~8 register reads, ~64 accelerator
cycles, plus loop overhead. Peripheral register traffic on the S3 costs a
handful of cycles per access (writes are buffered, reads stall).

**Estimate, explicitly an estimate:**

| cycles/compression assumed | 400,000 compressions | wall clock at 240 MHz |
|---|---|---|
| 400 (optimistic) | 1.6e8 | **0.67 s** |
| 700 (realistic) | 2.8e8 | **1.17 s** |
| 1,200 (pessimistic) | 4.8e8 | **2.0 s** |
| 17,400 (today, software) | 7.0e9 | 29 s |

So **0.7 s to 2.0 s per slot at the unchanged 100,000 iterations**, a 15x to
40x improvement. The sanity check: 700 cycles/block is 4x Espressif's bulk-DMA
figure of 171, which is the right direction and the right order for a pattern
that saves and restores the digest state on every single block.

This is the number the bench has to confirm. It is a range, not a promise.

### 2.4 Risks

**Concurrent use by TLS, and this one is real.** On the S3 the lock is
`SHA_LOCK() = esp_crypto_sha_aes_lock_acquire()` - it is the **shared SHA and
AES** lock, not a SHA-only one. Holding it for a second blocks every TLS
record MAC *and* every AES operation on the device. That matters specifically
because of the WiFi-standalone locked-boot flow: a locked board announces its
ephemeral unlock pubkey (kind 24135) and receives the vault key live (kind
24136) over TLS, so TLS is running *during* the unseal in that tier. Mitigation
is to acquire and release per PBKDF2 output block, or per chunk of a few
thousand iterations, yielding between chunks - which the code must do anyway
for the watchdog (§2.5). Do not hold the lock across a whole `derive_km`.

**Watchdog.** `CONFIG_ESP_TASK_WDT_TIMEOUT_S=60` with idle-task monitoring.
`firmware/src/pin.rs` currently yields *between* slots, not inside the KDF,
which is fine at 29 s and would be fine at 1 s. A chunked hardware loop must
keep feeding.

**Derivation parity is non-negotiable.** A hardware SHA-256 must produce
byte-identical output. The gate is a host test that runs a table of
(pin, salt, iterations) vectors through both the existing `pbkdf2_hmac` path
and the new one, plus the existing `legacy_blob_still_unlocks_at_the_legacy_cost`
test. A wrong derivation is the one genuinely dangerous failure here; the
watchdog reboot in the opt-level experiment was benign precisely because
derivation did not change.

**Cross-board.** Only the S3 boards get this shape. The classic ESP32
(T-Display) uses `SOC_SHA_SUPPORT_PARALLEL_ENG`, a different port with a
markedly lower floor (`esp32/idf_performance_target.h` sets 6.0 or 8.0 MB/s,
versus the S3's 90). The C6 is `SOC_SHA_SUPPORT_DMA` like the S3. Any
implementation must keep the pure-Rust path as the fallback for boards without
a wired-up accelerator, selected at compile time, with the parity test run on
both.

**Code size.** Unknown until built; likely small (a few hundred bytes of loop
against 34 KB for the unrolling experiment), but the 2 MB OTA slot has roughly
11 KB of headroom on CI's numbers, so it must be measured before merge.

### 2.5 The cheaper experiment to run first

Before writing any crypto, two sdkconfig lines test the §1.5 diagnosis
directly and cost nothing but a rebuild:

```
CONFIG_ESP32S3_INSTRUCTION_CACHE_32KB=y
CONFIG_ESP32S3_INSTRUCTION_CACHE_LINE_32B=y   # already the default
```

Doubling the instruction cache from 16 KB to 32 KB costs 16 KB of heap, which
this firmware has already shown it is short of (the `CONFIG_MBEDTLS_DYNAMIC_BUFFER`
comment documents a ~180 KB heap that fragments under load). So it may not be
keepable. But as a *diagnostic* it is decisive: if the unseal time drops
materially, the bottleneck is confirmed as instruction fetch, and the hardware
path is confirmed as the right fix rather than a guess. If it does not move,
the model in §1.5 is wrong and this note needs revisiting before anyone writes
the accelerator loop.

Order of work: cache-size diagnostic, then hardware SHA behind a parity gate,
then re-measure, then and only then revisit the constant.

---

## 3. The blob-format escape hatch

**This already landed.** #155 (`fix: version sealed seed KDF cost`, 2026-09-15)
implemented exactly what the issue proposed as option 1. It is on `main`. This
section records what shipped rather than proposing it, and confirms the read
and write sites are complete.

### 3.1 The encoding as shipped

```
legacy (92 B, immutable):  salt(16) || nonce(12) || ct(32) || tag(32)
current (101 B):           magic "HWSC"(4) || version(1) || rounds(4, big-endian)
                           || salt(16) || nonce(12) || ct(32) || tag(32)
```

The dispatch in `decrypt_seed` is on length alone:

- 92 bytes: `LEGACY_PBKDF2_ITERATIONS` (100,000), permanently pinned, MAC over
  `nonce || ct` as before.
- 101 bytes: magic and version checked, `rounds` parsed and range-checked
  against `MAX_PBKDF2_ITERATIONS`, MAC over `header || nonce || ct`.
- anything else: `BadLength`.

Three details worth keeping:

1. `LEGACY_PBKDF2_ITERATIONS` is a *separate constant* from
   `PBKDF2_ITERATIONS`. A future retune moves the latter and must never move
   the former. Today they happen to be equal, which is the one way this could
   be got wrong later.
2. The header is **authenticated** - it is fed to the MAC. A flipped bit in
   the rounds field fails the tag rather than silently unsealing at a different
   cost. Tested by `current_blob_authenticates_its_cost_and_format`.
3. `is_blob_len()` is the single length predicate, and both lengths are
   accepted everywhere.

### 3.2 Every read and write site

Verified by grep across the whole repo and the Sapwood checkout.

| site | what it does | already correct |
|---|---|---|
| `common/src/seed_cipher.rs` | the codec itself | yes |
| `firmware/src/masters.rs:71` | `read_secret_enc`, gated on `is_blob_len` | yes, both lengths |
| `firmware/src/masters.rs:90` | locked-slot scan, gated on `is_blob_len` | yes |
| `firmware/src/masters.rs:103` | `SEED_ENC_MAX_LEN = MAX_BLOB_LEN` (101) | yes |
| `firmware/src/pin.rs:121,126` | seal + self-check on enable | yes, via `encrypt_seed` |
| `firmware/src/pin.rs:181` | `try_unlock` per slot | yes, via `decrypt_seed` |
| `firmware/src/notes.rs:795` | `[u8; MAX_BLOB_LEN]` read buffer for `nk` | yes |
| `firmware/src/notes.rs:804,825,830,857,860` | note-key wrap/unwrap/self-check | yes |

**Sapwood does not parse the blob.** `src/lib/vault.ts:124` and
`src/lib/device.svelte.ts:2436` only reference the *duration* (a comment
recording the measurement, and a 200 s client timeout that covers the slowest
path). Both are upper bounds; a faster KDF cannot break them. Nothing in
Sapwood knows the blob is 92 or 101 bytes.

**heartwoodd does not parse it either.** `backend/serial.rs:486` is a comment
about how long a frame may take. heartwoodd's own at-rest encryption is a
separate Argon2id + XChaCha20-Poly1305 keyfile and shares no format with this.

**`common/src/note_seal.rs` is unaffected.** It has its own `HWNS` format with
no KDF at all (the note key is full-entropy random, so there is nothing to
stretch). Only the `nk` *wrap* of that key goes through `seed_cipher`, and it
goes through the same `encrypt_seed`/`decrypt_seed` pair as a master seed.

So: the escape hatch is complete, and nothing outside `common` and `firmware`
has to change when `PBKDF2_ITERATIONS` moves. There is no migration to write.

### 3.3 One defect found in the shipped version

`MAX_PBKDF2_ITERATIONS = 1_000_000` does not do the job its comment claims:

> Refuse a corrupted header before it can turn an unlock attempt into an
> arbitrary-length CPU burn.

At the current software speed, 1,000,000 iterations is **290 s** on a V4. The
task watchdog fires at 60 s and `try_unlock` yields only *between* slots, never
inside a KDF. So a blob whose rounds field is corrupted to any value above
roughly 200,000 is a watchdog reboot loop, and the board never gets far enough
to report a bad PIN.

Worse, the check cannot be fixed by authentication: the MAC over the header can
only be verified *after* the KDF has run, so the rounds field is attacker- or
corruption-chosen work performed before anything is authenticated. That is
inherent to the construction and it is why the ceiling matters.

The ceiling should be tied to what one slot can complete inside the watchdog
window with margin, on the *slowest* board, at whatever the then-current speed
is - not left at a round number. At today's speed that is roughly 100,000. If
the hardware path lands, it rises with it. This is a small, self-contained fix
and does not need to wait for the rest.

---

## 4. Recommended target count, against the stated threat model

### 4.1 What the count actually buys

The threat model from the issue: no stored PIN hash, the AEAD tag is the only
check, a flash dump means offline brute force of a 4 to 8 digit PIN.

One detail nobody has written down: **the attacker's work is half the
defender's.** The tag is verified with `mac_key = km[32..64]`, which is PBKDF2
output block 2. Output blocks are independent, so an attacker computes block 2
alone - 200,000 compressions per guess - and only bothers with block 1 on the
one guess that verifies. The device pays 400,000 for both. Every "cost per
guess" figure below is therefore half what the device pays, by construction.

Measured on an 8-core arm64 laptop, 32-byte output, 100,000 iterations, with
the same crate versions:

```
69.5 ms per guess per core  ->  14.4 guesses/s/core
8 cores at ~80% scaling     ->  92 guesses/s
```

| PIN space | laptop, one machine | one modern GPU (~20 GH/s raw SHA-256) |
|---|---|---|
| 4 digits (1e4) | **109 s** | well under a second |
| 6 digits (1e6) | **3.0 hours** | ~10 s |
| 8 digits (1e8) | **12.6 days** | ~17 minutes |

The GPU column is an order-of-magnitude extrapolation from published raw
SHA-256 rates (20e9 / 200,000 = ~100,000 guesses/s), not a measurement. It does
not need to be precise to make the point.

### 4.2 What that means

A 4-digit PIN is gone in under two minutes on a laptop that is not even trying.
A 6-digit PIN is an afternoon. Raising the count tenfold to 1,000,000 moves
6-digit from 3 hours to 30 hours on that same laptop, and from 10 seconds to
100 seconds on a GPU. Lowering it to 10,000 moves 6-digit to 18 minutes on the
laptop.

**Every one of those outcomes is "lost".** The iteration count is not the axis
that decides this. PBKDF2-HMAC-SHA256 is cheap to parallelise and has no memory
hardness, so the attacker's advantage scales with hardware and the defender's
does not. The design doc's own honest limitation - "a real uplift, not
hardware-wallet-grade" - is understated: against a numeric PIN and a flash
dump, it is a speed bump whose height barely matters.

Note the vault-key path is entirely different and entirely fine: a 32-byte
host-held random secret is unguessable at *one* iteration. The KDF there is
pure ceremony, and it costs the operator 29 s per slot for nothing at all.

### 4.3 The recommendation

**Keep `PBKDF2_ITERATIONS` at 100,000. Do not lower it. Do not raise it. Fix
the speed instead.**

The reasoning:

- Lowering it is the only option on the table that costs security, and §4.1
  shows it buys the operator seconds that the hardware path gives back by the
  tens of seconds. It would be trading the one axis we have for a fraction of
  a fix.
- Raising it does not reach a threshold that changes any attacker's plan, and
  every extra round is paid in full by the owner at every unlock.
- 100,000 is a defensible, conventional figure that matches what the rest of
  the ecosystem uses for PBKDF2-HMAC-SHA256, and it is what is already in the
  field. Leaving it alone means the legacy and current blobs share a cost and
  the `LEGACY_PBKDF2_ITERATIONS` divergence trap in §3.1 stays closed.
- If §2.3's estimate holds, 100,000 *is* the tuned value: 0.7 to 2.0 s per
  slot is precisely the "1-2 s on the slowest board" the doc comment asks for.
  The constant was never wrong. The implementation was.

Projected seconds per slot at 100,000 iterations, to be confirmed on the bench:

| board | today (software) | with hardware SHA (estimated) |
|---|---|---|
| Heltec V4 (S3, 240 MHz) | ~29 s (measured) | 0.7 - 2 s |
| Heltec V3 (S3, 160 MHz default) | ~29-44 s (not measured) | 1 - 3 s |
| C6 (RISC-V, DMA SHA port) | not measured | 1 - 3 s |
| T-Display (classic ESP32, parallel-engine port) | not measured | 3 - 15 s |

A three-master board pays that per sealed slot, plus **one more** if the note
locker is enabled (the `nk` wrap is a full extra `derive_km`). So a
three-master board with the locker is four runs, not three - the recorded
86.9 s was three slots with the locker off.

The T-Display row is the one that could still force a per-board count. The
header now supports that, and seed blobs never travel between boards (backups
carry slots and policies, never seeds), so a per-board constant would be safe.
Do not introduce one on speculation - only if a measurement demands it.

### 4.4 The change that would actually move the threat model

Out of scope for #121, but it should be written down because #121 keeps
circling it. The fix for §4.1 is not the count. It is one of:

- **A memory-hard KDF.** Argon2id destroys the GPU advantage that makes the
  table in §4.1 hopeless. heartwoodd already uses Argon2id for its keyfile and
  for encrypted backups, so the ecosystem has already made this choice once.
  The new versioned header makes it a **format version 2** with no migration:
  old blobs keep decrypting at PBKDF2/100k forever, new ones use Argon2id.
  This is the single strongest argument for #155 having been worth doing.
  Cost: memory, on a board with ~180 KB of fragmented heap. That is the whole
  question and it needs its own investigation.
- **A larger secret.** Allowing an alphanumeric passphrase rather than 4 to 8
  digits changes the exponent, which is worth more than any change to the
  multiplier.
- **Accepting it.** The 5-failure wipe already protects the on-device path,
  and the security model already says physical security is the model. If the
  answer is "a flash dump is game over and the KDF is a speed bump", that is a
  legitimate position - but then the count should be tuned purely for operator
  comfort, and §4.3's reasoning changes.

That is a concept-rung decision, not a tuning one.

---

## 5. What I would not do, and why

1. **Not lower the iteration count.** It is the only option that spends
   security, and it buys a fraction of what §2 buys for free. If §2 fails on
   the bench this comes back on the table; until then it is the wrong lever.

2. **Not re-encrypt or migrate existing blobs.** #155 made this unnecessary,
   and a torn migration is the one way this subsystem can lose a seed. There
   is no scenario in this note that requires touching a blob already on flash.

3. **Not call `mbedtls_internal_sha256_process` per compression.** §2.2:
   mutex, bus-clock gate and register-block reset per 64 bytes. 400,000 of
   those is plausibly slower than the software path we already have. If the
   hardware path is done, it is done with one acquire per chunk.

4. **Not hold the SHA lock across a whole `derive_km`.** §2.4: on the S3 it is
   the shared SHA *and AES* lock, and a locked WiFi-standalone board is doing
   TLS at exactly that moment to receive its vault key.

5. **Not replace `sha2` globally.** Only the PBKDF2 inner loop should change.
   Event-ID hashing, the NIP-44 HKDF, the nsec-tree derivation and the OTA
   digest keep the audited pure-Rust path. The frozen derivation vector in
   `common/src/derive.rs` must remain untouched and must keep passing.

6. **Not touch `opt-level` again.** Already measured, already reverted,
   already counter-intuitive. `opt-level = "z"` is the faster choice on this
   chip and the issue comment explains why. Anyone reaching for it again
   should read §1.5 first.

7. **Not set per-board iteration counts on speculation.** The header supports
   it; nothing yet demands it.

8. **Not flash anything.** Everything above is from source, from the pinned
   ESP-IDF tree, and from host benchmarks. The bench steps in §2.5 need a
   board and an operator, and that is a separate, deliberate act.

---

## 6. What the operator has to decide

1. **Run the §2.5 cache diagnostic?** One sdkconfig line, one build, one
   unlock timing. It either confirms or refutes the whole model in this note
   and costs nothing but bench time. Recommended: yes, first.

2. **Commit to the hardware SHA path?** It is new crypto-adjacent code on the
   function that protects every seed. It needs a parity gate, a size check
   against the OTA slot, and a fallback for boards without it. The payoff is
   29 s to ~1 s with no protocol change and no security given up. Recommended:
   yes, after (1), behind the parity gate.

3. **Leave the count at 100,000?** This note recommends yes, and that #121
   closes on speed rather than cost. The alternative view - that 25 s is
   unacceptable *today* and the count should drop now while the hardware work
   is pending - is coherent, but it spends the only security axis available to
   buy something (1) and (2) may deliver within the same bench session.

4. **Fix `MAX_PBKDF2_ITERATIONS`?** §3.3 is a real defect: the ceiling is
   three to five times higher than the watchdog can survive. Small, isolated,
   independent of everything else here. Recommended: yes, separately.

5. **Open the Argon2id question?** §4.4. Concept rung, its own investigation,
   and the honest answer to the threat model this issue states. Not part of
   #121.
