// firmware/src/sha_accel.rs
//
// The sealed-seed KDF on the chip's SHA accelerator.
//
// Background and measurements: docs/2026-09-18-pbkdf2-cost-and-sha-acceleration.md.
// `derive_km` is 400,000 SHA-256 compressions. In pure-Rust software on this
// board each one costs about 17,400 cycles: it is stalling on instruction
// fetch through a 16 KB cache rather than computing, so one sealed slot takes ~29 s
// and a three-master board takes a minute and a half. The ESP32-S3 and C6 both
// carry a SHA accelerator that mbedTLS already drives for TLS, and it sits idle
// through every unseal.
//
// What this module does NOT change: the answer. Byte-identical output is the
// hard requirement, because a sealed seed that stops opening is lost keys. The
// PBKDF2 and HMAC state handling lives in `heartwood_common::kdf`, is host-
// tested against RFC-shape vectors and against the `pbkdf2` crate over a
// spread of PINs, salts and round counts, and is exercised there behind the
// same [`Sha256Engine`] trait this module implements. All that is new here is
// the compression function and the locking around it.
//
// Three guards sit between the accelerator and a key:
//
//   1. **Self-check.** Before the first real derivation after boot, the chosen
//      engine runs a known-answer vector whose constant was verified against
//      the reference implementation on the host. A mismatch is logged, the
//      session drops to software, and no hardware-derived key is ever used.
//   2. **Bounded lock hold.** On the S3 the SHA lock is the *shared SHA and
//      AES* lock, and a WiFi-standalone board can be mid-TLS during an unseal
//      (that is exactly how a locked board receives its vault key). The lock is
//      taken and released around each chunk of `kdf::CHUNK_ROUNDS` rounds,
//      about 512 compressions or roughly 1.5 ms, never across a whole
//      derivation. Nothing else is held while it is taken, so no lock cycle
//      exists and a deadlock is not possible; a TLS record MAC waits for one
//      chunk at worst.
//   3. **Contention retreat.** If an acquire takes longer than
//      `CONTENDED_ACQUIRE_US`, something else is hammering the peripheral. The
//      derivation finishes in software rather than fighting for it. Slower, but
//      it holds nothing and produces the same bytes.
//
// Boards without an accelerated path (the classic ESP32 T-Display, whose SHA
// is the parallel-engine block with no digest-state resume, and the ESP8266,
// which has no accelerator at all) compile none of the hardware code and run
// the same driver over the software compression function. They still gain the
// in-loop watchdog feed and yield.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use heartwood_common::kdf::{self, Block, Sha256Engine};

/// Feed the watchdog every chunk, but only give up the CPU this often. A
/// FreeRTOS tick is 10 ms, so yielding per chunk would cost far more than the
/// work itself; yielding on a time budget keeps the overhead near 4%.
const YIELD_INTERVAL_US: i64 = 250_000;

/// An acquire slower than this means the shared SHA/AES lock is genuinely
/// contended, so this chunk runs in software instead of queueing behind TLS.
///
/// 5 ms is generous by two orders of magnitude for a legitimate holder: a TLS
/// record MAC is microseconds, and even a 16 KB bulk hash through the DMA port
/// at Espressif's own 90 MB/s floor is about 180 us. A wait above this means
/// something is genuinely sitting on the peripheral, not that TLS is busy.
/// The retreat is now per CHUNK, not per derivation, so tripping it costs one
/// chunk rather than the rest of the unseal; `max_acquire_ms` in the telemetry
/// is there so this number can be tuned from a bench run instead of guessed.
const CONTENDED_ACQUIRE_US: i64 = 5_000;

// ---------------------------------------------------------------------------
// ESP-IDF SHA port
// ---------------------------------------------------------------------------

#[cfg(feature = "sha-accel")]
mod hw {
    use core::ffi::c_void;

    /// `SHA2_256` in ESP-IDF's `esp_sha_type` (`rom/sha.h`). The enum is
    /// `SHA1 = 0, SHA2_224, SHA2_256, …` on every target with a resumable SHA
    /// (S3, C6); the classic ESP32's different numbering never reaches here
    /// because that board does not build this module.
    pub const SHA2_256: u32 = 2;

    // These are ESP-IDF's mbedTLS SHA port and HAL. They are not in
    // esp-idf-sys's generated bindings, but they are in the image already,
    // because TLS drives the same code, so declaring them is a link, not a new
    // component. `esp_sha_{acquire,release}_hardware` and
    // `esp_sha_{read,write}_digest_state` are declared in the public port
    // header `sha/sha_dma.h`; `sha_hal_hash_block` is the HAL block step that
    // the port's own non-DMA path calls.
    //
    // `sha_hal_hash_block` rather than `esp_sha_dma`: for a single 64-byte
    // block from internal RAM, `esp_sha_dma` builds a DMA descriptor, syncs
    // caches and starts the shared GDMA, which is far more ceremony than the
    // 64 accelerator cycles it would be wrapping.
    extern "C" {
        pub fn esp_sha_acquire_hardware();
        pub fn esp_sha_release_hardware();
        pub fn esp_sha_write_digest_state(sha_type: u32, digest_state: *mut c_void);
        pub fn esp_sha_read_digest_state(sha_type: u32, digest_state: *mut c_void);
        pub fn sha_hal_hash_block(
            sha_type: u32,
            data_block: *const c_void,
            block_word_len: usize,
            first_block: bool,
        );
    }
}

/// Whether this build has a wired-up accelerator at all.
pub const fn accelerator_available() -> bool {
    cfg!(feature = "sha-accel")
}

fn now_us() -> i64 {
    unsafe { esp_idf_svc::sys::esp_timer_get_time() }
}

// Thin shims so the engine below has no `cfg` in its control flow: on a board
// without the peripheral these are dead code that is never reached, because
// `DeviceEngine::hardware` can only be true when the feature is on.

#[cfg(feature = "sha-accel")]
fn hw_acquire() {
    unsafe { hw::esp_sha_acquire_hardware() }
}

#[cfg(not(feature = "sha-accel"))]
fn hw_acquire() {}

/// Release the peripheral, scrubbing the digest registers first.
///
/// Those registers still hold the last HMAC midstate when a chunk ends, and a
/// midstate under the PIN-derived key is key-equivalent: anything that can
/// acquire the SHA block could read it out. Overwriting with the SHA-256 IV
/// costs eight register writes per release, so about 6,300 writes across a
/// 100,000-round derivation: tens of microseconds against roughly a second of
/// work, and it is not on the hot inner path at all.
#[cfg(feature = "sha-accel")]
fn hw_release() {
    let mut scrub = kdf::SHA256_IV;
    unsafe {
        // The engine is idle here: every compression ends in a digest read,
        // which waits for idle itself.
        hw::esp_sha_write_digest_state(hw::SHA2_256, scrub.as_mut_ptr().cast());
        hw::esp_sha_release_hardware();
    }
}

#[cfg(not(feature = "sha-accel"))]
fn hw_release() {}

/// One SHA-256 compression on the accelerator, continuing from `state`.
#[cfg(feature = "sha-accel")]
fn hw_compress(state: &mut [u32; 8], block: &Block) {
    // `Block` is `align(4)`: ESP-IDF's register fill reads the caller's buffer
    // with 32-bit loads, and an unaligned 32-bit load on Xtensa is the fault
    // class that made k256 unusable on this chip.
    debug_assert_eq!(block.0.as_ptr() as usize % 4, 0);
    unsafe {
        // Load the saved midstate, hash one block continuing from it
        // (`first_block = false`, so the engine does not reset to the IV), and
        // read the new midstate back. `esp_sha_read_digest_state` waits for
        // idle itself.
        hw::esp_sha_write_digest_state(hw::SHA2_256, state.as_mut_ptr().cast());
        hw::sha_hal_hash_block(hw::SHA2_256, block.0.as_ptr().cast(), 16, false);
        hw::esp_sha_read_digest_state(hw::SHA2_256, state.as_mut_ptr().cast());
    }
    // A deliberately wrong answer, for the bench step that proves the
    // self-check catches one. Opt-in at build time; normal images never
    // compile it.
    #[cfg(feature = "sha-selfcheck-fail")]
    {
        state[0] ^= 1;
    }
}

#[cfg(not(feature = "sha-accel"))]
fn hw_compress(state: &mut [u32; 8], block: &Block) {
    kdf::soft_compress(state, block);
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// A [`Sha256Engine`] for this board: the accelerator when it is available and
/// trusted, the portable software compression function otherwise, with the
/// watchdog fed and the CPU yielded on chunk boundaries either way.
pub struct DeviceEngine {
    /// The session's mode says hardware, and this board has some.
    hw_allowed: bool,
    /// This chunk holds the accelerator. False outside a chunk, and false for
    /// a chunk that retreated.
    chunk_hw: bool,
    held: bool,
    /// No chunk of this derivation retreated.
    all_hw: bool,
    last_yield_us: i64,
}

impl DeviceEngine {
    /// `hardware` is honoured only if this build actually has the peripheral.
    pub fn new(hardware: bool) -> Self {
        DeviceEngine {
            hw_allowed: hardware && accelerator_available(),
            chunk_hw: false,
            held: false,
            all_hw: true,
            last_yield_us: now_us(),
        }
    }

    /// True if every chunk of the derivation just run stayed on the hardware.
    pub fn stayed_in_hardware(&self) -> bool {
        self.hw_allowed && self.all_hw
    }
}

impl Sha256Engine for DeviceEngine {
    fn compress(&mut self, state: &mut [u32; 8], block: &Block) {
        if self.chunk_hw {
            hw_compress(state, block);
        } else {
            // Also the HMAC pad precompute, which happens outside any chunk:
            // two compressions out of 400,002, not worth an acquire.
            kdf::soft_compress(state, block);
        }
    }

    fn begin_chunk(&mut self) {
        CHUNKS.fetch_add(1, Ordering::Relaxed);
        if !self.hw_allowed {
            return;
        }
        let before = now_us();
        hw_acquire();
        let waited = (now_us() - before).clamp(0, u32::MAX as i64) as u32;
        // Plain load/store rather than `fetch_max`: this is a telemetry
        // high-water mark, a lost update between two tasks costs nothing, and
        // the Xtensa backend expands an `atomicrmw umax` into a CAS loop whose
        // temporary labels it then fails to assemble here.
        if waited > MAX_ACQUIRE_US.load(Ordering::Relaxed) {
            MAX_ACQUIRE_US.store(waited, Ordering::Relaxed);
        }
        if waited as i64 > CONTENDED_ACQUIRE_US {
            // Something is sitting on the shared SHA/AES lock. Give it back at
            // once and do this chunk in software; the next chunk tries again,
            // so one long TLS hold no longer costs the whole derivation.
            hw_release();
            self.chunk_hw = false;
            self.all_hw = false;
            RETREATS.fetch_add(1, Ordering::Relaxed);
        } else {
            self.held = true;
            self.chunk_hw = true;
        }
    }

    fn end_chunk(&mut self) {
        if self.held {
            hw_release();
            self.held = false;
        }
        self.chunk_hw = false;

        // The unseal path used to yield only between slots, which was fine at
        // 29 s a slot and is fine at 1 s, but a large or corrupted round count
        // should not be able to starve the idle tasks either.
        crate::wdt::feed();
        let now = now_us();
        if now - self.last_yield_us >= YIELD_INTERVAL_US {
            self.last_yield_us = now;
            esp_idf_hal::delay::FreeRtos::delay_ms(1);
        }
    }
}

impl Drop for DeviceEngine {
    fn drop(&mut self) {
        // Belt and braces: an early return or a panic between begin_chunk and
        // end_chunk must not leave the shared SHA/AES lock held, or TLS stops
        // for good.
        if self.held {
            hw_release();
            self.held = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Mode selection and the boot-time self-check
// ---------------------------------------------------------------------------

const MODE_UNTESTED: u8 = 0;
const MODE_HARDWARE: u8 = 1;
/// Accelerator present and correct, but the software path measured faster.
const MODE_SOFTWARE: u8 = 2;
/// Accelerator present and WRONG. Never used again this session.
const MODE_SELFCHECK_FAILED: u8 = 3;
/// This board has no accelerated path at all.
const MODE_NO_ACCEL: u8 = 4;

static MODE: AtomicU8 = AtomicU8::new(MODE_UNTESTED);

// Telemetry. Counters only: no secret, no per-PIN datum, nothing that depends
// on what was derived. The Heltecs ship with the log console compiled out, so
// without these there is no way at all to tell which path a board actually
// ran, and the first bench run of the accelerator could not be read.
static SELFCHECK_HW: AtomicU8 = AtomicU8::new(0); // 0 untried, 1 pass, 2 fail
static HW_SELFCHECK_US: AtomicU32 = AtomicU32::new(0);
static SW_SELFCHECK_US: AtomicU32 = AtomicU32::new(0);
static DERIVATIONS: AtomicU32 = AtomicU32::new(0);
static HW_FULL: AtomicU32 = AtomicU32::new(0);
static RETREATS: AtomicU32 = AtomicU32::new(0);
static CHUNKS: AtomicU32 = AtomicU32::new(0);
static MAX_ACQUIRE_US: AtomicU32 = AtomicU32::new(0);
static LAST_DERIVE_MS: AtomicU32 = AtomicU32::new(0);
static LAST_UNLOCK_MS: AtomicU32 = AtomicU32::new(0);
static UNLOCK_START_MS: AtomicU32 = AtomicU32::new(0);

fn now_ms() -> u32 {
    (now_us() / 1000).clamp(0, u32::MAX as i64) as u32
}

/// Mark the start of a whole unlock, so the telemetry can report what the
/// owner actually waited rather than only the last slot.
pub fn unlock_begin() {
    UNLOCK_START_MS.store(now_ms(), Ordering::Relaxed);
}

/// Mark the end of a whole unlock.
pub fn unlock_end() {
    let start = UNLOCK_START_MS.load(Ordering::Relaxed);
    if start != 0 {
        LAST_UNLOCK_MS.store(now_ms().saturating_sub(start), Ordering::Relaxed);
    }
}

// Written as an if-chain rather than a `match`: a dense integer match that
// yields string literals lowers to a jump table of address constants, and the
// Xtensa backend fails to assemble one out of a literal pool here ("Undefined
// temporary symbol"). An if-chain over five values costs nothing.
fn mode_wire(mode: u8) -> &'static str {
    if mode == MODE_HARDWARE {
        "hw"
    } else if mode == MODE_SOFTWARE {
        "sw"
    } else if mode == MODE_SELFCHECK_FAILED {
        "sw-selfcheck-failed"
    } else if mode == MODE_NO_ACCEL {
        "sw-no-accel"
    } else {
        "untested"
    }
}

fn selfcheck_wire() -> &'static str {
    let v = SELFCHECK_HW.load(Ordering::Relaxed);
    if v == 1 {
        "pass"
    } else if v == 2 {
        "fail"
    } else {
        "untried"
    }
}

/// The `kdf` object for FIRMWARE_INFO, as a leading-comma JSON fragment.
///
/// `mode` says which path this session derives on and why. `hw_selfcheck_us`
/// and `sw_selfcheck_us` are the two timed known-answer runs that chose it, so
/// the accelerator's real cost on this silicon is readable without a console.
/// `retreats` and `max_acquire_ms` are the contention picture; `chunks` scales
/// them. `last_derive_ms` is one slot, `last_unlock_ms` the whole unlock.
pub fn telemetry_json() -> String {
    format!(
        ",\"kdf\":{{\"mode\":\"{}\",\"selfcheck\":\"{}\",\
         \"hw_selfcheck_us\":{},\"sw_selfcheck_us\":{},\"derivations\":{},\
         \"hw_full\":{},\"retreats\":{},\"chunks\":{},\"max_acquire_ms\":{},\
         \"last_derive_ms\":{},\"last_unlock_ms\":{}}}",
        mode_wire(MODE.load(Ordering::Relaxed)),
        selfcheck_wire(),
        HW_SELFCHECK_US.load(Ordering::Relaxed),
        SW_SELFCHECK_US.load(Ordering::Relaxed),
        DERIVATIONS.load(Ordering::Relaxed),
        HW_FULL.load(Ordering::Relaxed),
        RETREATS.load(Ordering::Relaxed),
        CHUNKS.load(Ordering::Relaxed),
        MAX_ACQUIRE_US.load(Ordering::Relaxed) / 1000,
        LAST_DERIVE_MS.load(Ordering::Relaxed),
        LAST_UNLOCK_MS.load(Ordering::Relaxed),
    )
}

/// Decide, once per boot, which engine derives keys this session.
///
/// Both candidates must pass the same known-answer vector, and the faster of
/// the ones that pass wins. Measuring rather than assuming is the point: the
/// model behind this work predicted 0.7 to 2 s a slot for the accelerator and
/// the first bench run came back at 17 s, which is exactly the kind of thing a
/// board can settle for itself in 2,400 compressions. Neither candidate can
/// win without matching the vector, so a wrong engine is never selected, only
/// a slow one is rejected.
///
/// Racing tasks may both run this; they do identical work and store identical
/// results.
fn resolve_mode() -> u8 {
    let cached = MODE.load(Ordering::Relaxed);
    if cached != MODE_UNTESTED {
        return cached;
    }

    let mut hw_ok = false;
    let mut hw_us = u32::MAX;
    if accelerator_available() {
        let started = now_us();
        let mut engine = DeviceEngine::new(true);
        hw_ok = kdf::self_check(&mut engine);
        hw_us = (now_us() - started).clamp(0, u32::MAX as i64) as u32;
        HW_SELFCHECK_US.store(hw_us, Ordering::Relaxed);
        SELFCHECK_HW.store(if hw_ok { 1 } else { 2 }, Ordering::Relaxed);
        if !hw_ok {
            // The one genuinely dangerous failure in this subsystem would be a
            // hardware path that derives a *different* key. It is caught here,
            // before any blob is touched, and the session never uses it.
            log::error!(
                "SHA accelerator self-check FAILED: known-answer mismatch. \
                 Falling back to software for this session; no hardware-derived \
                 key will be used."
            );
        }
    }

    let started = now_us();
    let sw_ok = kdf::self_check(&mut kdf::SoftEngine);
    let sw_us = (now_us() - started).clamp(0, u32::MAX as i64) as u32;
    SW_SELFCHECK_US.store(sw_us, Ordering::Relaxed);
    if !sw_ok {
        log::error!("Software SHA self-check FAILED: the KDF vector does not match");
    }

    let chosen = if !accelerator_available() {
        MODE_NO_ACCEL
    } else if !hw_ok {
        MODE_SELFCHECK_FAILED
    } else if hw_us <= sw_us {
        MODE_HARDWARE
    } else {
        MODE_SOFTWARE
    };
    log::info!(
        "Sealed-seed KDF: {} (hw self-check {} us, sw {} us)",
        mode_wire(chosen),
        hw_us,
        sw_us
    );

    MODE.store(chosen, Ordering::Relaxed);
    chosen
}

/// The installed KDF: `heartwood_common::seed_cipher` calls this for every
/// sealed seed and every note-key wrap.
///
/// One engine type covers both modes at runtime, so the driver is monomorphised
/// exactly once in the image: the 2 MB OTA slot has no room for two copies of
/// it.
fn device_kdf(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    let hardware = resolve_mode() == MODE_HARDWARE;
    let started = now_us();
    let mut engine = DeviceEngine::new(hardware);
    kdf::pbkdf2_hmac_sha256(&mut engine, password, salt, rounds, out);
    LAST_DERIVE_MS.store(
        ((now_us() - started) / 1000).clamp(0, u32::MAX as i64) as u32,
        Ordering::Relaxed,
    );
    DERIVATIONS.fetch_add(1, Ordering::Relaxed);
    if engine.stayed_in_hardware() {
        HW_FULL.fetch_add(1, Ordering::Relaxed);
    }
}

/// Point the sealed-seed KDF at this board's engine.
///
/// Call once from `main`, before anything can read or write a sealed blob. The
/// self-check is deliberately deferred to first use rather than run here: boot
/// is already long, and a board with no sealed seed never needs to pay for it.
pub fn install() {
    kdf::install_hook(device_kdf);
}
