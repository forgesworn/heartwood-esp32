// common/src/kdf.rs
//
// PBKDF2-HMAC-SHA256 written against a swappable SHA-256 compression
// function, so a board with a SHA accelerator can run the sealed-seed KDF on
// the peripheral while the host, the daemon and every un-accelerated board
// keep the pure-Rust `pbkdf2` crate path.
//
// Why this exists at all: see docs/2026-09-18-pbkdf2-cost-and-sha-acceleration.md.
// The short version is that `derive_km` is 400,000 SHA-256 compressions and the
// software path spends ~17,400 cycles on each of them, so a single sealed slot
// costs about 29 s. The ESP32-S3 and C6 have an idle SHA accelerator that TLS
// already uses. Nothing about the *output* may change: a sealed seed that stops
// opening is lost keys, so this module is written so that the exact same
// PBKDF2/HMAC state handling runs on the host with a software compression
// function substituted behind [`Sha256Engine`].
//
// Structure notes that matter for speed and for correctness:
//
//   * The HMAC inner/outer pad states are compressed ONCE and then reused for
//     every round. Rehashing the key each round would double the work and
//     throw away most of the accelerator's win.
//   * Every message block handed to an engine is 4-byte aligned ([`Block`]).
//     The ESP-IDF register fill does 32-bit loads straight off the caller's
//     buffer, and an unaligned 32-bit load on Xtensa is the same class of
//     fault that made k256 unusable on this chip.
//   * The driver calls [`Sha256Engine::begin_chunk`] / `end_chunk` around runs
//     of [`CHUNK_ROUNDS`] HMAC rounds. A hardware engine acquires and releases
//     the shared SHA/AES lock on those boundaries, so a TLS record MAC never
//     waits behind a whole derivation; a software engine uses them to feed the
//     watchdog and yield.

use zeroize::Zeroize;

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3).
pub const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// HMAC rounds performed between two [`Sha256Engine::begin_chunk`] /
/// [`Sha256Engine::end_chunk`] boundaries.
///
/// Each round is two compressions, so a chunk is 512 compressions. On the S3
/// accelerator that is on the order of a millisecond and a half of held lock —
/// short enough that a concurrent TLS record MAC waits for one chunk, not for
/// a derivation. Larger chunks amortise the acquire better and starve TLS for
/// longer; this is the trade-off knob.
pub const CHUNK_ROUNDS: u32 = 256;

/// A 4-byte-aligned SHA-256 message block.
///
/// The alignment is load-bearing, not cosmetic: ESP-IDF's `sha_ll_fill_text_block`
/// casts the caller's pointer to `uint32_t *` and dereferences it.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct Block(pub [u8; 64]);

impl Block {
    pub const fn zero() -> Self {
        Block([0u8; 64])
    }
}

impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A SHA-256 compression function, plus the chunk boundaries the driver uses
/// to bound how long an implementation may hold a shared resource.
///
/// An implementation MUST be byte-identical to FIPS 180-4 SHA-256: `state` is
/// `h0..h7` in the usual numeric order, the same convention `sha2` uses.
pub trait Sha256Engine {
    /// Compress one 64-byte block into `state`.
    fn compress(&mut self, state: &mut [u32; 8], block: &Block);

    /// Called before a run of at most [`CHUNK_ROUNDS`] HMAC rounds.
    fn begin_chunk(&mut self) {}

    /// Called after that run. An engine that acquired anything in
    /// `begin_chunk` MUST release it here, on every path.
    fn end_chunk(&mut self) {}
}

/// The portable software compression function — `sha2`'s, unchanged.
///
/// This is the reference every other engine is graded against, on the host and
/// in the device self-check.
// `GenericArray` is deprecated in favour of generic-array 1.x, but it is the
// parameter type of `sha2::compress256` at the pinned version, so there is
// nothing else to pass.
#[allow(deprecated)]
pub fn soft_compress(state: &mut [u32; 8], block: &Block) {
    use sha2::digest::generic_array::{typenum::U64, GenericArray};
    let ga: &GenericArray<u8, U64> = (&block.0).into();
    sha2::compress256(state, core::slice::from_ref(ga));
}

/// [`Sha256Engine`] over [`soft_compress`]. No chunk behaviour.
#[derive(Default, Clone, Copy)]
pub struct SoftEngine;

impl Sha256Engine for SoftEngine {
    fn compress(&mut self, state: &mut [u32; 8], block: &Block) {
        soft_compress(state, block);
    }
}

fn state_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// Streaming SHA-256 absorber that starts from an arbitrary midstate.
///
/// `prefix_len` is how many bytes have already been absorbed into `state` —
/// 64 when resuming from an HMAC pad block — so the length suffix is right.
struct Absorb {
    state: [u32; 8],
    block: Block,
    fill: usize,
    total: u64,
}

impl Absorb {
    fn new(state: [u32; 8], prefix_len: u64) -> Self {
        Absorb {
            state,
            block: Block::zero(),
            fill: 0,
            total: prefix_len,
        }
    }

    fn update<E: Sha256Engine + ?Sized>(&mut self, engine: &mut E, mut data: &[u8]) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let take = core::cmp::min(64 - self.fill, data.len());
            self.block.0[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 64 {
                engine.compress(&mut self.state, &self.block);
                self.fill = 0;
            }
        }
    }

    fn finish<E: Sha256Engine + ?Sized>(mut self, engine: &mut E) -> [u8; 32] {
        let bits = self.total * 8;
        self.block.0[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > 56 {
            self.block.0[self.fill..].fill(0);
            engine.compress(&mut self.state, &self.block);
            self.fill = 0;
        }
        self.block.0[self.fill..56].fill(0);
        self.block.0[56..].copy_from_slice(&bits.to_be_bytes());
        engine.compress(&mut self.state, &self.block);
        let out = state_bytes(&self.state);
        self.block.zeroize();
        self.state.zeroize();
        out
    }
}

/// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2) driven by `engine`.
///
/// Byte-identical to `pbkdf2::pbkdf2_hmac::<Sha256>` for every input; that is
/// asserted by the host tests in this module, both against RFC vectors and
/// against the crate itself over a spread of passwords, salts and counts.
///
/// `rounds` must be non-zero; the caller range-checks it (see
/// `seed_cipher::MAX_PBKDF2_ITERATIONS`) long before this is reached.
pub fn pbkdf2_hmac_sha256<E: Sha256Engine + ?Sized>(
    engine: &mut E,
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    out: &mut [u8],
) {
    debug_assert!(rounds > 0, "PBKDF2 needs at least one round");

    // --- HMAC key schedule, done once for the whole derivation -------------
    let mut key = [0u8; 64];
    if password.len() > 64 {
        let mut hashed = Absorb::new(SHA256_IV, 0);
        hashed.update(engine, password);
        key[..32].copy_from_slice(&hashed.finish(engine));
    } else {
        key[..password.len()].copy_from_slice(password);
    }

    let mut pad = Block::zero();
    for (b, k) in pad.0.iter_mut().zip(key.iter()) {
        *b = k ^ 0x36;
    }
    let mut ipad_state = SHA256_IV;
    engine.compress(&mut ipad_state, &pad);

    for (b, k) in pad.0.iter_mut().zip(key.iter()) {
        *b = k ^ 0x5c;
    }
    let mut opad_state = SHA256_IV;
    engine.compress(&mut opad_state, &pad);

    key.zeroize();
    pad.zeroize();

    // Every round after the first hashes exactly 32 bytes on top of a 64-byte
    // pad block, so the padded message is one fixed block whose first 32 bytes
    // are the only thing that changes. Build it once.
    let mut tail = Block::zero();
    tail.0[32] = 0x80;
    tail.0[56..].copy_from_slice(&(768u64).to_be_bytes()); // (64 + 32) * 8

    for (i, out_block) in out.chunks_mut(32).enumerate() {
        let index = (i as u32) + 1;

        engine.begin_chunk();

        // U_1 = HMAC(password, salt || INT_32_BE(index))
        let mut inner = Absorb::new(ipad_state, 64);
        inner.update(engine, salt);
        inner.update(engine, &index.to_be_bytes());
        let mut u = inner.finish(engine);
        let mut outer = Absorb::new(opad_state, 64);
        outer.update(engine, &u);
        u = outer.finish(engine);

        let mut acc = u;
        let mut in_chunk = 1u32;

        // U_2 .. U_rounds, each one inner + one outer compression.
        for _ in 1..rounds {
            tail.0[..32].copy_from_slice(&u);
            let mut st = ipad_state;
            engine.compress(&mut st, &tail);
            u = state_bytes(&st);

            tail.0[..32].copy_from_slice(&u);
            st = opad_state;
            engine.compress(&mut st, &tail);
            u = state_bytes(&st);

            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }

            in_chunk += 1;
            if in_chunk >= CHUNK_ROUNDS {
                engine.end_chunk();
                engine.begin_chunk();
                in_chunk = 0;
            }
        }

        engine.end_chunk();

        let n = out_block.len();
        out_block.copy_from_slice(&acc[..n]);
        acc.zeroize();
        u.zeroize();
    }

    ipad_state.zeroize();
    opad_state.zeroize();
    tail.zeroize();
}

// ---------------------------------------------------------------------------
// Device-side known-answer self-check
// ---------------------------------------------------------------------------

/// Password for the boot-time known-answer check.
pub const SELF_CHECK_PASSWORD: &[u8] = b"heartwood-kdf-self-check";
/// Salt for the boot-time known-answer check.
pub const SELF_CHECK_SALT: &[u8] = b"heartwood-salt-0";
/// Round count for the boot-time known-answer check. Deliberately small: it
/// runs once per boot before the first real derivation, and 64 rounds already
/// exercise the pad precompute, both output blocks and the XOR accumulator.
pub const SELF_CHECK_ROUNDS: u32 = 64;
/// Expected 64-byte output of
/// `PBKDF2-HMAC-SHA256(SELF_CHECK_PASSWORD, SELF_CHECK_SALT, SELF_CHECK_ROUNDS)`.
///
/// Verified against the `pbkdf2` crate by `self_check_vector_is_the_reference`
/// below, so a board comparing against this constant is comparing against the
/// reference implementation.
pub const SELF_CHECK_KM: [u8; 64] = [
    0xb5, 0xae, 0x75, 0xe1, 0xbd, 0xa9, 0x63, 0xad, 0x3f, 0xb9, 0x76, 0x4c, 0x03, 0x32, 0xfc, 0x35,
    0x8f, 0x29, 0xfa, 0xc8, 0x0e, 0x04, 0x0c, 0x3b, 0x45, 0xbf, 0x9c, 0xbe, 0x65, 0x19, 0xa0, 0x53,
    0x43, 0x56, 0x52, 0xf0, 0x36, 0x15, 0x61, 0xd8, 0x7b, 0xe2, 0x68, 0x05, 0xda, 0xa5, 0x0a, 0x1b,
    0x26, 0x46, 0xd8, 0x73, 0x5e, 0x02, 0x1f, 0xbf, 0xbf, 0x32, 0xb9, 0x34, 0x28, 0x01, 0x71, 0xf2,
];

/// Run the known-answer vector through `engine` and report whether it matched.
///
/// A device calls this once, before its first real derivation, and must never
/// derive a key with an engine that failed.
pub fn self_check<E: Sha256Engine + ?Sized>(engine: &mut E) -> bool {
    let mut km = [0u8; 64];
    pbkdf2_hmac_sha256(
        engine,
        SELF_CHECK_PASSWORD,
        SELF_CHECK_SALT,
        SELF_CHECK_ROUNDS,
        &mut km,
    );
    let matched = km == SELF_CHECK_KM;
    km.zeroize();
    matched
}

// ---------------------------------------------------------------------------
// Optional device KDF hook
// ---------------------------------------------------------------------------

/// A whole-PBKDF2 replacement installed by the firmware at boot.
pub type KdfHook = fn(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]);

// A plain `static mut` rather than an atomic: `common` is built for the lx106
// too, which has no atomic CAS, and the value is a `Copy` function pointer
// written exactly once during single-threaded boot before any KDF can run.
static mut KDF_HOOK: Option<KdfHook> = None;

/// Install a device-specific PBKDF2 implementation.
///
/// # Safety contract
///
/// Call once, from the boot task, before any other task exists and before any
/// sealed blob is read or written. The hook MUST be byte-identical to
/// [`reference_pbkdf2_hmac_sha256`] for every input; the firmware proves that
/// on the board with [`self_check`] before its first real derivation.
pub fn install_hook(hook: KdfHook) {
    unsafe {
        KDF_HOOK = Some(hook);
    }
}

/// The installed hook, if any.
pub fn installed_hook() -> Option<KdfHook> {
    unsafe { KDF_HOOK }
}

/// The unchanged pure-Rust path: the `pbkdf2` crate over `sha2`.
///
/// This is what the host tools, the host tests and `heartwoodd` use, and it is
/// the last-resort fallback for a board whose engine fails its self-check.
pub fn reference_pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, out);
}

/// PBKDF2-HMAC-SHA256 as the sealed-seed KDF should compute it: the installed
/// device hook when there is one, the reference implementation otherwise.
pub fn pbkdf2_for_seed(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    match installed_hook() {
        Some(hook) => hook(password, salt, rounds, out),
        None => reference_pbkdf2_hmac_sha256(password, salt, rounds, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A stand-in for the accelerator: the same trait, a software compression
    /// function, and chunk bookkeeping that asserts the driver never leaves a
    /// chunk open or closes one twice. The real peripheral cannot run on the
    /// host, so this is what makes the accelerated path's *logic* testable.
    #[derive(Default)]
    struct FakeAcceleratorEngine {
        held: bool,
        acquires: u32,
        releases: u32,
        compressions: u64,
        max_run: u32,
        run: u32,
    }

    impl Sha256Engine for FakeAcceleratorEngine {
        fn compress(&mut self, state: &mut [u32; 8], block: &Block) {
            // Alignment is part of the contract the real engine relies on.
            assert_eq!(
                block.0.as_ptr() as usize % 4,
                0,
                "message block must be 4-byte aligned"
            );
            soft_compress(state, block);
            self.compressions += 1;
            if self.held {
                self.run += 1;
                self.max_run = self.max_run.max(self.run);
            }
        }

        fn begin_chunk(&mut self) {
            assert!(!self.held, "begin_chunk while already holding");
            self.held = true;
            self.acquires += 1;
            self.run = 0;
        }

        fn end_chunk(&mut self) {
            assert!(self.held, "end_chunk without begin_chunk");
            self.held = false;
            self.releases += 1;
        }
    }

    fn reference(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        reference_pbkdf2_hmac_sha256(password, salt, rounds, &mut out);
        out
    }

    fn driven(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        pbkdf2_hmac_sha256(&mut SoftEngine, password, salt, rounds, &mut out);
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// (a) Known PBKDF2-HMAC-SHA256 vectors, in the RFC 6070 shape, asserted
    /// against BOTH implementations. A vector that only agreed with itself
    /// would prove nothing.
    #[test]
    fn known_answer_vectors_match_both_implementations() {
        let cases: [(&[u8], &[u8], u32, usize, &str); 5] = [
            (
                b"password",
                b"salt",
                1,
                32,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                b"password",
                b"salt",
                2,
                32,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                b"password",
                b"salt",
                4096,
                32,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                40,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                16,
                "89b69d0516f829893c696226650a8687",
            ),
        ];

        for (password, salt, rounds, len, expected) in cases {
            let want = hex(expected);
            assert_eq!(reference(password, salt, rounds, len), want, "reference");
            assert_eq!(driven(password, salt, rounds, len), want, "driver");
        }
    }

    /// (b) A spread of PINs, salts and round counts through both paths, with
    /// the driver running behind the fake-accelerator engine so the chunk
    /// handling is exercised rather than bypassed.
    #[test]
    fn both_paths_agree_over_a_spread_of_inputs() {
        let passwords: [&[u8]; 7] = [
            b"",
            b"0000",
            b"123456",
            b"87654321",
            &[0xA5u8; 32],
            b"a password longer than one SHA-256 block, so the HMAC key is hashed first",
            &[0x00u8; 65],
        ];
        let salts: [&[u8]; 5] = [b"", &[7u8; 16], &[0u8; 16], &[0xFFu8; 16], &[3u8; 64]];
        let round_counts: [u32; 8] = [1, 2, 3, 255, 256, 257, 512, 1000];
        let lengths: [usize; 4] = [16, 32, 33, 64];

        for password in passwords {
            for salt in salts {
                for rounds in round_counts {
                    for len in lengths {
                        let want = reference(password, salt, rounds, len);

                        let mut engine = FakeAcceleratorEngine::default();
                        let mut got = vec![0u8; len];
                        pbkdf2_hmac_sha256(&mut engine, password, salt, rounds, &mut got);

                        assert_eq!(
                            got, want,
                            "mismatch: password={password:?} salt={salt:?} rounds={rounds} len={len}"
                        );
                        assert!(!engine.held, "engine left holding the accelerator");
                        assert_eq!(engine.acquires, engine.releases, "unbalanced chunks");
                        assert!(
                            engine.max_run <= CHUNK_ROUNDS as u32 * 2 + 8,
                            "chunk ran longer than the declared bound: {}",
                            engine.max_run
                        );
                    }
                }
            }
        }
    }

    /// The whole point of the pad precompute: an engine must never see the
    /// key hashed again inside the round loop. 2 compressions per round, plus
    /// the fixed setup, is the shape that makes the accelerator worth using.
    #[test]
    fn the_round_loop_costs_exactly_two_compressions() {
        let mut engine = FakeAcceleratorEngine::default();
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(&mut engine, b"123456", &[7u8; 16], 1000, &mut out);
        // 2 pad blocks, then per output block: U1 (salt||index padded to one
        // block inner + one block outer = 2) and 999 further rounds at 2 each.
        let expected = 2 + 2 * (2 + 999 * 2);
        assert_eq!(engine.compressions, expected as u64);
    }

    /// The device self-check constant is the reference implementation's
    /// answer, so a board that matches it has matched the reference.
    #[test]
    fn self_check_vector_is_the_reference() {
        let want = reference(
            SELF_CHECK_PASSWORD,
            SELF_CHECK_SALT,
            SELF_CHECK_ROUNDS,
            64,
        );
        assert_eq!(&SELF_CHECK_KM[..], &want[..]);
        assert!(self_check(&mut SoftEngine));
        assert!(self_check(&mut FakeAcceleratorEngine::default()));
    }

    /// An engine that is subtly wrong must fail the self-check. This is the
    /// device-side mismatch path, proven on the host.
    #[test]
    fn a_wrong_engine_fails_the_self_check() {
        struct BrokenEngine;
        impl Sha256Engine for BrokenEngine {
            fn compress(&mut self, state: &mut [u32; 8], block: &Block) {
                soft_compress(state, block);
                state[0] ^= 1; // one bit, the way a byte-order slip would look
            }
        }
        assert!(!self_check(&mut BrokenEngine));
    }

    /// With no hook installed — host, tests, heartwoodd — the seed KDF is the
    /// unchanged pure-Rust path.
    #[test]
    fn seed_kdf_defaults_to_the_reference_path() {
        assert!(installed_hook().is_none());
        let mut got = [0u8; 64];
        pbkdf2_for_seed(b"123456", &[7u8; 16], 137, &mut got);
        assert_eq!(&got[..], &reference(b"123456", &[7u8; 16], 137, 64)[..]);
    }
}
