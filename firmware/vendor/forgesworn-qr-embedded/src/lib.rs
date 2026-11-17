#![no_std]
#![doc = include_str!("../README.md")]
//! Allocation-free encoder for QR versions 1–8.
//!
//! A separate `no_std` crate with fixed caller-owned buffers. Byte input and
//! optional optimal text follow the shared specification; compact text uses
//! one segment. The repository's conformance harness checks both APIs.

use core::sync::atomic::{compiler_fence, Ordering};

#[rustfmt::skip]
mod tables;

/// Largest supported QR version (49 by 49 modules).
pub const MAX_VERSION: u8 = 8;
/// Packed output storage for 49 × 49 modules (metadata is held separately).
pub const MODULE_BYTES: usize = 301;
/// Version 8-L holds at most 461 digits, or 192 arbitrary bytes.
pub const MAX_TEXT_BYTES: usize = 461;
const ALPHANUMERIC: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
#[cfg(feature = "optimal")]
const STATE_MODE: [i8; 7] = [-1, 0, 0, 0, 1, 1, 2];
#[cfg(feature = "optimal")]
const STEP_BITS: [u32; 7] = [0, 4, 3, 3, 6, 5, 8];
#[cfg(feature = "optimal")]
const STEP_NEXT: [usize; 7] = [0, 2, 3, 1, 5, 4, 6];
#[cfg(feature = "optimal")]
const OPENING: [usize; 3] = [1, 4, 6];
// At most 461 segments: low bits break ties by segment count.
#[cfg(feature = "optimal")]
const COST_SCALE: u32 = 512;
const COUNT_BITS: [usize; 3] = [10, 9, 8];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecc {
    L,
    M,
    Q,
    H,
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub ecc: Ecc,
    pub version: Option<u8>,
    pub min_version: u8,
    pub max_version: u8,
    pub mask: Option<u8>,
    pub eci: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ecc: Ecc::M,
            version: None,
            min_version: 1,
            max_version: MAX_VERSION,
            mask: None,
            eci: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidVersionRange,
    InvalidMask,
    OutputTooSmall,
    Capacity,
}

/// Caller-owned scratch reused for interleaved codewords, then the mask map.
pub struct Workspace {
    buffer: [u8; MODULE_BYTES],
}

impl Workspace {
    pub const fn new() -> Self {
        Self {
            buffer: [0; MODULE_BYTES],
        }
    }
    pub fn clear(&mut self) {
        wipe(&mut self.buffer);
    }
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Optional caller-owned planner. Compact encoding never reserves this space.
#[cfg(feature = "optimal")]
pub struct TextPlanner {
    decisions: [u16; MAX_TEXT_BYTES],
    costs: [u32; 7],
    next: [u32; 7],
}
#[cfg(feature = "optimal")]
impl TextPlanner {
    pub const fn new() -> Self {
        Self {
            decisions: [0; MAX_TEXT_BYTES],
            costs: [0; 7],
            next: [0; 7],
        }
    }
    pub fn clear(&mut self) {
        wipe(&mut self.decisions);
        wipe(&mut self.costs);
        wipe(&mut self.next);
    }
}
#[cfg(feature = "optimal")]
impl Default for TextPlanner {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "optimal")]
impl Drop for TextPlanner {
    fn drop(&mut self) {
        self.clear();
    }
}

// Reed-Solomon's small local arrays are wiped when this phase ends.
struct ReedSolomon {
    divisor: [u8; 29],
    remainder: [u8; 28],
}
impl Drop for ReedSolomon {
    fn drop(&mut self) {
        wipe(&mut self.divisor);
        wipe(&mut self.remainder);
    }
}

// Volatile stores prevent dead-store elimination. This scrubs owned buffers;
// it does not promise erasure of register spills, compiler copies or input.
fn wipe<T: Copy + Default>(buffer: &mut [T]) {
    for value in buffer {
        // SAFETY: value is a live, uniquely borrowed, correctly aligned T.
        unsafe {
            core::ptr::write_volatile(value, T::default());
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[derive(Clone, Copy, Debug)]
struct Metadata {
    version: u8,
    ecc: Ecc,
    mask: u8,
    bits: usize,
}

/// A borrowed symbol. Dropping it wipes the entire supplied output slice.
/// Deliberately neither Clone nor Debug: drawing need not copy the payload.
pub struct Symbol<'a> {
    output: &'a mut [u8],
    meta: Metadata,
}

impl Symbol<'_> {
    pub fn version(&self) -> u8 {
        self.meta.version
    }
    pub fn size(&self) -> usize {
        17 + 4 * self.meta.version as usize
    }
    pub fn ecc(&self) -> Ecc {
        self.meta.ecc
    }
    pub fn mask(&self) -> u8 {
        self.meta.mask
    }
    pub fn bits(&self) -> usize {
        self.meta.bits
    }
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.size() && y < self.size() && get(self.output, self.size(), x, y)
    }
}

impl Drop for Symbol<'_> {
    fn drop(&mut self) {
        wipe(self.output);
    }
}

/// Encode automatic mixed text using explicit, optional planner storage.
#[cfg(feature = "optimal")]
pub fn encode_text<'a>(
    text: &str,
    options: &Options,
    planner: &mut TextPlanner,
    scratch: &mut Workspace,
    output: &'a mut [u8],
) -> Result<Symbol<'a>, Error> {
    planner.clear();
    scratch.clear();
    wipe(output);
    let result = (|| {
        let highest = validate(options, output.len())?;
        check_length(text.len(), true, highest, options.ecc)?;
        if text.is_empty() {
            return encode_inner(&[], Some(2), options, scratch, output);
        }
        plan(text, planner);
        let has_byte = text
            .chars()
            .any(|c| !c.is_ascii() || !ALPHANUMERIC.contains(&(c as u8)));
        let bits =
            (planner.costs[0] / COST_SCALE) as usize + if options.eci && has_byte { 12 } else { 0 };
        let version = choose_version(options, highest, bits)?;
        let mut at = 0;
        if options.eci && has_byte {
            eci(output, &mut at);
        }
        let (mut state, mut start, mut mode) = (0usize, 0usize, 2usize);
        for (i, _) in text.char_indices() {
            let chosen = ((planner.decisions[i] >> (state * 2)) & 3) as usize;
            let open = STATE_MODE[state] != chosen as i8;
            if open {
                if i > 0 {
                    append(output, &mut at, &text.as_bytes()[start..i], mode);
                }
                start = i;
                mode = chosen;
            }
            state = STEP_NEXT[if open { OPENING[chosen] } else { state }];
        }
        append(output, &mut at, &text.as_bytes()[start..], mode);
        debug_assert_eq!(at, bits);
        // Decisions are no longer needed once the data stream has been written.
        planner.clear();
        finish(output, scratch, options, version, bits, at)
    })();
    planner.clear();
    scratch.clear();
    result_symbol(result, output)
}

/// Encode text as one numeric, alphanumeric or UTF-8 byte segment.
/// This deliberately does not promise the main encoder's optimal segmentation.
pub fn encode_simple_text<'a>(
    text: &str,
    options: &Options,
    scratch: &mut Workspace,
    output: &'a mut [u8],
) -> Result<Symbol<'a>, Error> {
    encode_compact(text.as_bytes(), None, options, scratch, output)
}

pub fn encode_bytes<'a>(
    bytes: &[u8],
    options: &Options,
    scratch: &mut Workspace,
    output: &'a mut [u8],
) -> Result<Symbol<'a>, Error> {
    encode_compact(bytes, Some(2), options, scratch, output)
}

fn encode_compact<'a>(
    bytes: &[u8],
    mode: Option<usize>,
    options: &Options,
    scratch: &mut Workspace,
    output: &'a mut [u8],
) -> Result<Symbol<'a>, Error> {
    scratch.clear();
    wipe(output);
    let result = encode_inner(bytes, mode, options, scratch, output);
    scratch.clear();
    result_symbol(result, output)
}

fn result_symbol(result: Result<Metadata, Error>, output: &mut [u8]) -> Result<Symbol<'_>, Error> {
    match result {
        Ok(meta) => Ok(Symbol { output, meta }),
        Err(error) => {
            wipe(output);
            Err(error)
        }
    }
}

fn blocks(version: u8, ecc: Ecc) -> [usize; 4] {
    tables::EC_BLOCKS[version as usize - 1][ecc as usize].map(|n| n as usize)
}

fn capacity(version: u8, ecc: Ecc) -> usize {
    let [_, g1, d1, g2] = blocks(version, ecc);
    (g1 * d1 + g2 * (d1 + 1)) * 8
}

fn validate(o: &Options, output_len: usize) -> Result<u8, Error> {
    if o.min_version == 0
        || o.max_version > MAX_VERSION
        || o.min_version > o.max_version
        || o.version
            .is_some_and(|v| v < o.min_version || v > o.max_version)
    {
        return Err(Error::InvalidVersionRange);
    }
    if o.mask.is_some_and(|m| m > 7) {
        return Err(Error::InvalidMask);
    }
    if output_len < MODULE_BYTES {
        return Err(Error::OutputTooSmall);
    }
    Ok(o.version.unwrap_or(o.max_version))
}

fn check_length(length: usize, text: bool, highest: u8, ecc: Ecc) -> Result<(), Error> {
    let available = capacity(highest, ecc);
    let limit = if text {
        (available - 12) * 3 / 10
    } else {
        (available - 12) / 8
    };
    if length > limit || length > MAX_TEXT_BYTES {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}

fn choose_version(o: &Options, highest: u8, bits: usize) -> Result<u8, Error> {
    (o.version.unwrap_or(o.min_version)..=highest)
        .find(|&v| bits <= capacity(v, o.ecc))
        .ok_or(Error::Capacity)
}

fn eci(output: &mut [u8], at: &mut usize) {
    push(output, at, 7, 4);
    push(output, at, 26, 8);
}

fn encode_inner(
    bytes: &[u8],
    requested: Option<usize>,
    o: &Options,
    scratch: &mut Workspace,
    output: &mut [u8],
) -> Result<Metadata, Error> {
    let highest = validate(o, output.len())?;
    check_length(bytes.len(), requested.is_none(), highest, o.ecc)?;
    let mode = requested.unwrap_or_else(|| {
        if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit) {
            0
        } else if !bytes.is_empty() && bytes.iter().all(|b| ALPHANUMERIC.contains(b)) {
            1
        } else {
            2
        }
    });
    let n = bytes.len();
    let data_bits = match mode {
        0 => n / 3 * 10 + [0, 4, 7][n % 3],
        1 => n / 2 * 11 + n % 2 * 6,
        _ => n * 8,
    };
    let bits = 4 + COUNT_BITS[mode] + data_bits + if mode == 2 && o.eci { 12 } else { 0 };
    let version = choose_version(o, highest, bits)?;
    let mut at = 0;
    if mode == 2 && o.eci {
        eci(output, &mut at);
    }
    append(output, &mut at, bytes, mode);
    finish(output, scratch, o, version, bits, at)
}

fn finish(
    output: &mut [u8],
    scratch: &mut Workspace,
    o: &Options,
    version: u8,
    bits: usize,
    mut at: usize,
) -> Result<Metadata, Error> {
    let cap = capacity(version, o.ecc);
    let terminator = (cap - at).min(4);
    push(output, &mut at, 0, terminator);
    while at & 7 != 0 {
        push(output, &mut at, 0, 1);
    }
    let mut pad = 0xec;
    while at < cap {
        push(output, &mut at, pad, 8);
        pad ^= 0xec ^ 0x11;
    }
    let stream_len = interleave(output, &mut scratch.buffer, version, o.ecc);
    draw_base(output, &scratch.buffer[..stream_len], version, o.ecc);
    // Interleaved codewords are dead. Reuse their storage for the mask map.
    wipe(&mut scratch.buffer);
    let size = 17 + 4 * version as usize;
    for y in 0..size {
        for x in 0..size {
            if function_module(version, x, y) {
                set(&mut scratch.buffer, size, x, y, true);
            }
        }
    }
    let mask = if let Some(mask) = o.mask {
        mask
    } else {
        let (mut best, mut chosen) = (u32::MAX, 0);
        for mask in 0..8 {
            toggle_mask(output, &scratch.buffer, size, mask);
            header(output, size, o.ecc, mask);
            let score = penalty(output, size, best);
            toggle_mask(output, &scratch.buffer, size, mask);
            if score < best {
                best = score;
                chosen = mask;
            }
        }
        chosen
    };
    toggle_mask(output, &scratch.buffer, size, mask);
    header(output, size, o.ecc, mask);
    Ok(Metadata {
        version,
        ecc: o.ecc,
        mask,
        bits,
    })
}

// The main encoder's exact seven-state planner, with rolling costs and two
// decision bits per state at each UTF-8 byte boundary instead of heap vectors.
#[cfg(feature = "optimal")]
fn plan(text: &str, w: &mut TextPlanner) {
    for (i, c) in text.char_indices().rev() {
        let kind = if c.is_ascii_digit() {
            0
        } else if c.is_ascii() && ALPHANUMERIC.contains(&(c as u8)) {
            1
        } else {
            2
        };
        for (s, &old_mode) in STATE_MODE.iter().enumerate() {
            let (mut best, mut chosen) = (u32::MAX, 2);
            for m in kind..3 {
                let open = old_mode != m as i8;
                let t = if open { OPENING[m] } else { s };
                let step = STEP_BITS[t] * if m == 2 { c.len_utf8() as u32 } else { 1 }
                    + if open { 4 + COUNT_BITS[m] as u32 } else { 0 };
                let cost = step * COST_SCALE + open as u32 + w.next[STEP_NEXT[t]];
                if cost < best {
                    best = cost;
                    chosen = m;
                }
            }
            w.costs[s] = best;
            w.decisions[i] |= (chosen as u16) << (s * 2);
        }
        w.next.copy_from_slice(&w.costs);
    }
}

fn push(data: &mut [u8], at: &mut usize, value: u32, bits: usize) {
    for i in (0..bits).rev() {
        data[*at / 8] |= (((value >> i) & 1) as u8) << (7 - *at % 8);
        *at += 1;
    }
}

fn append(data: &mut [u8], at: &mut usize, bytes: &[u8], mode: usize) {
    push(data, at, [1, 2, 4][mode], 4);
    push(data, at, bytes.len() as u32, COUNT_BITS[mode]);
    match mode {
        0 => {
            for group in bytes.chunks(3) {
                let n = group.iter().fold(0u32, |n, &b| n * 10 + (b - b'0') as u32);
                push(data, at, n, group.len() * 3 + 1);
            }
        }
        1 => {
            for group in bytes.chunks(2) {
                let index = |b| ALPHANUMERIC.iter().position(|&a| a == b).unwrap() as u32;
                let n = if group.len() == 2 {
                    index(group[0]) * 45 + index(group[1])
                } else {
                    index(group[0])
                };
                push(data, at, n, if group.len() == 2 { 11 } else { 6 });
            }
        }
        _ => {
            for &b in bytes {
                push(data, at, b as u32, 8);
            }
        }
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            out ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1d } else { 0 };
        b >>= 1;
    }
    out
}

fn interleave(data: &[u8], stream: &mut [u8], version: u8, ecc: Ecc) -> usize {
    let mut rs = ReedSolomon {
        divisor: [0; 29],
        remainder: [0; 28],
    };
    let [degree, g1, d1, g2] = blocks(version, ecc);
    let count = g1 + g2;
    let data_len = g1 * d1 + g2 * (d1 + 1);
    // In-place monic generator multiplication, retaining no extra polynomial.
    rs.divisor[0] = 1;
    let mut root = 1;
    for i in 0..degree {
        for j in (0..=i + 1).rev() {
            rs.divisor[j] = if j <= i { rs.divisor[j] } else { 0 }
                ^ if j > 0 {
                    gf_mul(rs.divisor[j - 1], root)
                } else {
                    0
                };
        }
        root = gf_mul(root, 2);
    }
    let mut out = 0;
    for i in 0..=d1 {
        for b in 0..count {
            let len = d1 + usize::from(b >= g1);
            if i < len {
                let start = b * d1 + b.saturating_sub(g1);
                stream[out] = data[start + i];
                out += 1;
            }
        }
    }
    for b in 0..count {
        rs.remainder.fill(0);
        let start = b * d1 + b.saturating_sub(g1);
        let len = d1 + usize::from(b >= g1);
        for &byte in &data[start..start + len] {
            let factor = byte ^ rs.remainder[0];
            rs.remainder.copy_within(1..degree, 0);
            rs.remainder[degree - 1] = 0;
            for j in 0..degree {
                rs.remainder[j] ^= gf_mul(rs.divisor[j + 1], factor);
            }
        }
        for j in 0..degree {
            stream[data_len + j * count + b] = rs.remainder[j];
        }
    }
    data_len + degree * count
}

fn get(data: &[u8], size: usize, x: usize, y: usize) -> bool {
    let at = y * size + x;
    data[at / 8] & (1 << (at % 8)) != 0
}

fn set(data: &mut [u8], size: usize, x: usize, y: usize, dark: bool) {
    let at = y * size + x;
    let mask = 1 << (at % 8);
    data[at / 8] = (data[at / 8] & !mask) | if dark { mask } else { 0 };
}

const FORMAT_COORDS: [(usize, usize); 15] = [
    (8, 0),
    (8, 1),
    (8, 2),
    (8, 3),
    (8, 4),
    (8, 5),
    (8, 7),
    (8, 8),
    (7, 8),
    (5, 8),
    (4, 8),
    (3, 8),
    (2, 8),
    (1, 8),
    (0, 8),
];

fn header(data: &mut [u8], size: usize, ecc: Ecc, mask: u8) {
    let level = match ecc {
        Ecc::L => 1,
        Ecc::M => 0,
        Ecc::Q => 3,
        Ecc::H => 2,
    };
    let value = (level << 3) | mask as u32;
    let mut rem = value;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    let format = ((value << 10) | rem) ^ 0x5412;
    for (i, &(x, y)) in FORMAT_COORDS.iter().enumerate() {
        let bit = (format >> i) & 1 != 0;
        set(data, size, x, y, bit);
        if i < 8 {
            set(data, size, size - 1 - i, 8, bit);
        } else {
            set(data, size, 8, size - 7 + i - 8, bit);
        }
    }
}

fn in_finder(s: usize, x: usize, y: usize) -> bool {
    (x < 8 && y < 8) || (x >= s - 8 && y < 8) || (x < 8 && y >= s - 8)
}

fn function_module(version: u8, x: usize, y: usize) -> bool {
    let s = 17 + 4 * version as usize;
    if in_finder(s, x, y)
        || x == 6
        || y == 6
        || (x == 8 && (y <= 8 || y >= s - 8))
        || (y == 8 && (x <= 8 || x >= s - 8))
        || (version >= 7
            && ((x < 6 && (s - 11..s - 8).contains(&y)) || (y < 6 && (s - 11..s - 8).contains(&x))))
    {
        return true;
    }
    let centres = tables::ALIGNMENT_CENTRES[version as usize - 1];
    for &cy in centres {
        for &cx in centres {
            let (cx, cy) = (cx as usize, cy as usize);
            if !in_finder(s, cx, cy) && x.abs_diff(cx) <= 2 && y.abs_diff(cy) <= 2 {
                return true;
            }
        }
    }
    false
}

fn draw_base(output: &mut [u8], stream: &[u8], version: u8, ecc: Ecc) {
    wipe(output);
    let s = 17 + 4 * version as usize;
    for (left, top) in [(0i32, 0i32), (s as i32 - 7, 0), (0, s as i32 - 7)] {
        for dy in -1..=7i32 {
            for dx in -1..=7i32 {
                let (x, y) = (left + dx, top + dy);
                if x >= 0 && y >= 0 && x < s as i32 && y < s as i32 {
                    let ring = (dx - 3).abs().max((dy - 3).abs());
                    set(output, s, x as usize, y as usize, ring != 2 && ring != 4);
                }
            }
        }
    }
    set(output, s, 8, s - 8, true);
    for i in 8..s - 8 {
        set(output, s, i, 6, i % 2 == 0);
        set(output, s, 6, i, i % 2 == 0);
    }
    // Alignment patterns overwrite timing patterns where they cross.
    let centres = tables::ALIGNMENT_CENTRES[version as usize - 1];
    for &cy in centres {
        for &cx in centres {
            let (cx, cy) = (cx as usize, cy as usize);
            if in_finder(s, cx, cy) {
                continue;
            }
            for dy in -2i32..=2 {
                for dx in -2i32..=2 {
                    set(
                        output,
                        s,
                        (cx as i32 + dx) as usize,
                        (cy as i32 + dy) as usize,
                        dx.abs().max(dy.abs()) != 1,
                    );
                }
            }
        }
    }
    if version >= 7 {
        let mut rem = version as u32;
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
        }
        let info = ((version as u32) << 12) | rem;
        for k in 0..18 {
            let bit = (info >> k) & 1 != 0;
            let (i, j) = (k / 3, k % 3);
            set(output, s, i, s - 11 + j, bit);
            set(output, s, s - 11 + j, i, bit);
        }
    }
    header(output, s, ecc, 0);
    let (mut k, mut upward, mut right) = (0, true, s as i32 - 1);
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for step in 0..s {
            let y = if upward { s - 1 - step } else { step };
            for i in 0..2 {
                let x = (right - i) as usize;
                if !function_module(version, x, y) {
                    if k < stream.len() * 8 {
                        set(output, s, x, y, (stream[k / 8] >> (7 - k % 8)) & 1 != 0);
                    }
                    k += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

// Retain the specification's literal mask equations on the older ESP compiler.
#[allow(clippy::manual_is_multiple_of)]
fn mask_bit(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (y / 2 + x / 3) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        _ => (((x + y) % 2) + ((x * y) % 3)) % 2 == 0,
    }
}

fn toggle_mask(output: &mut [u8], reserved: &[u8], size: usize, mask: u8) {
    for y in 0..size {
        for x in 0..size {
            if !get(reserved, size, x, y) && mask_bit(mask, x, y) {
                set(output, size, x, y, !get(output, size, x, y));
            }
        }
    }
}

// Same penalty rules and tie order as the main encoder, reading packed bits.
fn penalty(m: &[u8], size: usize, limit: u32) -> u32 {
    let (mut score, mut dark) = (0u32, 0u32);
    for y in 0..size {
        let (mut row_run, mut col_run, mut row_bits, mut col_bits) = (0u32, 0u32, 0u32, 0u32);
        for x in 0..size {
            let here = get(m, size, x, y);
            dark += here as u32;
            if x > 0 && here == get(m, size, x - 1, y) {
                row_run += 1;
            } else {
                if row_run >= 5 {
                    score += row_run - 2;
                }
                row_run = 1;
            }
            let down = get(m, size, y, x);
            if x > 0 && down == get(m, size, y, x - 1) {
                col_run += 1;
            } else {
                if col_run >= 5 {
                    score += col_run - 2;
                }
                col_run = 1;
            }
            if x < size - 1
                && y < size - 1
                && here == get(m, size, x + 1, y)
                && here == get(m, size, x, y + 1)
                && here == get(m, size, x + 1, y + 1)
            {
                score += 3;
            }
            row_bits = (row_bits << 1) | here as u32;
            col_bits = (col_bits << 1) | down as u32;
            if x >= 10 {
                for bits in [row_bits, col_bits] {
                    if bits & 0x7ff == 0x05d {
                        score += 40;
                    }
                    if bits & 0x7ff == 0x5d0 && (x < 14 || bits & 0x7800 != 0) {
                        score += 40;
                    }
                }
            }
        }
        if row_run >= 5 {
            score += row_run - 2;
        }
        if col_run >= 5 {
            score += col_run - 2;
        }
        if score >= limit {
            return score;
        }
    }
    let total = (size * size) as u32;
    score + (dark * 2).abs_diff(total) * 10 / total * 10
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scratch_is_cleared_before_drawing_and_after_failure() {
        let mut w = Workspace::new();
        let mut output = [0; MODULE_BYTES];
        let code = encode_simple_text(
            "throwaway123456789012secret",
            &Options::default(),
            &mut w,
            &mut output,
        )
        .unwrap();
        assert!(w.buffer.iter().all(|&b| b == 0));
        assert!(code.is_dark(0, 0));
        drop(code);
        w.buffer.fill(0xff);
        assert!(encode_bytes(
            &[],
            &Options {
                mask: Some(8),
                ..Options::default()
            },
            &mut w,
            &mut output
        )
        .is_err());
        assert!(w.buffer.iter().all(|&b| b == 0));
    }
    #[cfg(feature = "optimal")]
    #[test]
    fn planner_is_cleared_after_success_and_late_capacity_error() {
        let mut p = TextPlanner::new();
        let mut w = Workspace::new();
        let mut output = [0; MODULE_BYTES];
        drop(
            encode_text(
                "a123456789012b",
                &Options::default(),
                &mut p,
                &mut w,
                &mut output,
            )
            .unwrap(),
        );
        for fail in [false, true] {
            if fail {
                p.decisions.fill(0xffff);
                p.costs.fill(u32::MAX);
                p.next.fill(u32::MAX);
                assert!(encode_text(
                    "abcdefghijklmnopqrstuvwxyz",
                    &Options {
                        version: Some(1),
                        ecc: Ecc::H,
                        ..Options::default()
                    },
                    &mut p,
                    &mut w,
                    &mut output
                )
                .is_err());
            }
            assert!(p.decisions.iter().all(|&n| n == 0));
            assert_eq!(p.costs, [0; 7]);
            assert_eq!(p.next, [0; 7]);
            assert!(w.buffer.iter().all(|&b| b == 0));
        }
    }
}
