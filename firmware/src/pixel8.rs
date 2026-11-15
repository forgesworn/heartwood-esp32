// firmware/src/pixel8.rs
//
// One byte a pixel for the colour panels' RAM framebuffers (st7789.rs,
// jd9853.rs): the screens still draw in `Rgb565`, the framebuffer keeps an
// index into a 256-entry table, and the table is turned back into `Rgb565` as
// the frame is streamed to the panel. Halves the framebuffer: 64.8 KB -> 32.4 KB
// on the T-Display, 110 KB -> 55 KB on the C6.
//
// Pure (no esp-idf), so ui-preview includes this file verbatim via #[path] and
// its tests run on the host in the `ui-preview-tests` CI job, like palette.rs.
//
// Table layout (see `Codec::new`):
//
//   * The base is the full RGB332 cube, entry `i` = bits `RRRGGGBB`, each
//     channel widened to Rgb565 by bit replication (black stays 0x0000, white
//     0xFFFF). This is the same expansion as the identity picture's RGB332
//     format (`heartwood_common::identity_avatar::rgb332_to_rgb565`), so those
//     pictures sit on cube entries and survive the trip untouched.
//   * Every colour in `palette.rs`, plus pure white, is then written over the
//     nearest cube entry not already taken, so each one is stored EXACTLY. The
//     cube entry it displaced is no longer reachable by its own colour (a
//     picture pixel that lands there comes out as the neighbouring palette
//     colour); the worst such shift is pinned by a test.
//
// Encoding is cheap: a compare against the handful of palette colours (almost
// every pixel on a screen is one of them), then plain integer arithmetic into
// the cube. No search over the 256 entries per pixel.

#![allow(dead_code)]

use core::slice;

use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;

use crate::palette;

/// Every colour the screens draw in that must be stored exactly: the
/// `palette.rs` constants (a test checks this list against the file, so a new
/// colour cannot be forgotten) and pure white. Hottest first: the encoder
/// scans in this order.
pub const PALETTE: [(&str, Rgb565); 10] = [
    ("BG", palette::BG),
    ("FG", palette::FG),
    ("MUTED", palette::MUTED),
    ("ACCENT", palette::ACCENT),
    ("OK", palette::OK),
    ("WARN", palette::WARN),
    ("DANGER", palette::DANGER),
    ("GHOST", palette::GHOST),
    ("NOSTR", palette::NOSTR),
    ("WHITE", Rgb565::WHITE),
];

/// Most distinct exact colours (`PALETTE` has duplicates: ACCENT == OK).
const MAX_EXACT: usize = PALETTE.len();

/// An RGB332 byte as Rgb565 by bit replication.
pub const fn cube_to_raw(i: u8) -> u16 {
    let r3 = (i >> 5) as u16;
    let g3 = ((i >> 2) & 7) as u16;
    let b2 = (i & 3) as u16;
    let r5 = (r3 << 2) | (r3 >> 1);
    let g6 = (g3 << 3) | g3;
    let b5 = (b2 << 3) | (b2 << 1) | (b2 >> 1);
    (r5 << 11) | (g6 << 5) | b5
}

/// The RGB332 cube entry nearest an Rgb565 value, by rounding each channel to
/// its 3/3/2-bit level. Integer arithmetic only.
pub const fn raw_to_cube(raw: u16) -> u8 {
    let r5 = (raw >> 11) as u32;
    let g6 = ((raw >> 5) & 0x3F) as u32;
    let b5 = (raw & 0x1F) as u32;
    let r3 = (r5 * 7 + 15) / 31;
    let g3 = (g6 * 7 + 31) / 63;
    let b2 = (b5 * 3 + 15) / 31;
    ((r3 << 5) | (g3 << 2) | b2) as u8
}

/// A colour's channels widened to 8 bits, for distances.
const fn rgb888(raw: u16) -> (i32, i32, i32) {
    let r5 = (raw >> 11) as i32;
    let g6 = ((raw >> 5) & 0x3F) as i32;
    let b5 = (raw & 0x1F) as i32;
    ((r5 << 3) | (r5 >> 2), (g6 << 2) | (g6 >> 4), (b5 << 3) | (b5 >> 2))
}

fn dist2(a: u16, b: u16) -> i32 {
    let (ar, ag, ab) = rgb888(a);
    let (br, bg, bb) = rgb888(b);
    (ar - br).pow(2) + (ag - bg).pow(2) + (ab - bb).pow(2)
}

/// The encode/decode table. 512 bytes of RAM plus a 10-entry exact list.
pub struct Codec {
    /// Index -> raw Rgb565.
    decode: [u16; 256],
    /// Exact colours (raw, index), scanned first when encoding.
    exact: [(u16, u8); MAX_EXACT],
    exact_len: usize,
}

impl Codec {
    pub fn new() -> Self {
        let mut decode = [0u16; 256];
        let mut i = 0;
        while i < 256 {
            decode[i] = cube_to_raw(i as u8);
            i += 1;
        }
        let mut taken = [false; 256];
        let mut exact = [(0u16, 0u8); MAX_EXACT];
        let mut exact_len = 0;
        for (_, colour) in PALETTE.iter() {
            let raw = colour.into_storage();
            if exact[..exact_len].iter().any(|&(r, _)| r == raw) {
                continue; // ACCENT == OK
            }
            // An untaken cube entry that already is this colour, else the
            // nearest untaken one.
            let mut best = 0usize;
            let mut best_d = i32::MAX;
            for (cell, &d) in decode.iter().enumerate() {
                if taken[cell] {
                    continue;
                }
                let dd = dist2(d, raw);
                if dd < best_d {
                    best_d = dd;
                    best = cell;
                }
            }
            decode[best] = raw;
            taken[best] = true;
            exact[exact_len] = (raw, best as u8);
            exact_len += 1;
        }
        Self { decode, exact, exact_len }
    }

    /// The index to store for `colour`.
    #[inline]
    pub fn encode(&self, colour: Rgb565) -> u8 {
        let raw = colour.into_storage();
        for &(r, idx) in &self.exact[..self.exact_len] {
            if r == raw {
                return idx;
            }
        }
        raw_to_cube(raw)
    }

    /// The colour an index stands for.
    #[inline]
    pub fn decode(&self, index: u8) -> Rgb565 {
        Rgb565::from(RawU16::new(self.decode[index as usize]))
    }

    /// `frame` as the pixel stream the panel is sent: in order, or the whole
    /// picture turned through 180 degrees (last pixel first).
    pub fn stream<'a>(&'a self, frame: &'a [u8], flipped: bool) -> Stream<'a> {
        if flipped {
            Stream::Reversed(frame.iter().rev(), self)
        } else {
            Stream::Forward(frame.iter(), self)
        }
    }
}

/// The decoded pixels of a framebuffer, see [`Codec::stream`].
pub enum Stream<'a> {
    Forward(slice::Iter<'a, u8>, &'a Codec),
    Reversed(core::iter::Rev<slice::Iter<'a, u8>>, &'a Codec),
}

impl Iterator for Stream<'_> {
    type Item = Rgb565;

    #[inline]
    fn next(&mut self) -> Option<Rgb565> {
        match self {
            Stream::Forward(it, c) => it.next().map(|&i| c.decode(i)),
            Stream::Reversed(it, c) => it.next().map(|&i| c.decode(i)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Stream::Forward(it, _) => it.size_hint(),
            Stream::Reversed(it, _) => it.size_hint(),
        }
    }
}

impl ExactSizeIterator for Stream<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(c: Rgb565) -> u16 {
        c.into_storage()
    }

    /// Per-channel error in 8-bit units, worst channel.
    fn err(a: u16, b: u16) -> i32 {
        let (ar, ag, ab) = rgb888(a);
        let (br, bg, bb) = rgb888(b);
        (ar - br).abs().max((ag - bg).abs()).max((ab - bb).abs())
    }

    #[test]
    fn every_palette_colour_round_trips_exactly() {
        let codec = Codec::new();
        for (name, c) in PALETTE {
            assert_eq!(codec.decode(codec.encode(c)), c, "{name}");
        }
        // Compared by colour, not index: ACCENT and OK are one colour.
        assert_eq!(codec.encode(palette::ACCENT), codec.encode(palette::OK));
        assert_eq!(codec.decode(codec.encode(Rgb565::BLACK)), Rgb565::BLACK);
        assert_eq!(codec.decode(codec.encode(Rgb565::WHITE)), Rgb565::WHITE);
    }

    #[test]
    fn palette_list_matches_palette_rs() {
        let src = include_str!("palette.rs");
        let mut in_file = Vec::new();
        for line in src.lines() {
            if let Some(rest) = line.trim().strip_prefix("pub const ") {
                if let Some((name, ty)) = rest.split_once(':') {
                    if ty.trim_start().starts_with("Rgb565") {
                        in_file.push(name.trim().to_string());
                    }
                }
            }
        }
        assert!(in_file.len() >= 9, "found {in_file:?}");
        for name in &in_file {
            assert!(
                PALETTE.iter().any(|(n, _)| n == name),
                "palette.rs colour {name} is missing from pixel8::PALETTE"
            );
        }
    }

    #[test]
    fn table_is_the_cube_with_palette_written_over_it() {
        let codec = Codec::new();
        let displaced = (0..=255u8)
            .filter(|&i| raw(codec.decode(i)) != cube_to_raw(i))
            .count();
        // 9 distinct exact colours, black and white's cells already match.
        assert!(displaced <= 9, "{displaced} cube entries displaced");
        // The encoder's exact list is what the table holds.
        for &(r, idx) in &codec.exact[..codec.exact_len] {
            assert_eq!(raw(codec.decode(idx)), r);
        }
    }

    #[test]
    fn cube_colours_round_trip() {
        let codec = Codec::new();
        for i in 0..=255u8 {
            let c = cube_to_raw(i);
            assert_eq!(raw_to_cube(c), i, "arithmetic encode of cube {i:#04x}");
            let back = raw(codec.decode(codec.encode(Rgb565::from(RawU16::new(c)))));
            let is_exact_palette = PALETTE.iter().any(|(_, p)| raw(*p) == c);
            if is_exact_palette || raw(codec.decode(i)) == c {
                assert_eq!(back, c, "cube {i:#04x}");
            } else {
                // A displaced cell: comes back as the palette colour that took it.
                assert!(err(back, c) <= 40, "cube {i:#04x}: {c:#06x} -> {back:#06x}");
            }
        }
    }

    #[test]
    fn rgb332_picture_bytes_match_the_picture_format_expansion() {
        // heartwood_common::identity_avatar::rgb332_to_rgb565, restated: black
        // and white keep their ends, and the middle levels are replicated bits.
        assert_eq!(cube_to_raw(0x00), 0x0000);
        assert_eq!(cube_to_raw(0xFF), 0xFFFF);
        assert_eq!(cube_to_raw(0b100_100_10), (0b10010 << 11) | (0b100100 << 5) | 0b10101);
    }

    #[test]
    fn any_rgb565_lands_within_the_expected_error() {
        let codec = Codec::new();
        let mut worst = 0;
        let mut worst_at = 0u16;
        for v in 0..=u16::MAX {
            let back = raw(codec.decode(codec.encode(Rgb565::from(RawU16::new(v)))));
            let e = err(v, back);
            if e > worst {
                worst = e;
                worst_at = v;
            }
        }
        // Plain RGB332 rounding is 41 at worst in 8-bit units (blue has two
        // bits, so steps of 85); the nine palette colours written over cube
        // entries lift that to 66 where a displaced entry is the nearest.
        assert!(worst <= 66, "worst channel error {worst} at {worst_at:#06x}");
    }

    #[test]
    fn flipped_stream_is_the_reverse_of_the_forward_stream() {
        let codec = Codec::new();
        let frame: Vec<u8> = (0..=255u8).chain(0..=20u8).collect();
        let fwd: Vec<Rgb565> = codec.stream(&frame, false).collect();
        let mut rev: Vec<Rgb565> = codec.stream(&frame, true).collect();
        assert_eq!(fwd.len(), frame.len());
        assert_eq!(codec.stream(&frame, true).len(), frame.len());
        rev.reverse();
        assert_eq!(fwd, rev);
        assert_eq!(fwd[0], codec.decode(frame[0]));
        assert_eq!(codec.stream(&frame, true).next(), Some(codec.decode(*frame.last().unwrap())));
    }
}
