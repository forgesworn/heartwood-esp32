//! Identity pictures: the pixel formats, and how the signer stores one.
//!
//! On the wire (SET_IDENTITY_META 0x5B and the relay `set_identity_meta`) a
//! picture is `w * h` pixels, and its byte length picks the format
//! ([`classify`], the rule of #278): `w * h * 2` is Rgb565, two bytes a pixel,
//! big-endian, as it always was; `w * h` is RGB332, one byte a pixel, bits
//! `RRRGGGBB`, row-major; any other length is refused. The signer stores
//! either at one byte a pixel, RGB332 (an Rgb565 picture converted, an RGB332
//! one as it came), so a 48x48 picture takes 2,308 bytes of NVS instead of
//! 4,610, and a 64x64 one 4,100 instead of 8,194.
//!
//! The stored blob (`imav<slot>`) is one of:
//!
//! - legacy, as beta.38 and earlier wrote it: `[w][h]` then `w * h * 2`
//!   bytes of Rgb565. Still read, never written for a picture with pixels.
//! - version 1: `[0x00][0x01][w][h]` then `w * h` bytes of RGB332, for a
//!   picture of non-zero area.
//!
//! The two never collide: a legacy blob starting `0x00` has zero area and so
//! is exactly two bytes long, and a version-1 blob is at least five. A
//! zero-area picture (a name-only card) is stored in the legacy form, which
//! every firmware reads. Firmware that knows only the legacy form finds a
//! version-1 blob the wrong length and shows no card for that identity, the
//! name included, until the picture is sent again (`docs/PERSISTENT-STATE.md`).
//!
//! RGB332 is the cube the colour panels' framebuffers already use
//! (`firmware/src/pixel8.rs`, `raw_to_cube` / `cube_to_raw`): each channel is
//! rounded to its nearest 3/3/2-bit level, and widened back by bit
//! replication, so black and white keep their ends. Plain RGB332, not the
//! framebuffer's palette indices, so a change to `palette.rs` never recolours
//! a stored picture. ui-preview pins the two implementations equal.

use alloc::vec::Vec;

/// How a picture's pixels are packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarFormat {
    /// Two bytes a pixel, Rgb565 big-endian.
    Rgb565,
    /// One byte a pixel, `RRRGGGBB`.
    Rgb332,
}

/// The pixel format a `w` x `h` picture of `len` pixel bytes is in, or
/// `None` if `len` fits neither. The two agree only at zero area, which is
/// Rgb565, as the signer has always taken it.
pub fn classify(w: u8, h: u8, len: usize) -> Option<AvatarFormat> {
    let pixels = usize::from(w) * usize::from(h);
    if len == pixels * 2 {
        Some(AvatarFormat::Rgb565)
    } else if len == pixels {
        Some(AvatarFormat::Rgb332)
    } else {
        None
    }
}

/// An RGB332 byte as Rgb565, by bit replication: black stays `0x0000` and
/// white `0xFFFF`.
pub fn rgb332_to_rgb565(byte: u8) -> u16 {
    let r3 = u16::from(byte >> 5);
    let g3 = u16::from((byte >> 2) & 7);
    let b2 = u16::from(byte & 3);
    let r5 = (r3 << 2) | (r3 >> 1);
    let g6 = (g3 << 3) | g3;
    let b5 = (b2 << 3) | (b2 << 1) | (b2 >> 1);
    (r5 << 11) | (g6 << 5) | b5
}

/// The RGB332 byte nearest an Rgb565 value, each channel rounded to its
/// level. Integer arithmetic only.
pub fn rgb565_to_rgb332(raw: u16) -> u8 {
    let r5 = u32::from(raw >> 11);
    let g6 = u32::from((raw >> 5) & 0x3F);
    let b5 = u32::from(raw & 0x1F);
    let r3 = (r5 * 7 + 15) / 31;
    let g3 = (g6 * 7 + 31) / 63;
    let b2 = (b5 * 3 + 15) / 31;
    ((r3 << 5) | (g3 << 2) | b2) as u8
}

/// Pixel `index` (row-major) of `pixels` as Rgb565. An index past the end
/// reads as black rather than panicking.
pub fn pixel_rgb565(format: AvatarFormat, pixels: &[u8], index: usize) -> u16 {
    match format {
        AvatarFormat::Rgb565 => match index.checked_mul(2).and_then(|at| pixels.get(at..at + 2)) {
            Some(c) => u16::from_be_bytes([c[0], c[1]]),
            None => 0,
        },
        AvatarFormat::Rgb332 => pixels.get(index).copied().map_or(0, rgb332_to_rgb565),
    }
}

/// First byte of a versioned stored picture. A legacy picture starting with
/// it has zero area.
pub const STORED_MAGIC: u8 = 0x00;
/// Version of the one-byte-a-pixel stored form.
pub const STORED_RGB332: u8 = 0x01;
/// Bytes before the pixels of a version-1 picture.
pub const STORED_HEADER: usize = 4;

/// Why a picture could not be made into a stored blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The pixels are neither `w * h * 2` bytes (Rgb565) nor `w * h`
    /// (RGB332).
    BadLength,
    /// The blob's buffer could not be allocated.
    NoMemory,
}

/// The length of the blob [`encode_stored`] makes for a `w` x `h` picture.
pub fn stored_len(w: u8, h: u8) -> usize {
    let pixels = usize::from(w) * usize::from(h);
    if pixels == 0 {
        2
    } else {
        STORED_HEADER + pixels
    }
}

/// The blob to store for a `w` x `h` picture of `pixels` as on the wire
/// (Rgb565 big-endian or RGB332, by [`classify`]): version 1 at one byte a
/// pixel, Rgb565 converted and RGB332 copied as it came, or the two size
/// bytes alone for zero area. One allocation of [`stored_len`] bytes,
/// reserved fallibly so a fragmented heap refuses rather than aborts.
pub fn encode_stored(w: u8, h: u8, pixels: &[u8]) -> Result<Vec<u8>, StoreError> {
    let format = classify(w, h, pixels.len()).ok_or(StoreError::BadLength)?;
    let len = stored_len(w, h);
    let mut blob = Vec::new();
    blob.try_reserve_exact(len).map_err(|_| StoreError::NoMemory)?;
    if pixels.is_empty() {
        blob.extend_from_slice(&[w, h]);
        return Ok(blob);
    }
    blob.extend_from_slice(&[STORED_MAGIC, STORED_RGB332, w, h]);
    match format {
        AvatarFormat::Rgb565 => blob.extend(
            pixels.chunks_exact(2).map(|c| rgb565_to_rgb332(u16::from_be_bytes([c[0], c[1]]))),
        ),
        AvatarFormat::Rgb332 => blob.extend_from_slice(pixels),
    }
    Ok(blob)
}

/// A stored picture, read: its size, its format and where its pixels start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub w: u8,
    pub h: u8,
    pub format: AvatarFormat,
    /// Offset of the pixels in the blob.
    pub pixels_at: usize,
}

/// Read a stored blob's header: version 1, or legacy Rgb565. `None` for
/// anything else (a newer version, a torn or corrupt blob).
pub fn decode_stored(blob: &[u8]) -> Option<Stored> {
    if let [STORED_MAGIC, STORED_RGB332, w, h, ..] = *blob {
        let pixels = usize::from(w) * usize::from(h);
        if pixels > 0 && blob.len() == STORED_HEADER + pixels {
            return Some(Stored { w, h, format: AvatarFormat::Rgb332, pixels_at: STORED_HEADER });
        }
    }
    match *blob {
        [w, h, ..] if blob.len() == 2 + usize::from(w) * usize::from(h) * 2 => {
            Some(Stored { w, h, format: AvatarFormat::Rgb565, pixels_at: 2 })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb332_expands_by_bit_replication() {
        // Vectors shared with the Sapwood mirror (#278's, unchanged).
        for (byte, expect) in [
            (0x00u8, 0x0000u16),
            (0xFF, 0xFFFF),
            (0xE0, 0xF800),
            (0x1C, 0x07E0),
            (0x03, 0x001F),
            (0x92, 0x9495),
            (0x49, 0x4A4A),
            (0x25, 0x212A),
        ] {
            assert_eq!(rgb332_to_rgb565(byte), expect, "{byte:#04x}");
        }
    }

    #[test]
    fn every_rgb332_byte_survives_the_round_trip() {
        for byte in 0..=255u8 {
            assert_eq!(rgb565_to_rgb332(rgb332_to_rgb565(byte)), byte, "{byte:#04x}");
        }
    }

    #[test]
    fn every_rgb565_value_lands_on_its_nearest_level() {
        // Each channel within half a level of the original, so the worst a
        // picture moves is half the RGB332 step: red and green 18 of 255,
        // blue 42.
        let to888 = |v: u16| {
            let r = i32::from(v >> 11) * 255 / 31;
            let g = i32::from((v >> 5) & 0x3F) * 255 / 63;
            let b = i32::from(v & 0x1F) * 255 / 31;
            (r, g, b)
        };
        for v in 0..=u16::MAX {
            let (r, g, b) = to888(v);
            let (r2, g2, b2) = to888(rgb332_to_rgb565(rgb565_to_rgb332(v)));
            assert!((r - r2).abs() <= 19 && (g - g2).abs() <= 19 && (b - b2).abs() <= 43, "{v:#06x}");
        }
        assert_eq!(rgb565_to_rgb332(0x0000), 0x00);
        assert_eq!(rgb565_to_rgb332(0xFFFF), 0xFF);
    }

    #[test]
    fn the_length_picks_the_display_format() {
        assert_eq!(classify(64, 64, 64 * 64 * 2), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(64, 64, 64 * 64), Some(AvatarFormat::Rgb332));
        assert_eq!(classify(0, 0, 0), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(64, 64, 64 * 64 + 1), None);
        assert_eq!(classify(0, 64, 2), None);
    }

    #[test]
    fn a_picture_is_stored_at_one_byte_a_pixel() {
        // Red, green, blue, white, as on the wire.
        let wire = [0xF8, 0x00, 0x07, 0xE0, 0x00, 0x1F, 0xFF, 0xFF];
        let blob = encode_stored(2, 2, &wire).unwrap();
        assert_eq!(blob, [0x00, 0x01, 2, 2, 0xE0, 0x1C, 0x03, 0xFF]);
        assert_eq!(blob.len(), stored_len(2, 2));
        let stored = decode_stored(&blob).unwrap();
        assert_eq!(stored, Stored { w: 2, h: 2, format: AvatarFormat::Rgb332, pixels_at: 4 });
        let pixels = &blob[stored.pixels_at..];
        let drawn: Vec<u16> = (0..4).map(|i| pixel_rgb565(stored.format, pixels, i)).collect();
        assert_eq!(drawn, [0xF800, 0x07E0, 0x001F, 0xFFFF]);
        assert_eq!(classify(stored.w, stored.h, pixels.len()), Some(stored.format));
        // The sizes the signer is sent.
        assert_eq!(stored_len(48, 48), 2308);
        assert_eq!(stored_len(64, 64), 4100);
    }

    #[test]
    fn a_legacy_picture_still_reads() {
        let mut blob = vec![2, 2];
        blob.extend_from_slice(&[0xF8, 0x00, 0x07, 0xE0, 0x00, 0x1F, 0xFF, 0xFF]);
        let stored = decode_stored(&blob).unwrap();
        assert_eq!(stored, Stored { w: 2, h: 2, format: AvatarFormat::Rgb565, pixels_at: 2 });
        assert_eq!(pixel_rgb565(stored.format, &blob[2..], 3), 0xFFFF);
        // A name-only card: stored in the legacy form, read by any firmware.
        let empty = encode_stored(0, 0, &[]).unwrap();
        assert_eq!(empty, [0, 0]);
        assert_eq!(decode_stored(&empty).unwrap().format, AvatarFormat::Rgb565);
        assert_eq!(encode_stored(5, 0, &[]).unwrap(), [5, 0]);
    }

    #[test]
    fn the_two_stored_forms_never_collide() {
        // Every size, on real blob lengths: a legacy blob reads as legacy and
        // a version-1 blob as version 1, whatever the pixel bytes hold.
        let mut buf = vec![0u8; 2 + 255 * 255 * 2];
        for w in 0..=255u8 {
            for h in 0..=255u8 {
                let area = usize::from(w) * usize::from(h);
                buf[0] = w;
                buf[1] = h;
                buf[2..6].copy_from_slice(&[w, h, 0x00, 0x01]);
                let legacy = decode_stored(&buf[..2 + area * 2]).unwrap();
                assert_eq!((legacy.format, legacy.w, legacy.h), (AvatarFormat::Rgb565, w, h), "legacy {w}x{h}");
                buf[..4].copy_from_slice(&[STORED_MAGIC, STORED_RGB332, w, h]);
                let v1 = decode_stored(&buf[..STORED_HEADER + area]);
                if area == 0 {
                    // Zero area is stored as legacy, and a version-1 header
                    // with no pixels is nothing.
                    assert_eq!(v1, None, "{w}x{h}");
                } else {
                    let v1 = v1.unwrap();
                    assert_eq!((v1.format, v1.w, v1.h), (AvatarFormat::Rgb332, w, h), "v1 {w}x{h}");
                }
            }
        }
        assert_eq!(decode_stored(&[0, 1]).unwrap().format, AvatarFormat::Rgb565);
        assert_eq!(decode_stored(&[0, 1, 1, 1, 0xE0]).unwrap().format, AvatarFormat::Rgb332);
    }

    #[test]
    fn anything_else_is_not_a_picture() {
        assert_eq!(decode_stored(&[]), None);
        assert_eq!(decode_stored(&[1]), None);
        assert_eq!(decode_stored(&[2, 2, 0, 0]), None, "short legacy");
        assert_eq!(decode_stored(&[0, 1, 2, 2, 0, 0, 0]), None, "short version 1");
        assert_eq!(decode_stored(&[0, 2, 1, 1, 0]), None, "an unknown version");
        assert_eq!(encode_stored(2, 2, &[0; 7]), Err(StoreError::BadLength));
        assert_eq!(encode_stored(2, 2, &[0; 3]), Err(StoreError::BadLength));
        assert_eq!(encode_stored(2, 2, &[0; 5]), Err(StoreError::BadLength));
        assert_eq!(encode_stored(0, 64, &[0; 2]), Err(StoreError::BadLength));
    }

    #[test]
    fn an_rgb332_picture_is_stored_as_it_came() {
        // Red, green, blue, white at one byte a pixel: the same blob as the
        // Rgb565 picture of those colours makes.
        let wire = [0xE0, 0x1C, 0x03, 0xFF];
        let blob = encode_stored(2, 2, &wire).unwrap();
        assert_eq!(blob, [0x00, 0x01, 2, 2, 0xE0, 0x1C, 0x03, 0xFF]);
        assert_eq!(blob, encode_stored(2, 2, &[0xF8, 0x00, 0x07, 0xE0, 0x00, 0x1F, 0xFF, 0xFF]).unwrap());
        // Every byte value passes through untouched.
        let all: Vec<u8> = (0..=255u8).collect();
        let blob = encode_stored(16, 16, &all).unwrap();
        assert_eq!(blob.len(), stored_len(16, 16));
        assert_eq!(&blob[STORED_HEADER..], &all[..]);
        let stored = decode_stored(&blob).unwrap();
        assert_eq!((stored.w, stored.h, stored.format), (16, 16, AvatarFormat::Rgb332));
        assert_eq!(encode_stored(64, 64, &[0x25; 64 * 64]).unwrap().len(), 4100);
    }

    // #278's tests, carried over unchanged so its Sapwood draft's wire rule
    // holds here too.

    #[test]
    fn every_rgb332_byte_keeps_its_top_bits_and_the_extremes() {
        for byte in 0..=255u8 {
            let v = rgb332_to_rgb565(byte);
            // The top bits of each Rgb565 channel are the Rgb332 bits.
            assert_eq!(v >> 13, u16::from(byte >> 5), "{byte:#04x} red");
            assert_eq!((v >> 8) & 7, u16::from((byte >> 2) & 7), "{byte:#04x} green");
            assert_eq!((v >> 3) & 3, u16::from(byte & 3), "{byte:#04x} blue");
        }
        // A full channel is a full channel.
        assert_eq!(rgb332_to_rgb565(0xE0) >> 11, 0x1F);
        assert_eq!((rgb332_to_rgb565(0x1C) >> 5) & 0x3F, 0x3F);
        assert_eq!(rgb332_to_rgb565(0x03) & 0x1F, 0x1F);
    }

    #[test]
    fn the_length_picks_the_format() {
        assert_eq!(classify(64, 64, 64 * 64 * 2), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(64, 64, 64 * 64), Some(AvatarFormat::Rgb332));
        assert_eq!(classify(48, 48, 48 * 48 * 2), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(255, 255, 255 * 255 * 2), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(255, 255, 255 * 255), Some(AvatarFormat::Rgb332));
        assert_eq!(classify(2, 2, 8), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(2, 2, 4), Some(AvatarFormat::Rgb332));
        assert_eq!(classify(1, 1, 1), Some(AvatarFormat::Rgb332));
        assert_eq!(classify(1, 1, 2), Some(AvatarFormat::Rgb565));
    }

    #[test]
    fn any_other_length_is_refused() {
        assert_eq!(classify(64, 64, 0), None);
        assert_eq!(classify(64, 64, 64 * 64 - 1), None);
        assert_eq!(classify(64, 64, 64 * 64 + 1), None);
        assert_eq!(classify(64, 64, 64 * 64 * 2 - 1), None);
        assert_eq!(classify(64, 64, 64 * 64 * 2 + 1), None);
        assert_eq!(classify(64, 64, 64 * 64 * 3), None);
        assert_eq!(classify(2, 2, 6), None);
        assert_eq!(classify(2, 2, 5), None);
    }

    #[test]
    fn the_two_lengths_agree_only_at_zero_area() {
        // No non-zero area has w*h == w*h*2, so the format is never
        // ambiguous there.
        for w in 1..=255u8 {
            for h in [1u8, 2, 17, 255] {
                let n = usize::from(w) * usize::from(h);
                assert_ne!(n, n * 2);
            }
        }
        // At zero area an empty picture stays Rgb565, as it always was;
        // anything longer is refused.
        assert_eq!(classify(0, 0, 0), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(0, 64, 0), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(64, 0, 0), Some(AvatarFormat::Rgb565));
        assert_eq!(classify(0, 0, 1), None);
        assert_eq!(classify(0, 64, 2), None);
        assert_eq!(classify(64, 0, 4096), None);
    }

    #[test]
    fn the_shared_payload_is_a_valid_rgb332_card() {
        // pubkey 32 x 0x11, w=2, h=2, name "A", avatar 00 FF E0 03.
        let mut payload = vec![0x11u8; 32];
        payload.extend_from_slice(&[2, 2, 1, b'A', 0x00, 0xFF, 0xE0, 0x03]);
        assert_eq!(payload.len(), 40);
        let (w, h, name_len) = (payload[32], payload[33], usize::from(payload[34]));
        let avatar = &payload[35 + name_len..];
        assert_eq!(&payload[35..35 + name_len], b"A");
        assert_eq!(classify(w, h, avatar.len()), Some(AvatarFormat::Rgb332));
        let drawn: Vec<u16> =
            (0..4).map(|i| pixel_rgb565(AvatarFormat::Rgb332, avatar, i)).collect();
        assert_eq!(drawn, [0x0000, 0xFFFF, 0xF800, 0x001F]);
        // Here it is also stored: as it came, behind the version-1 header,
        // and drawn the same from flash.
        let blob = encode_stored(w, h, avatar).unwrap();
        assert_eq!(blob, [0x00, 0x01, 2, 2, 0x00, 0xFF, 0xE0, 0x03]);
        let stored = decode_stored(&blob).unwrap();
        let from_flash: Vec<u16> =
            (0..4).map(|i| pixel_rgb565(stored.format, &blob[stored.pixels_at..], i)).collect();
        assert_eq!(from_flash, drawn);
    }

    #[test]
    fn rgb565_pixels_read_big_endian_as_before() {
        let bytes = [0xF8, 0x00, 0x07, 0xE0, 0x00, 0x1F, 0xFF, 0xFF];
        let drawn: Vec<u16> =
            (0..4).map(|i| pixel_rgb565(AvatarFormat::Rgb565, &bytes, i)).collect();
        assert_eq!(drawn, [0xF800, 0x07E0, 0x001F, 0xFFFF]);
    }

    #[test]
    fn a_pixel_past_the_end_is_black_not_a_panic() {
        assert_eq!(pixel_rgb565(AvatarFormat::Rgb332, &[0xFF], 1), 0);
        assert_eq!(pixel_rgb565(AvatarFormat::Rgb565, &[0xFF, 0xFF, 0xFF], 1), 0);
        assert_eq!(pixel_rgb565(AvatarFormat::Rgb565, &[], usize::MAX), 0);
    }
}
