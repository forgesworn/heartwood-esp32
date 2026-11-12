//! Identity picture formats for SET_IDENTITY_META (0x5B) and the relay
//! `set_identity_meta` method.
//!
//! A picture is `w * h` pixels. Its byte length picks the pixel format:
//!
//! - `w * h * 2`: [`AvatarFormat::Rgb565`], two bytes a pixel, big-endian
//!   (the format the signer has always taken).
//! - `w * h`: [`AvatarFormat::Rgb332`], one byte a pixel, bits `RRRGGGBB`,
//!   row-major. A 64x64 picture is a 4,098-byte blob (two bytes of size and
//!   4,096 of pixels), against 8,194 for the same picture in Rgb565: about half
//!   the storage.
//!
//! Any other length is not a picture. The device stores the bytes as they
//! came (`[w][h][pixels]`) and converts a pixel only as it draws it, so no
//! expanded copy is ever allocated.

/// How a picture's pixels are packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarFormat {
    /// Two bytes a pixel, Rgb565 big-endian.
    Rgb565,
    /// One byte a pixel, `RRRGGGBB`.
    Rgb332,
}

/// The pixel format a `w` x `h` picture of `len` bytes is in, or `None` if
/// `len` fits neither.
///
/// Rgb565 is tested first. The two lengths agree only at zero area, where
/// an empty picture stays Rgb565, as the signer has always taken it (a
/// name-only card over the cable). With zero area any other length is
/// refused.
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

/// An RGB332 byte as Rgb565, by bit replication: each channel's top bits
/// are repeated into the low bits, so black stays `0x0000` and white
/// `0xFFFF`.
pub fn rgb332_to_rgb565(byte: u8) -> u16 {
    let r3 = u16::from(byte >> 5);
    let g3 = u16::from((byte >> 2) & 7);
    let b2 = u16::from(byte & 3);
    let r5 = (r3 << 2) | (r3 >> 1);
    let g6 = (g3 << 3) | g3;
    let b5 = (b2 << 3) | (b2 << 1) | (b2 >> 1);
    (r5 << 11) | (g6 << 5) | b5
}

/// Pixel `index` (row-major) of `pixels` as Rgb565. `pixels` is the picture
/// without its size bytes, already checked by [`classify`] against `format`.
/// An index past the end reads as black rather than panicking.
pub fn pixel_rgb565(format: AvatarFormat, pixels: &[u8], index: usize) -> u16 {
    match format {
        AvatarFormat::Rgb565 => match pixels.get(index * 2..index * 2 + 2) {
            Some(c) => u16::from_be_bytes([c[0], c[1]]),
            None => 0,
        },
        AvatarFormat::Rgb332 => pixels.get(index).copied().map_or(0, rgb332_to_rgb565),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb332_expands_by_bit_replication() {
        // Vectors shared with the Sapwood mirror.
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
        assert_eq!(pixel_rgb565(AvatarFormat::Rgb565, &[], usize::MAX / 4), 0);
    }
}
