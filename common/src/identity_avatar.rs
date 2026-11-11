//! Identity picture formats for SET_IDENTITY_META (0x5B) and the relay
//! `set_identity_meta` method, and the room check for replacing a stored one.
//!
//! A picture is `w * h` pixels. Its byte length picks the pixel format:
//!
//! - `w * h * 2`: [`AvatarFormat::Rgb565`], two bytes a pixel, big-endian
//!   (the format the signer has always taken).
//! - `w * h`: [`AvatarFormat::Rgb332`], one byte a pixel, bits `RRRGGGBB`,
//!   row-major. A 64x64 picture is a 4,098-byte blob (two bytes of size and
//!   4,096 of pixels), against 8,194 for the same picture in Rgb565, so it
//!   fits on a signer whose storage held only a 48x48 Rgb565 one (4,610).
//!
//! Any other length is not a picture. The device stores the bytes as they
//! came (`[w][h][pixels]`) and converts a pixel only as it draws it, so no
//! expanded copy is ever allocated.

use crate::nvs_room::{available_entries, blob_write_entries, min_blob_entries, NvsRoom};

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

/// What to do when writing a new picture blob failed and an older one is
/// stored under the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceVerdict {
    /// The estimate says the new blob fits beside the old one. Removing the
    /// old picture would not help the write that failed, so keep it and
    /// refuse.
    FitsBesideOld,
    /// The new blob fits only once the old one is erased: remove it and
    /// write again, once.
    FitsAfterRemoval,
    /// It does not fit even then. Keep the old picture and refuse.
    DoesNotFit,
}

impl ReplaceVerdict {
    /// Whether the caller should erase the stored picture and retry.
    pub fn remove_and_retry(self) -> bool {
        self == ReplaceVerdict::FitsAfterRemoval
    }
}

/// Decide what a failed picture write does, from the blob lengths
/// (`2 + pixel bytes` each) and the partition's room as read after the
/// failure. ESP-IDF writes the new blob before it erases the old one (see
/// [`crate::nvs_room`]), so the old picture's entries still count as used
/// while the new one is written; erasing it first frees at least
/// [`min_blob_entries`] of them.
///
/// A picture is cosmetic and can be sent again, but a working one is never
/// removed for a write the estimate says will still fail, nor when the
/// room is unknown (`None`).
pub fn replace_verdict(new_len: usize, old_len: usize, room: Option<NvsRoom>) -> ReplaceVerdict {
    let Some(room) = room else {
        return ReplaceVerdict::DoesNotFit;
    };
    let needed = blob_write_entries(new_len, room.pages());
    if room.fits_without_reclaim(needed) {
        return ReplaceVerdict::FitsBesideOld;
    }
    let freed = room.reclaimable_entries.saturating_add(min_blob_entries(old_len));
    if needed <= available_entries(room.free_entries.saturating_add(freed)) {
        ReplaceVerdict::FitsAfterRemoval
    } else {
        ReplaceVerdict::DoesNotFit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bench T-Display's partition: 756 entries, 6 pages.
    const BENCH_TOTAL: usize = 756;

    fn room(free: usize) -> Option<NvsRoom> {
        Some(NvsRoom { free_entries: free, total_entries: BENCH_TOTAL, reclaimable_entries: 0 })
    }

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

    #[test]
    fn a_picture_that_fits_beside_the_old_one_removes_nothing() {
        // 4,098 incoming, 4,610 stored: 129 data + 6 headers + 1 index + 13
        // slack = 149 entries needed, 6 pages. Plenty free.
        let v = replace_verdict(4098, 4610, room(126 + 149));
        assert_eq!(v, ReplaceVerdict::FitsBesideOld);
        assert!(!v.remove_and_retry());
        assert_eq!(replace_verdict(4098, 4610, room(126 + 148)), ReplaceVerdict::FitsAfterRemoval);
    }

    #[test]
    fn a_picture_that_fits_only_after_removal_removes_and_retries() {
        // The 48x48 Rgb565 blob frees 145 + 2 + 1 = 148 entries at least,
        // so 149 needed is reached from 126 + 1 free upwards.
        assert_eq!(min_blob_entries(4610), 148);
        assert_eq!(blob_write_entries(4098, 6), 149);
        let v = replace_verdict(4098, 4610, room(126 + 1));
        assert_eq!(v, ReplaceVerdict::FitsAfterRemoval);
        assert!(v.remove_and_retry());
        assert_eq!(replace_verdict(4098, 4610, room(126 + 148)), ReplaceVerdict::FitsAfterRemoval);
    }

    #[test]
    fn a_picture_that_does_not_fit_even_then_keeps_the_old_one() {
        // At 126 free there is no available entry; the old blob's 148 give
        // 148, one short of 149.
        let v = replace_verdict(4098, 4610, room(126));
        assert_eq!(v, ReplaceVerdict::DoesNotFit);
        assert!(!v.remove_and_retry());
        assert_eq!(replace_verdict(4098, 4610, room(0)), ReplaceVerdict::DoesNotFit);
        // A big new picture against a small old one.
        assert_eq!(replace_verdict(8194, 4610, room(200)), ReplaceVerdict::DoesNotFit);
        // An old blob of nothing frees only its index entry.
        assert_eq!(replace_verdict(4098, 0, room(126 + 147)), ReplaceVerdict::DoesNotFit);
        assert_eq!(replace_verdict(4098, 0, room(126 + 148)), ReplaceVerdict::FitsAfterRemoval);
    }

    #[test]
    fn unknown_room_never_removes_the_old_picture() {
        assert_eq!(replace_verdict(4098, 4610, None), ReplaceVerdict::DoesNotFit);
    }

    #[test]
    fn the_verdict_boundaries_match_the_estimate() {
        // Walk free entries across both edges for the bench partition.
        let needed = blob_write_entries(4098, 6);
        let freed = min_blob_entries(4610);
        for free in 0..800usize {
            let expect = if needed <= free.saturating_sub(126) {
                ReplaceVerdict::FitsBesideOld
            } else if needed <= (free + freed).saturating_sub(126) {
                ReplaceVerdict::FitsAfterRemoval
            } else {
                ReplaceVerdict::DoesNotFit
            };
            assert_eq!(replace_verdict(4098, 4610, room(free)), expect, "free {free}");
        }
    }
}
