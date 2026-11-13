// common/src/crc32.rs
//
// CRC-32 for the serial frames and the small checksummed records the firmware
// keeps. This is the standard CRC-32 (zlib, PNG, Ethernet: reflected
// polynomial 0xEDB88320, initial value and final XOR 0xFFFFFFFF), so every
// checksum is the one crc32fast produced before and the one host tools that
// still use crc32fast compute.
//
// It folds each byte in four bits at a time from a 16-entry table, 64 bytes
// in all. crc32fast's slice-by-16 table is 16 KiB, which the Heltec V4's
// 2 MB app slot cannot spare, and nothing here checksums more than one serial
// frame at a time, so its extra speed bought nothing.

/// The reflected CRC-32 polynomial.
const POLY: u32 = 0xEDB8_8320;

/// The CRC step for every four-bit value, built at compile time.
const NIBBLE: [u32; 16] = {
    let mut table = [0u32; 16];
    let mut n = 0;
    while n < 16 {
        let mut crc = n as u32;
        let mut bit = 0;
        while bit < 4 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[n] = crc;
        n += 1;
    }
    table
};

/// An incremental CRC-32 with the `new`, `update` and `finalize` calls of
/// `crc32fast::Hasher`. Feeding the input in pieces gives the same result as
/// feeding it at once.
#[derive(Clone, Debug)]
pub struct Hasher {
    state: u32,
}

impl Hasher {
    pub const fn new() -> Self {
        Self { state: !0 }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        for &byte in bytes {
            crc ^= u32::from(byte);
            crc = (crc >> 4) ^ NIBBLE[(crc & 0xF) as usize];
            crc = (crc >> 4) ^ NIBBLE[(crc & 0xF) as usize];
        }
        self.state = crc;
    }

    pub fn finalize(self) -> u32 {
        !self.state
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Hasher;
    use alloc::vec::Vec;

    fn ours(parts: &[&[u8]]) -> u32 {
        let mut h = Hasher::new();
        for part in parts {
            h.update(part);
        }
        h.finalize()
    }

    /// Deterministic bytes, so a failure names a reproducible input.
    fn bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn standard_check_values() {
        // The published CRC-32/ISO-HDLC check value, and the empty input.
        assert_eq!(ours(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(ours(&[]), 0);
        assert_eq!(ours(&[b""]), 0);
        assert_eq!(
            ours(&[b"The quick brown fox jumps over the lazy dog"]),
            0x414F_A339
        );
    }

    #[test]
    fn matches_crc32fast_whole_and_in_pieces() {
        // Every length up to a few frames' worth of header and payload, plus a
        // payload at the u16 frame limit, each fed whole and split three ways.
        let lens = (0..=300usize).chain([1021, 4096, 65_535, 65_535 + 9]);
        for (i, len) in lens.enumerate() {
            let data = bytes(len, 0x9E37_79B9 ^ i as u32);
            let mut reference = crc32fast::Hasher::new();
            reference.update(&data);
            let want = reference.finalize();
            assert_eq!(ours(&[&data]), want, "whole, len {len}");
            let a = len / 3;
            let b = len - len / 5;
            assert_eq!(
                ours(&[&data[..a], &data[a..b], &data[b..]]),
                want,
                "split, len {len}"
            );
            assert_eq!(
                ours(&[&data[..0], &data, &data[len..]]),
                want,
                "empty pieces, len {len}"
            );
        }
    }

    #[test]
    fn a_clone_continues_independently() {
        let data = bytes(64, 7);
        let mut h = Hasher::new();
        h.update(&data[..20]);
        let fork = h.clone();
        h.update(&data[20..]);
        assert_eq!(h.finalize(), ours(&[&data]));
        assert_eq!(fork.finalize(), ours(&[&data[..20]]));
    }
}
