//! Minimal bech32 encoder (no_std, no-alloc) for npub encoding.
//!
//! Verified on the host against the canonical NIP-19 vector
//! (`3bf0c63f…459d` → `npub180cvv…jh6w6`) before being embedded here.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

/// Encode `data8` (8-bit bytes) under `hrp` as bech32 ASCII into `out`.
/// Returns the number of bytes written, or `None` if `out` is too small.
/// (Sized for npub: 32-byte payload → 52 groups; `out` needs ≥ hrp+1+52+6.)
pub fn encode(hrp: &[u8], data8: &[u8], out: &mut [u8]) -> Option<usize> {
    // Regroup 8-bit bytes into 5-bit groups.
    let mut data5 = [0u8; 64];
    let mut d5len = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data8 {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data5[d5len] = ((acc >> bits) & 0x1f) as u8;
            d5len += 1;
        }
    }
    if bits > 0 {
        data5[d5len] = ((acc << (5 - bits)) & 0x1f) as u8;
        d5len += 1;
    }

    // Checksum over hrp-expansion + data + 6 zero placeholders.
    let mut values = [0u8; 160];
    let mut vlen = 0usize;
    for &c in hrp {
        values[vlen] = c >> 5;
        vlen += 1;
    }
    values[vlen] = 0;
    vlen += 1;
    for &c in hrp {
        values[vlen] = c & 0x1f;
        vlen += 1;
    }
    for &d in &data5[..d5len] {
        values[vlen] = d;
        vlen += 1;
    }
    for _ in 0..6 {
        values[vlen] = 0;
        vlen += 1;
    }
    let pm = polymod(&values[..vlen]) ^ 1;
    let mut checksum = [0u8; 6];
    for (i, c) in checksum.iter_mut().enumerate() {
        *c = ((pm >> (5 * (5 - i))) & 0x1f) as u8;
    }

    // Emit: hrp + '1' + data(charset) + checksum(charset).
    let total = hrp.len() + 1 + d5len + 6;
    if out.len() < total {
        return None;
    }
    let mut o = 0;
    for &c in hrp {
        out[o] = c;
        o += 1;
    }
    out[o] = b'1';
    o += 1;
    for &d in &data5[..d5len] {
        out[o] = CHARSET[d as usize];
        o += 1;
    }
    for &c in &checksum {
        out[o] = CHARSET[c as usize];
        o += 1;
    }
    Some(total)
}
