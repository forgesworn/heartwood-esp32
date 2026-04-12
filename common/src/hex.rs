// common/src/hex.rs
//
// Hex encoding utility.

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Encode bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

/// Decode a hex string to bytes. Returns an error if the input has odd length
/// or contains non-hex characters.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0]).ok_or("invalid hex character")?;
        let lo = hex_nibble(chunk[1]).ok_or("invalid hex character")?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_decode_roundtrip() {
        let bytes = vec![0x00u8, 0xff, 0xab, 0x12, 0x34];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn test_hex_decode_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_uppercase() {
        assert_eq!(hex_decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_decode_odd_length_error() {
        assert_eq!(hex_decode("abc"), Err("odd-length hex string"));
    }

    #[test]
    fn test_hex_decode_invalid_char_error() {
        assert_eq!(hex_decode("zz"), Err("invalid hex character"));
    }
}
