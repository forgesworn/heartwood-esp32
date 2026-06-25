//! HW serial frame protocol — no_std, no-alloc.
//!
//! Wire format: `[magic "HW"][type u8][len u16-be][payload][crc32-be]`. The CRC
//! covers `type + len + payload` (NOT the magic), byte-for-byte compatible with
//! `heartwood-esp32 common/src/frame.rs` and the `heartwood-bridge` daemon.
//!
//! Fixed buffers (no allocator). `MAX_PAYLOAD` is sized for the control plane
//! (auth, firmware-info, provision-list); the eventual `ENCRYPTED_REQUEST`
//! (0x10) ciphertext is larger and will want a bigger buffer or an allocator.

// The full protocol constant set is defined up front; some are not served yet.
#![allow(dead_code)]

pub const MAGIC: [u8; 2] = [0x48, 0x57]; // "HW"
pub const HEADER_LEN: usize = 5; // magic(2) + type(1) + len(2)
pub const OVERHEAD: usize = HEADER_LEN + 4; // + crc(4)
pub const MAX_PAYLOAD: usize = 512;
pub const MAX_FRAME: usize = OVERHEAD + MAX_PAYLOAD;

// Frame types (subset of common/src/types.rs that the device serves).
pub const NACK: u8 = 0x15;
pub const PROVISION_LIST: u8 = 0x05;
pub const PROVISION_LIST_RESPONSE: u8 = 0x07;
pub const ENCRYPTED_REQUEST: u8 = 0x10;
pub const SESSION_AUTH: u8 = 0x21;
pub const SESSION_ACK: u8 = 0x22;
pub const SIGN_ENVELOPE_RESPONSE: u8 = 0x35;
pub const FIRMWARE_INFO: u8 = 0x59;
pub const FIRMWARE_INFO_RESPONSE: u8 = 0x5A;

/// Build a frame into `out`; returns its total length, or `None` if the payload
/// is too large for the protocol or the output buffer.
pub fn build(out: &mut [u8], frame_type: u8, payload: &[u8]) -> Option<usize> {
    let total = OVERHEAD + payload.len();
    if payload.len() > MAX_PAYLOAD || out.len() < total {
        return None;
    }
    out[0..2].copy_from_slice(&MAGIC);
    out[2] = frame_type;
    out[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[5..5 + payload.len()].copy_from_slice(payload);
    let crc = crc32fast::hash(&out[2..5 + payload.len()]); // type + len + payload
    out[total - 4..total].copy_from_slice(&crc.to_be_bytes());
    Some(total)
}

/// Byte-at-a-time frame assembler. Feed bytes with [`Reader::push`]; when it
/// returns `Some(frame_type)`, a complete CRC-valid frame is available and its
/// payload is [`Reader::payload`] until the next `push`.
pub struct Reader {
    buf: [u8; MAX_FRAME],
    len: usize,
    payload_len: usize,
}

impl Reader {
    pub const fn new() -> Self {
        Self { buf: [0u8; MAX_FRAME], len: 0, payload_len: 0 }
    }

    /// Feed one received byte. Returns `Some(frame_type)` when a complete,
    /// CRC-valid frame has been assembled; the reader then resets for the next
    /// frame (so read [`payload`](Self::payload) before pushing again). Stray
    /// bytes before the magic are skipped; bad CRC / overflow resets silently.
    pub fn push(&mut self, byte: u8) -> Option<u8> {
        if self.len >= MAX_FRAME {
            self.len = 0; // overflow without a valid frame: resync
        }
        self.buf[self.len] = byte;
        self.len += 1;

        if self.len < HEADER_LEN {
            return None;
        }
        // Resynchronise on the magic preamble.
        if self.buf[0] != MAGIC[0] || self.buf[1] != MAGIC[1] {
            self.buf.copy_within(1..self.len, 0);
            self.len -= 1;
            return None;
        }
        let payload_len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        if payload_len > MAX_PAYLOAD {
            self.len = 0; // can't be one of our frames
            return None;
        }
        let total = OVERHEAD + payload_len;
        if self.len < total {
            return None;
        }
        // Full frame present — verify CRC over type + len + payload.
        let expected = u32::from_be_bytes([
            self.buf[total - 4],
            self.buf[total - 3],
            self.buf[total - 2],
            self.buf[total - 1],
        ]);
        let actual = crc32fast::hash(&self.buf[2..total - 4]);
        let frame_type = self.buf[2];
        self.payload_len = payload_len;
        self.len = 0; // reset; payload stays in buf until the next push
        if actual != expected {
            return None;
        }
        Some(frame_type)
    }

    /// Payload of the frame just returned by [`push`](Self::push).
    pub fn payload(&self) -> &[u8] {
        &self.buf[HEADER_LEN..HEADER_LEN + self.payload_len]
    }
}
