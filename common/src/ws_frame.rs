//! Masked client WebSocket text frames, written a small piece at a time.
//!
//! RFC 6455 §5.3 has every client-to-server frame masked. Building the whole
//! frame first holds a masked copy of the payload beside whatever the payload
//! was serialised from. For a sealed reply that is a second allocation the
//! size of the ciphertext, and on a fragmented no-PSRAM heap it can fail
//! where the first did not: a T-Display panicked asking for 14,526 B, the
//! frame for a `list_clients` reply whose 13,744 B ciphertext was already
//! held, after the transport guard had passed it.
//!
//! Here the caller's serialiser runs twice. The first pass is only counted,
//! for the length in the header. The second writes through one buffer the
//! caller supplies, which is masked and handed to the transport each time it
//! fills. That buffer is the only memory a frame costs.
//!
//! Apart from the optional event helpers this file needs nothing but
//! `std::io`, so `rustc --test` can build and test it on its own.

use std::io::{self, Write};

/// Longest header a client frame can need: two bytes, an eight-byte length
/// and the four-byte mask.
pub const MAX_HEADER_LEN: usize = 14;

/// A buffer size for [`write_masked_text_frame`]. The firmware runs mbedTLS
/// with dynamic buffers, which allocate each write's record as it goes out,
/// so a larger piece costs a larger transient allocation inside TLS.
pub const CHUNK_LEN: usize = 512;

const FIN_TEXT: u8 = 0x80 | 0x1;
const MASKED: u8 = 0x80;

/// Why a frame was not written whole.
///
/// Anything but `BufferTooSmall` can come after part of the frame has gone
/// out, so the caller must treat the connection as unusable.
#[derive(Debug)]
pub enum FrameError<E> {
    /// The buffer cannot hold the longest header and one payload byte.
    BufferTooSmall,
    /// The serialiser failed.
    Encode(io::Error),
    /// The serialiser produced a different length from the one counted.
    /// Nothing past the counted length is sent.
    LengthChanged { counted: usize, written: usize },
    /// The transport refused a piece.
    Send(E),
}

/// Bytes `emit` writes, counted without storing them.
pub fn payload_len(emit: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<usize> {
    let mut count = Count(0);
    emit(&mut count)?;
    Ok(count.0)
}

/// Write one masked, final text frame of `payload_len` bytes, produced by
/// `emit`, through `buf` to `send`. The header goes out with the first piece.
pub fn write_masked_text_frame<E>(
    emit: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    payload_len: usize,
    mask: [u8; 4],
    buf: &mut [u8],
    send: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), FrameError<E>> {
    if buf.len() <= MAX_HEADER_LEN {
        return Err(FrameError::BufferTooSmall);
    }
    let filled = write_header(payload_len, mask, buf);
    let mut out = Masked {
        buf,
        filled,
        written: 0,
        counted: payload_len,
        overran: false,
        mask,
        send,
        refused: None,
    };
    let emitted = emit(&mut out).and_then(|()| out.flush());
    if let Some(e) = out.refused.take() {
        return Err(FrameError::Send(e));
    }
    if out.overran || (emitted.is_ok() && out.written != payload_len) {
        return Err(FrameError::LengthChanged {
            counted: payload_len,
            written: out.written,
        });
    }
    emitted.map_err(FrameError::Encode)
}

/// The header for a final, masked text frame; returns its length.
fn write_header(payload_len: usize, mask: [u8; 4], out: &mut [u8]) -> usize {
    out[0] = FIN_TEXT;
    let mask_at = if payload_len < 126 {
        out[1] = MASKED | payload_len as u8;
        2
    } else if payload_len < 65_536 {
        out[1] = MASKED | 126;
        out[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        4
    } else {
        out[1] = MASKED | 127;
        out[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
        10
    };
    out[mask_at..mask_at + 4].copy_from_slice(&mask);
    mask_at + 4
}

struct Count(usize);

impl Write for Count {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0 += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Masked<'a, F, E> {
    buf: &'a mut [u8],
    filled: usize,
    /// Payload bytes taken so far, which is also the mask position.
    written: usize,
    counted: usize,
    overran: bool,
    mask: [u8; 4],
    send: F,
    refused: Option<E>,
}

impl<F: FnMut(&[u8]) -> Result<(), E>, E> Masked<'_, F, E> {
    fn drain(&mut self) -> io::Result<()> {
        if self.filled == 0 {
            return Ok(());
        }
        if let Err(e) = (self.send)(&self.buf[..self.filled]) {
            self.refused = Some(e);
            return Err(io::Error::new(io::ErrorKind::Other, "frame send refused"));
        }
        self.filled = 0;
        Ok(())
    }
}

impl<F: FnMut(&[u8]) -> Result<(), E>, E> Write for Masked<'_, F, E> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.written + data.len() > self.counted {
            self.overran = true;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "frame longer than counted",
            ));
        }
        if self.filled == self.buf.len() {
            self.drain()?;
        }
        let n = (self.buf.len() - self.filled).min(data.len());
        for (i, byte) in data[..n].iter().enumerate() {
            self.buf[self.filled + i] = byte ^ self.mask[(self.written + i) & 3];
        }
        self.filled += n;
        self.written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()
    }
}

/// The payload length of `[command, event]` as compact JSON.
#[cfg(feature = "nip46")]
pub fn event_payload_len(command: &str, event: &crate::nip46::SignedEvent) -> io::Result<usize> {
    payload_len(|w| serde_json::to_writer(w, &(command, event)).map_err(io::Error::from))
}

/// Write `[command, event]` as one masked text frame of `payload_len` bytes
/// (from [`event_payload_len`]); the bytes match `serde_json::to_vec` of the
/// same pair, masked.
#[cfg(feature = "nip46")]
pub fn write_event_frame<E>(
    command: &str,
    event: &crate::nip46::SignedEvent,
    payload_len: usize,
    mask: [u8; 4],
    buf: &mut [u8],
    send: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), FrameError<E>> {
    write_masked_text_frame(
        |w| serde_json::to_writer(w, &(command, event)).map_err(io::Error::from),
        payload_len,
        mask,
        buf,
        send,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    /// The whole-frame build the firmware used, kept as the reference.
    fn whole_frame(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![FIN_TEXT];
        let len = payload.len();
        if len < 126 {
            frame.push(MASKED | len as u8);
        } else if len < 65_536 {
            frame.push(MASKED | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(MASKED | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        frame
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    /// Feeds `data` in uneven slices, as a serialiser does.
    fn emit_in_slices(data: &[u8]) -> impl FnOnce(&mut dyn Write) -> io::Result<()> + '_ {
        move |w| {
            let mut rest = data;
            let mut step = 1;
            while !rest.is_empty() {
                let n = step.min(rest.len());
                w.write_all(&rest[..n])?;
                rest = &rest[n..];
                step = step % 97 + 3;
            }
            Ok(())
        }
    }

    fn streamed(data: &[u8], buf_len: usize) -> (Vec<u8>, Vec<usize>) {
        let len = payload_len(emit_in_slices(data)).unwrap();
        assert_eq!(len, data.len());
        let mut out = Vec::new();
        let mut pieces = Vec::new();
        let mut buf = vec![0u8; buf_len];
        write_masked_text_frame(
            emit_in_slices(data),
            len,
            MASK,
            &mut buf,
            |piece: &[u8]| {
                pieces.push(piece.len());
                out.extend_from_slice(piece);
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        (out, pieces)
    }

    #[test]
    fn matches_the_whole_frame_at_every_length_boundary() {
        for len in [0, 1, 4, 125, 126, 127, 13_744, 65_535, 65_536, 70_001] {
            let data = payload(len);
            let expected = whole_frame(&data, MASK);
            for buf_len in [15, 17, 18, 63, CHUNK_LEN, CHUNK_LEN + 1, 4_099] {
                let (got, pieces) = streamed(&data, buf_len);
                assert_eq!(got, expected, "payload {len}, buffer {buf_len}");
                assert!(
                    pieces.iter().all(|&p| p > 0 && p <= buf_len),
                    "payload {len}, buffer {buf_len}"
                );
            }
        }
    }

    #[test]
    fn a_buffer_without_room_past_the_header_sends_nothing() {
        let mut buf = [0u8; MAX_HEADER_LEN];
        let mut sent = 0;
        let r = write_masked_text_frame(emit_in_slices(b"x"), 1, MASK, &mut buf, |_: &[u8]| {
            sent += 1;
            Ok::<(), ()>(())
        });
        assert!(matches!(r, Err(FrameError::BufferTooSmall)));
        assert_eq!(sent, 0);
    }

    #[test]
    fn a_refused_piece_stops_the_frame() {
        let data = payload(2_000);
        let mut buf = [0u8; 64];
        let mut calls = 0;
        let r = write_masked_text_frame(
            emit_in_slices(&data),
            data.len(),
            MASK,
            &mut buf,
            |_: &[u8]| {
                calls += 1;
                if calls == 3 {
                    Err("socket closed")
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(r, Err(FrameError::Send("socket closed"))));
        assert_eq!(calls, 3);
    }

    #[test]
    fn a_longer_second_pass_is_cut_at_the_counted_length() {
        let data = payload(300);
        let mut buf = [0u8; 64];
        let mut out = Vec::new();
        let r = write_masked_text_frame(
            emit_in_slices(&data),
            200,
            MASK,
            &mut buf,
            |piece: &[u8]| {
                out.extend_from_slice(piece);
                Ok::<(), ()>(())
            },
        );
        assert!(matches!(
            r,
            Err(FrameError::LengthChanged { counted: 200, .. })
        ));
        let header = write_header(200, MASK, &mut [0u8; MAX_HEADER_LEN]);
        assert!(out.len() <= header + 200);
    }

    #[test]
    fn a_shorter_second_pass_is_an_error() {
        let data = payload(150);
        let mut buf = [0u8; 64];
        let r =
            write_masked_text_frame(emit_in_slices(&data), 200, MASK, &mut buf, |_: &[u8]| {
                Ok::<(), ()>(())
            });
        assert!(matches!(
            r,
            Err(FrameError::LengthChanged {
                counted: 200,
                written: 150
            })
        ));
    }

    #[test]
    fn a_serialiser_error_is_reported() {
        let mut buf = [0u8; 64];
        let r = write_masked_text_frame(
            |w| {
                w.write_all(b"[")?;
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad value"))
            },
            10,
            MASK,
            &mut buf,
            |_: &[u8]| Ok::<(), ()>(()),
        );
        assert!(matches!(r, Err(FrameError::Encode(_))));
    }
}
