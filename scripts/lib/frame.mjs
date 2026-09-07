// scripts/lib/frame.mjs
//
// The host half of the serial frame protocol, and the retry policy that makes
// a read land while the device is busy. `common/src/frame.rs` is the
// authority on the wire format; this is its JavaScript twin:
//
//   [0x48 0x57] [type_u8] [length_u16_be] [payload...] [crc32_4]
//
// CRC32 covers the type byte, the length bytes and the payload — never the
// magic. Every bench script had its own copy of this codec, which is why the
// polling fix below had to be written four times before it lived anywhere.
//
// Pure by design, in the style of session-auth.mjs: nothing here imports
// node-serialport, so the codec and the retry policy are testable without a
// board on the desk.

/** Frame delimiter. Not covered by the CRC. */
export const MAGIC = Buffer.from([0x48, 0x57])

/** Mirrors `MAX_PAYLOAD_SIZE` in common/src/types.rs. */
export const MAX_PAYLOAD_SIZE = 32768

/** Universal NACK. Every request can answer with one, so every reader wants it. */
export const NACK = 0x15

/** Universal ACK, for the frames that answer with nothing else. */
export const ACK = 0x06

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let value = n
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    table[n] = value >>> 0
  }
  return table
})()

/** CRC32 (IEEE, reflected) over `bytes`. */
export function crc32(bytes) {
  let value = 0xffffffff
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8)
  return (value ^ 0xffffffff) >>> 0
}

/** Encode one frame ready for the wire. */
export function buildFrame(type, payload = Buffer.alloc(0)) {
  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError(`payload ${payload.length} exceeds MAX_PAYLOAD_SIZE ${MAX_PAYLOAD_SIZE}`)
  }
  const header = Buffer.from([type, (payload.length >> 8) & 0xff, payload.length & 0xff])
  const body = Buffer.concat([header, payload])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([MAGIC, body, crc])
}

/**
 * Incremental frame decoder. Feed it chunks; it returns whole frames.
 *
 * It resynchronises rather than trusting the first magic it sees, because the
 * magic is only two bytes and the link is not guaranteed clean: firmware built
 * before #113 logs ANSI-coloured text down the same USB-Serial-JTAG FIFO, so a
 * stray `HW` in a log line arrives carrying a length field. A bad CRC or an
 * impossible length steps one byte past the magic and keeps looking, which
 * recovers the frame behind it instead of stalling on the garbage.
 *
 * A false magic whose length happens to be plausible is only rejected once
 * that many bytes have arrived and the CRC fails, so it can hold a real frame
 * back for up to MAX_PAYLOAD_SIZE bytes. That is survivable rather than fixed:
 * pollForReply resends, and the retry lands after the resync.
 */
export function createFrameReader() {
  let buffered = Buffer.alloc(0)
  return function push(chunk) {
    buffered = Buffer.concat([buffered, chunk])
    const frames = []
    for (;;) {
      const start = buffered.indexOf(MAGIC)
      if (start === -1) {
        // Nothing usable, but the tail may be the first byte of a split magic.
        buffered = buffered.subarray(Math.max(0, buffered.length - (MAGIC.length - 1)))
        return frames
      }
      if (buffered.length < start + 5) {
        buffered = buffered.subarray(start)
        return frames
      }
      const type = buffered[start + 2]
      const length = buffered.readUInt16BE(start + 3)
      if (length > MAX_PAYLOAD_SIZE) {
        buffered = buffered.subarray(start + 1)
        continue
      }
      const end = start + 5 + length + 4
      if (buffered.length < end) {
        buffered = buffered.subarray(start)
        return frames
      }
      const body = buffered.subarray(start + 2, start + 5 + length)
      if (crc32(body) !== buffered.readUInt32BE(start + 5 + length)) {
        buffered = buffered.subarray(start + 1)
        continue
      }
      frames.push({ type, payload: buffered.subarray(start + 5, start + 5 + length) })
      buffered = buffered.subarray(end)
    }
  }
}

/**
 * Send a request until the device answers, or the deadline passes.
 *
 * A single send with one long read is the obvious shape and it is wrong, which
 * cost this bench a whole diagnosis on 2026-09-07: `net-config.mjs` and
 * `device-status.mjs` reported "no reply" against a board that was answering
 * perfectly well. In WiFi mode the relay loop blocks inside
 * `wifi.connect().and_then(wait_netif_up)` and only polls USB in a ~3 s window
 * per pass, so on a board that cannot join an AP the cable is deaf for
 * twenty-odd seconds at a time. The request has to be in flight when the
 * window opens, which means resending, not waiting longer.
 *
 * `send` writes the frame; `waitFor(timeoutMs)` resolves with a reply or null.
 * Both are injected so this is testable without a serial port — the same
 * split authenticateSession() uses.
 */
export async function pollForReply({
  send,
  waitFor,
  deadlineMs = 90_000,
  intervalMs = 2_000,
  now = () => Date.now(),
}) {
  const deadline = now() + deadlineMs
  for (;;) {
    const remaining = deadline - now()
    if (remaining <= 0) return null
    const pending = waitFor(Math.min(intervalMs, remaining))
    send()
    const reply = await pending
    if (reply) return reply
  }
}
