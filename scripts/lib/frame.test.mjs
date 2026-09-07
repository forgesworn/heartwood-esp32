import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  buildFrame,
  createFrameReader,
  crc32,
  MAGIC,
  MAX_PAYLOAD_SIZE,
  pollForReply,
} from './frame.mjs'

test('builds a frame the firmware codec would accept', () => {
  const frame = buildFrame(0x5c, Buffer.from('hi'))
  assert.deepEqual(frame.subarray(0, 2), MAGIC)
  assert.equal(frame[2], 0x5c)
  assert.equal(frame.readUInt16BE(3), 2)
  // CRC covers type + length + payload, never the magic.
  assert.equal(frame.readUInt32BE(7), crc32(frame.subarray(2, 7)))
})

test('refuses a payload the device would discard', () => {
  assert.throws(() => buildFrame(0x30, Buffer.alloc(MAX_PAYLOAD_SIZE + 1)), RangeError)
})

test('reads a frame split across chunks', () => {
  const read = createFrameReader()
  const frame = buildFrame(0x5d, Buffer.from('{"ok":true}'))
  assert.deepEqual(read(frame.subarray(0, 4)), [])
  const frames = read(frame.subarray(4))
  assert.equal(frames.length, 1)
  assert.equal(frames[0].type, 0x5d)
  assert.equal(frames[0].payload.toString(), '{"ok":true}')
})

test('skips log noise ahead of a frame', () => {
  const read = createFrameReader()
  const noise = Buffer.from('I (261299) heartwood_esp32::relay: [relay] locked\n')
  const frames = read(Buffer.concat([noise, buildFrame(0x5a, Buffer.from('v'))]))
  assert.equal(frames.length, 1)
  assert.equal(frames[0].payload.toString(), 'v')
})

test('resynchronises past a false magic instead of swallowing the real frame', () => {
  const read = createFrameReader()
  // "HW" appears in text on the same link; its "length" must not be trusted.
  // 0xffff is past MAX_PAYLOAD_SIZE, so this one is rejected on sight.
  const decoy = Buffer.from([...MAGIC, 0x00, 0xff, 0xff])
  const frames = read(Buffer.concat([decoy, buildFrame(0x06, Buffer.alloc(0))]))
  assert.equal(frames.length, 1)
  assert.equal(frames[0].type, 0x06)
})

test('recovers a frame held back by a false magic with a plausible length', () => {
  const read = createFrameReader()
  // A believable length is only disproved by the CRC, once the bytes are in.
  const decoy = Buffer.from([...MAGIC, 0x00, 0x00, 0x08, ...Buffer.alloc(12)])
  const real = buildFrame(0x5a, Buffer.from('late'))
  assert.deepEqual(read(decoy.subarray(0, 5)), [])
  const frames = read(Buffer.concat([decoy.subarray(5), real]))
  assert.equal(frames.length, 1)
  assert.equal(frames[0].payload.toString(), 'late')
})

test('drops a frame whose CRC does not match', () => {
  const read = createFrameReader()
  const corrupt = buildFrame(0x5d, Buffer.from('abc'))
  corrupt[corrupt.length - 1] ^= 0xff
  assert.deepEqual(read(corrupt), [])
})

test('resends until the relay loop opens its USB window', async () => {
  // The board is blocking in wifi.connect(); the cable is deaf until the
  // third attempt lands inside the 3 s poll window.
  let sends = 0
  let attempts = 0
  const reply = await pollForReply({
    send: () => { sends++ },
    waitFor: async () => (++attempts === 3 ? { type: 0x5d, payload: Buffer.alloc(0) } : null),
    deadlineMs: 100,
    intervalMs: 1,
  })
  assert.equal(sends, 3)
  assert.equal(reply.type, 0x5d)
})

test('gives up at the deadline rather than resending for ever', async () => {
  let sends = 0
  let clock = 0
  const reply = await pollForReply({
    send: () => { sends++ },
    waitFor: async () => { clock += 2_000; return null },
    deadlineMs: 10_000,
    intervalMs: 2_000,
    now: () => clock,
  })
  assert.equal(reply, null)
  assert.equal(sends, 5)
})
