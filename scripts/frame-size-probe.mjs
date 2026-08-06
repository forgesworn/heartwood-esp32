#!/usr/bin/env node
// scripts/frame-size-probe.mjs
//
// Isolate "can the signer RECEIVE and PARSE an N-byte frame" from "can the
// signer SIGN an N-byte event".
//
// A sign_event sweep cannot tell those apart: every step needs a button press,
// and if the device reboots you cannot tell whether it died on the USB
// transfer, in the JSON parse, or in the signing itself. This probe sends
// `get_public_key` with the payload padded out through `params`, which the
// method ignores. The device still has to take the whole frame off the wire,
// CRC it, and run it through serde, but it answers immediately with a short
// response and never opens an approval prompt. No button, no signing.
//
// Uptime is read before and after each size, so a reboot is detected directly
// rather than inferred from silence.
//
// Usage:
//   node scripts/frame-size-probe.mjs --port /dev/cu.usbmodemXXXX

import { argv, env } from 'node:process'

// This repo is Rust and carries no node_modules. node-serialport lives in the
// sapwood checkout, which is the CLI that already speaks this frame protocol.
// Try a plain resolve first (works if someone installs it here), then the
// sibling checkout. SAPWOOD_DIR overrides for a non-standard layout.
const { SerialPort } = await (async () => {
  const candidates = [
    'serialport',
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../', import.meta.url)).href,
  ]
  for (const c of candidates) {
    try {
      return await import(c)
    } catch {
      // try the next candidate
    }
  }
  console.error('cannot resolve node-serialport; set SAPWOOD_DIR to a checkout that has it')
  process.exit(2)
})()

const PORT = argv[argv.indexOf('--port') + 1]
if (!PORT || PORT.startsWith('--')) {
  console.error('usage: node scripts/frame-size-probe.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

const MAGIC = [0x48, 0x57]
const NIP46_REQUEST = 0x02
const NIP46_RESPONSE = 0x03
const FIRMWARE_INFO = 0x59
const FIRMWARE_INFO_RESPONSE = 0x5a
const NACK = 0x15

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

function crc32(bytes) {
  let c = 0xffffffff
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function buildFrame(type, payload) {
  const head = Buffer.from([type, (payload.length >> 8) & 0xff, payload.length & 0xff])
  const body = Buffer.concat([head, payload])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([Buffer.from(MAGIC), body, crc])
}

// Sapwood's measured cadence for the V4's USB-Serial-JTAG ring. Bursting whole
// frames overruns it (this is what the v0.13.9 OTA pacing fix was about), so a
// probe that bursts would measure the host's write pattern, not the device.
const PACE_CHUNK = 64
const PACE_HEAD_BYTES = 3072
const PACE_HEAD_GAP = 24
const PACE_GAP = 6
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function writePaced(port, bytes) {
  if (bytes.length <= 512) {
    port.write(bytes)
    return
  }
  for (let off = 0; off < bytes.length; off += PACE_CHUNK) {
    port.write(bytes.subarray(off, off + PACE_CHUNK))
    await sleep(off < PACE_HEAD_BYTES ? PACE_HEAD_GAP : PACE_GAP)
  }
}

// Hunt the byte stream for a frame of one of `want`, ignoring interleaved log
// output. Returns null on timeout.
function readFrame(port, want, timeoutMs) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0)
    const done = (v) => {
      clearTimeout(timer)
      port.removeListener('data', onData)
      resolve(v)
    }
    const timer = setTimeout(() => done(null), timeoutMs)
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk])
      for (;;) {
        const i = buf.indexOf(Buffer.from(MAGIC))
        if (i === -1 || buf.length < i + 5) return
        const type = buf[i + 2]
        const len = buf.readUInt16BE(i + 3)
        if (buf.length < i + 5 + len + 4) return
        const payload = buf.subarray(i + 5, i + 5 + len)
        buf = buf.subarray(i + 5 + len + 4)
        if (want.includes(type)) return done({ type, payload })
      }
    }
    port.on('data', onData)
  })
}

function open() {
  return new Promise((resolve, reject) => {
    const port = new SerialPort({ path: PORT, baudRate: 115200, autoOpen: false })
    port.open((e) => (e ? reject(e) : resolve(port)))
  })
}

/** Full FIRMWARE_INFO, or null if the device did not answer. */
async function firmwareInfo(port) {
  await writePaced(port, buildFrame(FIRMWARE_INFO, Buffer.alloc(0)))
  const f = await readFrame(port, [FIRMWARE_INFO_RESPONSE], 5000)
  if (!f) return null
  try {
    return JSON.parse(f.payload.toString())
  } catch {
    return null
  }
}

async function uptime(port) {
  return (await firmwareInfo(port))?.uptime_s ?? null
}

const kb = (n) => (typeof n === 'number' ? `${Math.round(n / 1024)}K` : '--')

// --sign switches from get_public_key to a real sign_event.
//
// This stays unattended on purpose. handle_sign_event parses the inner event
// (a SECOND parse, which duplicates the content) and builds the OLED preview
// BEFORE it opens the approval prompt, so a memory failure in that window
// reboots the device with no button press involved. The three outcomes are
// therefore all self-reporting:
//
//   REBOOT        died before the prompt: pre-approval parse/preview ceiling
//   approval_timeout  survived the parse, prompted, nobody pressed: SURVIVED
//   signed        someone happened to press the button
//
// approval_timeout is a PASS for what this probe measures.
const SIGN = argv.includes('--sign')
// --sizes 20480,32000 narrows the sweep. Post-approval testing costs a human
// button press per size, so being able to spend them only where the answer is
// still unknown matters.
const SIZES_ARG = argv[argv.indexOf('--sizes') + 1]
const SIZES = argv.includes('--sizes')
  ? SIZES_ARG.split(',').map((s) => Number(s.trim()))
  : SIGN
    ? [1024, 2048, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32000]
    : [512, 1024, 2048, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32000]

const port = await open()
// Settle: the device may still be enumerating right after open.
await sleep(2000)

let before = await uptime(port)
console.log(`device uptime ${before}s`)
console.log('probing receive+parse only (no signing, no button)\n')

const results = []
for (const size of SIZES) {
  const pad = 'a'.repeat(size)
  let body
  if (SIGN) {
    const event = {
      pubkey: '0'.repeat(64),
      created_at: 1785000000,
      kind: 1,
      tags: [],
      content: pad,
    }
    body = JSON.stringify({ id: 'probe', method: 'sign_event', params: [JSON.stringify(event)] })
  } else {
    // Pad through params, which get_public_key ignores, so the device parses
    // the whole thing then answers from a path that allocates almost nothing.
    body = JSON.stringify({ id: 'probe', method: 'get_public_key', params: [pad] })
  }
  const frame = buildFrame(NIP46_REQUEST, Buffer.from(body))

  process.stdout.write(`frame ${String(frame.length).padStart(6)} B ... `)
  await writePaced(port, frame)
  // Signing has to outwait the 30s on-device approval timeout.
  const reply = await readFrame(port, [NIP46_RESPONSE, NACK], SIGN ? 45000 : 20000)
  // Firmware 0.14+ reports heap alongside uptime, so each step records what
  // the allocator looked like straight after handling it. largest_block is the
  // number that actually binds a large response, not free_heap.
  const info = await firmwareInfo(port)
  const after = info?.uptime_s ?? null
  // Uptime going backwards is a reboot, full stop. Reading it directly beats
  // inferring a crash from a missing reply, which is what made the sign_event
  // sweep ambiguous.
  const rebooted = after !== null && before !== null && after < before

  let outcome
  if (rebooted) outcome = 'REBOOT'
  else if (!reply) outcome = 'no_reply'
  else if (reply.type === NACK) outcome = 'nack'
  else if (SIGN) {
    let parsedReply = null
    try {
      parsedReply = JSON.parse(reply.payload.toString())
    } catch {
      // fall through to raw classification below
    }
    const err = parsedReply?.error
    if (typeof err === 'string' ? /timeout/i.test(err) : /timeout/i.test(JSON.stringify(err ?? '')))
      outcome = 'approval_timeout'
    else if (parsedReply?.result) outcome = 'signed'
    else outcome = `error:${JSON.stringify(err ?? 'unknown').slice(0, 60)}`
  } else outcome = 'ok'

  results.push({
    payloadBytes: body.length,
    frameBytes: frame.length,
    outcome,
    uptimeAfter: after,
    freeHeap: info?.free_heap ?? null,
    largestBlock: info?.largest_block ?? null,
  })
  const heap = info?.free_heap !== undefined
    ? `  free ${kb(info.free_heap)} largest ${kb(info.largest_block)}`
    : ''
  console.log(`${outcome.padEnd(17)}${after !== null ? `uptime ${after}s` : ''}${heap}`)

  before = after
  if (rebooted) {
    console.log(
      SIGN
        ? '\ndevice rebooted: crashed in the pre-approval event parse/preview, before the button'
        : '\ndevice rebooted: this is the receive/parse ceiling, before any signing'
    )
    break
  }
  // A reboot leaves the device booting for a few seconds; give it room either
  // way so the next step measures the device and not the boot.
  await sleep(SIGN ? 2000 : 500)
}

port.close()
const survived = results.filter((r) => ['ok', 'approval_timeout', 'signed'].includes(r.outcome))
console.log(
  `\nlargest frame ${SIGN ? 'survived through sign dispatch' : 'received and parsed'}: ` +
    `${survived.length ? survived[survived.length - 1].frameBytes : 0} B`
)
console.log(JSON.stringify(results, null, 2))
