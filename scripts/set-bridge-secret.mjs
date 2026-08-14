#!/usr/bin/env node
// scripts/set-bridge-secret.mjs
//
// Provision the USB session secret (SET_BRIDGE_SECRET, 0x23) from a host
// file, for heartwoodd/bench setups without the Sapwood tethered wizard —
// today Sapwood is the only other sender of this frame. The device shows a
// confirmation card and requires a 2-second button hold; expect up to a
// minute before the ACK. The secret is read from a file and never printed.
//
// Usage:
//   node scripts/set-bridge-secret.mjs --port /dev/cu.usbmodemXXXX \
//     --secret-file ~/heartwood-bench/bridge.secret

import { argv, env } from 'node:process'
import { readFileSync } from 'node:fs'

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

function arg(name) {
  const i = argv.indexOf(name)
  return i === -1 ? undefined : argv[i + 1]
}

const PORT = arg('--port')
const SECRET_FILE = arg('--secret-file')
if (!PORT || !SECRET_FILE) {
  console.error('usage: node scripts/set-bridge-secret.mjs --port <port> --secret-file <path>')
  process.exit(2)
}

const hex = readFileSync(SECRET_FILE, 'utf8').trim()
if (!/^[0-9a-f]{64}$/.test(hex)) {
  console.error('secret file must contain exactly 64 lowercase hex characters')
  process.exit(2)
}
const secret = Buffer.from(hex, 'hex')

const MAGIC = [0x48, 0x57]
const SET_BRIDGE_SECRET = 0x23
const ACK = 0x06
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
        if (want.includes(type)) {
          done({ type, payload })
          return
        }
      }
    }
    port.on('data', onData)
  })
}

const port = new SerialPort({ path: PORT, baudRate: 115200 })
await new Promise((resolve, reject) => {
  port.once('open', resolve)
  port.once('error', reject)
})

console.log('Sending SET_BRIDGE_SECRET — confirm on the device (2 s button hold)...')
port.write(buildFrame(SET_BRIDGE_SECRET, secret))

const reply = await readFrame(port, [ACK, NACK], 90_000)
port.close()

if (!reply) {
  console.error('No reply within 90 s (prompt expired or device unresponsive).')
  process.exit(1)
}
if (reply.type === ACK) {
  console.log('ACK — bridge secret set and stored in NVS.')
  process.exit(0)
}
console.error('NACK — device refused (bad payload, or approval denied/timed out).')
process.exit(1)
