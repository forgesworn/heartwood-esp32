#!/usr/bin/env node
// scripts/set-operator.mjs
//
// Replace the device's management trust root (SET_OPERATOR, 0x5f) from a host
// file holding the operator's x-only PUBLIC key — for bench setups without
// the Sapwood wizard. The frame carries the caller's observed network
// revision (probed here via GET_NET_CONFIG) so a concurrent network change
// NACKs instead of racing. The device shows "Replace operator?" and requires
// a button hold; on ACK it reboots — a vault-locked board needs unlocking
// again afterwards (scripts/vault-unlock.mjs).
//
// Usage:
//   node scripts/set-operator.mjs --port /dev/cu.usbmodemXXXX \
//     --pub-file ~/heartwood-bench/operator.pub

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
const PUB_FILE = arg('--pub-file')
if (!PORT || !PUB_FILE) {
  console.error('usage: node scripts/set-operator.mjs --port <port> --pub-file <path>')
  process.exit(2)
}

const hex = readFileSync(PUB_FILE, 'utf8').trim()
if (!/^[0-9a-f]{64}$/.test(hex)) {
  console.error('pub file must contain exactly 64 lowercase hex characters (x-only pubkey)')
  process.exit(2)
}
const pubkey = Buffer.from(hex, 'hex')

const MAGIC = [0x48, 0x57]
const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d
const SET_OPERATOR = 0x5f
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

port.write(buildFrame(GET_NET_CONFIG, Buffer.alloc(0)))
const cfg = await readFrame(port, [GET_NET_CONFIG_RESPONSE, NACK], 10_000)
if (!cfg || cfg.type === NACK) {
  console.error('could not read the network config (no reply or NACK); is the device booted?')
  port.close()
  process.exit(1)
}
const revision = JSON.parse(cfg.payload.toString('utf8')).revision
if (!Number.isInteger(revision)) {
  console.error('network config carried no revision; refusing to guess')
  port.close()
  process.exit(1)
}

const payload = Buffer.alloc(36)
payload.writeUInt32BE(revision >>> 0, 0)
pubkey.copy(payload, 4)

console.log(`Sending SET_OPERATOR (revision ${revision}, pub ${hex.slice(0, 8)}…) — confirm on the device (button hold)...`)
port.write(buildFrame(SET_OPERATOR, payload))

const reply = await readFrame(port, [ACK, NACK], 90_000)
port.close()

if (!reply) {
  console.error('No reply within 90 s (prompt expired or device unresponsive).')
  process.exit(1)
}
if (reply.type === ACK) {
  console.log('ACK — operator replaced; the device is rebooting. Vault-locked boards need scripts/vault-unlock.mjs again.')
  process.exit(0)
}
console.error(`NACK — device refused: ${reply.payload.toString('utf8') || '(no reason)'}`)
process.exit(1)
