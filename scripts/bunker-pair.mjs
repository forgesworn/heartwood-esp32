#!/usr/bin/env node
// scripts/bunker-pair.mjs
//
// Mint a NIP-46 connection slot over USB and print the bunker:// URI.
// Bridge-auths with SESSION_AUTH (0x21), creates the slot (0x40), then
// assembles the URI from the create response and the relay list the
// device reports in GET_NET_CONFIG (0x5c) — so the URI always matches
// the relays the signer is actually listening on.
//
// The URI (which embeds the one-time-visible slot secret) is printed to
// stdout ONLY; write it somewhere private, never into the repo.
//
// Usage:
//   node scripts/bunker-pair.mjs --port /dev/cu.usbmodemXXXX \
//     [--master 0] [--label bray-bench] \
//     [--secret-file ~/heartwood-bench/bridge.secret]

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

function arg(name, dflt) {
  const i = argv.indexOf(name)
  return i === -1 ? dflt : argv[i + 1]
}

const PORT = arg('--port')
if (!PORT) {
  console.error('usage: node scripts/bunker-pair.mjs --port <port> [--master N] [--label S]')
  process.exit(2)
}
const MASTER = Number(arg('--master', '0'))
const LABEL = arg('--label', 'bray-bench')
const SECRET_FILE = arg('--secret-file', `${env.HOME}/heartwood-bench/bridge.secret`)

const bridgeSecretHex = readFileSync(SECRET_FILE, 'utf8').trim()
if (!/^[0-9a-f]{64}$/.test(bridgeSecretHex)) {
  console.error('bridge secret file must contain exactly 64 lowercase hex characters')
  process.exit(2)
}

const MAGIC = [0x48, 0x57]
const NACK = 0x15
const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
const CONNSLOT_CREATE = 0x40
const CONNSLOT_CREATE_RESP = 0x41
const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d

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

// Relay list first — read-only, no auth needed.
port.write(buildFrame(GET_NET_CONFIG, Buffer.alloc(0)))
const net = await readFrame(port, [GET_NET_CONFIG_RESPONSE, NACK], 5_000)
if (!net || net.type === NACK) {
  console.error('GET_NET_CONFIG failed — cannot learn the relay list.')
  port.close()
  process.exit(1)
}
const relays = JSON.parse(net.payload.toString()).relays ?? []
if (relays.length === 0) {
  console.error('Device reports no relays; a bunker URI needs at least one.')
  port.close()
  process.exit(1)
}

port.write(buildFrame(SESSION_AUTH, Buffer.from(bridgeSecretHex, 'hex')))
const auth = await readFrame(port, [SESSION_ACK], 10_000)
if (!auth || auth.payload[0] !== 0x00) {
  console.error(`SESSION_AUTH failed (${auth ? `0x${auth.payload[0].toString(16)}` : 'no reply'}).`)
  port.close()
  process.exit(1)
}

const payload = Buffer.concat([Buffer.from([MASTER]), Buffer.from(LABEL, 'utf8')])
port.write(buildFrame(CONNSLOT_CREATE, payload))
const created = await readFrame(port, [CONNSLOT_CREATE_RESP, NACK], 10_000)
port.close()

if (!created || created.type === NACK) {
  console.error(`CONNSLOT_CREATE failed (${created ? created.payload.toString() : 'no reply'}).`)
  process.exit(1)
}
const slot = JSON.parse(created.payload.toString())
const relayParams = relays.map((r) => `relay=${r}`).join('&')
console.error(`Created slot ${slot.slot_index} ("${slot.label}") on master ${MASTER}.`)
console.log(`bunker://${slot.npub}?${relayParams}&secret=${slot.secret}`)
