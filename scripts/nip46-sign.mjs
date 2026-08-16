#!/usr/bin/env node
// scripts/nip46-sign.mjs
//
// Bench NIP-46 driver that tolerates the S3 reset-on-open trap: the Rust
// serialport open resets a native-USB S3 (DTR/RTS emulate the reset
// circuit), bouncing a vault-locked signer back to its locked phase. This
// script opens the port ONCE (node's open is benign), unlocks first when
// the device reports locked, then sends a plaintext sign_event (0x02) and
// waits for the response — printing how long after approval it arrived.
//
// Usage:
//   node scripts/nip46-sign.mjs --port /dev/cu.usbmodemXXXX \
//     [--secret-file ~/heartwood-bench/bridge.secret] \
//     [--vault-key-file ~/heartwood-bench/vault.key] \
//     [--kind 1] [--content "hello"]

import { argv, env } from 'node:process'
import { readFileSync } from 'node:fs'
import { promptForPress } from './press-prompt.mjs'

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
  console.error('usage: node scripts/nip46-sign.mjs --port <port> [--kind N] [--content S]')
  process.exit(2)
}
const KIND = Number(arg('--kind', '1'))
const CONTENT = arg('--content', 'Hello from nip46-sign')
const SECRET_FILE = arg('--secret-file', `${env.HOME}/heartwood-bench/bridge.secret`)
const VAULT_KEY_FILE = arg('--vault-key-file', `${env.HOME}/heartwood-bench/vault.key`)

function readHex32(path, what) {
  const hex = readFileSync(path, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    console.error(`${what} file must contain exactly 64 lowercase hex characters`)
    process.exit(2)
  }
  return Buffer.from(hex, 'hex')
}

const MAGIC = [0x48, 0x57]
const NIP46_REQUEST = 0x02
const NIP46_RESPONSE = 0x03
const PROVISION_LIST = 0x05
const PROVISION_LIST_RESPONSE = 0x07
const ACK = 0x06
const NACK = 0x15
const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
const VAULT_UNLOCK = 0x63

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

// Locked? PROVISION_LIST answers in every state and names the locked slots.
port.write(buildFrame(PROVISION_LIST, Buffer.alloc(0)))
const list = await readFrame(port, [PROVISION_LIST_RESPONSE], 5_000)
if (!list) {
  console.error('Device did not answer PROVISION_LIST.')
  port.close()
  process.exit(1)
}
const masters = JSON.parse(list.payload.toString())
if (masters.some((m) => m.locked)) {
  console.log('Device is locked — unlocking first...')
  port.write(buildFrame(SESSION_AUTH, readHex32(SECRET_FILE, 'bridge secret')))
  const auth = await readFrame(port, [SESSION_ACK], 10_000)
  if (!auth || auth.payload[0] !== 0x00) {
    console.error(`SESSION_AUTH failed (${auth ? `0x${auth.payload[0].toString(16)}` : 'no reply'}).`)
    port.close()
    process.exit(1)
  }
  port.write(buildFrame(VAULT_UNLOCK, readHex32(VAULT_KEY_FILE, 'vault key')))
  const unlocked = await readFrame(port, [ACK, NACK], 120_000)
  if (!unlocked || unlocked.type !== ACK) {
    console.error(`VAULT_UNLOCK failed (${unlocked ? unlocked.payload.toString() : 'no reply'}).`)
    port.close()
    process.exit(1)
  }
  console.log('Unlocked. Waiting for the signer loop to come up...')
  await new Promise((r) => setTimeout(r, 3_000))
}

const request = {
  id: `bench-${KIND}-${masters.length}`,
  method: 'sign_event',
  params: [JSON.stringify({
    created_at: Math.floor(Date.now() / 1000),
    kind: KIND,
    tags: [],
    content: CONTENT,
  })],
}
promptForPress(`the sign_event (kind ${KIND})`)
const sent = Date.now()
port.write(buildFrame(NIP46_REQUEST, Buffer.from(JSON.stringify(request))))

const reply = await readFrame(port, [NIP46_RESPONSE, NACK], 90_000)
const elapsed = ((Date.now() - sent) / 1000).toFixed(1)
port.close()

if (!reply) {
  console.error('No response within 90 s.')
  process.exit(1)
}
if (reply.type === NACK) {
  // The firmware puts its reason in the NACK payload (e.g. "approval on
  // screen" when a relay card owns the display). Printing only "NACK" threw
  // that away and left the operator guessing.
  const reason = reply.payload.length ? `: ${reply.payload.toString()}` : ''
  console.error(`NACK after ${elapsed}s${reason}`)
  process.exit(1)
}
const json = JSON.parse(reply.payload.toString())
if (json.error) {
  console.error(`Error after ${elapsed}s: ${json.error}`)
  process.exit(1)
}
const event = JSON.parse(json.result)
console.log(`Signed response in ${elapsed}s (includes your approval time).`)
console.log(`kind ${event.kind}, id ${event.id.slice(0, 16)}…, sig ${event.sig.slice(0, 16)}…`)
