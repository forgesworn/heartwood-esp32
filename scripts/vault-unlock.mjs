#!/usr/bin/env node
// scripts/vault-unlock.mjs
//
// Host-side vault unlock over USB: SESSION_AUTH (0x21) with the bridge
// secret, then VAULT_UNLOCK (0x63) with the vault key. This is the same
// sequence heartwoodd's auto-unlock performs — usable standalone on a bench
// where no daemon is running. Secrets are read from files, never printed.
//
// The unseal runs a deliberately slow KDF per identity (~26 s for three
// masters on a V4), so the ACK wait is generous.
//
// Usage:
//   node scripts/vault-unlock.mjs --port /dev/cu.usbmodemXXXX \
//     --secret-file ~/heartwood-bench/bridge.secret \
//     --vault-key-file ~/heartwood-bench/vault.key

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

function readHex32(path, what) {
  const hex = readFileSync(path, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    console.error(`${what} file must contain exactly 64 lowercase hex characters`)
    process.exit(2)
  }
  return Buffer.from(hex, 'hex')
}

const PORT = arg('--port')
const SECRET_FILE = arg('--secret-file')
const VAULT_KEY_FILE = arg('--vault-key-file')
if (!PORT || !SECRET_FILE || !VAULT_KEY_FILE) {
  console.error(
    'usage: node scripts/vault-unlock.mjs --port <port> --secret-file <path> --vault-key-file <path>')
  process.exit(2)
}

const secret = readHex32(SECRET_FILE, 'bridge secret')
const vaultKey = readHex32(VAULT_KEY_FILE, 'vault key')

const MAGIC = [0x48, 0x57]
const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
const VAULT_UNLOCK = 0x63
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

console.log('SESSION_AUTH...')
port.write(buildFrame(SESSION_AUTH, secret))
const auth = await readFrame(port, [SESSION_ACK], 10_000)
if (!auth) {
  console.error('No SESSION_ACK within 10 s.')
  port.close()
  process.exit(1)
}
const code = auth.payload[0]
if (code !== 0x00) {
  console.error(
    code === 0x01 ? 'SESSION_ACK 0x01 — wrong bridge secret.'
      : code === 0x02 ? 'SESSION_ACK 0x02 — no bridge secret configured on the device.'
        : `SESSION_ACK 0x${code.toString(16)} — unexpected.`)
  port.close()
  process.exit(1)
}
console.log('Authenticated. VAULT_UNLOCK (slow unseal — allow up to 2 minutes)...')
port.write(buildFrame(VAULT_UNLOCK, vaultKey))
const reply = await readFrame(port, [ACK, NACK], 120_000)
port.close()

if (!reply) {
  console.error('No reply within 120 s.')
  process.exit(1)
}
if (reply.type === ACK) {
  console.log('ACK — device unlocked; seeds unsealed and boot continuing.')
  process.exit(0)
}
console.error(`NACK — ${reply.payload.toString() || 'unlock refused'}.`)
process.exit(1)
