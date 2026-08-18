#!/usr/bin/env node
// scripts/note-cmd.mjs
//
// Bearer-note locker bench driver: send one lnurl-vault-protocol JSON
// command as a NOTE_CMD (0x70) frame and print the NOTE_RESP (0x71) JSON.
// The command set and semantics are lnurl-vault's docs/PROTOCOL.md; the
// device side is common/src/note_cmd.rs. Gated commands (export_secret,
// mark_spent, discard, rename, delete) put a card up and wait for the hold,
// so the default timeout is the physical-confirm one.
//
// Usage:
//   node scripts/note-cmd.mjs --port /dev/cu.usbmodemXXXX '{"cmd":"get_info"}'
//   node scripts/note-cmd.mjs --port ... '{"cmd":"new_secret","label":"float"}'
//   node scripts/note-cmd.mjs --port ... '{"cmd":"export_secret","id":"a1b2c3d4"}'
//
// node-serialport opens do not reset a native-USB S3 (unlike Rust tools) —
// safe against an unlocked bench device. A locked device NACKs 0x70.

import { argv, env } from 'node:process'

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

const portFlag = argv.indexOf('--port')
const PORT = portFlag === -1 ? undefined : argv[portFlag + 1]
const CMD = argv[argv.length - 1]
if (!PORT || PORT.startsWith('--') || !CMD || CMD.startsWith('--') || CMD === PORT) {
  console.error(`usage: node scripts/note-cmd.mjs --port /dev/cu.usbmodemXXXX '<json command>'`)
  process.exit(2)
}
try {
  JSON.parse(CMD)
} catch {
  console.error('command is not valid JSON:', CMD)
  process.exit(2)
}

const MAGIC = [0x48, 0x57]
const NOTE_CMD = 0x70
const NOTE_RESP = 0x71
const NACK = 0x15

// Gated commands wait on a 30 s approval card; everything else is quick.
const GATED = ['export_secret', 'mark_spent', 'discard', 'rename', 'delete']
const TIMEOUT_MS = GATED.includes(JSON.parse(CMD).cmd) ? 40_000 : 5_000

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

port.write(buildFrame(NOTE_CMD, Buffer.from(CMD)))
const resp = await readFrame(port, [NOTE_RESP, NACK], TIMEOUT_MS)
if (!resp) {
  console.error('no reply (locked device? another process on the port?)')
  process.exitCode = 1
} else if (resp.type === NACK) {
  console.error('NACK:', resp.payload.toString() || '(no reason)')
  process.exitCode = 1
} else {
  const body = JSON.parse(resp.payload.toString())
  console.log(JSON.stringify(body, null, 2))
  if (body.ok === false) process.exitCode = 1
}
port.close()
