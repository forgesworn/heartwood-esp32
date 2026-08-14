#!/usr/bin/env node
// scripts/device-status.mjs
//
// Read-only status probe: FIRMWARE_INFO (0x59) and PROVISION_LIST (0x05).
// Both are served in every device state, including the locked boot phase,
// so this answers "what firmware, which masters, locked or not" without
// touching any authority.
//
// Usage: node scripts/device-status.mjs --port /dev/cu.usbmodemXXXX

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

const PORT = argv[argv.indexOf('--port') + 1]
if (!PORT || PORT.startsWith('--')) {
  console.error('usage: node scripts/device-status.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

const MAGIC = [0x48, 0x57]
const FIRMWARE_INFO = 0x59
const FIRMWARE_INFO_RESPONSE = 0x5a
const PROVISION_LIST = 0x05
const PROVISION_LIST_RESPONSE = 0x07
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

port.write(buildFrame(FIRMWARE_INFO, Buffer.alloc(0)))
const info = await readFrame(port, [FIRMWARE_INFO_RESPONSE, NACK], 5_000)
console.log('firmware:', info ? info.payload.toString() : 'no reply')

port.write(buildFrame(PROVISION_LIST, Buffer.alloc(0)))
const list = await readFrame(port, [PROVISION_LIST_RESPONSE, NACK], 5_000)
if (!list) {
  console.log('masters: no reply')
} else if (list.type === NACK) {
  console.log('masters: NACK')
} else {
  console.log('masters:', list.payload.toString())
}
port.close()
