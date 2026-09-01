#!/usr/bin/env node
// Physically switch between WiFi relay mode and radio-off USB mode without
// resending or exposing the stored WiFi password. The request is revision-
// bound and the device reboots after ACK, so vault-locked boards need the
// normal vault-unlock sequence again.
//
// Usage: node scripts/net-mode.mjs --port /dev/cu.usbmodemXXXX --mode usb

import { argv, env } from 'node:process'
import { promptForPress } from './press-prompt.mjs'

const { SerialPort } = await (async () => {
  const candidates = [
    'serialport',
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../', import.meta.url)).href,
  ]
  for (const candidate of candidates) {
    try {
      return await import(candidate)
    } catch {
      // try the next candidate
    }
  }
  console.error('cannot resolve node-serialport; set SAPWOOD_DIR to a checkout that has it')
  process.exit(2)
})()

function arg(name) {
  const index = argv.indexOf(name)
  return index === -1 ? undefined : argv[index + 1]
}

const portPath = arg('--port')
const requestedMode = arg('--mode')
if (!portPath || !['usb', 'wifi'].includes(requestedMode)) {
  console.error('usage: node scripts/net-mode.mjs --port <port> --mode <usb|wifi>')
  process.exit(2)
}

const MAGIC = Buffer.from([0x48, 0x57])
const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d
const PATCH_NET_CONFIG = 0x5e
const ACK = 0x06
const NACK = 0x15

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let value = n
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    table[n] = value >>> 0
  }
  return table
})()

function crc32(bytes) {
  let value = 0xffffffff
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8)
  return (value ^ 0xffffffff) >>> 0
}

function buildFrame(type, payload) {
  const header = Buffer.from([type, (payload.length >> 8) & 0xff, payload.length & 0xff])
  const body = Buffer.concat([header, payload])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([MAGIC, body, crc])
}

function readFrame(port, wanted, timeoutMs) {
  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0)
    const finish = (reply) => {
      clearTimeout(timer)
      port.removeListener('data', onData)
      resolve(reply)
    }
    const timer = setTimeout(() => finish(null), timeoutMs)
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      for (;;) {
        const offset = buffer.indexOf(MAGIC)
        if (offset === -1 || buffer.length < offset + 5) return
        const type = buffer[offset + 2]
        const length = buffer.readUInt16BE(offset + 3)
        if (buffer.length < offset + 5 + length + 4) return
        const payload = buffer.subarray(offset + 5, offset + 5 + length)
        buffer = buffer.subarray(offset + 5 + length + 4)
        if (wanted.includes(type)) return finish({ type, payload })
      }
    }
    port.on('data', onData)
  })
}

const port = new SerialPort({ path: portPath, baudRate: 115200 })
await new Promise((resolve, reject) => {
  port.once('open', resolve)
  port.once('error', reject)
})

let pending = readFrame(port, [GET_NET_CONFIG_RESPONSE, NACK], 10_000)
port.write(buildFrame(GET_NET_CONFIG, Buffer.alloc(0)))
const currentReply = await pending
if (!currentReply || currentReply.type === NACK) {
  port.close()
  console.error('could not read the current network config')
  process.exit(1)
}
const current = JSON.parse(currentReply.payload.toString('utf8'))
if (!Number.isInteger(current.revision) || !['usb', 'wifi'].includes(current.mode)) {
  port.close()
  console.error('device returned an invalid network revision or mode')
  process.exit(1)
}
if (current.mode === requestedMode) {
  port.close()
  console.log(`Already in ${requestedMode} mode; no change made.`)
  process.exit(0)
}

const payload = Buffer.from(JSON.stringify({
  base_revision: current.revision,
  patch: { mode: requestedMode },
}))
promptForPress(`switch Heartwood from ${current.mode} to ${requestedMode} mode`)
pending = readFrame(port, [ACK, NACK], 60_000)
port.write(buildFrame(PATCH_NET_CONFIG, payload))
const reply = await pending
port.close()
if (!reply) {
  console.error('no reply within 60 s; the device did not confirm the change')
  process.exit(1)
}
if (reply.type === NACK) {
  console.error(`NACK — ${reply.payload.toString('utf8') || 'device refused the change'}`)
  process.exit(1)
}
console.log(`ACK — ${requestedMode} mode saved without exposing the password; device is rebooting.`)
