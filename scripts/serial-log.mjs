#!/usr/bin/env node
// scripts/serial-log.mjs
//
// Passive serial log tap. Opens the port with node-serialport (no DTR/RTS
// reset, unlike the Rust tools) and prints every text line the firmware
// emits, prefixed with a host timestamp — for correlating on-device log
// lines (e.g. "sign_event: auto-approved by policy") with host-side
// activity during relay-path bench runs. Binary frame traffic on the same
// port is dropped; only printable lines get through.
//
// Usage: node scripts/serial-log.mjs --port /dev/cu.usbmodemXXXX

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
  console.error('usage: node scripts/serial-log.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

const port = new SerialPort({ path: PORT, baudRate: 115200 })
await new Promise((resolve, reject) => {
  port.once('open', resolve)
  port.once('error', reject)
})
console.error(`tapping ${PORT} — ctrl-c to stop`)

let buf = Buffer.alloc(0)
port.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk])
  for (;;) {
    const nl = buf.indexOf(0x0a)
    if (nl === -1) {
      // Cap the buffer so a long binary run cannot grow it unbounded.
      if (buf.length > 65536) buf = buf.subarray(buf.length - 4096)
      return
    }
    const line = buf.subarray(0, nl)
    buf = buf.subarray(nl + 1)
    // Strip ANSI colour codes, drop lines that are mostly unprintable
    // (frame traffic) or empty.
    const text = line.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '').replace(/\r$/, '')
    const printable = text.replace(/[^\x20-\x7e]/g, '')
    if (printable.length < 4 || printable.length < text.length * 0.8) continue
    const ts = new Date().toISOString().slice(11, 23)
    console.log(`${ts} ${printable}`)
  }
})
