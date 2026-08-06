#!/usr/bin/env node
// scripts/heap-watch.mjs
//
// Poll FIRMWARE_INFO over USB and record the heap over time.
//
// The size guards care about ONE number: the largest contiguous free block.
// response_transportable needs a block a little over the base64-expanded
// response size, and the relay loop's own thresholds (DIAL_MIN_LARGEST_BLOCK
// 24_000, RELAY_HEALTH_MIN_BLOCK 16_384) describe a heap far more fragmented
// than a freshly booted board shows. This tells you which regime a device is
// actually in, and whether it decays toward the fragmented one while the relay
// runs.
//
// Read it alongside docs/BENCH-2026-08-06-message-sizes.md, whose figures were
// all taken within minutes of a reboot.
//
// Usage:
//   node scripts/heap-watch.mjs --port /dev/cu.usbmodemXXXX [--minutes 30] [--every 30]

import { argv, env } from 'node:process'
import { appendFileSync } from 'node:fs'

const { SerialPort } = await (async () => {
  const candidates = [
    'serialport',
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../', import.meta.url)).href,
  ]
  for (const c of candidates) {
    try { return await import(c) } catch { /* next */ }
  }
  console.error('cannot resolve node-serialport; set SAPWOOD_DIR to a checkout that has it')
  process.exit(2)
})()

const arg = (n, d = null) => { const i = argv.indexOf(n); return i === -1 ? d : argv[i + 1] }
const PORT = arg('--port')
const MINUTES = Number(arg('--minutes', '30'))
const EVERY = Number(arg('--every', '30'))
const OUT = arg('--out')
if (!PORT) { console.error('usage: node scripts/heap-watch.mjs --port /dev/cu.usbmodemXXXX'); process.exit(2) }

const MAGIC = [0x48, 0x57]
const FIRMWARE_INFO = 0x59
const FIRMWARE_INFO_RESPONSE = 0x5a
const CRC = (() => { const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0 }
  return t })()
const crc32 = (b) => { let c = 0xffffffff; for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0 }
const build = (ty) => { const h = Buffer.from([ty, 0, 0]); const c = Buffer.alloc(4); c.writeUInt32BE(crc32(h)); return Buffer.concat([Buffer.from(MAGIC), h, c]) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const port = await new Promise((res, rej) => {
  const p = new SerialPort({ path: PORT, baudRate: 115200, autoOpen: false })
  p.open((e) => (e ? rej(e) : res(p)))
})
await sleep(1500)

function read(timeoutMs) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0)
    const done = (v) => { clearTimeout(t); port.removeListener('data', on); resolve(v) }
    const t = setTimeout(() => done(null), timeoutMs)
    const on = (chunk) => {
      buf = Buffer.concat([buf, chunk])
      for (;;) {
        const i = buf.indexOf(Buffer.from(MAGIC))
        if (i === -1 || buf.length < i + 5) return
        const ty = buf[i + 2], len = buf.readUInt16BE(i + 3)
        if (buf.length < i + 5 + len + 4) return
        const pl = buf.subarray(i + 5, i + 5 + len)
        buf = buf.subarray(i + 5 + len + 4)
        if (ty === FIRMWARE_INFO_RESPONSE) return done(pl.toString())
      }
    }
    port.on('data', on)
  })
}

const kb = (n) => (typeof n === 'number' ? (n / 1024).toFixed(0) : '--')
console.log('elapsed  uptime   free   largest  ratio  reset')
if (OUT) appendFileSync(OUT, 'elapsed_s,uptime_s,free_heap,largest_block,last_reset\n')

const started = Date.now()
const deadline = started + MINUTES * 60_000
let minLargest = Infinity

while (Date.now() < deadline) {
  const reply = await (async () => { const p = read(5000); port.write(build(FIRMWARE_INFO)); return p })()
  let info = null
  try { info = JSON.parse(reply) } catch { /* no reply / bad frame */ }
  const elapsed = Math.round((Date.now() - started) / 1000)
  if (info) {
    // The ratio is the fragmentation signal: a largest block far below total
    // free is the condition behind the bulk-decrypt crashes. Sapwood's own UI
    // flags it below 0.4.
    const ratio = info.free_heap ? info.largest_block / info.free_heap : 0
    minLargest = Math.min(minLargest, info.largest_block ?? Infinity)
    console.log(
      `${String(elapsed).padStart(6)}s ${String(info.uptime_s).padStart(6)}s ` +
      `${kb(info.free_heap).padStart(5)}K ${kb(info.largest_block).padStart(7)}K ` +
      `${ratio.toFixed(2).padStart(6)}  ${info.last_reset ?? ''}`,
    )
    if (OUT) appendFileSync(OUT, `${elapsed},${info.uptime_s},${info.free_heap},${info.largest_block},${info.last_reset}\n`)
  } else {
    console.log(`${String(elapsed).padStart(6)}s  no reply`)
  }
  await sleep(EVERY * 1000)
}

console.log(`\nlowest largest-block seen: ${minLargest === Infinity ? 'n/a' : `${minLargest} B (${kb(minLargest)}K)`}`)
console.log('relay guards for reference: DIAL_MIN_LARGEST_BLOCK 24000, RELAY_HEALTH_MIN_BLOCK 16384')
port.close()
