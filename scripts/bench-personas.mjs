// Bench driver for hardware checklist section 9 (packed persona registry).
// Drives the plaintext NIP-46 path (0x02 -> 0x03) plus PROVISION_LIST and
// FIRMWARE_INFO over the cable. Physical-possession semantics: no button
// needed for derive/rename/remove on the direct USB path. Fails closed on a
// vault-locked signer (the locked boot loop NACKs plaintext NIP-46): unlock
// first, then bench.
//
// Usage: node scripts/bench-personas.mjs {round-trip|post-reboot|cap} [arg] [port]
//   round-trip   derive/rename/idempotence + NVS stats growth
//   post-reboot  run after a reset: persistence, removal, registry-only proof
//                (arg = the bench-a npub printed by round-trip)
//   cap          fill the registry to the board cap, verify the clean refusal,
//                clean up
//
// Needs the `serialport` package: run from a checkout with a sibling sapwood
// clone (its node_modules is reused), or `npm install serialport` anywhere.
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const { SerialPort } = (() => {
  try { return require('serialport') } catch {
    return require(new URL('../../sapwood/node_modules/serialport/dist/index.js', import.meta.url).pathname)
  }
})()

const PORT = process.env.HEARTWOOD_PORT
  ?? [process.argv[3], process.argv[4]].find((a) => a?.startsWith('/dev/'))
  ?? '/dev/cu.usbmodem3401'
const FT = { NIP46_REQ: 0x02, NIP46_RESP: 0x03, LIST: 0x05, LIST_RESP: 0x07, NACK: 0x15, FW: 0x59, FW_RESP: 0x5a }

function crc32(bytes) {
  let c = 0xffffffff
  for (const b of bytes) {
    c ^= b
    for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1))
  }
  return (c ^ 0xffffffff) >>> 0
}

function buildFrame(type, payload) {
  const head = Buffer.from([type, payload.length >> 8, payload.length & 0xff])
  const body = Buffer.concat([head, payload])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([Buffer.from([0x48, 0x57]), body, crc])
}

let rx = Buffer.alloc(0)
let port

function feed(chunk) { rx = Buffer.concat([rx, chunk]) }

function tryParse() {
  while (true) {
    const at = rx.indexOf(Buffer.from([0x48, 0x57]))
    if (at < 0) { if (rx.length > 4096) rx = rx.subarray(rx.length - 1); return null }
    if (at > 0) rx = rx.subarray(at)
    if (rx.length < 9) return null
    const type = rx[2]
    const len = (rx[3] << 8) | rx[4]
    if (rx.length < 5 + len + 4) return null
    const body = rx.subarray(2, 5 + len)
    const crc = rx.readUInt32BE(5 + len)
    if (crc32(body) !== crc) { rx = rx.subarray(2); continue }
    const payload = Buffer.from(rx.subarray(5, 5 + len))
    rx = rx.subarray(5 + len + 4)
    return { type, payload }
  }
}

const waiters = []
function onData(chunk) {
  feed(chunk)
  let f
  while ((f = tryParse())) {
    const idx = waiters.findIndex((w) => w.types.includes(f.type))
    if (idx >= 0) waiters.splice(idx, 1)[0].resolve(f)
  }
}

function transact(frame, types, ms = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const i = waiters.findIndex((w) => w.resolve === done)
      if (i >= 0) waiters.splice(i, 1)
      reject(new Error(`timeout waiting for ${types}`))
    }, ms)
    const done = (f) => { clearTimeout(timer); resolve(f) }
    waiters.push({ types, resolve: done })
    port.write(frame)
  })
}

let seq = 0
async function rpc(method, params) {
  const req = { id: `bench-${++seq}`, method, params }
  const f = await transact(buildFrame(FT.NIP46_REQ, Buffer.from(JSON.stringify(req))), [FT.NIP46_RESP, FT.NACK])
  if (f.type === FT.NACK) throw new Error(`${method}: NACK`)
  const resp = JSON.parse(f.payload.toString())
  if (resp.id !== req.id) throw new Error(`${method}: id mismatch`)
  return resp
}

async function list() {
  const f = await transact(buildFrame(FT.LIST, Buffer.alloc(0)), [FT.LIST_RESP])
  return JSON.parse(f.payload.toString())
}

async function fwInfo() {
  const f = await transact(buildFrame(FT.FW, Buffer.alloc(0)), [FT.FW_RESP])
  return JSON.parse(f.payload.toString())
}

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
}

async function main() {
  const mode = process.argv[2] ?? 'round-trip'
  port = new SerialPort({ path: PORT, baudRate: 115200 })
  port.on('data', onData)
  await new Promise((r, j) => { port.on('open', r); port.on('error', j) })
  await new Promise((r) => setTimeout(r, 300))

  if (mode === 'round-trip') {
    const base = await list()
    const basePersonas = base.filter((r) => r.persona)
    check('baseline list', true, `${base.length - basePersonas.length} masters, ${basePersonas.length} personas`)
    const stats0 = await fwInfo()

    const a1 = JSON.parse((await rpc('heartwood_derive_persona', ['bench-a', 0])).result)
    check('derive bench-a', a1.purpose === 'nostr:persona:bench-a', a1.npub)
    const b1 = JSON.parse((await rpc('heartwood_derive_persona', ['bench-b', 0])).result)
    check('derive bench-b', b1.purpose === 'nostr:persona:bench-b', b1.npub)
    const a2 = JSON.parse((await rpc('heartwood_derive_persona', ['bench-a', 0])).result)
    check('re-derive bench-a is idempotent', a2.npub === a1.npub)

    const mid = await list()
    const midP = mid.filter((r) => r.persona)
    check('list shows both personas once', midP.length === basePersonas.length + 2,
      midP.map((p) => p.label).join(','))

    const stats1 = await fwInfo()
    check('nvs usage grew', stats1.nvs_used_entries > stats0.nvs_used_entries,
      `${stats0.nvs_used_entries} -> ${stats1.nvs_used_entries}`)

    const ren = await rpc('heartwood_rename_persona', [pkOf(a1), 'Bench Alpha'])
    check('rename bench-a', !ren.error, JSON.stringify(ren.result ?? ren.error))
    const renamed = (await list()).find((r) => r.persona && r.label === 'Bench Alpha')
    check('rename visible in list', !!renamed)
    process.exit(results.some((r) => !r.ok) ? 1 : 0)
  }

  if (mode === 'post-reboot') {
    const rows = await list()
    const p = rows.filter((r) => r.persona)
    check('personas survived reboot', p.length === 2, p.map((x) => x.label).join(','))
    check('rename survived reboot', p.some((x) => x.label === 'Bench Alpha'))
    const a = JSON.parse((await rpc('heartwood_derive_persona', ['bench-a', 0])).result)
    check('post-reboot re-derive stable', a.npub === process.argv[3], a.npub.slice(0, 20))

    const removed = await rpc('heartwood_remove_persona', [pkFromNpub(rows, 'Bench Alpha')])
    check('remove bench-a', !removed.error, JSON.stringify(removed.result ?? removed.error))
    const afterRemove = (await list()).filter((r) => r.persona)
    check('list after remove', afterRemove.length === 1, afterRemove.map((x) => x.label).join(','))

    const aAgain = JSON.parse((await rpc('heartwood_derive_persona', ['bench-a', 0])).result)
    check('removal is registry-only (same key back)', aAgain.npub === process.argv[3])

    // Cleanup both bench personas.
    for (const label of ['bench-a', 'bench-b']) {
      const row = (await list()).find((r) => r.persona && (r.label === label))
      if (row) await rpc('heartwood_remove_persona', [pkFromNpub([row], row.label)])
    }
    const final = (await list()).filter((r) => r.persona)
    check('cleanup complete', final.length === 0, `personas left: ${final.length}`)
    process.exit(results.some((r) => !r.ok) ? 1 : 0)
  }

  if (mode === 'cap') {
    const start = (await list()).filter((r) => r.persona).length
    const info = await fwInfo()
    const cap = info.max_personas
    let full = null
    let created = 0
    for (let i = start; i < cap + 1; i++) {
      const resp = await rpc('heartwood_derive_persona', [`cap-${String(i).padStart(2, '0')}`, 0])
      if (resp.error) { full = resp.error; break }
      created++
    }
    check('cap reached cleanly', full !== null && created === cap - start,
      `created ${created}, refusal: ${full ?? 'none'}`)
    check('refusal names the condition', (full ?? '').includes('identity storage full'))
    const at = await fwInfo()
    console.log(`at cap: nvs ${at.nvs_used_entries}/${at.nvs_total_entries} used, free ${at.nvs_free_entries}`)
    check('device still answers list at cap', (await list()).length > 0)
    // Cleanup.
    let cleaned = 0
    for (const row of (await list()).filter((r) => r.persona && r.label?.startsWith('cap-'))) {
      const resp = await rpc('heartwood_remove_persona', [pkFromNpub([row], row.label)])
      if (!resp.error) cleaned++
    }
    const final = (await list()).filter((r) => r.persona)
    check('cap cleanup complete', final.length === start, `cleaned ${cleaned}, left ${final.length}`)
    const statsEnd = await fwInfo()
    console.log(`after cleanup: nvs ${statsEnd.nvs_used_entries}/${statsEnd.nvs_total_entries} used`)
    process.exit(results.some((r) => !r.ok) ? 1 : 0)
  }
}

// npub (bech32) -> hex, minimal decoder for x-only keys.
function pkFromNpub(rows, label) {
  const row = rows.find((r) => r.label === label) ?? rows[0]
  return npubToHex(row.npub)
}
function pkOf(derived) { return npubToHex(derived.npub) }
function npubToHex(npub) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const data = npub.slice(npub.lastIndexOf('1') + 1).split('').map((c) => CHARSET.indexOf(c))
  const words = data.slice(0, -6)
  let acc = 0, bits = 0
  const out = []
  for (const w of words) {
    acc = (acc << 5) | w
    bits += 5
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff) }
  }
  return Buffer.from(out).toString('hex')
}

main().catch((e) => { console.error('BENCH ERROR:', e.message); process.exit(2) })
