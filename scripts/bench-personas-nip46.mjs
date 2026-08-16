// One-shot bench for heartwood checklist section 9 over the ENCRYPTED USB
// path (0x10/0x35) — the exact transport the Sapwood manager pairing uses.
// Deps resolve from a sibling sapwood checkout (or SAPWOOD_DIR, or npm i).
//
//   node scripts/bench-personas-nip46.mjs {full|resume <npub>|cap-only}
//
// Phases: auth → pair (BUTTON on the signer once) → round-trip → reset →
// re-unlock → post-reboot → cap → cleanup → revoke bench slot.
import { createRequire } from 'node:module'
import { env } from 'node:process'
const loadDep = async (name, subpath) => {
  const candidates = [
    name,
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/${subpath}`,
      new URL('../', import.meta.url)).href,
  ]
  for (const c of candidates) {
    try { return await import(c) } catch { /* next */ }
  }
  throw new Error(`cannot resolve ${name}; set SAPWOOD_DIR or npm install ${name}`)
}
const { SerialPort } = await loadDep('serialport', 'serialport/dist/index.js')
const { generateSecretKey, getPublicKey } = await loadDep('nostr-tools/pure', 'nostr-tools/lib/esm/pure.js')
const { getConversationKey, encrypt, decrypt } = await loadDep('nostr-tools/nip44', 'nostr-tools/lib/esm/nip44.js')
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { promptForPress } from './press-prompt.mjs'

const PORT = '/dev/cu.usbmodem3401'
const BENCH = `${homedir()}/heartwood-bench`
const FW_REPO = new URL('..', import.meta.url).pathname
const FT = {
  ENC_REQ: 0x10, ENVELOPE: 0x35, NACK: 0x15, ACK: 0x03,
  LIST: 0x05, LIST_RESP: 0x07, FW: 0x59, FW_RESP: 0x5a,
  AUTH: 0x21, AUTH_ACK: 0x22,
  CS_CREATE: 0x40, CS_CREATE_RESP: 0x41, CS_UPDATE: 0x44, CS_UPDATE_RESP: 0x45,
  CS_REVOKE: 0x46, CS_REVOKE_RESP: 0x47,
}
const MASTER_NPUB = 'npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2'

function crc32(bytes) {
  let c = 0xffffffff
  for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)) }
  return (c ^ 0xffffffff) >>> 0
}
function buildFrame(type, payload) {
  const head = Buffer.from([type, payload.length >> 8, payload.length & 0xff])
  const body = Buffer.concat([head, Buffer.from(payload)])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([Buffer.from([0x48, 0x57]), body, crc])
}
function npubToHex(npub) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const words = npub.slice(npub.lastIndexOf('1') + 1).split('').map((c) => CHARSET.indexOf(c)).slice(0, -6)
  let acc = 0, bits = 0
  const out = []
  for (const w of words) { acc = (acc << 5) | w; bits += 5; if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff) } }
  return Buffer.from(out).toString('hex')
}
const MASTER_HEX = npubToHex(MASTER_NPUB)

let port, rx = Buffer.alloc(0)
const waiters = []
function onData(chunk) {
  rx = Buffer.concat([rx, chunk])
  while (true) {
    const at = rx.indexOf(Buffer.from([0x48, 0x57]))
    if (at < 0) { if (rx.length > 8192) rx = rx.subarray(rx.length - 1); return }
    if (at > 0) rx = rx.subarray(at)
    if (rx.length < 9) return
    const len = (rx[3] << 8) | rx[4]
    if (rx.length < 5 + len + 4) return
    const body = rx.subarray(2, 5 + len)
    if (crc32(body) !== rx.readUInt32BE(5 + len)) { rx = rx.subarray(2); continue }
    const f = { type: rx[2], payload: Buffer.from(rx.subarray(5, 5 + len)) }
    rx = rx.subarray(5 + len + 4)
    const idx = waiters.findIndex((w) => w.types.includes(f.type))
    if (idx >= 0) waiters.splice(idx, 1)[0].resolve(f)
  }
}
async function openPort() {
  port = new SerialPort({ path: PORT, baudRate: 115200 })
  port.on('data', onData)
  await new Promise((r, j) => { port.on('open', r); port.on('error', j) })
  await new Promise((r) => setTimeout(r, 400))
}
function closePort() { return new Promise((r) => port.close(() => r())) }
function transact(frame, types, ms = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const i = waiters.findIndex((w) => w.resolve === done)
      if (i >= 0) waiters.splice(i, 1)
      reject(new Error(`timeout waiting for [${types.map((t) => '0x' + t.toString(16))}]`))
    }, ms)
    const done = (f) => { clearTimeout(timer); resolve(f) }
    waiters.push({ types, resolve: done })
    port.write(frame)
  })
}

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
}

// --- transport ops ---
async function auth() {
  const secret = Buffer.from(readFileSync(`${BENCH}/bridge.secret`, 'utf8').trim(), 'hex')
  const f = await transact(buildFrame(FT.AUTH, secret), [FT.AUTH_ACK])
  if (f.payload[0] !== 0) throw new Error(`SESSION_AUTH status ${f.payload[0]}`)
}
function clientKey() {
  const path = `${BENCH}/bench-client.key`
  if (existsSync(path)) return Buffer.from(readFileSync(path, 'utf8').trim(), 'hex')
  const sk = generateSecretKey()
  writeFileSync(path, Buffer.from(sk).toString('hex') + '\n', { mode: 0o600 })
  return sk
}
let seq = 0
async function nip46(method, params, ms = 30000) {
  const sk = clientKey()
  const rpc = { id: `bench-${Date.now()}-${++seq}`, method, params }
  const ct = Buffer.from(encrypt(JSON.stringify(rpc), getConversationKey(sk, MASTER_HEX)))
  const payload = Buffer.alloc(72 + ct.length)
  Buffer.from(MASTER_HEX, 'hex').copy(payload, 0)
  Buffer.from(getPublicKey(sk), 'hex').copy(payload, 32)
  payload.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000)), 64)
  ct.copy(payload, 72)
  const f = await transact(buildFrame(FT.ENC_REQ, payload), [FT.ENVELOPE, FT.NACK], ms)
  if (f.type === FT.NACK) throw new Error(`${method}: NACK (policy or decrypt)`)
  const envelope = JSON.parse(f.payload.toString())
  const plain = decrypt(envelope.content, getConversationKey(sk, envelope.pubkey))
  const resp = JSON.parse(plain)
  if (resp.id !== rpc.id) throw new Error(`${method}: id mismatch`)
  return resp
}
async function list() {
  return JSON.parse((await transact(buildFrame(FT.LIST, []), [FT.LIST_RESP])).payload.toString())
}
async function fwInfo() {
  return JSON.parse((await transact(buildFrame(FT.FW, []), [FT.FW_RESP])).payload.toString())
}
async function pair() {
  const pairFile = `${BENCH}/bench-client.pairing.json`
  if (existsSync(pairFile)) { console.log('pairing exists, reusing'); return }
  const create = await transact(buildFrame(FT.CS_CREATE, Buffer.concat([Buffer.from([0]), Buffer.from('Bench manager')])), [FT.CS_CREATE_RESP, FT.NACK])
  if (create.type === FT.NACK) throw new Error('CONNSLOT_CREATE NACK (slots full?)')
  const { slot_index, secret } = JSON.parse(create.payload.toString())
  console.log('\n*** Get ready at the signer: the approval prompt appears in 15 seconds. ***')
  for (let s = 15; s > 0; s -= 5) { console.log(`   ${s}...`); await new Promise((r) => setTimeout(r, 5000)) }
  promptForPress('the "Bench manager" policy', { hold: '2 s, 30 s window' })
  const policy = { slot_index, allowed_methods: ['get_public_key', 'heartwood_derive_persona', 'heartwood_remove_persona', 'heartwood_rename_persona'], allowed_kinds: [], auto_approve: true }
  const upd = await transact(buildFrame(FT.CS_UPDATE, Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify(policy))])), [FT.CS_UPDATE_RESP, FT.NACK], 40000)
  if (upd.type === FT.NACK) throw new Error('CONNSLOT_UPDATE denied or timed out')
  const conn = await nip46('connect', [MASTER_HEX, secret])
  if (conn.error) throw new Error(`connect: ${conn.error}`)
  writeFileSync(pairFile, JSON.stringify({ slot_index, client: getPublicKey(clientKey()) }) + '\n', { mode: 0o600 })
  check('pairing ceremony (create + button ceiling + connect)', true, `slot ${slot_index}`)
}
async function derive(name) {
  const resp = await nip46('heartwood_derive_persona', [name, 0])
  if (resp.error) return { error: resp.error }
  return JSON.parse(resp.result)
}

function unlockWithRetries() {
  // The S3 re-enumerates its native USB after a reset and the vault unseal
  // KDF is deliberately slow; probe until SESSION_AUTH answers.
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      execSync(
        `node ${FW_REPO}/scripts/vault-unlock.mjs --port ${PORT} --secret-file ${BENCH}/bridge.secret --vault-key-file ${BENCH}/vault.key`,
        { stdio: 'inherit', timeout: 180000 },
      )
      return
    } catch (e) {
      if (attempt === 4) throw e
      console.log(`unlock attempt ${attempt} failed; retrying in 8 s...`)
      execSync('sleep 8')
    }
  }
}

async function main() {
  const mode = process.argv[2] ?? 'full'
  if (mode === 'cap-only') {
    // Post-fix verification: everything here must run with ZERO button
    // presses — cleanup of leftover bench personas, a fresh cap fill with
    // the proper storage refusal, and cleanup again.
    unlockWithRetries()
    await openPort()
    await auth()
    let cleaned = 0
    for (const row of (await list()).filter((r) => r.persona)) {
      const r = await nip46('heartwood_remove_persona', [npubToHex(row.npub)])
      if (!r.error) cleaned++
    }
    check('silent cleanup of leftovers', (await list()).filter((r) => r.persona).length === 0, `removed ${cleaned}`)
    const capInfo = await fwInfo()
    let created = 0, refusal = null
    for (let i = 0; i < capInfo.max_personas + 1; i++) {
      const r = await derive(`cap-${String(i).padStart(2, '0')}`)
      if (r.error) { refusal = r.error; break }
      created++
    }
    check('cap reached, all silent', refusal !== null && created === capInfo.max_personas, `created ${created}`)
    check('refusal names storage', (refusal ?? '').includes('identity storage full'), refusal)
    const atCap = await fwInfo()
    console.log(`at cap: nvs ${atCap.nvs_used_entries}/${atCap.nvs_total_entries}, free ${atCap.nvs_free_entries}`)
    let removed = 0
    for (const row of (await list()).filter((r) => r.persona)) {
      const r = await nip46('heartwood_remove_persona', [npubToHex(row.npub)])
      if (!r.error) removed++
    }
    check('silent cap cleanup', (await list()).filter((r) => r.persona).length === 0, `removed ${removed}`)
    const statsEnd = await fwInfo()
    console.log(`final: nvs ${statsEnd.nvs_used_entries}/${statsEnd.nvs_total_entries}`)
    await closePort()
    const failed = results.filter((r) => !r.ok).length
    console.log(`\n${results.length - failed}/${results.length} checks passed`)
    process.exit(failed ? 1 : 0)
  }
  if (mode === 'resume') {
    // Board is locked post-reset with the round-trip personas persisted:
    // unlock, then continue from the post-reboot phase.
    const a1 = { npub: process.argv[3] }
    if (!a1.npub?.startsWith('npub1')) throw new Error('resume needs the bench-a npub as arg')
    unlockWithRetries()
    await openPort()
    await auth()
    const base = { length: 0 }
    await postRebootAndOn(base, a1)
    return
  }
  await openPort()
  await auth()
  await pair()

  // --- round-trip ---
  const base = (await list()).filter((r) => r.persona)
  const stats0 = await fwInfo()
  check('baseline', true, `${base.length} personas, nvs ${stats0.nvs_used_entries}/${stats0.nvs_total_entries}`)
  const a1 = await derive('bench-a')
  check('derive bench-a', a1.purpose === 'nostr:persona:bench-a', a1.npub)
  const b1 = await derive('bench-b')
  check('derive bench-b', b1.purpose === 'nostr:persona:bench-b')
  const a2 = await derive('bench-a')
  check('re-derive idempotent', a2.npub === a1.npub)
  const mid = (await list()).filter((r) => r.persona)
  check('list shows both once', mid.length === base.length + 2, mid.map((p) => p.label).join(','))
  const stats1 = await fwInfo()
  check('nvs usage grew', stats1.nvs_used_entries > stats0.nvs_used_entries, `${stats0.nvs_used_entries} -> ${stats1.nvs_used_entries}`)
  const ren = await nip46('heartwood_rename_persona', [npubToHex(a1.npub), 'Bench Alpha'])
  check('rename', !ren.error, ren.result ?? ren.error)
  check('rename visible', (await list()).some((r) => r.persona && r.label === 'Bench Alpha'))

  // --- reboot + re-unlock ---
  console.log('resetting signer...')
  await closePort()
  execSync(`espflash reset --port ${PORT}`, { stdio: 'ignore' })
  await new Promise((r) => setTimeout(r, 12000))
  console.log('re-unlocking...')
  unlockWithRetries()
  await openPort()
  await auth()
  await postRebootAndOn(base, a1)
}

async function postRebootAndOn(base, a1) {
  // --- post-reboot ---
  const after = (await list()).filter((r) => r.persona)
  check('personas survived reboot', after.length === base.length + 2, after.map((p) => p.label).join(','))
  check('rename survived reboot', after.some((r) => r.label === 'Bench Alpha'))
  const a3 = await derive('bench-a')
  check('post-reboot re-derive stable', a3.npub === a1.npub)
  const rm = await nip46('heartwood_remove_persona', [npubToHex(a1.npub)])
  check('remove bench-a', !rm.error, rm.result ?? rm.error)
  check('removed from list', !(await list()).some((r) => r.persona && (r.label === 'Bench Alpha' || r.label === 'bench-a')))
  const a4 = await derive('bench-a')
  check('removal registry-only (same key back)', a4.npub === a1.npub)

  // --- cap ---
  const capInfo = await fwInfo()
  const cap = capInfo.max_personas
  let created = 0, refusal = null
  const startCount = (await list()).filter((r) => r.persona).length
  for (let i = startCount; i < cap + 1; i++) {
    const r = await derive(`cap-${String(i).padStart(2, '0')}`)
    if (r.error) { refusal = r.error; break }
    created++
  }
  check('cap reached with clean refusal', refusal !== null && created === cap - startCount, `created ${created}, refusal: ${refusal}`)
  check('refusal names storage', (refusal ?? '').includes('identity storage full'))
  const atCap = await fwInfo()
  console.log(`at cap: nvs ${atCap.nvs_used_entries}/${atCap.nvs_total_entries}, free ${atCap.nvs_free_entries}`)
  check('device healthy at cap', (await list()).length > 0)

  // --- cleanup ---
  let removed = 0
  for (const row of (await list()).filter((r) => r.persona)) {
    const r = await nip46('heartwood_remove_persona', [npubToHex(row.npub)])
    if (!r.error) removed++
  }
  const final = (await list()).filter((r) => r.persona)
  check('cleanup complete', final.length === 0, `removed ${removed}`)
  const statsEnd = await fwInfo()
  console.log(`final: nvs ${statsEnd.nvs_used_entries}/${statsEnd.nvs_total_entries}`)

  await closePort()
  const failed = results.filter((r) => !r.ok).length
  console.log(`\n${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

main().catch((e) => { console.error('BENCH ERROR:', e.message); process.exit(2) })
