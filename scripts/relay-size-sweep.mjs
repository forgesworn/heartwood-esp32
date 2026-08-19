#!/usr/bin/env node
// scripts/relay-size-sweep.mjs
//
// Size sweep over the RELAY transport — the one MAX_SIGN_CONTENT_RELAY (20480)
// actually describes.
//
// The USB probes in frame-size-probe.mjs measure a path with no NIP-44 and no
// base64, bounded only by MAX_PAYLOAD_SIZE. The relay path is bounded far
// lower: a response is NIP-44 padded, base64'd (4/3) and wrapped in a
// kind:24133 event before it crosses a WebSocket frame capped at 32768. Undo
// that chain and the largest response that fits lands on the NIP-44 padding
// step of 20480. This sweep tests that derivation against the real device.
//
// Runs as an ordinary NIP-46 client against a bunker URI. Point it at a
// throwaway connection slot and revoke the slot afterwards: the secret in the
// URI authorises signing.
//
// The slot must have auto-sign enabled, or every step waits on a button press.
//
// Usage:
//   HEARTWOOD_SWEEP_BUNKER='bunker://<pubkey>?relay=<url>&secret=<hex>' \
//     node scripts/relay-size-sweep.mjs
//   node scripts/relay-size-sweep.mjs --uri-file <path-to-0600-file>
//
// The URI carries a live signing credential: pass it via the env var or a
// file, not inline — argv leaks into shell history and `ps`. A bare argv URI
// still works as a fallback for a one-off throwaway slot.

import { env, argv } from 'node:process'
import { readFileSync, writeFileSync } from 'node:fs'

const load = async (spec) => {
  const candidates = [
    spec,
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/${spec}/lib/esm/index.js`,
      new URL('../', import.meta.url)).href,
  ]
  for (const c of candidates) {
    try { return await import(c) } catch { /* next */ }
  }
  throw new Error(`cannot resolve ${spec}; set SAPWOOD_DIR to a checkout that has it`)
}
const nt = await load('nostr-tools')
const { finalizeEvent, generateSecretKey, getPublicKey, nip44 } = nt

const uriFile = argv.includes('--uri-file') ? argv[argv.indexOf('--uri-file') + 1] : null
const uri = env.HEARTWOOD_SWEEP_BUNKER ?? (uriFile ? readFileSync(uriFile, 'utf8').trim() : argv[2])
if (!uri?.startsWith('bunker://')) {
  console.error("usage: HEARTWOOD_SWEEP_BUNKER='bunker://<pubkey>?relay=<url>&secret=<hex>' node scripts/relay-size-sweep.mjs")
  console.error('   or: node scripts/relay-size-sweep.mjs --uri-file <path>')
  console.error('   (a bare argv URI still works, but leaks into shell history / ps)')
  process.exit(2)
}

const parsed = new URL(uri.replace('bunker://', 'https://'))
const remotePubkey = parsed.hostname
const relays = parsed.searchParams.getAll('relay')
const secret = parsed.searchParams.get('secret')
if (!remotePubkey || relays.length === 0) { console.error('bunker URI needs a pubkey and at least one relay'); process.exit(2) }

// Reuse the client identity across runs, keyed by signer pubkey.
//
// A connection slot BINDS to the first client pubkey that uses it. Generating
// a fresh keypair per run therefore burns a slot on every invocation: the
// first run works, and every re-run is silently ignored by the signer because
// its key is not the bound one. Persisting the key makes a sweep repeatable
// against one slot, which is what narrowing a threshold needs.
//
// The file holds a signing credential for that slot. It lives beside the
// script deliberately (not in the repo — scripts/.sweep-clients.json is
// gitignored) and the slot should be revoked when the sweep is done.
const keyStore = new URL('.sweep-clients.json', import.meta.url)
let store = {}
try { store = JSON.parse(readFileSync(keyStore, 'utf8')) } catch { /* first run */ }

// Same argv-leak caveat for an explicit client key: prefer HEARTWOOD_SWEEP_SK
// over `--sk <hex>` (the argv fallback is kept for one-off runs).
const skHexArg = env.HEARTWOOD_SWEEP_SK ?? (argv.includes('--sk') ? argv[argv.indexOf('--sk') + 1] : null)
const hexToBytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)))
const bytesToHex = (b) => Buffer.from(b).toString('hex')

let sk
if (skHexArg) sk = hexToBytes(skHexArg)
else if (store[remotePubkey]) sk = hexToBytes(store[remotePubkey])
else {
  sk = generateSecretKey()
  store[remotePubkey] = bytesToHex(sk)
  writeFileSync(keyStore, JSON.stringify(store, null, 2), { mode: 0o600 })
  console.log('minted a new client identity for this signer (stored for re-runs)')
}
const pk = getPublicKey(sk)
const convKey = nip44.getConversationKey(sk, remotePubkey)
const NIP46_KIND = 24133

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// --- relay socket ----------------------------------------------------------

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url)
    const t = setTimeout(() => { try { ws.close() } catch {} ; reject(new Error(`timeout dialling ${url}`)) }, 12_000)
    ws.onopen = () => { clearTimeout(t); resolve(ws) }
    ws.onerror = () => { clearTimeout(t); reject(new Error(`failed dialling ${url}`)) }
  })
}

const pending = new Map()   // request id -> {resolve, sentAt}

// A relay that refuses our EVENT and a signer that dies on it look identical
// from here — both end in silence — and they call for opposite responses. The
// relay's OK frame distinguishes them, so surface it rather than waiting out
// the timeout. Relays cap event size at wildly different points: one of the
// four configured on this signer refused at ~17 KB while another carried
// 27 KB, so the effective ceiling in the field is the minimum of the signer's
// and the tightest relay's.
let lastRejection = null

function attach(ws) {
  ws.onmessage = (ev) => {
    let msg
    try { msg = JSON.parse(ev.data) } catch { return }

    if (msg[0] === 'OK' && msg[2] === false) {
      lastRejection = msg[3] || 'rejected without a reason'
      for (const [id, waiter] of pending) {
        pending.delete(id)
        waiter.resolve({ rejected: lastRejection })
      }
      return
    }

    if (msg[0] !== 'EVENT') return
    const event = msg[2]
    if (event?.kind !== NIP46_KIND) return
    let body
    try { body = JSON.parse(nip44.decrypt(event.content, convKey)) } catch { return }
    const waiter = pending.get(body.id)
    if (waiter) { pending.delete(body.id); waiter.resolve({ body, bytes: event.content.length }) }
  }
}

async function request(ws, id, method, params, timeoutMs) {
  const ciphertext = nip44.encrypt(JSON.stringify({ id, method, params }), convKey)
  const event = finalizeEvent({
    kind: NIP46_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', remotePubkey]],
    content: ciphertext,
  }, sk)
  const wire = JSON.stringify(['EVENT', event])
  const started = Date.now()
  const reply = new Promise((resolve) => {
    pending.set(id, { resolve })
    setTimeout(() => { if (pending.delete(id)) resolve(null) }, timeoutMs)
  })
  ws.send(wire)
  const out = await reply
  return { ...(out ?? {}), ms: Date.now() - started, requestBytes: wire.length }
}

// --- run -------------------------------------------------------------------

let ws = null
for (const url of relays) {
  try { ws = await connect(url); console.log(`connected ${url}`); break }
  catch (e) { console.log(`  ${e.message}`) }
}
if (!ws) { console.error('no relay reachable'); process.exit(1) }
attach(ws)

ws.send(JSON.stringify(['REQ', 'sweep', { kinds: [NIP46_KIND], '#p': [pk], authors: [remotePubkey], since: Math.floor(Date.now() / 1000) - 10 }]))
await sleep(800)

console.log(`client ${pk.slice(0, 12)}…  signer ${remotePubkey.slice(0, 12)}…\n`)

const connectReply = await request(ws, 'sweep-connect', 'connect', [remotePubkey, secret ?? ''], 25_000)
if (!connectReply.body) { console.error('connect got no reply; is the signer online?'); process.exit(1) }
console.log(`connect: ${connectReply.body.result ?? connectReply.body.error} (${connectReply.ms}ms)\n`)

// NIP-44 padding steps either side of the derived 20480 ceiling.
// --sizes 16384,18432 narrows in on a measured cutoff.
const OBJECT_PARAMS = argv.includes('--object-params')
const COMPACT = argv.includes('--compact')
if (OBJECT_PARAMS) console.log('params[0] as a JSON object (no second escaping)')
if (COMPACT) console.log('sign_event_compact: reply carries {id, sig, pubkey, created_at} only')
if (OBJECT_PARAMS || COMPACT) console.log('')
const SIZES_ARG = argv.includes('--sizes') ? argv[argv.indexOf('--sizes') + 1] : null
const SIZES = SIZES_ARG
  ? SIZES_ARG.split(',').map((s) => Number(s.trim()))
  : [1024, 4096, 8192, 10240, 16384, 20480, 20992, 24576, 32768]

console.log('content   request    response  ms     outcome')
const results = []
for (const [i, size] of SIZES.entries()) {
  const event = { kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'a'.repeat(size) }
  // --object-params sends params[0] as a JSON OBJECT rather than the stringified
  // event NIP-46 specifies. The signer accepts both, and the difference is the
  // whole point: the string form is escaped a second time, and unescaping it
  // grows a Vec by doubling, which is what aborts the chip. The object form
  // never takes that path, so this measures how much of the ceiling was the
  // encoding rather than the hardware.
  const params = OBJECT_PARAMS ? [event] : [JSON.stringify(event)]
  // --compact asks for {id, sig, pubkey, created_at} instead of the whole signed
  // event echoed back. The reply is then a couple of hundred bytes whatever the
  // content, which is the other half of the ceiling: the full reply needs one
  // contiguous allocation of about twice the content.
  const method = COMPACT ? 'sign_event_compact' : 'sign_event'
  const r = await request(ws, `sweep-${i}`, method, params, 40_000)

  let outcome
  if (r.rejected) outcome = `RELAY REFUSED: ${r.rejected}`
  else if (!r.body) outcome = 'NO REPLY (signer silent: dropped frame, or crashed)'
  else if (r.body.error) outcome = `error: ${r.body.error}`
  else if (r.body.result) {
    try {
      const signed = JSON.parse(r.body.result)
      if (COMPACT) {
        // The premise of the compact reply is that the client can rebuild the
        // event from what it already had. So rebuild it and VERIFY, rather than
        // trusting that bytes came back: this is the assertion that the smaller
        // reply is actually usable.
        const rebuilt = {
          ...event,
          pubkey: signed.pubkey,
          created_at: signed.created_at,
          id: signed.id,
          sig: signed.sig,
        }
        outcome = nt.verifyEvent(rebuilt) ? 'signed (compact, verified)' : 'compact reply failed verification'
      } else {
        outcome = signed.sig?.length === 128 && signed.content?.length === size
          ? 'signed'
          : 'signed but mismatched'
      }
    } catch (e) { outcome = `unparseable result: ${e.message}` }
  } else outcome = 'empty'

  results.push({ size, requestBytes: r.requestBytes, responseBytes: r.bytes ?? null, ms: r.ms, outcome })
  console.log(
    `${String(size).padStart(7)}  ${String(r.requestBytes).padStart(8)}  ` +
    `${String(r.bytes ?? '--').padStart(8)}  ${String(r.ms).padStart(5)}  ${outcome}`,
  )
  await sleep(1500)
}

const signed = results.filter((r) => r.outcome === 'signed')
console.log(`\nlargest content signed over relay: ${signed.length ? signed[signed.length - 1].size : 0} B`)
console.log('derived MAX_SIGN_CONTENT_RELAY: 20480 B')
console.log(JSON.stringify(results, null, 2))
ws.close()
