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
//   node scripts/relay-size-sweep.mjs 'bunker://<pubkey>?relay=<url>&secret=<hex>'
//
// The URI is an ARGUMENT, never a file: it carries a live signing credential.

import { env, argv } from 'node:process'

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

const uri = argv[2]
if (!uri?.startsWith('bunker://')) {
  console.error("usage: node scripts/relay-size-sweep.mjs 'bunker://<pubkey>?relay=<url>&secret=<hex>'")
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
const { readFileSync, writeFileSync } = await import('node:fs')
let store = {}
try { store = JSON.parse(readFileSync(keyStore, 'utf8')) } catch { /* first run */ }

const skHexArg = argv.includes('--sk') ? argv[argv.indexOf('--sk') + 1] : null
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

function attach(ws) {
  ws.onmessage = (ev) => {
    let msg
    try { msg = JSON.parse(ev.data) } catch { return }
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
const SIZES_ARG = argv.includes('--sizes') ? argv[argv.indexOf('--sizes') + 1] : null
const SIZES = SIZES_ARG
  ? SIZES_ARG.split(',').map((s) => Number(s.trim()))
  : [1024, 4096, 8192, 10240, 16384, 20480, 20992, 24576, 32768]

console.log('content   request    response  ms     outcome')
const results = []
for (const [i, size] of SIZES.entries()) {
  const event = { kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'a'.repeat(size) }
  const r = await request(ws, `sweep-${i}`, 'sign_event', [JSON.stringify(event)], 40_000)

  let outcome
  if (!r.body) outcome = 'NO REPLY (frame dropped or signer reset)'
  else if (r.body.error) outcome = `error: ${r.body.error}`
  else if (r.body.result) {
    try {
      const signed = JSON.parse(r.body.result)
      outcome = signed.sig?.length === 128 && signed.content?.length === size
        ? 'signed'
        : 'signed but mismatched'
    } catch { outcome = 'unparseable result' }
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
