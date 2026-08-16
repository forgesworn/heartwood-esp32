#!/usr/bin/env node
// scripts/nip46-client.mjs
//
// Minimal NIP-46 relay client for bench runs: one {id, method, params[]}
// request, kind 24133, NIP-44 to the addressed identity (#p routing is what
// picks the signing identity on the device). The client keypair persists in
// --client-key-file, so a slot's pubkey binding survives across invocations —
// use a fresh file per bench client, the same file to keep being that client.
//
// Prints the request event id on stderr: that id IS the C4 park handle, which
// is what `resolve_approval` takes. Deps resolve via scripts/relay-deps.mjs.
//
// Usage:
//   node scripts/nip46-client.mjs --target <identityHex> --client-key-file k.key \
//     --method connect --params '["<targetHex>","<slotSecret>"]'
//   node scripts/nip46-client.mjs --target <identityHex> --client-key-file k.key \
//     --method sign_event --params-file template.json   (template → [json])
//   [--relay wss://...] [--timeout 30000]

import { argv, exit } from 'node:process'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import {
  finalizeEvent,
  getPublicKey,
  nip44,
  arg,
  relayList,
  RelayFanout,
} from './relay-deps.mjs'
import { startPressPrompt } from './press-prompt.mjs'

const RELAYS = relayList(argv)
const TARGET = arg(argv, '--target')
const METHOD = arg(argv, '--method')
const TIMEOUT = Number(arg(argv, '--timeout', '30000'))
const KEY_FILE = arg(argv, '--client-key-file')
const PARAMS_FILE = arg(argv, '--params-file')

if (!TARGET || !METHOD || !KEY_FILE || !/^[0-9a-f]{64}$/.test(TARGET)) {
  console.error(
    'usage: node scripts/nip46-client.mjs --target <hex> --client-key-file <path> ' +
      '--method <m> [--params JSON|--params-file f]',
  )
  exit(2)
}
const params = PARAMS_FILE
  ? [readFileSync(PARAMS_FILE, 'utf8').trim()]
  : JSON.parse(arg(argv, '--params', '[]'))

if (!existsSync(KEY_FILE)) {
  writeFileSync(KEY_FILE, `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 })
}
const sk = Uint8Array.from(Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'hex'))
const clientPub = getPublicKey(sk)
const ck = nip44.v2.utils.getConversationKey(sk, TARGET)

// Methods the signer may stop and ask about. For these the prompt keeps
// sounding until the answer lands, so the operator is not relying on
// happening to glance at the OLED inside the window.
const MAY_NEED_APPROVAL =
  METHOD === 'sign_event' || METHOD === 'sign_event_compact' || METHOD.startsWith('heartwood_')
let stopPrompt = () => {}

const ws = new RelayFanout(RELAYS)
const started = Date.now()
setTimeout(() => {
  stopPrompt()
  console.error(`timeout: no response within ${TIMEOUT} ms (tried ${RELAYS.join(', ')})`)
  ws.close()
  exit(3)
}, TIMEOUT)

{
  const live = await ws.open()
  if (live.length < RELAYS.length) {
    console.error(`(connected to ${live.length}/${RELAYS.length} relays)`)
  }
  ws.req('c', { kinds: [24133], authors: [TARGET], '#p': [clientPub], limit: 0 })
  const id = randomBytes(8).toString('hex')
  const ev = finalizeEvent(
    {
      kind: 24133,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', TARGET]],
      content: nip44.v2.encrypt(JSON.stringify({ id, method: METHOD, params }), ck),
    },
    sk,
  )
  ws.on((data) => {
    let msg
    try {
      msg = JSON.parse(data.toString())
    } catch {
      return
    }
    if (msg[0] !== 'EVENT' || msg[1] !== 'c') return
    const e = msg[2]
    let inner
    try {
      inner = JSON.parse(nip44.v2.decrypt(e.content, ck))
    } catch {
      return
    }
    if (inner.id !== id) return
    // However it was answered — approved, denied or expired — stop asking.
    stopPrompt()
    const out = {
      elapsed_ms: Date.now() - started,
      client_pubkey: clientPub,
      response_created_at: e.created_at,
      ...inner,
    }
    console.log(JSON.stringify(out, null, 2))
    ws.close()
    exit(inner.error !== undefined ? 1 : 0)
  })
  // The request event id doubles as the C4 park id — surface it for benches.
  console.error(`request event id: ${ev.id}`)
  ws.send(['EVENT', ev])
  if (MAY_NEED_APPROVAL) {
    stopPrompt = startPressPrompt(`the ${METHOD} request`)
  }
}
