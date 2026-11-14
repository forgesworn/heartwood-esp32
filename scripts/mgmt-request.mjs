#!/usr/bin/env node
// scripts/mgmt-request.mjs
//
// Relay operator client for the kind-24134 management channel: NIP-44
// encrypts one {id, method, params} request to the master/operator
// conversation key, publishes it #p-tagged to the master, and waits for the
// master-authored response addressed back to the operator. On a timeout it
// also prints, for each relay, whether that relay acknowledged the request
// and whether the reply subscription was up, to show where a lost reply went
// missing. With --challenge
// it first fetches get_management_challenge and injects mutation_challenge —
// required for every mutating method (unknown methods are fail-closed, so
// when in doubt pass it).
//
// The operator key is the one baked into the device as `op_mgmt`; install it
// with scripts/set-operator.mjs. Deps resolve via scripts/relay-deps.mjs.
//
// Usage:
//   node scripts/mgmt-request.mjs --method get_status
//   node scripts/mgmt-request.mjs --method update_client --challenge \
//     --params '{"slot_index":3, ...}'
//   [--relay wss://...] [--master <hex|npub>] [--key-file <path>]
//   [--timeout 30000] [--target <identity hex>]
//
// --target sets the #p route when managing a non-primary master.

import { argv, env, exit } from 'node:process'
import { readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import {
  finalizeEvent,
  getPublicKey,
  nip44,
  arg,
  toHex,
  relayList,
  RelayFanout,
} from './relay-deps.mjs'

const has = (name) => argv.includes(name)

const RELAYS = relayList(argv)
const KEY_FILE = arg(argv, '--key-file', `${env.HOME}/heartwood-bench/operator.key`)
const METHOD = arg(argv, '--method')
const PARAMS = JSON.parse(arg(argv, '--params', '{}'))
const TIMEOUT = Number(arg(argv, '--timeout', '30000'))
const MASTER_ARG = arg(argv, '--master', env.HEARTWOOD_MASTER)

if (!METHOD || !MASTER_ARG) {
  console.error(
    'usage: node scripts/mgmt-request.mjs --method <m> [--params JSON] [--challenge]\n' +
      '       --master <hex|npub> (or set HEARTWOOD_MASTER)',
  )
  exit(2)
}

const master = toHex(MASTER_ARG, '--master')
const target = arg(argv, '--target', master)

const skHex = readFileSync(KEY_FILE, 'utf8').trim()
if (!/^[0-9a-f]{64}$/.test(skHex)) {
  console.error(`operator key file ${KEY_FILE} must hold 64 lowercase hex chars`)
  exit(2)
}
const sk = Uint8Array.from(Buffer.from(skHex, 'hex'))
const opPub = getPublicKey(sk)
const ck = nip44.v2.utils.getConversationKey(sk, master)

const ws = new RelayFanout(RELAYS)

// What each relay said during the run, kept for the timeout report. A
// timeout alone cannot say whether the relay took the request, so record its
// OK for each request, the reply subscription's EOSE or CLOSED, NOTICEs and
// any AUTH challenge (this client does not answer one). Times are ms from
// start.
const started = Date.now()
const sinceStart = () => Date.now() - started
const sentIds = new Set()
let sentAt = null
const heard = new Map()
const heardFrom = (url) => {
  if (!heard.has(url)) heard.set(url, { eose: null, closed: null, ok: null, notices: [], auth: false })
  return heard.get(url)
}
ws.on((data, url) => {
  let msg
  try {
    msg = JSON.parse(data.toString())
  } catch {
    return
  }
  if (!Array.isArray(msg)) return
  const h = heardFrom(url)
  if (msg[0] === 'EOSE' && msg[1] === 'mgmt' && h.eose === null) h.eose = sinceStart()
  else if (msg[0] === 'CLOSED' && msg[1] === 'mgmt') h.closed = String(msg[2] ?? '')
  else if (msg[0] === 'OK' && sentIds.has(msg[1])) {
    h.ok = { accepted: msg[2] === true, reason: String(msg[3] ?? ''), at: sinceStart() }
  } else if (msg[0] === 'NOTICE' && h.notices.length < 3) h.notices.push(String(msg[1] ?? ''))
  else if (msg[0] === 'AUTH') h.auth = true
})

/** One line per relay: did it take the request, and was the reply subscription up? */
function relayReport(liveUrls) {
  return RELAYS.map((url) => {
    if (!liveUrls.includes(url)) return `${url}: not connected`
    const h = heardFrom(url)
    const parts = []
    if (!h.ok) parts.push('request not acknowledged')
    else if (h.ok.accepted) parts.push(`request accepted at ${h.ok.at} ms`)
    else parts.push(`request refused (${h.ok.reason})`)
    if (h.closed !== null) parts.push(`reply subscription closed (${h.closed})`)
    else if (h.eose === null) parts.push('no EOSE on the reply subscription')
    else parts.push(`reply subscription up at ${h.eose} ms`)
    parts.push(`last request sent at ${sentAt ?? '-'} ms`)
    if (h.auth) parts.push('relay sent an AUTH challenge (not answered)')
    for (const notice of h.notices) parts.push(`notice: ${notice}`)
    return `${url}: ${parts.join('; ')}`
  })
}

let liveUrls = []
const deadline = setTimeout(() => {
  console.error(
    `timeout: no response within ${TIMEOUT} ms (tried ${RELAYS.join(', ')})`,
  )
  for (const line of relayReport(liveUrls)) console.error(line)
  ws.close()
  exit(1)
}, TIMEOUT)

/** One request, resolved to its decrypted result (rejects on {error}). */
function roundTrip(method, params, extra = {}) {
  return new Promise((resolve, reject) => {
    const id = randomBytes(8).toString('hex')
    const plaintext = JSON.stringify({ id, method, params, ...extra })
    const ev = finalizeEvent(
      {
        kind: 24134,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', target]],
        content: nip44.v2.encrypt(plaintext, ck),
      },
      sk,
    )
    let off = () => {}
    const onMessage = (data) => {
      let msg
      try {
        msg = JSON.parse(data.toString())
      } catch {
        return
      }
      if (msg[0] !== 'EVENT' || msg[1] !== 'mgmt') return
      const e = msg[2]
      if (e.kind !== 24134 || e.pubkey !== master) return
      let inner
      try {
        inner = JSON.parse(nip44.v2.decrypt(e.content, ck))
      } catch {
        return
      }
      if (inner.id !== id) return
      off()
      if (inner.error !== undefined) reject(new Error(inner.error))
      else resolve(inner.result)
    }
    off = ws.on(onMessage)
    sentIds.add(ev.id)
    sentAt = sinceStart()
    ws.send(['EVENT', ev])
  })
}

try {
  const live = await ws.open()
  liveUrls = live
  // Ephemeral kind: the forward-only subscription must be up before publishing.
  ws.req('mgmt', { kinds: [24134], authors: [master], '#p': [opPub], limit: 0 })
  if (live.length < RELAYS.length) {
    console.error(`(connected to ${live.length}/${RELAYS.length} relays)`)
  }
  {
    let extra = {}
    if (has('--challenge')) {
      const { challenge } = await roundTrip('get_management_challenge', {})
      extra = { mutation_challenge: challenge }
    }
    const result = await roundTrip(METHOD, PARAMS, extra)
    console.log(JSON.stringify(result, null, 2))
    clearTimeout(deadline)
    ws.close()
    exit(0)
  }
} catch (e) {
  console.error(`error: ${e.message}`)
  clearTimeout(deadline)
  ws.close()
  exit(1)
}
