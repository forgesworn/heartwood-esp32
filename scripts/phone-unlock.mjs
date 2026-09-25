#!/usr/bin/env node
// scripts/phone-unlock.mjs
//
// A bench stand-in for Cambium, so phone unlock can be proved on hardware
// before the Android side exists (docs/specs/2026-09-24-phone-unlock-design.md).
//
//   enrol    over USB: make a one-off enrolment key P, send PHONE_UNLOCK_CMD
//            (0x64) {op:"enrol"}, press on the board, open the sealed
//            hand-off with P, and keep {id, s, relays} in the state file.
//            With --over-relay, the same through the device operator's
//            kind-24134 channel (enrol_unlock_phone): the board holds it on a
//            card, and the press is still at the board. Either way the card
//            leads with the request code, four words from the enrolment key:
//            hold only if they match the phone that made the key (for enrol,
//            this script; for enrol-for, the phone's own screen).
//   enrol-for  stand in for Sapwood's panel: take the code a real phone
//            (Cambium) shows, enrol its key over USB with a press, and publish
//            the board's sealed answer to the phone as a kind-24137 hand-off
//            tagged with the code's rendezvous tag. Nothing here can read the
//            slot secret: the answer is sealed to the phone's enrolment key.
//   list     over USB: the board's enrolled phones.
//   revoke   over USB: remove one (--id), and forget it locally.
//   listen   over the relays, as the phone: subscribe to EVERY kind-24135
//            with no #p or #h filter, match the per-boot hint locally, open
//            the sealed context, apply the prompt rule, and on a yes answer
//            with a kind-24136 from a fresh throwaway key. Every message it
//            opens (a lock announcement, or a relay update, t = "relays",
//            which never prompts) adds the board's relays to the state file;
//            run listen again to listen on them.
//
// The state file holds slot secrets, which unlock the board together with
// its flash. It is written 0600, and nothing here prints a secret.
//
// Usage:
//   node scripts/phone-unlock.mjs enrol  --port <port> --secret-file <bridge.secret> [--label "bench phone"]
//   node scripts/phone-unlock.mjs enrol-for --code '<heartwood-unlock:enrol?...>' --port <port> --secret-file <bridge.secret>
//   node scripts/phone-unlock.mjs enrol|enrol-for ... --over-relay --master <hex|npub>
//        [--key-file ~/heartwood-bench/operator.key] [--mgmt-relay wss://...] (instead of --port/--secret-file)
//   node scripts/phone-unlock.mjs list   --port <port> --secret-file <bridge.secret>
//   node scripts/phone-unlock.mjs revoke --port <port> --secret-file <bridge.secret> --id <id>
//   node scripts/phone-unlock.mjs announce-operator on|off --port <port> --secret-file <bridge.secret>
//   node scripts/phone-unlock.mjs listen [--relay wss://...] [--timeout 600000] [--yes]
//   [--state ~/heartwood-bench/phones.json]

import { argv, env, exit } from 'node:process'
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline/promises'

import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { authenticateSession } from './lib/session-auth.mjs'
import { startPressPrompt } from './press-prompt.mjs'
import {
  ANNOUNCE_KIND,
  DELIVERY_KIND,
  HANDOFF_KIND,
  checkCode,
  deliveryJson,
  requestCode,
  hintMatches,
  judge,
  openContext,
  parseEnrolmentCode,
} from './lib/phone-unlock.mjs'

const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
const SESSION_END = 0x2d
const PHONE_UNLOCK_CMD = 0x64
const PHONE_UNLOCK_RESP = 0x65

function arg(name, dflt) {
  const i = argv.indexOf(name)
  return i === -1 ? dflt : argv[i + 1]
}

const COMMAND = argv[2]
const STATE_FILE = arg('--state', `${env.HOME}/heartwood-bench/phones.json`)

function loadState() {
  if (!existsSync(STATE_FILE)) return { phones: [] }
  return JSON.parse(readFileSync(STATE_FILE, 'utf8'))
}

function saveState(state) {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 })
  chmodSync(STATE_FILE, 0o600)
}

// `press` sends the frame ONCE and waits, speaking the press prompt until the
// board answers. A command that raises a card must never go through
// session.request: it resends every 2 s, and each resend queued behind the
// card is a whole second command once the first is answered (on 2026-09-24
// one enrol became four records, three of whose secrets were never read).
async function usbCommand(command, deadlineMs, { press } = {}) {
  const port = arg('--port')
  const secretFile = arg('--secret-file')
  if (!port || !secretFile) {
    console.error(`usage: node scripts/phone-unlock.mjs ${COMMAND} --port <port> --secret-file <path>`)
    exit(2)
  }
  const secret = Buffer.from(readFileSync(secretFile, 'utf8').trim(), 'hex')
  const session = await openFramedPort(port, { env })
  const auth = await authenticateSession({
    sendAuth: () => session.send(SESSION_AUTH, secret),
    waitForAck: (timeoutMs) => session.waitFor([SESSION_ACK], timeoutMs),
  })
  if (!auth || auth.reply.payload[0] !== 0x00) {
    session.close()
    throw new Error('bridge session authentication failed')
  }
  const payload = Buffer.from(JSON.stringify(command))
  let reply
  if (press) {
    session.send(PHONE_UNLOCK_CMD, payload)
    const stop = startPressPrompt(press)
    reply = await session.waitFor([PHONE_UNLOCK_RESP, NACK], deadlineMs)
    stop()
  } else {
    reply = await session.request(PHONE_UNLOCK_CMD, [PHONE_UNLOCK_RESP, NACK], { payload, deadlineMs })
  }
  // End the bridge session before letting go of the port, or the next program
  // to open it inherits it. Firmware without SESSION_END NACKs; harmless.
  session.send(SESSION_END, secret)
  await session.waitFor([ACK, NACK], 2_000)
  secret.fill(0)
  session.close()
  if (!reply) throw new Error(`no answer within ${deadlineMs / 1000}s`)
  if (reply.type === NACK) throw new Error(`refused: ${reply.payload.toString() || 'no reason'}`)
  return JSON.parse(reply.payload.toString())
}

async function relayDeps() {
  return import('./relay-deps.mjs')
}

const OVER_RELAY = argv.includes('--over-relay')

// A relay enrolment waits on a card: up to 90 s behind other cards, then 30 s
// on screen. Sent once, like the cable's, and given longer than both.
const RELAY_ENROL_DEADLINE_MS = 150_000

/**
 * Enrol over the device operator's kind-24134 channel: fetch a fresh mutation
 * challenge, send enrol_unlock_phone ONCE, and wait for the card to answer.
 * Resolves with the same answer the cable returns.
 */
async function relayEnrol(enrolPubkey, label) {
  const { finalizeEvent, getPublicKey, nip44, toHex, DEFAULT_RELAYS, RelayFanout } = await relayDeps()
  const masterArg = arg('--master', env.HEARTWOOD_MASTER)
  if (!masterArg) {
    console.error(`usage: node scripts/phone-unlock.mjs ${COMMAND} ... --over-relay --master <hex|npub> [--key-file <operator.key>] [--mgmt-relay wss://...]`)
    exit(2)
  }
  const master = toHex(masterArg, '--master')
  const keyFile = arg('--key-file', `${env.HOME}/heartwood-bench/operator.key`)
  const skHex = readFileSync(keyFile, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/.test(skHex)) throw new Error(`operator key file ${keyFile} must hold 64 lowercase hex chars`)
  const sk = Uint8Array.from(Buffer.from(skHex, 'hex'))
  const ck = nip44.v2.utils.getConversationKey(sk, master)
  const picked = []
  argv.forEach((a, i) => { if (a === '--mgmt-relay' && argv[i + 1]) picked.push(argv[i + 1]) })
  const relays = picked.length ? picked : DEFAULT_RELAYS
  if (!relays.length) throw new Error('no relay: pass --mgmt-relay or set HEARTWOOD_RELAYS')
  const fanout = new RelayFanout(relays)

  const roundTrip = (method, params, extra, deadlineMs) => new Promise((resolve, reject) => {
    const id = randomBytes(16).toString('hex')
    const timer = setTimeout(() => { off(); reject(new Error(`${method}: no answer within ${deadlineMs / 1000}s`)) }, deadlineMs)
    const off = fanout.on((data) => {
      let msg
      try { msg = JSON.parse(data.toString()) } catch { return }
      if (msg[0] !== 'EVENT' || msg[1] !== 'mgmt') return
      const e = msg[2]
      if (e.kind !== 24134 || e.pubkey !== master) return
      let inner
      try { inner = JSON.parse(nip44.v2.decrypt(e.content, ck)) } catch { return }
      if (inner.id !== id) return
      clearTimeout(timer)
      off()
      if (inner.error !== undefined) reject(new Error(`refused: ${inner.error}`))
      else resolve(inner.result)
    })
    fanout.send(['EVENT', finalizeEvent({
      kind: 24134,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', master]],
      content: nip44.v2.encrypt(JSON.stringify({ id, method, params, ...extra }), ck),
    }, sk)])
  })

  try {
    await fanout.open()
    // Ephemeral kind: the subscription must be up before anything is sent.
    fanout.req('mgmt', { kinds: [24134], authors: [master], '#p': [getPublicKey(sk)], limit: 0 })
    const { challenge } = await roundTrip('get_management_challenge', {}, {}, 20_000)
    const stop = startPressPrompt(`adding ${label} as an unlock phone`)
    try {
      return await roundTrip(
        'enrol_unlock_phone',
        { enrol_pubkey: enrolPubkey, label },
        { mutation_challenge: challenge },
        RELAY_ENROL_DEADLINE_MS,
      )
    } finally {
      stop()
    }
  } finally {
    fanout.close()
    sk.fill(0)
  }
}

/**
 * Enrol `enrolPubkey`, over the cable or (--over-relay) the relay. `ownKey`
 * is true when this script made the key (enrol), so it is the phone and its
 * words are the ones to compare; for enrol-for the real phone made it, and
 * the owner compares the board with that phone's screen.
 */
async function boardEnrol(enrolPubkey, label, { ownKey = false } = {}) {
  const words = requestCode(enrolPubkey)
  if (ownKey) {
    console.log(`\n    the board's card must read: ${words}\n    (this script is the phone here) hold only if it does\n`)
  } else {
    console.log(`\n    compare the board's card with the PHONE, not with this line: hold only if they match\n    (for convenience only: ${words})\n`)
  }
  if (OVER_RELAY) return relayEnrol(enrolPubkey, label)
  return usbCommand(
    { op: 'enrol', enrol_pubkey: enrolPubkey, label },
    45_000,
    { press: `adding ${label} as an unlock phone` },
  )
}

async function enrol() {
  const { getPublicKey, nip44 } = await relayDeps()
  const enrolSk = randomBytes(32)
  const enrolPk = getPublicKey(enrolSk)
  const label = arg('--label', 'bench phone')
  console.log(`enrolling "${label}"`)
  const answer = await boardEnrol(enrolPk, label, { ownKey: true })
  const ck = nip44.v2.utils.getConversationKey(enrolSk, answer.ephemeral_pubkey)
  const handoff = JSON.parse(nip44.v2.decrypt(answer.sealed, ck))
  enrolSk.fill(0)
  if (handoff.v !== 1 || handoff.id !== answer.id || !/^[0-9a-f]{64}$/.test(handoff.s)) {
    throw new Error('hand-off did not match the enrolment')
  }
  const state = loadState()
  state.phones = state.phones.filter((p) => p.id !== handoff.id)
  state.phones.push({ id: handoff.id, label, s: handoff.s, relays: handoff.relays, last: null })
  saveState(state)
  console.log(`enrolled as id ${handoff.id}; relays ${handoff.relays.join(', ')}`)
  console.log(`check code ${checkCode(answer.ephemeral_pubkey)} (the board shows the same after the press)`)
  console.log(`slot secret kept in ${STATE_FILE} (0600)`)
}

async function enrolFor() {
  const code = parseEnrolmentCode(arg('--code'))
  if (!code) {
    console.error("enrol-for needs --code '<heartwood-unlock:enrol?...>' as the phone shows it")
    exit(2)
  }
  const { finalizeEvent, RelayFanout } = await relayDeps()
  // Connect first: the hand-off is ephemeral, and the phone is already listening.
  const fanout = new RelayFanout(code.relays)
  const live = await fanout.open()
  console.log(`enrolling "${code.label}" for a phone waiting on ${live.length}/${code.relays.length} relay(s)`)
  const answer = await boardEnrol(code.enrolPubkey, code.label)
  const throwaway = randomBytes(32)
  const handoff = finalizeEvent({
    kind: HANDOFF_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['h', code.rendezvous]],
    content: JSON.stringify({ id: answer.id, ephemeral_pubkey: answer.ephemeral_pubkey, sealed: answer.sealed }),
  }, throwaway)
  throwaway.fill(0)
  const accepted = await new Promise((resolve) => {
    const seen = new Set()
    const timer = setTimeout(() => resolve([...seen]), 10_000)
    fanout.on((data, url) => {
      let msg
      try { msg = JSON.parse(data) } catch { return }
      if (msg[0] === 'OK' && msg[1] === handoff.id && msg[2] === true) {
        seen.add(url)
        if (seen.size === live.length) {
          clearTimeout(timer)
          resolve([...seen])
        }
      }
    })
    fanout.send(['EVENT', handoff])
  })
  fanout.close()
  if (!accepted.length) throw new Error(`board enrolled record ${answer.id}, but no relay accepted the hand-off; revoke it and retry`)
  console.log(`board record ${answer.id}; hand-off accepted by ${accepted.join(', ')}`)
  console.log(`\n    check code ${checkCode(answer.ephemeral_pubkey)}  (the phone must show the same six characters)\n`)
  console.log("the phone now asks for its screen lock to keep the key")
}

async function list() {
  const answer = await usbCommand({ op: 'list' }, 10_000)
  console.log(`${answer.phones.length}/${answer.max} phone(s); operator announcement ${answer.announce_operator ? 'on' : 'off'}`)
  const local = new Set(loadState().phones.map((p) => p.id))
  for (const p of answer.phones) {
    console.log(`  ${p.id}  ${p.label}${local.has(p.id) ? '  (this bench)' : ''}`)
  }
}

async function revoke() {
  const id = Number(arg('--id'))
  if (!Number.isInteger(id)) {
    console.error('revoke needs --id')
    exit(2)
  }
  await usbCommand({ op: 'revoke', id }, 10_000)
  const state = loadState()
  state.phones = state.phones.filter((p) => p.id !== id)
  saveState(state)
  console.log(`revoked ${id} on the board and forgot it here`)
}

async function announceOperator() {
  const value = argv[3]
  if (value !== 'on' && value !== 'off') {
    console.error('usage: node scripts/phone-unlock.mjs announce-operator on|off --port <port> --secret-file <path>')
    exit(2)
  }
  const answer = await usbCommand({ op: 'set_announce_operator', on: value === 'on' }, 10_000)
  console.log(`operator announcement ${answer.announce_operator ? 'on' : 'off'} (from the next locked boot)`)
}

/** Add a board's relay list to what this phone listens on, never dropping one. */
function followRelays(id, relays) {
  const state = loadState()
  const stored = state.phones.find((p) => p.id === id)
  if (!stored || !Array.isArray(relays)) return
  const merged = [...new Set([...stored.relays, ...relays.filter((r) => /^wss?:\/\/\S+$/.test(r))])]
  if (merged.length === stored.relays.length) return
  console.log(`  following the board to ${merged.filter((r) => !stored.relays.includes(r)).join(', ')}`)
  stored.relays = merged
  saveState(state)
}

async function listen() {
  const { finalizeEvent, nip44, RelayFanout } = await relayDeps()
  const state = loadState()
  if (!state.phones.length) {
    console.error(`no enrolled phone in ${STATE_FILE}; run enrol first`)
    exit(2)
  }
  const { phoneKey } = await import('./lib/phone-unlock.mjs')
  const phones = state.phones.map((p) => ({ ...p, k: phoneKey(Buffer.from(p.s, 'hex')) }))
  // The union of every relay the phone has been told about, plus any given.
  const extra = []
  argv.forEach((a, i) => { if (a === '--relay' && argv[i + 1]) extra.push(argv[i + 1]) })
  const relays = [...new Set([...phones.flatMap((p) => p.relays), ...extra])]
  const timeout = Number(arg('--timeout', '600000'))
  const assumeYes = argv.includes('--yes')

  const fanout = new RelayFanout(relays)
  const live = await fanout.open()
  console.log(`listening on ${live.length}/${relays.length} relay(s) for any lock announcement`)
  // No #p, no #h: the relay learns only that this client reads 24135s.
  fanout.req('locks', { kinds: [ANNOUNCE_KIND], limit: 0 })

  const found = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeout)
    const seen = new Set()
    fanout.on((data) => {
      let msg
      try { msg = JSON.parse(data) } catch { return }
      if (msg[0] !== 'EVENT' || msg[1] !== 'locks') return
      const ev = msg[2]
      if (ev.kind !== ANNOUNCE_KIND || seen.has(ev.id)) return
      seen.add(ev.id)
      const h = ev.tags.find((t) => t[0] === 'h')?.[1]
      if (!h || !/^[0-9a-f]{64}$/.test(ev.pubkey)) return
      const author = Buffer.from(ev.pubkey, 'hex')
      for (const phone of phones) {
        if (!hintMatches(phone.k, author, h)) continue
        const context = openContext(phone.k, author, ev.content)
        if (!context || context.id !== phone.id) continue
        const now = Math.floor(Date.now() / 1000)
        const verdict = judge(context, ev.pubkey, ev.created_at, now, phone.last)
        // Follow the board's relays from any message it opens, whatever the
        // verdict, as Cambium does. A relay update (t = "relays") exists only
        // to carry them.
        followRelays(phone.id, context.relays)
        if (verdict !== 'prompt') {
          const what = context.t === 'relays' ? 'relay update' : verdict
          console.log(`  ${what}: restart #${context.boot}, relays ${context.relays.join(', ')} (${now - ev.created_at}s old)`)
          continue
        }
        clearTimeout(timer)
        resolve({ ev, phone, context })
      }
    })
  })
  if (!found) {
    console.error(`no announcement for an enrolled phone within ${timeout / 1000}s`)
    fanout.close()
    exit(1)
  }

  const { ev, phone, context } = found
  const network = context.ssid ? `${context.ssid}${context.bssid ? ` ${context.bssid}` : ''}` : 'unknown network'
  console.log(`\nHeartwood restarted (${context.reset}, ${network}, restart #${context.boot}, firmware ${context.fw}).`)
  console.log('This also appears if someone else powers it on. Only unlock if you expect it.')
  if (!assumeYes) {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    const answer = await rl.question(`Unlock as "${phone.label}"? [y/N] `)
    rl.close()
    if (!/^y(es)?$/i.test(answer.trim())) {
      console.log('Declined; nothing sent.')
      fanout.close()
      exit(1)
    }
  }

  // A fresh throwaway author every time: the phone has no stable key on the wire.
  const throwaway = randomBytes(32)
  const ck = nip44.v2.utils.getConversationKey(throwaway, ev.pubkey)
  const delivery = finalizeEvent({
    kind: DELIVERY_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', ev.pubkey]],
    content: nip44.v2.encrypt(deliveryJson(phone.id, Buffer.from(phone.s, 'hex')), ck),
  }, throwaway)
  throwaway.fill(0)
  // The board listens on the relays its announcement lists, which after a
  // relay change are not the ones this listener opened. Deliver there too,
  // as Cambium does.
  const listed = context.relays.filter((r) => /^wss?:\/\/\S+$/.test(r) && !live.includes(r))
  let listedFanout = null
  if (listed.length) {
    listedFanout = new RelayFanout(listed)
    try {
      await listedFanout.open()
    } catch {
      listedFanout = null
    }
  }
  fanout.send(['EVENT', delivery])
  listedFanout?.send(['EVENT', delivery])
  const reached = live.length + (listedFanout?.sockets.length ?? 0)
  console.log(`delivery published to ${reached} relay(s); the board says "Unlocked by" on its screen`)

  const state2 = loadState()
  const stored = state2.phones.find((p) => p.id === phone.id)
  if (stored) {
    stored.last = { boot: context.boot, author: ev.pubkey }
    saveState(state2)
  }
  setTimeout(() => { fanout.close(); listedFanout?.close(); exit(0) }, 3000)
}

const commands = { enrol, 'enrol-for': enrolFor, list, revoke, listen, 'announce-operator': announceOperator }
if (!commands[COMMAND]) {
  console.error('usage: node scripts/phone-unlock.mjs {enrol|enrol-for|list|revoke|announce-operator|listen} ...')
  exit(2)
}
try {
  await commands[COMMAND]()
} catch (error) {
  console.error(error.message)
  exit(1)
}
