#!/usr/bin/env node
// scripts/phone-unlock.mjs
//
// A bench stand-in for Cambium, so phone unlock can be proved on hardware
// before the Android side exists (docs/specs/2026-09-24-phone-unlock-design.md).
//
//   enrol    over USB: make a one-off enrolment key P, send PHONE_UNLOCK_CMD
//            (0x64) {op:"enrol"}, press on the board, open the sealed
//            hand-off with P, and keep {id, s, relays} in the state file.
//   list     over USB: the board's enrolled phones.
//   revoke   over USB: remove one (--id), and forget it locally.
//   listen   over the relays, as the phone: subscribe to EVERY kind-24135
//            with no #p or #h filter, match the per-boot hint locally, open
//            the sealed context, apply the prompt rule, and on a yes answer
//            with a kind-24136 from a fresh throwaway key.
//
// The state file holds slot secrets, which unlock the board together with
// its flash. It is written 0600, and nothing here prints a secret.
//
// Usage:
//   node scripts/phone-unlock.mjs enrol  --port <port> --secret-file <bridge.secret> [--label "bench phone"]
//   node scripts/phone-unlock.mjs list   --port <port> --secret-file <bridge.secret>
//   node scripts/phone-unlock.mjs revoke --port <port> --secret-file <bridge.secret> --id <id>
//   node scripts/phone-unlock.mjs listen [--relay wss://...] [--timeout 600000] [--yes]
//   [--state ~/heartwood-bench/phones.json]

import { argv, env, exit } from 'node:process'
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline/promises'

import { NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { authenticateSession } from './lib/session-auth.mjs'
import {
  ANNOUNCE_KIND,
  DELIVERY_KIND,
  deliveryJson,
  hintMatches,
  judge,
  openContext,
} from './lib/phone-unlock.mjs'

const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
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

async function usbCommand(command, deadlineMs) {
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
  const reply = await session.request(
    PHONE_UNLOCK_CMD,
    [PHONE_UNLOCK_RESP, NACK],
    { payload: Buffer.from(JSON.stringify(command)), deadlineMs },
  )
  session.close()
  if (!reply) throw new Error(`no answer within ${deadlineMs / 1000}s`)
  if (reply.type === NACK) throw new Error(`refused: ${reply.payload.toString() || 'no reason'}`)
  return JSON.parse(reply.payload.toString())
}

async function relayDeps() {
  return import('./relay-deps.mjs')
}

async function enrol() {
  const { getPublicKey, nip44 } = await relayDeps()
  const enrolSk = randomBytes(32)
  const enrolPk = getPublicKey(enrolSk)
  const label = arg('--label', 'bench phone')
  console.log(`enrolling "${label}": press and hold on the board when it asks`)
  const answer = await usbCommand({ op: 'enrol', enrol_pubkey: enrolPk, label }, 60_000)
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
  console.log(`slot secret kept in ${STATE_FILE} (0600)`)
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
        if (verdict !== 'prompt') {
          console.log(`  ${verdict}: restart #${context.boot} (${now - ev.created_at}s old)`)
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
  fanout.send(['EVENT', delivery])
  console.log(`delivery published to ${live.length} relay(s); the board says "Unlocked by" on its screen`)

  const state2 = loadState()
  const stored = state2.phones.find((p) => p.id === phone.id)
  if (stored) {
    stored.last = { boot: context.boot, author: ev.pubkey }
    // Follow relay changes carried in the lock message.
    stored.relays = [...new Set([...stored.relays, ...context.relays])]
    saveState(state2)
  }
  setTimeout(() => { fanout.close(); exit(0) }, 3000)
}

const commands = { enrol, list, revoke, listen }
if (!commands[COMMAND]) {
  console.error('usage: node scripts/phone-unlock.mjs {enrol|list|revoke|listen} ...')
  exit(2)
}
try {
  await commands[COMMAND]()
} catch (error) {
  console.error(error.message)
  exit(1)
}
