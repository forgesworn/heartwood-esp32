#!/usr/bin/env node
// scripts/bench-approval-cards.mjs
//
// Machine-driven half of hardware checklist section 12 — the non-blocking
// approval cards (#64). Everything here runs without touching the board,
// because every assertion is about what the signer does while a card is up,
// or about how it answers a card nobody presses.
//
//   node scripts/bench-approval-cards.mjs --master <hex|npub> [--only <phase>]
//   [--port /dev/cu.usbmodemXXXX] [--relay wss://...] [--key-file <operator.key>]
//   [--keep-slot] [--window 30]
//
// Phases (checklist step in brackets):
//   setup      mint a disposable button-required slot and connect a client
//   usb    [1] the cable answers while a card is on screen
//   relay  [2] another client is served while a card is on screen
//   refuse[16] a USB signing request is refused, not painted over the card
//   expiry [6] an unanswered card expires and answers `timeout`
//   stamp [14] that late answer is stamped for when it was sent
//   batch[8,9] three same-kind asks share one card and are answered together
//   queue [10] a second client waits its turn rather than being answered wrongly
//   busy  [11] past the caps, an ask is refused instead of held
//   cleanup    revoke the disposable slot
//
// The button steps (3-5, 7, 12, 13) and the T-Display pass (15) are NOT here:
// they need a finger on the device. Run those from the checklist by hand.
//
// Every phase that raises a card costs a full window (30 s by default) because
// the card is deliberately left to expire, so a whole run takes a few minutes.

import { argv, env, exit } from 'node:process'
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  WebSocket,
  finalizeEvent,
  getPublicKey,
  nip44,
  arg,
  toHex,
  DEFAULT_RELAY,
} from './relay-deps.mjs'

const RELAY = arg(argv, '--relay', DEFAULT_RELAY)
const KEY_FILE = arg(argv, '--key-file', `${env.HOME}/heartwood-bench/operator.key`)
const PORT = arg(argv, '--port', '/dev/cu.usbmodem3401')
const MASTER_ARG = arg(argv, '--master', env.HEARTWOOD_MASTER)
const ONLY = arg(argv, '--only')
const WINDOW = Number(arg(argv, '--window', '30'))
const KEEP_SLOT = argv.includes('--keep-slot')

if (!MASTER_ARG) {
  console.error(
    'usage: node scripts/bench-approval-cards.mjs --master <hex|npub> [--only <phase>]',
  )
  exit(2)
}
const MASTER = toHex(MASTER_ARG, '--master')
const SCRATCH = mkdtempSync(join(tmpdir(), 'heartwood-cards-'))

const results = []
const record = (step, name, ok, detail) => {
  results.push({ step, name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${step}] ${name}${detail ? ` — ${detail}` : ''}`)
}
const note = (msg) => console.log(`      ${msg}`)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------------------------------------------------------------------------
// Operator channel (kind 24134)
// ---------------------------------------------------------------------------

const opSk = Uint8Array.from(Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'hex'))
const opPub = getPublicKey(opSk)
const opCk = nip44.v2.utils.getConversationKey(opSk, MASTER)

let mgmtWs
function openMgmt() {
  return new Promise((resolve, reject) => {
    mgmtWs = new WebSocket(RELAY)
    mgmtWs.on('error', reject)
    mgmtWs.on('open', () => {
      mgmtWs.send(
        JSON.stringify([
          'REQ',
          'mgmt',
          { kinds: [24134], authors: [MASTER], '#p': [opPub], limit: 0 },
        ]),
      )
      resolve()
    })
  })
}

function mgmt(method, params = {}, extra = {}, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const id = randomBytes(8).toString('hex')
    const ev = finalizeEvent(
      {
        kind: 24134,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', MASTER]],
        content: nip44.v2.encrypt(JSON.stringify({ id, method, params, ...extra }), opCk),
      },
      opSk,
    )
    const timer = setTimeout(() => {
      mgmtWs.removeListener('message', onMessage)
      reject(new Error(`mgmt ${method}: timeout`))
    }, timeoutMs)
    const onMessage = (data) => {
      let msg
      try {
        msg = JSON.parse(data.toString())
      } catch {
        return
      }
      if (msg[0] !== 'EVENT' || msg[1] !== 'mgmt') return
      const e = msg[2]
      if (e.kind !== 24134 || e.pubkey !== MASTER) return
      let inner
      try {
        inner = JSON.parse(nip44.v2.decrypt(e.content, opCk))
      } catch {
        return
      }
      if (inner.id !== id) return
      clearTimeout(timer)
      mgmtWs.removeListener('message', onMessage)
      if (inner.error !== undefined) reject(new Error(inner.error))
      else resolve(inner.result)
    }
    mgmtWs.on('message', onMessage)
    mgmtWs.send(JSON.stringify(['EVENT', ev]))
  })
}

/** Mutating methods are challenge-gated; fetch and attach one per call. */
async function mgmtMutate(method, params) {
  const { challenge } = await mgmt('get_management_challenge', {})
  return mgmt(method, params, { mutation_challenge: challenge })
}

// ---------------------------------------------------------------------------
// NIP-46 clients (kind 24133)
// ---------------------------------------------------------------------------

/** A bench client with its own key and its own relay socket. */
class Client {
  constructor(name, targetHex) {
    this.name = name
    this.target = targetHex
    this.sk = Uint8Array.from(randomBytes(32))
    this.pub = getPublicKey(this.sk)
    this.ck = nip44.v2.utils.getConversationKey(this.sk, targetHex)
    this.pending = new Map()
  }

  open() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(RELAY)
      this.ws.on('error', reject)
      this.ws.on('message', (data) => {
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
          inner = JSON.parse(nip44.v2.decrypt(e.content, this.ck))
        } catch {
          return
        }
        const waiter = this.pending.get(inner.id)
        if (!waiter) return
        this.pending.delete(inner.id)
        waiter({ ...inner, at: Date.now(), created_at: e.created_at })
      })
      this.ws.on('open', () => {
        this.ws.send(
          JSON.stringify([
            'REQ',
            'c',
            { kinds: [24133], authors: [this.target], '#p': [this.pub], limit: 0 },
          ]),
        )
        resolve()
      })
    })
  }

  /** Publish one request; resolves with the answer whenever it arrives.
   *  `settled` is the answer as soon as one lands, so a caller can ask
   *  "is this still waiting?" without racing a timer — which is how the
   *  card phases know a card is genuinely on screen. */
  send(method, params) {
    const id = randomBytes(8).toString('hex')
    const sentAt = Math.floor(Date.now() / 1000)
    const ev = finalizeEvent(
      {
        kind: 24133,
        created_at: sentAt,
        tags: [['p', this.target]],
        content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), this.ck),
      },
      this.sk,
    )
    const ask = { id, sentAt, eventId: ev.id, settled: null }
    ask.answered = new Promise((resolve) =>
      this.pending.set(id, (answer) => {
        ask.settled = answer
        resolve(answer)
      }),
    )
    this.ws.send(JSON.stringify(['EVENT', ev]))
    return ask
  }

  close() {
    this.ws?.close()
  }
}

/** The firmware's per-card batch cap (common/src/approval_queue.rs). Kept
 *  here as a constant rather than read from the device: get_status does not
 *  report it, and the phase only needs to push a little past it. */
const heartwoodMaxBatch = () => 8

/** A note template the disposable slot's policy admits. */
const noteTemplate = (text) =>
  JSON.stringify({
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: text,
  })

/** Resolve when `p` settles, or `null` when `ms` elapses first. */
const within = (p, ms) =>
  Promise.race([p, new Promise((r) => setTimeout(() => r(null), ms))])

// ---------------------------------------------------------------------------
// USB probes (subprocess, so the serial handling stays in one place)
// ---------------------------------------------------------------------------

function run(script, args, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now()
    execFile(
      'node',
      [new URL(script, import.meta.url).pathname, ...args],
      { timeout: timeoutMs },
      (error, stdout, stderr) => {
        resolve({
          ok: !error,
          elapsed: Date.now() - started,
          stdout: stdout ?? '',
          stderr: stderr ?? '',
        })
      },
    )
  })
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

let slotIndex = null
let slotFingerprint = null
let client = null
/** Extra slots minted mid-run (e.g. the second client), revoked at the end. */
const extraSlots = []

/** Mint a TOFU slot and bind a fresh client to it.
 *
 * A client that has NOT done this is refused outright as an unknown client,
 * so it never reaches an approval card — which made the queue check pass
 * against both firmwares while testing nothing. Anything that has to wait
 * its turn for the button must be properly bound first.
 */
async function mintBoundClient(name) {
  const created = await mgmtMutate('create_client', {
    label: `card-bench-${name}-${randomBytes(2).toString('hex')}`,
  })
  if (created.signing_approved !== false) {
    throw new Error('minted slot is already signing-approved')
  }
  const target = created.npub_hex ?? MASTER
  const c = new Client(name, target)
  await c.open()
  const connected = await within(c.send('connect', [target, created.secret ?? '']).answered, 20000)
  if (!connected || connected.error) {
    throw new Error(`connect failed for ${name}: ${connected?.error ?? 'timeout'}`)
  }
  return {
    client: c,
    target,
    slotIndex: created.slot_index,
    fingerprint: created.secret_fingerprint,
  }
}

/** Mint a slot that needs the button: in-ceiling kind, auto_approve false. */
async function setup() {
  const status = await mgmt('get_status', {})
  note(`device ${status.board} ${status.version ?? ''} mode=${status.mode}`)
  if (!status.capabilities?.includes('client_policy_v2')) {
    throw new Error('device does not advertise client_policy_v2')
  }

  const label = `card-bench-${randomBytes(2).toString('hex')}`
  // A legacy TOFU slot, deliberately, NOT create_client_v2: naming sign_event
  // in an operator-installed exact policy IS the operator approving it, so a
  // v2 slot answers "signing pre-approved by operator" and auto-signs. That
  // raises no card at all, and every liveness probe below would then pass
  // against a signer that never stopped. A v1 slot's first sign_event needs
  // the button, and stays that way as long as nobody presses it.
  const created = await mgmtMutate('create_client', { label })
  if (created.signing_approved !== false) {
    throw new Error(
      `minted slot is already signing-approved (${created.note ?? 'no note'}); ` +
        'these phases need a slot whose first sign_event stops for the button',
    )
  }
  slotIndex = created.slot_index
  // revoke_client is fingerprint-gated, so keep the one the mint handed back.
  slotFingerprint = created.secret_fingerprint
  note(`minted slot ${slotIndex} (${label})`)

  const targetHex = created.npub_hex ?? MASTER
  client = new Client('A', targetHex)
  await client.open()
  const connected = await within(
    client.send('connect', [targetHex, created.secret ?? '']).answered,
    20000,
  )
  if (!connected || connected.error) {
    throw new Error(`connect failed: ${connected?.error ?? 'timeout'}`)
  }
  note(`client A bound (${client.pub.slice(0, 8)}…)`)
  return targetHex
}

/** Raise a card and leave it up. Returns the in-flight ask. */
function raiseCard(c = client) {
  return c.send('sign_event', [noteTemplate('approval card bench')])
}

/** Refuse to run if anything answers a card these phases need left alone.
 *
 * Every machine-driven phase below measures what the signer does with a card
 * NOBODY answers, so one approval makes the run meaningless — and green.
 * Worse on pre-#64 firmware, where the first approved sign_event upgrades the
 * slot (TOFU) and the rest of a burst then auto-signs and lands together,
 * which is exactly what the batch-collapse check looks for.
 *
 * Two things answer a card: a helpful operator watching the desk, and a
 * button held down (a stuck switch, or a host pinning GPIO 0). Both look
 * identical from here, so this names both rather than guessing — guessing
 * wrong cost this bench a false hardware finding on 2026-08-16.
 */
async function assertNothingAnswersCards() {
  const ask = raiseCard()
  const answer = await within(ask.answered, 12000)
  if (answer && !answer.error) {
    throw new Error(
      'a card was APPROVED during the pre-flight. If that was you at the ' +
        'desk, leave this run alone — every phase here needs cards nobody ' +
        'answers. If nobody touched it, the button is being held down ' +
        '(stuck switch, or something resting on the board).',
    )
  }
  if (answer?.error) {
    note(`pre-flight ask answered "${answer.error}" — no card was raised`)
    return
  }
  note('pre-flight: card is up and unanswered, as these phases need')
  // Let it expire so the phases start from a clear screen.
  await within(ask.answered, (WINDOW + 20) * 1000)
}

/** Refuse to judge a "while a card is up" step when no card is up. Without
 *  this an ask that was answered outright — auto-approved, or refused before
 *  it ever reached the button — makes every liveness probe pass trivially,
 *  which is the one way this harness could report green on a broken signer. */
function cardUp(step, name, ask) {
  if (!ask.settled) return true
  record(step, name, false, `no card was raised: the ask answered "${ask.settled.error ?? 'ok'}"`)
  return false
}

/** How quick counts as "served". A blocked signer answers only when its
 *  window ends, so anything near the window is a fail however it is dressed. */
const PROMPT_MS = 6000

/** Probe repeatedly for as long as the ask is outstanding, and judge the
 *  worst case. A single probe cannot tell a live signer from one that had not
 *  yet raised the card when the probe ran — this way at least one probe is
 *  guaranteed to land in the middle of the card. */
async function probeThroughout(ask, probe) {
  const samples = []
  const deadline = Date.now() + (WINDOW + 15) * 1000
  while (!ask.settled && Date.now() < deadline) {
    const result = await probe()
    // Only samples that finished while the ask was still outstanding say
    // anything about being served *under a card*.
    if (!ask.settled) samples.push(result)
    else break
    await sleep(1500)
  }
  return samples
}

function judgeProbes(step, name, samples, ask) {
  const worst = samples.length ? Math.max(...samples.map((s) => s.elapsed)) : null
  const ok =
    samples.length >= 3 && samples.every((s) => s.ok && s.elapsed < PROMPT_MS)
  const why = ask?.settled
    ? `the card resolved first ("${ask.settled.error ?? 'ok'}") — a probe that slow outlasts the card`
    : 'the card outlasted every probe attempt'
  record(
    step,
    name,
    ok,
    samples.length
      ? `${samples.length} probes under the card, worst ${worst} ms (want < ${PROMPT_MS})`
      : `no probe landed while the card was up: ${why}`,
  )
}

async function phaseUsb(ask) {
  await sleep(2000)
  if (!cardUp(1, 'cable answers throughout a card', ask)) return ask
  const samples = await probeThroughout(ask, () =>
    run('./device-status.mjs', ['--port', PORT], 25000),
  )
  judgeProbes(1, 'cable answers throughout a card', samples, ask)
  return ask
}

async function phaseRelay(targetHex, ask) {
  // Another client asking for something that needs no authority: if the loop
  // is alive under the card, this is answered straight away.
  await sleep(2000)
  if (!cardUp(2, 'relay is served throughout a card', ask)) return ask
  const other = new Client('probe', targetHex)
  await other.open()
  const samples = await probeThroughout(ask, async () => {
    const started = Date.now()
    const answer = await within(other.send('get_public_key', []).answered, PROMPT_MS * 2)
    return { ok: answer !== null, elapsed: Date.now() - started }
  })
  judgeProbes(2, 'relay is served throughout a card', samples, ask)
  other.close()
  return ask
}

// Relies on the device being unlocked, which getting this far already proves:
// the relay only answers an unlocked signer. That matters because nip46-sign
// authenticates the bridge when it finds a locked device, and the plaintext
// USB path NACKs while bridge-authenticated — which would look exactly like
// the refusal being tested here.
async function phaseRefuse(ask) {
  if (!cardUp(16, 'USB signing is refused, not painted over the card', ask)) return ask
  const probe = await run(
    './nip46-sign.mjs',
    ['--port', PORT, '--kind', '1', '--content', 'usb under a card'],
    25000,
  )
  const refused = /approval on screen/i.test(probe.stdout + probe.stderr)
  record(
    16,
    'USB signing is refused, not painted over the card',
    refused,
    refused ? 'NACK "approval on screen"' : 'no such refusal seen (see note)',
  )
  if (!refused) {
    note('a device without the #64 firmware simply blocks here instead')
  }
  return ask
}

async function phaseExpiry(ask) {
  const started = Date.now()
  const answer = await within(ask.answered, (WINDOW + 20) * 1000)
  const elapsed = answer ? Math.round((answer.at - started) / 1000) : null
  record(
    6,
    'an unanswered card expires and answers',
    Boolean(answer?.error),
    answer ? `${answer.error ?? 'no error field'} after ~${elapsed} s` : 'never answered',
  )
  return answer
}

function phaseStamp(ask, answer) {
  if (!answer) {
    record(14, 'the late answer is stamped for when it was sent', false, 'no answer to check')
    return
  }
  const drift = answer.created_at - ask.sentAt
  // The reply is published a whole window after the ask arrived. Before #64 it
  // echoed the request's own created_at, so this drift was 0.
  const ok = drift >= WINDOW - 5
  record(
    14,
    'the late answer is stamped for when it was sent',
    ok,
    `reply created_at is ${drift} s after the request (want >= ${WINDOW - 5})`,
  )
}

async function phaseBatch() {
  const asks = [raiseCard(), raiseCard(), raiseCard()]
  // Long enough for the FAILING shape as well as the passing one: collapsed
  // onto one card these answer together in a single window, but serialised —
  // which is what the fix removes — they take one window each. Waiting only
  // for the passing shape reports "not all answered", which says nothing
  // about how far apart they were.
  const answers = await Promise.all(
    asks.map((a) => within(a.answered, (WINDOW * asks.length + 30) * 1000)),
  )
  const all = answers.every(Boolean)
  const spread = all ? Math.max(...answers.map((a) => a.at)) - Math.min(...answers.map((a) => a.at)) : null
  // Collapsed onto one card, all three are answered by the one expiry — so
  // they land together. Serialised windows would be a window apart.
  const ok = all && spread < 5000
  record(
    8,
    'three same-kind asks share one card',
    ok,
    all ? `answers ${spread} ms apart` : 'not all answered',
  )
  record(
    9,
    'one expiry answers the whole batch',
    ok && answers.every((a) => a.error),
    all ? answers.map((a) => a.error ?? 'ok').join(', ') : 'not all answered',
  )
}

async function phaseQueue() {
  // B needs a slot of its own, or it is refused as an unknown client and
  // never reaches a card at all.
  const b = await mintBoundClient('B')
  extraSlots.push({ slotIndex: b.slotIndex, fingerprint: b.fingerprint })

  const a = raiseCard()
  await sleep(2000)
  const bAsk = b.client.send('sign_event', [noteTemplate('second client')])
  const [aAnswer, bAnswer] = await Promise.all([
    within(a.answered, (WINDOW * 3 + 30) * 1000),
    within(bAsk.answered, (WINDOW * 3 + 30) * 1000),
  ])
  const gap = aAnswer && bAnswer ? Math.round((bAnswer.at - aAnswer.at) / 1000) : null
  // B must not be answered while A's card is still up — that would mean its
  // decision was taken without ever being shown — and must then get a window
  // of its own rather than being swept up in A's.
  const ok = Boolean(aAnswer && bAnswer && bAnswer.at > aAnswer.at)
  record(
    10,
    'a second client waits its turn',
    ok,
    aAnswer && bAnswer
      ? `A "${aAnswer.error ?? 'ok'}", then B "${bAnswer.error ?? 'ok'}" ${gap} s later`
      : 'one of them never answered',
  )
  b.client.close()
}

async function phaseBusy() {
  // Past the batch cap (8) the next ask must be refused rather than queued.
  //
  // Probe with a small wave first. A signer that queues rather than refuses
  // gives every one of these a window of its own, so sending the full ten at
  // a device without the fix locks it up for five minutes and takes the
  // cleanup down with it. Three is enough to tell the two apart.
  const asks = Array.from({ length: 3 }, () => raiseCard())
  const probe = await Promise.all(asks.map((a) => within(a.answered, 20000)))
  if (!probe.some(Boolean)) {
    record(
      11,
      'past the caps an ask is refused, not held',
      false,
      'the first three asks were all queued, none answered — this signer ' +
        'holds them rather than refusing, so the caps were not reached',
    )
  } else {
    // Something is answering promptly, so it is safe to push to the cap.
    while (asks.length < heartwoodMaxBatch() + 2) asks.push(raiseCard())
    const answers = await Promise.all(asks.map((a) => within(a.answered, 20000)))
    const busy = answers.filter((a) => a?.error && /busy/i.test(a.error))
    record(
      11,
      'past the caps an ask is refused, not held',
      busy.length > 0,
      `${busy.length} of ${asks.length} answered busy promptly`,
    )
  }
  // Drain before handing back. On a signer that queues these instead of
  // refusing them — which is the whole point of the check, and what pre-#64
  // firmware does — they run a window EACH, so this is minutes, not one
  // window. Leaving early only moves the problem: the operator channel is
  // unanswered while the signer works through them, so cleanup then fails
  // and strands the slot (seen on the bench 2026-08-16).
  const drain = (WINDOW * asks.length + 60) * 1000
  const outstanding = asks.filter((a) => !a.settled).length
  if (outstanding) {
    note(`waiting out ${outstanding} unanswered ask(s) before cleanup`)
  }
  await Promise.all(asks.map((a) => within(a.answered, drain)))
}

/** Revoke one slot, retrying while the signer is busy with a card. */
async function revokeSlot(index, fingerprint) {
  for (const attempt of [1, 2, 3]) {
    try {
      await mgmtMutate('revoke_client', {
        slot_index: index,
        expected_secret_fingerprint: fingerprint,
      })
      note(`slot ${index} revoked`)
      return
    } catch (e) {
      if (attempt === 3) {
        note(
          `could not revoke slot ${index} after ${attempt} attempts (${e.message}). ` +
            `Revoke it by hand: scripts/mgmt-request.mjs --method revoke_client ` +
            `--challenge --params '{"slot_index":${index},` +
            `"expected_secret_fingerprint":"${fingerprint}"}'`,
        )
        return
      }
      note(`revoke attempt ${attempt} failed (${e.message}); waiting for the signer`)
      await sleep((WINDOW + 5) * 1000)
    }
  }
}

async function cleanup() {
  for (const extra of extraSlots.splice(0)) {
    if (!KEEP_SLOT) await revokeSlot(extra.slotIndex, extra.fingerprint)
  }
  if (slotIndex === null || KEEP_SLOT) {
    if (KEEP_SLOT) note(`slot ${slotIndex} kept (--keep-slot)`)
    return
  }
  // The operator channel goes unanswered while a card owns a blocked signer,
  // so a cleanup straight after a phase can time out and strand the slot.
  // Retry with room for a whole window to drain first.
  for (const attempt of [1, 2, 3]) {
    try {
      await mgmtMutate('revoke_client', {
        slot_index: slotIndex,
        expected_secret_fingerprint: slotFingerprint,
      })
      note(`slot ${slotIndex} revoked`)
      return
    } catch (e) {
      if (attempt === 3) {
        note(
          `could not revoke slot ${slotIndex} after ${attempt} attempts (${e.message}). ` +
            `Revoke it by hand: scripts/mgmt-request.mjs --method revoke_client ` +
            `--challenge --params '{"slot_index":${slotIndex},` +
            `"expected_secret_fingerprint":"${slotFingerprint}"}'`,
        )
        return
      }
      note(`revoke attempt ${attempt} failed (${e.message}); waiting for the signer`)
      await sleep((WINDOW + 5) * 1000)
    }
  }
}

// ---------------------------------------------------------------------------

const wanted = (name) => !ONLY || ONLY === name

try {
  await openMgmt()
  const targetHex = await setup()
  await assertNothingAnswersCards()

  // A card each: the liveness probes run for as long as their card is up, so
  // they cannot share one. Each phase leaves its card expired behind it.
  if (wanted('usb')) {
    const ask = raiseCard()
    await phaseUsb(ask)
    await within(ask.answered, (WINDOW + 20) * 1000)
  }
  if (wanted('relay')) {
    const ask = raiseCard()
    await phaseRelay(targetHex, ask)
    await within(ask.answered, (WINDOW + 20) * 1000)
  }
  if (wanted('refuse')) {
    const ask = raiseCard()
    await sleep(2000)
    await phaseRefuse(ask)
    await within(ask.answered, (WINDOW + 20) * 1000)
  }
  if (wanted('expiry') || wanted('stamp')) {
    const ask = raiseCard()
    const answer = await phaseExpiry(ask)
    if (wanted('stamp')) phaseStamp(ask, answer)
  }
  if (wanted('batch')) await phaseBatch()
  if (wanted('queue')) await phaseQueue()
  if (wanted('busy')) await phaseBusy()

  await cleanup()
} catch (e) {
  console.error(`\nbench aborted: ${e.message}`)
  await cleanup()
  client?.close()
  mgmtWs?.close()
  exit(1)
}

client?.close()
mgmtWs?.close()

const failed = results.filter((r) => !r.ok)
console.log(
  `\n${results.length - failed.length}/${results.length} machine-checkable steps passed`,
)
console.log(
  'Button steps 3-5, 7, 12, 13 and the T-Display pass (15) still need a desk session.',
)
writeFileSync(join(SCRATCH, 'results.json'), JSON.stringify(results, null, 2))
console.log(`results: ${join(SCRATCH, 'results.json')}`)
exit(failed.length ? 1 : 0)
