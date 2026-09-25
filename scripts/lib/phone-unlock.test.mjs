import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  deliveryJson,
  hint,
  hintMatches,
  judge,
  openContext,
  checkCode,
  requestCode,
  parseEnrolmentCode,
  phoneKey,
  sealContext,
} from './phone-unlock.mjs'

const fixture = JSON.parse(
  readFileSync(new URL('../../common/tests/fixtures/phone-unlock-v1.json', import.meta.url), 'utf8'),
)
const hex = (s) => Buffer.from(s, 'hex')
const S = hex(fixture.slot_secret)
const AUTHOR = hex(fixture.author)

// LockContext's field order, which is what the board serialises.
const ordered = (c) => ({
  v: c.v, t: c.t, id: c.id, boot: c.boot, reset: c.reset,
  ssid: c.ssid, bssid: c.bssid, fw: c.fw, relays: c.relays,
})

test('matches the Rust vectors', () => {
  const k = phoneKey(S)
  assert.equal(k.toString('hex'), fixture.phone_key)
  assert.equal(hint(k, AUTHOR), fixture.hint)
  assert.ok(hintMatches(k, AUTHOR, fixture.hint))
  assert.deepEqual(openContext(k, AUTHOR, fixture.content), fixture.context)
  assert.equal(sealContext(k, AUTHOR, ordered(fixture.context), hex(fixture.nonce)), fixture.content)
  assert.equal(deliveryJson(fixture.context.id, S), fixture.delivery)
})

test('a relay update opens like a lock announcement and never prompts', () => {
  const update = JSON.parse(
    readFileSync(new URL('../../common/tests/fixtures/phone-unlock-v1-relays.json', import.meta.url), 'utf8'),
  )
  const k = phoneKey(hex(update.slot_secret))
  const author = hex(update.author)
  assert.ok(hintMatches(k, author, update.hint))
  const context = openContext(k, author, update.content)
  assert.deepEqual(context, update.context)
  assert.equal(context.t, 'relays')
  assert.equal(sealContext(k, author, ordered(update.context), hex(update.nonce)), update.content)
  assert.equal(update.content.length, fixture.content.length, 'same size as the lock announcement')
  const now = 1_800_000_000
  assert.equal(judge(context, update.author, now, now, null), 'not-locked')
  assert.equal(judge(context, update.author, now, now, { boot: 1, author: update.author }), 'not-locked')
})

test('refuses another phone, another author and any tampering', () => {
  const k = phoneKey(S)
  const other = phoneKey(Buffer.alloc(32, 1))
  assert.equal(openContext(other, AUTHOR, fixture.content), null)
  assert.equal(openContext(k, Buffer.alloc(32, 9), fixture.content), null)
  assert.ok(!hintMatches(other, AUTHOR, fixture.hint))
  const raw = Buffer.from(fixture.content, 'base64')
  for (let i = 0; i < raw.length; i++) {
    raw[i] ^= 1
    assert.equal(openContext(k, AUTHOR, raw.toString('base64')), null, `flip at ${i}`)
    raw[i] ^= 1
  }
  assert.equal(openContext(k, AUTHOR, 'not base64!'), null)
})

test('the prompt rule', () => {
  const c = fixture.context
  const a = fixture.author
  const b = '08'.repeat(32)
  const now = 1_800_000_000
  assert.equal(judge(c, a, now, now, null), 'prompt')
  assert.equal(judge(c, a, now - 121, now, null), 'stale')
  assert.equal(judge(c, a, now + 61, now, null), 'stale')
  assert.equal(judge(c, a, now, now, { boot: 212, author: a }), 'duplicate')
  assert.equal(judge(c, a, now, now, { boot: 212, author: b }), 'prompt')
  assert.equal(judge(c, a, now, now, { boot: 213, author: a }), 'replay')
  assert.equal(judge({ ...c, t: 'relays' }, a, now, now, null), 'not-locked')
})

test('reads the enrolment code Cambium shows', () => {
  // The exact string Cambium's EnrolmentCodeTest pins, so the two stay in step.
  const p = 'ab'.repeat(32)
  const r = 'cd'.repeat(16)
  const code = `heartwood-unlock:enrol?v=1&p=${p}&r=${r}&label=Pixel+8+Pro&relay=wss%3A%2F%2Frelay.example` +
    '&relay=wss%3A%2F%2Ftwo.example%2Fpath%3Fx%3D1'
  assert.deepEqual(parseEnrolmentCode(code), {
    enrolPubkey: p,
    rendezvous: r,
    label: 'Pixel 8 Pro',
    relays: ['wss://relay.example', 'wss://two.example/path?x=1'],
  })
  for (const bad of [
    '',
    code.replace('v=1', 'v=2'),
    code.replace(`p=${p}`, `p=${p.toUpperCase()}`),
    code.replace(`r=${r}`, `r=${r}00`),
    code.replace('label=Pixel+8+Pro', `label=${'x'.repeat(17)}`),
    code.split('&relay=')[0],
    code.replace('wss%3A%2F%2Frelay.example', 'https%3A%2F%2Frelay.example'),
    `${code}&p=${p}`,
  ]) {
    assert.equal(parseEnrolmentCode(bad), null, bad)
  }
})

// Vectors from spoken-token 2.1.0 itself; Cambium's EnrolmentTest pins the same.
test('check codes are spoken-token hex tokens of the hand-off key', () => {
  assert.equal(checkCode('ab'.repeat(32)), '9B6 164')
  assert.equal(checkCode('00'.repeat(32)), 'EF1 645')
})

// Vectors from spoken-token 2.1.0 (format 'words', count 5);
// common/src/phone_unlock.rs pins the same.
test('request codes are five spoken-token words of the enrolment key', () => {
  assert.equal(requestCode('ab'.repeat(32)), 'swim behind stand bugle female')
  assert.equal(requestCode('00'.repeat(32)), 'talent humble reform admit narrow')
  assert.equal(requestCode('42'.repeat(32)), 'profit buddy moment aim kitten')
  assert.equal(requestCode('ff'.repeat(32)), 'what attitude price easy large')
})
