import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  deliveryJson,
  hint,
  hintMatches,
  judge,
  openContext,
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
