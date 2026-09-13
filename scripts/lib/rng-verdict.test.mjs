import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { BROKEN_CAUSES, KNOWN_CAUSES, rngVerdict } from './rng-verdict.mjs'

// Read the wire contract from the firmware's own source rather than a copy
// kept in step by hand. If common/src/entropy.rs grows a cause, renames a
// token, or changes which causes implicate the RNG, these fail — never a silent
// "unknown" for a stuck RNG at the bench.
const entropy = readFileSync(new URL('../../common/src/entropy.rs', import.meta.url), 'utf8')
const main = readFileSync(new URL('../../firmware/src/main.rs', import.meta.url), 'utf8')

/** Body of the `fn <name>` inside `impl SelfTestCause`. */
function causeFn(name) {
  const impl = entropy.slice(entropy.indexOf('impl SelfTestCause'))
  const start = impl.indexOf(`pub fn ${name}`)
  assert.ok(start !== -1, `entropy.rs: SelfTestCause::${name} is gone`)
  return impl.slice(start, impl.indexOf('\n    }\n', start))
}

/** Variant name -> wire token, from `SelfTestCause::wire`. */
function wireTokens() {
  const map = new Map()
  for (const m of causeFn('wire').matchAll(/Self::(\w+)\s*=>\s*"([a-z_]+)"/g)) map.set(m[1], m[2])
  assert.ok(map.size > 0, 'could not parse SelfTestCause::wire')
  return map
}

test('the script knows every cause the firmware can report', () => {
  for (const [variant, token] of wireTokens()) {
    assert.ok(KNOWN_CAUSES.has(token), `firmware cause ${variant} ("${token}") has no verdict`)
    assert.notEqual(rngVerdict({ rng_cause: token }).kind, 'unknown', token)
  }
})

test('the script and the firmware agree on which causes implicate the RNG', () => {
  const body = causeFn('rng_broken')
  const variants = [...body.matchAll(/Self::(\w+)/g)].map((m) => m[1])
  const tokens = wireTokens()
  const firmwareBroken = new Set(variants.map((v) => tokens.get(v)))
  assert.deepEqual([...firmwareBroken].sort(), [...BROKEN_CAUSES].sort())
})

test('FIRMWARE_INFO still carries the rng and rng_cause fields', () => {
  const fn = main.slice(main.indexOf('pub fn firmware_info_json'))
  const body = fn.slice(0, fn.indexOf('\n}\n'))
  assert.match(body, /\\"rng\\":/, 'firmware_info_json lost "rng"')
  assert.match(body, /\\"rng_cause\\":/, 'firmware_info_json lost "rng_cause"')
  assert.match(body, /rng_cause\(\)\.wire\(\)/, 'rng_cause is no longer the wire token')
})

test('verdicts', () => {
  assert.equal(rngVerdict({ rng: 'verified', rng_cause: 'draw_moved' }).kind, 'pass')
  assert.equal(rngVerdict({ rng: 'failed', rng_cause: 'draw_repeated' }).kind, 'broken')
  assert.equal(rngVerdict({ rng: 'failed', rng_cause: 'constant_draw' }).kind, 'broken')
  assert.equal(rngVerdict({ rng: 'needs_second_boot', rng_cause: 'no_previous_draw' }).kind, 'needs-reboot')
  assert.equal(rngVerdict({ rng: 'failed', rng_cause: 'proof_write_failed' }).kind, 'storage')
  assert.equal(rngVerdict({ rng: 'failed', rng_cause: 'proof_unreadable' }).kind, 'storage')
})

test('a storage fault is never reported as a broken RNG, and vice versa', () => {
  for (const cause of ['proof_unreadable', 'proof_write_failed']) {
    assert.notEqual(rngVerdict({ rng_cause: cause }).kind, 'broken', cause)
  }
  for (const cause of BROKEN_CAUSES) {
    assert.notEqual(rngVerdict({ rng_cause: cause }).kind, 'storage', cause)
  }
})

test('firmware that predates the field is unsupported, not a pass', () => {
  // 0.18.0-beta.5 as read off a real board: no rng fields at all.
  const beta5 = { version: '0.18.0-beta.5', board: 'heltec-v4', uptime_s: 138, last_reset: 'power-on' }
  assert.equal(rngVerdict(beta5).kind, 'unsupported')
  assert.equal(rngVerdict(null).kind, 'unsupported')
})
