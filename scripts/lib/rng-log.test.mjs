import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { classify, FATAL_VERDICTS } from './rng-log.mjs'

// Build every line the firmware can print from its OWN source, rather than a
// copy kept in step by hand. If entropy.rs rewords a verdict, these expectations
// move with it and the classifier either still recognises the line or this
// fails loudly — never a silent "inconclusive" for a stuck RNG.
const source = readFileSync(new URL('../../firmware/src/entropy.rs', import.meta.url), 'utf8')

function templateFor(prefix) {
  const re = new RegExp(`"(${prefix}[^"]*\\{why\\}[^"]*)"`)
  const hit = source.match(re)
  assert.ok(hit, `entropy.rs no longer has a "${prefix}...{why}..." log template`)
  // A multi-line format!("...\\\n  ...") literal joins with the continuation.
  return hit[1].replace(/\\\s*\n\s*/g, '')
}

const PASSED = templateFor('RNG self-test passed')
const WAITING = templateFor('RNG self-test: ')
const FAILED = templateFor('RNG self-test FAILED')

function reasons() {
  const found = new Set()
  for (const m of source.matchAll(/"((?:draw|no previous|proof|constant)[^"]*)"/g)) found.add(m[1])
  return found
}

const line = (template, why) => `I (1234) heartwood_esp32::entropy: ${template.replace('{why}', why)}`

test('entropy.rs still names every reason the classifier depends on', () => {
  const r = reasons()
  for (const why of [
    'draw moved',
    'no previous draw to compare against',
    'draw identical to last boot',
    'constant draw',
    'proof unreadable',
    'proof write failed',
  ]) {
    assert.ok(r.has(why), `entropy.rs no longer emits reason "${why}"`)
  }
})

test('a verified boot passes', () => {
  assert.equal(classify(line(PASSED, 'draw moved')).verdict, 'passed')
})

test('the post-wipe boot reads as no-proof, not as a pass', () => {
  const hit = classify(line(WAITING, 'no previous draw to compare against'))
  assert.equal(hit.verdict, 'no-proof')
  assert.ok(!FATAL_VERDICTS.has(hit.verdict))
})

test('a repeated draw is recognised as the stuck-RNG case, and is fatal', () => {
  const hit = classify(line(FAILED, 'draw identical to last boot'))
  assert.equal(hit.verdict, 'repeated')
  assert.ok(FATAL_VERDICTS.has(hit.verdict))
})

test('a constant draw is recognised and fatal', () => {
  const hit = classify(line(FAILED, 'constant draw'))
  assert.equal(hit.verdict, 'constant')
  assert.ok(FATAL_VERDICTS.has(hit.verdict))
})

test('an NVS fault is a refusal but not a verdict on the RNG itself', () => {
  for (const why of ['proof unreadable', 'proof write failed']) {
    const hit = classify(line(FAILED, why))
    assert.equal(hit.verdict, 'failed', why)
    assert.ok(!FATAL_VERDICTS.has(hit.verdict), why)
  }
})

test('pre-2026-09-12 firmware wording is still understood', () => {
  assert.equal(classify('RNG self-test passed').verdict, 'passed')
  assert.equal(
    classify('RNG self-test FAILED: draw identical to last boot — refusing key generation').verdict,
    'repeated',
  )
  assert.equal(
    classify('RNG self-test: no previous draw recorded, seeding proof').verdict,
    'no-proof',
  )
})

test('unrelated log lines are ignored', () => {
  assert.equal(classify('I (99) wifi: connected'), null)
  assert.equal(classify('sign_event: auto-approved by policy'), null)
})
