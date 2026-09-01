import assert from 'node:assert/strict'
import { test } from 'node:test'

import { authenticateSession } from './session-auth.mjs'

test('retries until native USB command handling becomes ready', async () => {
  let sends = 0
  const result = await authenticateSession({
    sendAuth: () => { sends++ },
    waitForAck: async () => sends === 2 ? { payload: Buffer.from([0]) } : null,
    attempts: 6,
    timeoutMs: 1,
  })
  assert.equal(sends, 3)
  assert.equal(result.attempt, 3)
  assert.equal(result.reply.payload[0], 0)
})

test('stops after the configured retry budget', async () => {
  let sends = 0
  const result = await authenticateSession({
    sendAuth: () => { sends++ },
    waitForAck: async () => null,
    attempts: 4,
    timeoutMs: 1,
  })
  assert.equal(result, null)
  assert.equal(sends, 4)
})
