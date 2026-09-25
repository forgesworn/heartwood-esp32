import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { buildSetNetConfig, SET_NET_CONFIG } from './net-config.mjs'

const A = 'ab'.repeat(32)
const C = 'cd'.repeat(32)
const board = (op) => ({ configured: true, revision: 4, mode: 'wifi', ssid: 'old', relays: [], op_mgmt: op })
const file = { ssid: 'home', password: 'secret', relays: ['wss://r.example'], mode: 'wifi' }

test('the operator is copied from the board by default', () => {
  const { payload, change, title } = buildSetNetConfig(board(A), file)
  const sent = JSON.parse(payload.toString())
  assert.equal(sent.op_mgmt, A)
  assert.equal(sent.password, 'secret')
  assert.equal(change, 'kept')
  assert.equal(title, 'Set network config?')
})

test('the same key in another case is no change', () => {
  assert.equal(buildSetNetConfig(board(A.toUpperCase()), file).change, 'kept')
})

test('--op-mgmt names the change the card will show', () => {
  const replaced = buildSetNetConfig(board(A), file, { opMgmt: C })
  assert.equal(replaced.change, 'replaced')
  assert.equal(replaced.title, 'Replace operator?\ncdcdcdcd... +network')
  const added = buildSetNetConfig(board(''), file, { opMgmt: C })
  assert.equal(added.change, 'added')
  assert.equal(added.title, 'New operator?\ncdcdcdcd... +network')
  const removed = buildSetNetConfig(board(A), file, { opMgmt: 'none' })
  assert.equal(removed.change, 'removed')
  assert.equal(JSON.parse(removed.payload.toString()).op_mgmt, '')
})

test('a malformed stored operator counts as none', () => {
  assert.equal(buildSetNetConfig(board('zz'), file, { opMgmt: C }).change, 'added')
  assert.equal(buildSetNetConfig(board('zz'), file, { opMgmt: 'none' }).change, 'kept')
})

test('bad input is refused before anything is sent', () => {
  assert.throws(() => buildSetNetConfig(board(A), { ...file, op_mgmt: C }), /leave op_mgmt out/)
  assert.throws(() => buildSetNetConfig(board(A), file, { opMgmt: 'npub1xyz' }), /64 hex/)
  assert.throws(() => buildSetNetConfig(board(A), { ...file, password: undefined }), /password/)
  assert.throws(() => buildSetNetConfig(board(A), { ...file, mode: 'lora' }), /mode/)
  assert.throws(() => buildSetNetConfig({ configured: false }, file), /no stored config/)
})

test('the titles and frame type match the firmware', () => {
  const types = readFileSync(new URL('../../common/src/types.rs', import.meta.url), 'utf8')
  assert.match(types, new RegExp(`FRAME_TYPE_SET_NET_CONFIG: u8 = 0x${SET_NET_CONFIG.toString(16)};`))
  const netConfig = readFileSync(new URL('../../common/src/net_config.rs', import.meta.url), 'utf8')
  for (const line of ['"Set network config?"', '"New operator?"', '"Replace operator?"', '"Remove operator?\\n+ set network"', '"{first}\\n{}... +network"']) {
    assert.ok(netConfig.includes(line), `net_config.rs no longer draws ${line}`)
  }
})
