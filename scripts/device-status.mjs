#!/usr/bin/env node
// scripts/device-status.mjs
//
// Read-only status probe: FIRMWARE_INFO (0x59) and PROVISION_LIST (0x05).
// Both are served in every device state, including the locked boot phase and
// the WiFi relay loop, so this answers "what firmware, which masters, locked
// or not" without touching any authority.
//
// Usage: node scripts/device-status.mjs --port /dev/cu.usbmodemXXXX

import { argv } from 'node:process'

import { NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'

const FIRMWARE_INFO = 0x59
const FIRMWARE_INFO_RESPONSE = 0x5a
const PROVISION_LIST = 0x05
const PROVISION_LIST_RESPONSE = 0x07

const PORT = argv[argv.indexOf('--port') + 1]
if (!PORT || PORT.startsWith('--')) {
  console.error('usage: node scripts/device-status.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

const session = await openFramedPort(PORT).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

function describe(label, reply) {
  if (!reply) return `${label}: no reply`
  if (reply.type === NACK) return `${label}: NACK — ${reply.payload.toString() || 'refused'}`
  return `${label}: ${reply.payload.toString()}`
}

console.log(describe('firmware', await session.request(FIRMWARE_INFO, [FIRMWARE_INFO_RESPONSE])))
console.log(describe('masters', await session.request(PROVISION_LIST, [PROVISION_LIST_RESPONSE])))
session.close()
