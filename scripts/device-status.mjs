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

// The sealed-seed KDF telemetry is the only way to see which path a board
// actually derived on: the log console is compiled out on every board, so
// without this a timing result cannot be attributed to hardware or software.
// Printed as its own line because the raw JSON is long and this is the part a
// bench run is reading.
function describeKdf(reply) {
  if (!reply || reply.type === NACK) return null
  let info
  try {
    info = JSON.parse(reply.payload.toString())
  } catch {
    return null
  }
  const k = info.kdf
  if (!k) return 'kdf: not reported (firmware predates the KDF telemetry)'
  const parts = [
    `mode=${k.mode}`,
    `selfcheck=${k.selfcheck}`,
    `hw_selfcheck=${k.hw_selfcheck_us} us`,
    `sw_selfcheck=${k.sw_selfcheck_us} us`,
    `derivations=${k.derivations}`,
    `fully_hw=${k.hw_full}`,
    `retreats=${k.retreats}/${k.chunks} chunks`,
    `max_acquire=${k.max_acquire_ms} ms`,
    `last_derive=${k.last_derive_ms} ms`,
    `last_unlock=${k.last_unlock_ms} ms`,
  ]
  return `kdf: ${parts.join(', ')}`
}

const firmware = await session.request(FIRMWARE_INFO, [FIRMWARE_INFO_RESPONSE])
console.log(describe('firmware', firmware))
const kdf = describeKdf(firmware)
if (kdf) console.log(kdf)
console.log(describe('masters', await session.request(PROVISION_LIST, [PROVISION_LIST_RESPONSE])))
session.close()
