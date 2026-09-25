#!/usr/bin/env node
// scripts/net-config.mjs
//
// Read-only network state probe: GET_NET_CONFIG (0x5c). Served in every
// device state except the locked relay phase, which answers only six frames
// and NACKs the rest — so a 0x5c that comes back is also proof the board is
// past its unlock wait. Passwords are redacted on-device, so this is safe to
// run on any channel. Prints mode, SSID, relay list and the runtime stage.
//
// Usage: node scripts/net-config.mjs --port /dev/cu.usbmodemXXXX
//
// --set-config <file.json> [--op-mgmt <64 hex>|none] sends a whole-config
// SET_NET_CONFIG (0x54) instead, for the bench steps that need one (checklist
// section 29 step 10d). The file holds { ssid, password, relays, mode,
// networks? } with the real password (the board only says whether one is
// set); op_mgmt is copied from the board unless --op-mgmt names another key or
// none. The script prints the card the board should show: "Set network
// config?" when the operator is kept (a recovery, which takes the screen from
// a relay card), otherwise "New operator?", "Replace operator?" or "Remove
// operator?" (an ordinary card, refused "approval on screen" under one). A
// wifi save reboots the board.

import { readFileSync } from 'node:fs'
import { argv, env } from 'node:process'

import { ACK, NACK } from './lib/frame.mjs'
import { buildSetNetConfig, SET_NET_CONFIG } from './lib/net-config.mjs'
import { openFramedPort } from './lib/port.mjs'
import { startPressPrompt } from './press-prompt.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d

const arg = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
const PORT = arg('--port')
const setConfig = arg('--set-config')
const opMgmt = arg('--op-mgmt')
if (!PORT || PORT.startsWith('--') || (argv.includes('--set-config') && !setConfig)) {
  console.error('usage: node scripts/net-config.mjs --port /dev/cu.usbmodemXXXX [--set-config file.json [--op-mgmt <hex>|none]]')
  process.exit(2)
}
let file
if (setConfig) {
  try {
    file = JSON.parse(readFileSync(setConfig, 'utf8'))
  } catch (error) {
    console.error(`${setConfig}: ${error.message}`)
    process.exit(2)
  }
}

const session = await openFramedPort(PORT, { env }).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

const reply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
if (!reply) {
  session.close()
  console.log('net config: no reply')
  process.exit(1)
}
if (reply.type === NACK) {
  session.close()
  console.log('net config: NACK — locked devices do not serve this frame')
  process.exit(1)
}
const current = JSON.parse(reply.payload.toString())
if (!setConfig) {
  session.close()
  console.log(JSON.stringify(current, null, 2))
  process.exit(0)
}

let built
try {
  built = buildSetNetConfig(current, file, { opMgmt })
} catch (error) {
  session.close()
  console.error(error.message)
  process.exit(2)
}
console.log(`operator ${built.change}; the card should read: ${built.title.replace('\n', ' / ')}`)
const stopPrompt = startPressPrompt('the network config card')
const answer = await session.requestApproval(SET_NET_CONFIG, [ACK], { payload: built.payload, timeoutMs: 70_000 })
stopPrompt()
// The payload carries the WiFi password.
built.payload.fill(0)
session.close()
if (!answer) { console.error('no reply; the device did not confirm the change'); process.exit(1) }
if (answer.type === NACK) { console.error(`NACK — ${answer.payload.toString() || 'refused'}`); process.exit(1) }
console.log('ACK — saved (a wifi save reboots the board).')
