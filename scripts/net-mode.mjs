#!/usr/bin/env node
// Physically switch between WiFi relay mode and radio-off USB mode without
// resending or exposing the stored WiFi password. The request is revision-
// bound and the device reboots after ACK, so vault-locked boards need the
// normal vault-unlock sequence again.
//
// Usage: node scripts/net-mode.mjs --port /dev/cu.usbmodemXXXX --mode usb

import { argv } from 'node:process'

import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { promptForPress } from './press-prompt.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d
const PATCH_NET_CONFIG = 0x5e

function arg(name) {
  const index = argv.indexOf(name)
  return index === -1 ? undefined : argv[index + 1]
}

const portPath = arg('--port')
const requestedMode = arg('--mode')
if (!portPath || !['usb', 'wifi'].includes(requestedMode)) {
  console.error('usage: node scripts/net-mode.mjs --port <port> --mode <usb|wifi>')
  process.exit(2)
}

const session = await openFramedPort(portPath).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

const currentReply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
if (!currentReply || currentReply.type === NACK) {
  session.close()
  console.error('could not read the current network config')
  process.exit(1)
}
const current = JSON.parse(currentReply.payload.toString())
if (!Number.isInteger(current.revision) || !['usb', 'wifi'].includes(current.mode)) {
  session.close()
  console.error('device returned an invalid network revision or mode')
  process.exit(1)
}
if (current.mode === requestedMode) {
  session.close()
  console.log(`Already in ${requestedMode} mode; no change made.`)
  process.exit(0)
}

const payload = Buffer.from(JSON.stringify({
  base_revision: current.revision,
  patch: { mode: requestedMode },
}))
promptForPress(`switch Heartwood from ${current.mode} to ${requestedMode} mode`)
const reply = await session.requestApproval(PATCH_NET_CONFIG, [ACK], { payload })
session.close()
if (!reply) {
  console.error('no reply; the device did not confirm the change')
  process.exit(1)
}
if (reply.type === NACK) {
  console.error(`NACK — ${reply.payload.toString() || 'device refused the change'}`)
  process.exit(1)
}
console.log(`ACK — ${requestedMode} mode saved without exposing the password; device is rebooting.`)
