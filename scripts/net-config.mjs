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

import { argv } from 'node:process'

import { NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d

const PORT = argv[argv.indexOf('--port') + 1]
if (!PORT || PORT.startsWith('--')) {
  console.error('usage: node scripts/net-config.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

const session = await openFramedPort(PORT).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

const reply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
session.close()
if (!reply) {
  console.log('net config: no reply')
  process.exit(1)
}
if (reply.type === NACK) {
  console.log('net config: NACK — locked devices do not serve this frame')
  process.exit(1)
}
console.log(JSON.stringify(JSON.parse(reply.payload.toString()), null, 2))
