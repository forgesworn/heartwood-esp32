#!/usr/bin/env node
// scripts/net-patch.mjs
//
// USB relays editor: PATCH_NET_CONFIG (0x5e) with a replacement relay list.
// Only `relays` is patched — mode, network, passwords and the fallback list
// stay as stored, so this script never sees a WiFi password. The board shows
// its "Change network?" card and the change takes a button hold on the
// device, as every cable mutation does; on approval it ACKs and reboots.
//
// Usage: node scripts/net-patch.mjs --port /dev/cu.usbserial-XXXX --relays wss://relay.primal.net,wss://nostr.mom
//
// Without --relays it prints the current config, like net-config.mjs.

import { argv, env } from 'node:process'

import { ACK, NACK } from './lib/frame.mjs'
import { buildNetConfigPatchRelays, PATCH_NET_CONFIG } from './lib/net-config.mjs'
import { openFramedPort } from './lib/port.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d

const arg = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
const PORT = arg('--port')
const relayArg = arg('--relays')
if (!PORT || PORT.startsWith('--') || (argv.includes('--relays') && !relayArg)) {
  console.error('usage: node scripts/net-patch.mjs --port /dev/cu.usbserial-XXXX [--relays wss://a,wss://b]')
  process.exit(2)
}

const session = await openFramedPort(PORT, { env }).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

const reply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
if (!reply || reply.type === NACK) {
  session.close()
  console.log(reply ? 'net config: NACK — locked devices do not serve this frame' : 'net config: no reply')
  process.exit(1)
}
const current = JSON.parse(reply.payload.toString())
if (!relayArg) {
  session.close()
  console.log(JSON.stringify(current, null, 2))
  process.exit(0)
}

const relays = relayArg.split(',').map((relay) => relay.trim()).filter(Boolean)
let built
try {
  built = buildNetConfigPatchRelays(current, relays)
} catch (error) {
  session.close()
  console.error(error.message)
  process.exit(2)
}
console.log(`now: ${(current.relays ?? []).join(' ')}`)
console.log(`new: ${relays.join(' ')}`)
console.log('the card should read: Change network?')
console.log('hold the button on the device to approve, or let the card expire')

const answer = await session.requestApproval(PATCH_NET_CONFIG, [ACK], { payload: built.payload, timeoutMs: 70_000 })
session.close()
if (!answer) { console.error('no reply; the device did not confirm the change'); process.exit(1) }
if (answer.type === NACK) {
  const reason = answer.payload.toString()
  console.error(`NACK — ${reason || 'refused'}${reason === 'stale network revision' ? ' (the board changed meanwhile; run again)' : ''}`)
  process.exit(1)
}
console.log('ACK — saved; the board reboots onto the new list.')
