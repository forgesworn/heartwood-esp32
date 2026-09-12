// Patch the signer's configured relay list over the cable: PATCH_NET_CONFIG
// (0x5e), revision-bound, physically confirmed, reboots on ACK. net-wifi.mjs
// covers the ssid and fallbacks half of the same frame; this is the relays.
//
// Usage: node net-relays.mjs --port <port> --relays wss://a,wss://b,...
import { argv, env } from 'node:process'
import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { startPressPrompt } from './press-prompt.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d
const PATCH_NET_CONFIG = 0x5e

const arg = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
const portPath = arg('--port')
const relaysArg = arg('--relays')
if (!portPath || !relaysArg) {
  console.error('usage: node net-relays.mjs --port <port> --relays wss://a,wss://b')
  process.exit(2)
}
const relays = relaysArg.split(',').map((r) => r.trim()).filter(Boolean)
for (const relay of relays) {
  if (!relay.startsWith('wss://')) { console.error(`${relay}: the device takes wss:// only`); process.exit(2) }
  if (/[?#]/.test(relay) || relay.slice(6).includes('/')) { console.error(`${relay}: no path, query or fragment`); process.exit(2) }
}

const session = await openFramedPort(portPath, { env }).catch((error) => { console.error(error.message); process.exit(2) })
const currentReply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
if (!currentReply || currentReply.type === NACK) {
  session.close()
  console.error('could not read the current network config (a locked device does not serve it)')
  process.exit(1)
}
const current = JSON.parse(currentReply.payload.toString())
console.log(`current relays: ${(current.relays ?? []).join(', ')} (revision ${current.revision})`)
console.log(`patching to:    ${relays.join(', ')}`)

const payload = Buffer.from(JSON.stringify({ base_revision: current.revision, patch: { relays } }))
const stopPrompt = startPressPrompt('the "Change network?" card')
const reply = await session.requestApproval(PATCH_NET_CONFIG, [ACK], { payload, timeoutMs: 70_000 })
stopPrompt()
session.close()
if (!reply) { console.error('no reply; the device did not confirm the change'); process.exit(1) }
if (reply.type === NACK) { console.error(`NACK — ${reply.payload.toString() || 'refused'}`); process.exit(1) }
console.log('ACK — saved; the device is rebooting and will come back locked.')
