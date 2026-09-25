// Raise the factory reset card over the cable: FACTORY_RESET (0x24), for
// checklist 30a. This is a bench step for DENYING the card, so it never plays
// the press prompt. Holding PRG on the card erases every key on the device.
//
// Usage: node factory-reset-card.mjs --port <port>
import { argv, env } from 'node:process'
import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'

const FACTORY_RESET = 0x24

const arg = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
const portPath = arg('--port')
if (!portPath) {
  console.error('usage: node factory-reset-card.mjs --port <port>')
  process.exit(2)
}

const session = await openFramedPort(portPath, { env }).catch((error) => { console.error(error.message); process.exit(2) })
console.log('card up: expect "FACTORY RESET / ERASE ALL KEYS / notes and pairings too". Deny it; do not hold PRG.')
const started = Date.now()
const reply = await session.requestApproval(FACTORY_RESET, [ACK], { timeoutMs: 45_000 })
session.close()
const seconds = Math.round((Date.now() - started) / 1000)
if (!reply) { console.error(`no reply after ${seconds} s`); process.exit(1) }
if (reply.type === NACK) { console.log(`NACK after ${seconds} s: refused, nothing erased`); process.exit(0) }
console.log(`ACK after ${seconds} s: the device approved the reset and is erasing`)
process.exit(1)
