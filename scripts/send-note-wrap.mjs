#!/usr/bin/env node
// scripts/send-note-wrap.mjs
//
// Bench the RECEIVE card: gift-wrap a LUD-25 note URL to a device identity and
// publish it. Builds rumor -> seal -> wrap by hand (kind 2525 inside 13 inside
// 1059, the shape common/src/note_wrap.rs reads), so it is an independent
// check of the wire format rather than a second copy of the firmware's.
//
// The note URL is bearer money: whoever reads this shell's history can spend
// it. Use a test mint.
//
// Usage:
//   node scripts/send-note-wrap.mjs --to <npub|hex> --note 'lnurlw://mint.example/w?k1=<64hex>&amount=<msat>' \
//     [--sender-key-file s.key] [--relay wss://...]

import { argv, exit } from 'node:process'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { finalizeEvent, getEventHash, getPublicKey, nip44, arg, toHex, relayList, RelayFanout } from './relay-deps.mjs'

const TO = arg(argv, '--to')
const NOTE = arg(argv, '--note')
const KEY_FILE = arg(argv, '--sender-key-file')
const RELAYS = relayList(argv)
if (!TO || !NOTE) {
  console.error("usage: node scripts/send-note-wrap.mjs --to <npub|hex> --note '<note url>' [--sender-key-file f] [--relay wss://...]")
  exit(2)
}
const target = toHex(TO, '--to')
const url = new URL(NOTE.replace(/^lnurlw:\/\//i, 'https://'))
const k1 = url.searchParams.get('k1')
const amount = Number(url.searchParams.get('amount'))
if (!/^[0-9a-f]{64}$/i.test(k1 ?? '') || !(amount > 0)) {
  console.error('the note needs a 64-hex k1 and a positive amount')
  exit(2)
}
const host = `${url.host}${url.pathname === '/' ? '' : url.pathname}`

let sk
if (KEY_FILE) {
  if (!existsSync(KEY_FILE)) writeFileSync(KEY_FILE, `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 })
  sk = Uint8Array.from(Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'hex'))
} else {
  sk = new Uint8Array(randomBytes(32))
}
const sender = getPublicKey(sk)
const now = Math.floor(Date.now() / 1000)
const backdated = () => now - Math.floor(Math.random() * 172_800)

const rumor = {
  pubkey: sender,
  created_at: now,
  kind: 2525,
  tags: [
    ['p', target],
    ['amount', String(amount)],
    ['u', host],
  ],
  content: `lnurlw://${host}?k1=${k1.toLowerCase()}&amount=${amount}`,
}
// The rumor carries its id but no signature.
rumor.id = getEventHash(rumor)

const sealKey = nip44.v2.utils.getConversationKey(sk, target)
const seal = finalizeEvent(
  { kind: 13, created_at: backdated(), tags: [], content: nip44.v2.encrypt(JSON.stringify(rumor), sealKey) },
  sk,
)
const eph = new Uint8Array(randomBytes(32))
const wrapKey = nip44.v2.utils.getConversationKey(eph, target)
const wrap = finalizeEvent(
  { kind: 1059, created_at: backdated(), tags: [['p', target]], content: nip44.v2.encrypt(JSON.stringify(seal), wrapKey) },
  eph,
)

const ws = new RelayFanout(RELAYS)
const live = await ws.open()
console.error(`sender ${sender}\nwrap ${wrap.id} -> ${live.length}/${RELAYS.length} relays`)
let acks = 0
ws.on((data) => {
  let msg
  try {
    msg = JSON.parse(data.toString())
  } catch {
    return
  }
  if (msg[0] === 'OK' && msg[1] === wrap.id) {
    console.error(`OK ${msg[2]} ${msg[3] ?? ''}`)
    if (++acks >= live.length) {
      ws.close()
      exit(0)
    }
  }
})
ws.send(['EVENT', wrap])
setTimeout(() => {
  ws.close()
  exit(acks ? 0 : 1)
}, 8000)
