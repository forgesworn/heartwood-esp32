#!/usr/bin/env node
// scripts/unwrap-notice.mjs
//
// Open a gift-wrapped C4/C5 notice by using the signer itself as the
// recipient's decryption oracle. The notice is wrapped to an identity whose
// key never leaves the device, so the only way to read one on the bench is to
// ask the device: two nip44_decrypt round-trips over the relay, peeling the
// wrap layer (peer = the ephemeral wrap author) and then the seal layer
// (peer = the seal author) to reach the unsigned rumor.
//
// The client key must already be bound to a slot that permits nip44_decrypt
// on the target identity. Deps resolve via scripts/relay-deps.mjs.
//
// Usage:
//   node scripts/unwrap-notice.mjs --wrap-file wrap.json --target <recipientHex> \
//     --client-key-file k.key [--relay wss://...] [--timeout 60000]
//
// Get wrap.json from scripts/fetch-events.mjs with a kind-1059 #p filter on
// the recipient.

import { argv, exit } from 'node:process'
import { readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import {
  WebSocket,
  finalizeEvent,
  getPublicKey,
  nip44,
  arg,
  DEFAULT_RELAY,
} from './relay-deps.mjs'

const RELAY = arg(argv, '--relay', DEFAULT_RELAY)
const TARGET = arg(argv, '--target')
const KEY_FILE = arg(argv, '--client-key-file')
const WRAP_FILE = arg(argv, '--wrap-file')
const TIMEOUT = Number(arg(argv, '--timeout', '60000'))

if (!TARGET || !KEY_FILE || !WRAP_FILE) {
  console.error(
    'usage: node scripts/unwrap-notice.mjs --wrap-file f --target <hex> --client-key-file k',
  )
  exit(2)
}
const wrap = JSON.parse(readFileSync(WRAP_FILE, 'utf8'))
const sk = Uint8Array.from(Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'hex'))
const clientPub = getPublicKey(sk)
const ck = nip44.v2.utils.getConversationKey(sk, TARGET)

const ws = new WebSocket(RELAY)
setTimeout(() => {
  console.error(`timeout: no response within ${TIMEOUT} ms`)
  exit(3)
}, TIMEOUT)

/** Ask the device to decrypt one layer on the recipient's behalf. */
function deviceDecrypt(peerHex, ciphertext) {
  return new Promise((resolve, reject) => {
    const id = randomBytes(8).toString('hex')
    const ev = finalizeEvent(
      {
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', TARGET]],
        content: nip44.v2.encrypt(
          JSON.stringify({ id, method: 'nip44_decrypt', params: [peerHex, ciphertext] }),
          ck,
        ),
      },
      sk,
    )
    const onMessage = (data) => {
      let msg
      try {
        msg = JSON.parse(data.toString())
      } catch {
        return
      }
      if (msg[0] !== 'EVENT' || msg[1] !== 'c') return
      let inner
      try {
        inner = JSON.parse(nip44.v2.decrypt(msg[2].content, ck))
      } catch {
        return
      }
      if (inner.id !== id) return
      ws.removeListener('message', onMessage)
      if (inner.error !== undefined) reject(new Error(inner.error))
      else resolve(inner.result)
    }
    ws.on('message', onMessage)
    ws.send(JSON.stringify(['EVENT', ev]))
  })
}

ws.on('open', async () => {
  ws.send(
    JSON.stringify([
      'REQ',
      'c',
      { kinds: [24133], authors: [TARGET], '#p': [clientPub], limit: 0 },
    ]),
  )
  try {
    const seal = JSON.parse(await deviceDecrypt(wrap.pubkey, wrap.content))
    const rumor = JSON.parse(await deviceDecrypt(seal.pubkey, seal.content))
    console.log(
      JSON.stringify({ seal_kind: seal.kind, seal_author: seal.pubkey, rumor }, null, 2),
    )
    ws.close()
    exit(0)
  } catch (e) {
    console.error(`error: ${e.message}`)
    exit(1)
  }
})
ws.on('error', (e) => {
  console.error(String(e.message))
  exit(1)
})
