#!/usr/bin/env node
// scripts/restore-from-dump.mjs
//
// Move identities off a board through a raw NVS dump, for a board that is
// dead, or a rehearsal onto a spare. A backup file cannot do this: it
// deliberately carries no seed.
//
// Reads the dump with scripts/nvs-dump-read.py (ESP-IDF's own parser, blobs
// reassembled), opens the data-key wrapper `dk_sec` with the vault key, opens
// each `m<slot>_seed_enc` (data-key seal, or the older PIN/vault format), and
// checks every seed's public key against the stored `master_<slot>_pubkey`
// before anything else happens.
//
//   --check            open and verify every identity; send nothing.
//   --port <p> --slot <n>
//                      also provision that one identity onto the board at <p>
//                      (PROVISION_ADD, one press on that board). The target
//                      should be in USB mode: two boards serving the same
//                      identities on the relays would both answer.
//
// Seeds and the vault key live only in this process: never written, printed
// or passed on argv.
//
// Usage:
//   node scripts/restore-from-dump.mjs --dump <nvs.bin> --vault-key-file <path> --check
//   node scripts/restore-from-dump.mjs --dump <nvs.bin> --vault-key-file <path> --port <p> --slot 0

import { argv, env, exit } from 'node:process'
import { execFileSync } from 'node:child_process'
import { createCipheriv, createHmac, pbkdf2Sync, timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'

import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { startPressPrompt } from './press-prompt.mjs'

const arg = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
const DUMP = arg('--dump')
const VAULT_KEY_FILE = arg('--vault-key-file')
const PORT = arg('--port')
const SLOT = arg('--slot')
if (!DUMP || !VAULT_KEY_FILE || (!argv.includes('--check') && !(PORT && SLOT !== undefined))) {
  console.error('usage: restore-from-dump.mjs --dump <nvs.bin> --vault-key-file <path> (--check | --port <p> --slot <n>)')
  exit(2)
}

const reader = new URL('./nvs-dump-read.py', import.meta.url).pathname
function get(key) {
  try {
    const hex = execFileSync('python3', [reader, DUMP, '--get', 'heartwood', key], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
    return Buffer.from(hex, 'hex')
  } catch {
    return null
  }
}

const chacha = (key, nonce, data) => {
  const c = createCipheriv('chacha20', key, Buffer.concat([Buffer.alloc(4), nonce]))
  return Buffer.concat([c.update(data), c.final()])
}

// seed_cipher: 92-byte legacy (100k rounds) or 101-byte "HWSC" v1 with rounds.
function openSecretWrap(blob, secret) {
  let header = Buffer.alloc(0), rounds = 100_000, body = blob
  if (blob.length === 101) {
    if (blob.subarray(0, 4).toString() !== 'HWSC' || blob[4] !== 1) throw new Error('unknown wrap format')
    header = blob.subarray(0, 9)
    rounds = blob.readUInt32BE(5)
    if (rounds === 0 || rounds > 150_000) throw new Error('implausible KDF cost')
    body = blob.subarray(9)
  } else if (blob.length !== 92) {
    throw new Error(`wrap is ${blob.length} bytes`)
  }
  const salt = body.subarray(0, 16), nonce = body.subarray(16, 28), ct = body.subarray(28, 60), tag = body.subarray(60, 92)
  const km = pbkdf2Sync(secret, salt, rounds, 64, 'sha256')
  const mac = createHmac('sha256', km.subarray(32)).update(header).update(nonce).update(ct).digest()
  if (!timingSafeEqual(mac, tag)) throw new Error('the vault key does not open this')
  const out = chacha(km.subarray(0, 32), nonce, ct)
  km.fill(0)
  return out
}

// data_key seal: "HWDK" v1, purpose, nonce(12), ct(32), tag(32).
function openDataKeySeal(dk, purpose, blob) {
  if (blob.length !== 82 || blob.subarray(0, 4).toString() !== 'HWDK' || blob[4] !== 1 || blob[5] !== purpose) {
    throw new Error('not a data-key seal for this purpose')
  }
  const sub = (label) => createHmac('sha256', dk).update(label).update(Buffer.from([purpose])).digest()
  const mac = createHmac('sha256', sub('heartwood-dk-mac')).update(blob.subarray(0, 50)).digest()
  if (!timingSafeEqual(mac, blob.subarray(50))) throw new Error('the data key does not open this')
  return chacha(sub('heartwood-dk-enc'), blob.subarray(6, 18), blob.subarray(18, 50))
}

const { getPublicKey } = await import('./relay-deps.mjs')
const vaultKey = Buffer.from(readFileSync(VAULT_KEY_FILE, 'utf8').trim(), 'hex')
const count = get('master_count')?.[0] ?? 0
const dkWrap = get('dk_sec')
let dk = null
if (dkWrap) {
  console.log('opening the data-key wrapper (one PBKDF2 stretch)...')
  dk = openSecretWrap(dkWrap, vaultKey)
}

const identities = []
for (let slot = 0; slot < count; slot++) {
  const label = get(`master_${slot}_label`)?.toString('utf8') ?? 'default'
  const mode = get(`master_${slot}_mode`)?.[0] ?? 1
  const pubkey = get(`master_${slot}_pubkey`)?.toString('hex')
  const sealed = get(`m${slot}_seed_enc`)
  let seed = get(`master_${slot}_secret`)
  if (sealed) seed = sealed.length === 82 ? openDataKeySeal(dk, 1, sealed) : openSecretWrap(sealed, vaultKey)
  if (!seed || seed.length !== 32) throw new Error(`slot ${slot}: no seed in the dump`)
  const derived = getPublicKey(seed)
  if (derived !== pubkey) throw new Error(`slot ${slot} '${label}': seed does not match its stored public key`)
  identities.push({ slot, label, mode, pubkey, seed })
  console.log(`slot ${slot}  '${label}'  mode ${mode}  ${sealed ? (sealed.length === 82 ? 'data-key sealed' : 'vault sealed') : 'plaintext'}  pubkey ${pubkey.slice(0, 16)}...  verified`)
}
vaultKey.fill(0)
dk?.fill(0)

if (argv.includes('--check')) {
  for (const id of identities) id.seed.fill(0)
  console.log(`\n${identities.length} identit${identities.length === 1 ? 'y' : 'ies'} recoverable from this dump`)
  exit(0)
}

const target = identities.find((id) => id.slot === Number(SLOT))
if (!target) {
  console.error(`no slot ${SLOT} in the dump`)
  exit(2)
}
const label = Buffer.from(target.label, 'utf8')
const payload = Buffer.concat([Buffer.from([target.mode, label.length]), label, target.seed])
for (const id of identities) id.seed.fill(0)

const session = await openFramedPort(PORT, { env })
// Once only: a resent PROVISION_ADD queued behind the card would be a second
// provisioning attempt.
session.send(0x01, payload)
payload.fill(0)
const stop = startPressPrompt(`restoring ${target.label}`)
const reply = await session.waitFor([ACK, NACK], 60_000)
stop()
session.close()
if (!reply) {
  console.error('no answer within 60 s')
  exit(1)
}
if (reply.type === NACK) {
  console.error(`refused: ${reply.payload.toString() || 'no reason'}`)
  exit(1)
}
console.log(`restored '${target.label}'; check it with scripts/device-status.mjs`)
