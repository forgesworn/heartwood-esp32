#!/usr/bin/env node
// scripts/vault-unlock-wifi.mjs
//
// Unlock a locked signer over WiFi, with no cable: wait for its kind-24135
// announcement, then answer with the kind-24136 vault delivery. This is the
// operator half of `locked_relay_phase`, and the same exchange Sapwood drives
// from `VaultUnlock.svelte` — here as a bench tool, so the path can be proved
// on hardware without a browser in the loop.
//
// The signer generates a one-time unlock keypair on every locked boot, keeps
// it in RAM only, and announces the public half p-tagged to the operator. We
// NIP-44 the vault key to that one-time pubkey. A flash dump of the device
// therefore yields no unlock capability, and there is no standing ciphertext
// on any relay to scrape: both kinds are ephemeral.
//
// The announcement is NOT authenticated — it cannot be, since every attesting
// key on the device is sealed at this point. A fake announcement can phish a
// vault key out of an inattentive operator, so this prints the pubkey it is
// about to answer and requires --yes to send unprompted. Sapwood makes the
// operator tap for the same reason.
//
// Usage:
//   node scripts/vault-unlock-wifi.mjs --vault-key-file ~/heartwood-bench/vault.key \
//     [--key-file ~/heartwood-bench/operator.key] [--relay wss://...]
//     [--timeout 180000] [--yes]

import { argv, env, exit } from 'node:process'
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'

import { finalizeEvent, getPublicKey, nip44, arg, relayList, RelayFanout } from './relay-deps.mjs'

const LOCKED_ANNOUNCE_KIND = 24135
const VAULT_DELIVERY_KIND = 24136
/** Two announce cycles plus slack; older is a stored replay, not a live offer. */
const MAX_ANNOUNCE_AGE_SECS = 150

const RELAYS = relayList(argv)
const KEY_FILE = arg(argv, '--key-file', `${env.HOME}/heartwood-bench/operator.key`)
const VAULT_KEY_FILE = arg(argv, '--vault-key-file')
const TIMEOUT = Number(arg(argv, '--timeout', '180000'))
const ASSUME_YES = argv.includes('--yes')

if (!VAULT_KEY_FILE) {
  console.error('usage: node scripts/vault-unlock-wifi.mjs --vault-key-file <path> [--yes]')
  exit(2)
}

function readHex32(path, what) {
  const hex = readFileSync(path, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    console.error(`${what} must be exactly 64 lowercase hex characters`)
    exit(2)
  }
  return hex
}

const operatorSkHex = readHex32(KEY_FILE, 'operator key')
const operatorSk = Buffer.from(operatorSkHex, 'hex')
const operatorPk = getPublicKey(operatorSk)
// Sent as the 64-char hex string the firmware expects, not raw bytes:
// `handle_vault_delivery` hex-decodes the decrypted plaintext.
const vaultKeyHex = readHex32(VAULT_KEY_FILE, 'vault key')

const fanout = new RelayFanout(RELAYS)
const live = await fanout.open()
console.log(`operator ${operatorPk.slice(0, 16)}… listening on ${live.length}/${RELAYS.length} relay(s)`)
console.log('waiting for a locked signer to announce (power-cycle it if it is already up)...')

// The signer announces every 60 s while locked, so a late start still catches
// one. Ephemeral kinds are never stored, which is why this must be live.
fanout.req('locked-announce', { kinds: [LOCKED_ANNOUNCE_KIND], '#p': [operatorPk] })

const announced = await new Promise((resolve) => {
  const timer = setTimeout(() => resolve(null), TIMEOUT)
  fanout.on((data, url) => {
    let msg
    try { msg = JSON.parse(data) } catch { return }
    if (msg[0] !== 'EVENT' || msg[1] !== 'locked-announce') return
    const ev = msg[2]
    if (ev.kind !== LOCKED_ANNOUNCE_KIND) return
    // Ephemeral kinds are not supposed to be stored, and some relays store
    // them anyway: a replayed announcement names a one-time unlock key from a
    // boot that has already ended, so a delivery to it is silently discarded
    // and the signer stays locked. The signer re-announces every 60 s, so
    // anything older than a couple of cycles is a ghost, not an offer.
    const age = Math.round(Date.now() / 1000) - ev.created_at
    if (age > MAX_ANNOUNCE_AGE_SECS) {
      console.log(`  ignoring a ${age}s-old replay of ${ev.pubkey.slice(0, 16)}…`)
      return
    }
    clearTimeout(timer)
    resolve({ ev, url })
  })
})

if (!announced) {
  console.error(`no announcement within ${TIMEOUT / 1000}s.`)
  console.error('A signer stamping created_at from boot time is rejected by relays as an')
  console.error('expired ephemeral event and never arrives — see #116.')
  fanout.close()
  exit(1)
}

const { ev, url } = announced
const age = Math.round(Date.now() / 1000) - ev.created_at
console.log(`\nannouncement on ${new URL(url).host}`)
console.log(`  unlock pubkey  ${ev.pubkey}`)
console.log(`  created_at     ${ev.created_at} (${age}s old — a boot-relative stamp reads as 1970)`)
console.log(`  content        ${ev.content}`)

if (!ASSUME_YES) {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question('\nSend the vault key to this pubkey? [y/N] ')
  rl.close()
  if (!/^y(es)?$/i.test(answer.trim())) {
    console.log('Declined; nothing sent.')
    fanout.close()
    exit(1)
  }
}

const conversationKey = nip44.v2.utils.getConversationKey(operatorSk, ev.pubkey)
const delivery = finalizeEvent({
  kind: VAULT_DELIVERY_KIND,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['p', ev.pubkey]],
  content: nip44.v2.encrypt(vaultKeyHex, conversationKey),
}, operatorSk)

fanout.send(['EVENT', delivery])
console.log(`\ndelivery ${delivery.id.slice(0, 16)}… published to ${live.length} relay(s)`)
console.log('the device unlocks silently; confirm with scripts/device-status.mjs')

// Give the sockets a moment to flush before tearing them down.
setTimeout(() => { fanout.close(); exit(0) }, 3000)
