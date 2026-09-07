#!/usr/bin/env node
// scripts/vault-unlock.mjs
//
// Host-side vault unlock over USB: SESSION_AUTH (0x21) with the bridge
// secret, then VAULT_UNLOCK (0x63) with the vault key. This is the same
// sequence heartwoodd's auto-unlock performs — usable standalone on a bench
// where no daemon is running. Secrets are read from files, never printed.
//
// Native USB can enumerate before the locked command loop is ready, so session
// auth retries for up to a minute. The unseal then runs a deliberately slow KDF
// per identity, so its ACK wait is generous: measured 2026-09-07 on a bench V4
// with three masters, ACK came back 73.8 s after SESSION_ACK, not the ~26 s
// this file used to claim. A wait that long with nothing on the terminal is
// the whole reason for the heartbeat below.
//
// Two things this does before and during that wait, both learned the hard way
// on 2026-09-07 (see #117):
//
//   * It asks PROVISION_LIST first. An unlock sent blind to a device that is
//     already unlocked runs the whole KDF only to answer `already unlocked`,
//     which is 25 s spent to learn nothing. `locked` is in that reply, it is
//     served in the locked relay phase, and it costs one round trip.
//   * It ticks while the unseal runs. A silent 25 s is indistinguishable from
//     a wedged board, which is exactly what makes an operator pull the cable
//     and start again — and the second attempt then hits the case above.
//
// Usage:
//   node scripts/vault-unlock.mjs --port /dev/cu.usbmodemXXXX \
//     --secret-file ~/heartwood-bench/bridge.secret \
//     --vault-key-file ~/heartwood-bench/vault.key
//   [--force]   unlock even if the device reports itself already unlocked

import { argv, env, stdout } from 'node:process'
import { readFileSync } from 'node:fs'

import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { authenticateSession } from './lib/session-auth.mjs'

const PROVISION_LIST = 0x05
const PROVISION_LIST_RESPONSE = 0x07
const SESSION_AUTH = 0x21
const SESSION_ACK = 0x22
const VAULT_UNLOCK = 0x63

function arg(name) {
  const i = argv.indexOf(name)
  return i === -1 ? undefined : argv[i + 1]
}

function readHex32(path, what) {
  const hex = readFileSync(path, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    console.error(`${what} file must contain exactly 64 lowercase hex characters`)
    process.exit(2)
  }
  return Buffer.from(hex, 'hex')
}

const PORT = arg('--port')
const SECRET_FILE = arg('--secret-file')
const VAULT_KEY_FILE = arg('--vault-key-file')
const FORCE = argv.includes('--force')
if (!PORT || !SECRET_FILE || !VAULT_KEY_FILE) {
  console.error(
    'usage: node scripts/vault-unlock.mjs --port <port> --secret-file <path> --vault-key-file <path> [--force]')
  process.exit(2)
}

const secret = readHex32(SECRET_FILE, 'bridge secret')
const vaultKey = readHex32(VAULT_KEY_FILE, 'vault key')

const session = await openFramedPort(PORT, { env }).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

// 1. Is there anything to do? Cheap, and served while locked.
if (!FORCE) {
  const listed = await session.request(PROVISION_LIST, [PROVISION_LIST_RESPONSE], {
    deadlineMs: 10_000,
  })
  if (listed && listed.type === PROVISION_LIST_RESPONSE) {
    try {
      const masters = JSON.parse(listed.payload.toString())
      const locked = masters.filter((m) => m.locked)
      if (masters.length && locked.length === 0) {
        console.log(`Already unlocked — ${masters.length} master(s), none sealed. Nothing to do.`)
        session.close()
        process.exit(0)
      }
      console.log(`${locked.length} of ${masters.length} master(s) sealed; unlocking.`)
    } catch {
      // A reply we cannot read is not a reason to refuse the unlock.
      console.log('Could not read the master list; unlocking anyway.')
    }
  }
  // No reply is not "unlocked": a device mid-KDF or still enumerating simply
  // has not answered yet, and refusing here would be worse than the 25 s.
}

// 2. Authenticate. Retries because native USB can enumerate before the
//    firmware reaches its locked command loop.
const authResult = await authenticateSession({
  sendAuth: () => session.send(SESSION_AUTH, secret),
  waitForAck: (timeoutMs) => session.waitFor([SESSION_ACK], timeoutMs),
  onAttempt: (attempt, attempts) => console.log(`SESSION_AUTH (${attempt}/${attempts})...`),
})
if (!authResult) {
  console.error('No SESSION_ACK after 6 attempts over 60 s.')
  session.close()
  process.exit(1)
}
const code = authResult.reply.payload[0]
if (code !== 0x00) {
  console.error(
    code === 0x01 ? 'SESSION_ACK 0x01 — wrong bridge secret.'
      : code === 0x02 ? 'SESSION_ACK 0x02 — no bridge secret configured on the device.'
        : `SESSION_ACK 0x${code.toString(16)} — unexpected.`)
  session.close()
  process.exit(1)
}

// 3. Unseal, and say so while it runs. The device is deriving a key per
//    identity and cannot answer until it finishes; silence here reads as a
//    hang, so keep a heartbeat on the terminal.
console.log('Authenticated. VAULT_UNLOCK — slow unseal, around 75 s for three masters.')
const started = Date.now()
const tick = setInterval(() => {
  const secs = Math.round((Date.now() - started) / 1000)
  stdout.write(`\r  unsealing... ${secs}s elapsed (do not unplug)`)
}, 1000)

session.send(VAULT_UNLOCK, vaultKey)
const reply = await session.waitFor([ACK], 120_000)

clearInterval(tick)
stdout.write('\r'.padEnd(50) + '\r')
session.close()

const took = ((Date.now() - started) / 1000).toFixed(1)
if (!reply) {
  console.error(`No reply within 120 s (waited ${took}s).`)
  process.exit(1)
}
if (reply.type === ACK) {
  console.log(`ACK in ${took}s — device unlocked; seeds unsealed and boot continuing.`)
  process.exit(0)
}
console.error(`NACK — ${reply.payload.toString() || 'unlock refused'}.`)
process.exit(1)
