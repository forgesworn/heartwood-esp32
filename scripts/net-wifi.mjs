#!/usr/bin/env node
// scripts/net-wifi.mjs
//
// Set the signer's WiFi credentials over the cable: the primary SSID and
// password, and the fallback network list the relay loop rotates through.
// PATCH_NET_CONFIG (0x5e), revision-bound, physically confirmed, reboots on
// ACK. net-mode.mjs already covered the mode switch; this covers the rest of
// the same frame, which until now only existed as hand-written one-offs.
//
// A fallback is not a nicety. `select_wifi_candidate` rotates
// `wifi_candidate_idx` on every failed join, and with one configured network
// that rotation re-selects the same AP for ever — so a single wedged access
// point is a permanent outage with nothing on the OLED but "WiFi unavailable".
// Diagnosed on the bench 2026-09-07: the board could see its own AP in a 0x55
// scan at -57 dBm with an unchanged WPA2 key and still not join it. Adding one
// fallback brought it back online in forty seconds and proved the firmware
// innocent in the same move.
//
// Passwords never go on the command line, where `ps` would show them. Give a
// file, or --from-keychain to read the AirPort password macOS already holds.
//
// Usage:
//   node scripts/net-wifi.mjs --port <port> --password-file psk.txt
//   node scripts/net-wifi.mjs --port <port> --ssid home --from-keychain
//   node scripts/net-wifi.mjs --port <port> --fallback other-ap=other.txt
//   node scripts/net-wifi.mjs --port <port> --fallback other-ap --from-keychain
//   node scripts/net-wifi.mjs --port <port> --clear-fallbacks
//
// The keychain recipe by hand, if you would rather see the file:
//   security find-generic-password -wa "<ssid>" > psk.txt && chmod 600 psk.txt

import { argv, env, platform } from 'node:process'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import { ACK, NACK } from './lib/frame.mjs'
import { openFramedPort } from './lib/port.mjs'
import { startPressPrompt } from './press-prompt.mjs'

const GET_NET_CONFIG = 0x5c
const GET_NET_CONFIG_RESPONSE = 0x5d
const PATCH_NET_CONFIG = 0x5e

function arg(name) {
  const index = argv.indexOf(name)
  return index === -1 ? undefined : argv[index + 1]
}
function argAll(name) {
  const values = []
  for (let i = 0; i < argv.length; i++) if (argv[i] === name) values.push(argv[i + 1])
  return values
}

const portPath = arg('--port')
const ssid = arg('--ssid')
const passwordFile = arg('--password-file')
const fromKeychain = argv.includes('--from-keychain')
const clearFallbacks = argv.includes('--clear-fallbacks')
const fallbackArgs = argAll('--fallback')

if (!portPath) {
  console.error('usage: node scripts/net-wifi.mjs --port <port> [--ssid <ssid>]')
  console.error('       [--password-file <path> | --from-keychain]')
  console.error('       [--fallback <ssid>[=<password-file>]]... [--clear-fallbacks]')
  process.exit(2)
}
if (clearFallbacks && fallbackArgs.length) {
  console.error('--clear-fallbacks and --fallback are mutually exclusive')
  process.exit(2)
}
if (passwordFile && fromKeychain) {
  console.error('--password-file and --from-keychain are mutually exclusive')
  process.exit(2)
}

/** The AirPort password macOS already holds for an SSID. Never echoed. */
function keychainPassword(network) {
  if (platform !== 'darwin') {
    throw new Error('--from-keychain needs macOS; pass a password file instead')
  }
  try {
    return execFileSync('security', ['find-generic-password', '-wa', network], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).replace(/\r?\n$/, '')
  } catch {
    throw new Error(`no AirPort password in the keychain for ${JSON.stringify(network)}`)
  }
}

/** `file` when a path was given for this network, otherwise the keychain. */
function readPassword(file, network) {
  const value = file
    ? readFileSync(file, 'utf8').replace(/\r?\n$/, '')
    : keychainPassword(network)
  // The device applies the same bounds and would answer a bare NACK; failing
  // here says which credential was wrong, before anyone reaches for a button.
  if (value.length < 8 || value.length > 63) {
    throw new Error(`password for ${JSON.stringify(network)} must be 8-63 characters (got ${value.length})`)
  }
  return value
}

function validateSsid(value) {
  if (!value || Buffer.byteLength(value) > 32) {
    throw new Error(`ssid ${JSON.stringify(value)} must be 1-32 bytes`)
  }
  return value
}

// Build the patch before opening the port, so a typo costs nothing. The
// primary password changes when a file is given, or when --from-keychain and
// --ssid together name a network to look up; a fallback takes its own file
// after `=`, or the keychain when --from-keychain is set.
const patch = {}
try {
  if (ssid) patch.ssid = validateSsid(ssid)
  if (passwordFile || (fromKeychain && ssid)) {
    patch.password = { action: 'set', value: readPassword(passwordFile, ssid) }
  }
  if (clearFallbacks) patch.networks = []
  if (fallbackArgs.length) {
    patch.networks = fallbackArgs.map((entry) => {
      const [name, file] = entry.split('=')
      validateSsid(name)
      if (!file && !fromKeychain) {
        throw new Error(`fallback ${JSON.stringify(name)} needs =<password-file> or --from-keychain`)
      }
      return { ssid: name, password: { action: 'set', value: readPassword(file, name) } }
    })
  }
} catch (error) {
  console.error(error.message)
  process.exit(2)
}

if (!Object.keys(patch).length) {
  console.error('nothing to change: pass --ssid, --password-file/--from-keychain, --fallback or --clear-fallbacks')
  process.exit(2)
}

const session = await openFramedPort(portPath, { env }).catch((error) => {
  console.error(error.message)
  process.exit(2)
})

const currentReply = await session.request(GET_NET_CONFIG, [GET_NET_CONFIG_RESPONSE])
if (!currentReply || currentReply.type === NACK) {
  session.close()
  console.error(currentReply
    ? 'device NACKed GET_NET_CONFIG — a locked device does not serve it; unlock first'
    : 'could not read the current network config')
  process.exit(1)
}
const current = JSON.parse(currentReply.payload.toString())
console.log(`current: ssid=${current.ssid} revision=${current.revision}`
  + ` fallbacks=[${(current.networks ?? []).map((n) => n.ssid).join(', ')}]`
  + ` stage=${current.runtime?.stage} error=${current.runtime?.last_error_class}`)

const summary = [
  patch.ssid ? `ssid -> ${patch.ssid}` : null,
  patch.password ? 'primary password' : null,
  patch.networks ? `fallbacks -> [${patch.networks.map((n) => n.ssid).join(', ')}]` : null,
].filter(Boolean).join(', ')
console.log(`patching revision ${current.revision}: ${summary}`)

const payload = Buffer.from(JSON.stringify({ base_revision: current.revision, patch }))

// The device gives a 45 s window and answers a bare "denied" for both a
// decline and an expiry, so a missed press is indistinguishable from a refusal
// from up here. Keep chiming until it is answered, and say which it was.
const stopPrompt = startPressPrompt('the "Change network?" card')
const reply = await session.requestApproval(PATCH_NET_CONFIG, [ACK], { payload, timeoutMs: 70_000 })
stopPrompt()
session.close()

if (!reply) {
  console.error('no reply; the device did not confirm the change')
  process.exit(1)
}
if (reply.type === NACK) {
  const reason = reply.payload.toString() || 'refused'
  console.error(reason === 'denied'
    ? 'NACK — denied: either the button was not held for 2 s, or the 45 s window expired'
    : `NACK — ${reason}`)
  process.exit(1)
}
console.log('ACK — saved; the device is rebooting and will come back locked.')
