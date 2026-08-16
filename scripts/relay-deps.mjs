// Shared dependency resolution for the relay-side bench tools.
//
// This repo is Rust and carries no node_modules of its own. The relay tools
// need `ws` and `nostr-tools`, which a sibling sapwood checkout already has,
// so they resolve in that order: an installed copy first (if you ran `npm i`
// somewhere that covers this directory), then the sibling checkout, then
// SAPWOOD_DIR for a non-standard layout.
//
//   SAPWOOD_DIR=~/code/sapwood node scripts/mgmt-request.mjs --method get_status
//
// Kept in one place because four tools need the same four packages, and a
// resolution that works for one but not the others is a confusing failure.

import { env } from 'node:process'

async function loadDep(name, subpath) {
  const candidates = [
    name,
    new URL(
      `${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/${subpath}`,
      new URL('../', import.meta.url),
    ).href,
  ]
  for (const candidate of candidates) {
    try {
      return await import(candidate)
    } catch {
      /* try the next one */
    }
  }
  throw new Error(
    `cannot resolve ${name}; set SAPWOOD_DIR to a checkout that has it, or npm install ${name}`,
  )
}

const wsModule = await loadDep('ws', 'ws/index.js')
const pure = await loadDep('nostr-tools/pure', 'nostr-tools/lib/esm/pure.js')
const nip19Module = await loadDep('nostr-tools/nip19', 'nostr-tools/lib/esm/nip19.js')
const nip44Module = await loadDep('nostr-tools/nip44', 'nostr-tools/lib/esm/nip44.js')

/** `ws` is CommonJS, so the constructor arrives as the module default. */
export const WebSocket = wsModule.default ?? wsModule
export const { finalizeEvent, getPublicKey } = pure
export const nip19 = nip19Module
export const nip44 = nip44Module

/** Read one CLI argument, or a default when it was not given. */
export function arg(argv, name, dflt) {
  const i = argv.indexOf(name)
  return i === -1 ? dflt : argv[i + 1]
}

/** Accept an identity as either 64 hex chars or an npub. */
export function toHex(value, what = 'value') {
  if (/^[0-9a-f]{64}$/.test(value)) return value
  const decoded = nip19.decode(value)
  if (decoded.type !== 'npub') throw new Error(`${what} must be 64 hex chars or an npub`)
  return decoded.data
}

/** The bench relay these tools default to; override with --relay. */
export const DEFAULT_RELAY = env.HEARTWOOD_RELAY ?? 'wss://relay.trotters.cc'
