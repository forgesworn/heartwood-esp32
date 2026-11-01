// Pure half of `net-config.mjs --set-config`: the SET_NET_CONFIG (0x54)
// payload built from a config file and the board's GET_NET_CONFIG answer.
//
// SET_NET_CONFIG replaces the WHOLE stored config, op_mgmt (the relay
// management key) included. So the operator is never taken from the file: it
// is copied from the board unless `--op-mgmt` names another (or `none`), and
// the card the board will show is worked out here the same way the firmware
// does (common/src/net_config.rs `operator_change` / `set_net_config_title`),
// so the bench knows what to expect, and whether the frame is a recovery that
// takes the screen from a relay card (operator kept) or an ordinary card that
// is refused under one (operator changed).

export const SET_NET_CONFIG = 0x54

const HEX64 = /^[0-9a-fA-F]{64}$/

/**
 * The key the board would use for `op`, lowercased, or null for none. The
 * board also needs it to be a curve point; this does not check that, so an
 * off-curve key is predicted as a key but NACKed "invalid config".
 */
function operatorKey(op) {
  return typeof op === 'string' && HEX64.test(op) ? op.toLowerCase() : null
}

/**
 * @param {object} current  the board's GET_NET_CONFIG answer
 * @param {object} file     { ssid, password, relays?, mode, networks? }
 * @param {{ opMgmt?: string }} [options]  `opMgmt`: 64 hex, or 'none'
 * @returns {{ payload: Buffer, change: 'kept'|'added'|'replaced'|'removed', title: string }}
 */
export function buildSetNetConfig(current, file, { opMgmt } = {}) {
  if (!current || current.configured !== true) throw new Error('the board has no stored config to compare with')
  if (!file || typeof file !== 'object' || Array.isArray(file)) throw new Error('the config file must hold a JSON object')
  if ('op_mgmt' in file) throw new Error('leave op_mgmt out of the file: it is copied from the board, or set with --op-mgmt')
  if (typeof file.ssid !== 'string') throw new Error('ssid must be a string')
  if (typeof file.password !== 'string') throw new Error('password must be a string (the board only reports whether one is set)')
  if (file.mode !== 'usb' && file.mode !== 'wifi') throw new Error('mode must be "usb" or "wifi"')
  const relays = file.relays ?? []
  if (!Array.isArray(relays) || relays.some((r) => typeof r !== 'string')) throw new Error('relays must be a list of URLs')

  // SET_NET_CONFIG replaces the fallback list too, and GET_NET_CONFIG serves
  // it without passwords, so it cannot be copied: the file must restate it.
  const stored = Array.isArray(current.networks) ? current.networks.length : 0
  if (stored > 0 && file.networks === undefined) {
    throw new Error(`the board holds ${stored} fallback network(s); list them under "networks" in the file (with passwords), or this would erase them`)
  }

  let op
  // A stored operator that is not 64 hex digits is no operator, and the board
  // now refuses one in a frame: send none, which it also reads as unchanged.
  if (opMgmt === undefined) op = operatorKey(current.op_mgmt) ?? ''
  else if (opMgmt === 'none') op = ''
  else if (HEX64.test(opMgmt)) op = opMgmt.toLowerCase()
  else throw new Error('--op-mgmt takes 64 hex digits or "none"')

  const cfg = { ssid: file.ssid, password: file.password, relays, mode: file.mode, op_mgmt: op }
  if (file.networks !== undefined) cfg.networks = file.networks

  const before = operatorKey(current.op_mgmt)
  const after = operatorKey(op)
  let change
  if (after === before) change = 'kept'
  else if (after === null) change = 'removed'
  else change = before === null ? 'added' : 'replaced'
  const title = {
    kept: 'Set network config?',
    added: `New operator?\n${after?.slice(0, 8)}... +network`,
    replaced: `Replace operator?\n${after?.slice(0, 8)}... +network`,
    removed: 'Remove operator?\n+ set network',
  }[change]
  return { payload: Buffer.from(JSON.stringify(cfg)), change, title }
}

// ---------------------------------------------------------------------------
// PATCH_NET_CONFIG (0x5e) — the USB-only relays editor's frame.

/** Physical-USB network patch frame (firmware net_config_store.rs). */
export const PATCH_NET_CONFIG = 0x5e

const HOST_RULE = /^[0-9a-zA-Z.-]+$/

/**
 * Pure half of `net-patch.mjs`: the PATCH_NET_CONFIG payload for a relay-list
 * replacement. Mirrors the firmware's own bounds (validate_remote_net_config
 * in common/src/net_config.rs: 1-8 relays, each a wss:// URL of at most 255
 * bytes on a dotted host, port empty or exactly 443) so a bad list fails
 * here, not on the card. Only `relays` is patched: mode, network, passwords
 * and the fallback list all stay as stored, so no password ever crosses this
 * script.
 *
 * @param {object} current  the board's GET_NET_CONFIG answer (revision required)
 * @param {string[]} relays the replacement relay list, in priority order
 * @returns {{ payload: Buffer }}
 */
export function buildNetConfigPatchRelays(current, relays) {
  const revision = current?.revision
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('board answered without a config revision')
  if (!Array.isArray(relays) || relays.length === 0 || relays.length > 8) throw new Error('one to eight relays')
  for (const relay of relays) {
    if (typeof relay !== 'string' || !relay.startsWith('wss://') || relay.length > 255) throw new Error('relay must be a wss:// URL no longer than 255 bytes')
    const authority = relay.slice(6).split(/[/?#]/)[0] ?? ''
    const host = authority.split(':')[0] ?? ''
    const port = authority.slice(host.length)
    if (port !== '' && port !== ':443') throw new Error('relay URL port must be 443')
    if (authority.includes('@') || host === '' || !HOST_RULE.test(host) || ![...host].some((b) => /[0-9a-zA-Z]/.test(b))) throw new Error(`relay URL requires a nonempty host: ${relay}`)
  }
  if (new Set(relays).size !== relays.length) throw new Error('duplicate relay')
  return { payload: Buffer.from(JSON.stringify({ base_revision: revision, patch: { relays } })) }
}
