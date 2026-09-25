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

/** The key the board would use for `op`, lowercased, or null for none. */
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

  let op
  if (opMgmt === undefined) op = current.op_mgmt ?? ''
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
