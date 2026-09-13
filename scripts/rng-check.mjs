#!/usr/bin/env node
// scripts/rng-check.mjs
//
// Checklist section 22 item 4, as one command: does this board's hardware RNG
// produce a DIFFERENT 32-byte draw on each boot?
//
// This is the one question the firmware cannot answer about itself in a single
// boot. Each boot compares its draw against a hash of the previous boot's, so
// a stuck RNG shows up as soon as one boot follows another with no wipe in
// between. Run this before trusting any key a board has generated.
//
// The answer is read from FIRMWARE_INFO (`rng`, `rng_cause`), a read-only
// query served in every device state. It is NOT read from the serial log: the
// log console is compiled out on every board so it cannot corrupt the frame
// protocol, and the first version of this script, which waited for a log line,
// could never have heard one (found on a real V4, 2026-09-13).
//
// It never writes the DTR/RTS lines, which on USB-Serial-JTAG are the chip's
// reset and boot straps, so it cannot reset a signer. When a reboot is needed
// it asks you to press RST and watches uptime go backwards.
//
// Usage:
//   node scripts/rng-check.mjs
//   node scripts/rng-check.mjs --port /dev/cu.usbmodem1101
//
// Exit codes: 0 the RNG moved, 1 the RNG is broken, 2 no verdict (old
// firmware, storage fault, no reboot seen, or the board did not answer).

import { argv, exit, stdout } from 'node:process'

import { openFramedPort } from './lib/port.mjs'
import { rngVerdict } from './lib/rng-verdict.mjs'

const FIRMWARE_INFO = 0x59
const FIRMWARE_INFO_RESPONSE = 0x5a

const args = argv.slice(2)
const flag = (name) => {
  const i = args.indexOf(name)
  return i === -1 ? null : (args[i + 1] ?? '')
}
const REBOOT_WAIT_MS = Number(flag('--timeout') ?? 600_000)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function resolvePath() {
  const explicit = flag('--port')
  if (explicit) return explicit
  const { SerialPort } = await import('serialport').catch(async () =>
    import(new URL(`${process.env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../', import.meta.url)).href),
  )
  const likely = (await SerialPort.list()).filter((p) => /usbmodem|usbserial|ttyACM|ttyUSB/.test(p.path))
  if (likely.length === 1) return likely[0].path
  if (likely.length === 0) {
    console.error('No serial device found. Plug the signer in, then re-run.')
    exit(2)
  }
  console.error('Several serial devices found; pass one with --port:')
  for (const p of likely) console.error(`  ${p.path}`)
  exit(2)
}

/**
 * One FIRMWARE_INFO read, opening and closing the port around it. The port can
 * report busy for a few seconds after a plug-in or a reset, and vanishes
 * entirely while a native-USB board re-enumerates, so a failed open is retried
 * until `giveUpMs`. Returns null when nothing answered.
 */
async function readInfo(path, giveUpMs = 20_000) {
  const giveUp = Date.now() + giveUpMs
  for (;;) {
    let session = null
    try {
      session = await openFramedPort(path)
      const reply = await session.request(FIRMWARE_INFO, [FIRMWARE_INFO_RESPONSE], {
        deadlineMs: 8_000,
        intervalMs: 1_000,
      })
      if (reply?.type === FIRMWARE_INFO_RESPONSE) return JSON.parse(reply.payload.toString())
    } catch {
      // busy, gone, or mid-boot: retry below
    } finally {
      try {
        session?.close()
      } catch {
        // already closed by a disconnect
      }
    }
    if (Date.now() > giveUp) return null
    await sleep(750)
  }
}

function describe(info) {
  return `${info.version} on ${info.board}, up ${info.uptime_s}s — rng=${info.rng ?? '?'} cause=${info.rng_cause ?? '?'}`
}

/** Print a verdict and exit. Returns only for 'needs-reboot' before a reboot. */
function settle(info, { afterReboot }) {
  const { kind } = rngVerdict(info)
  switch (kind) {
    case 'pass':
      console.log('\nVERDICT: PASS. This boot\'s draw differed from the previous boot\'s, and')
      console.log('the firmware verified it against the stored proof. The RNG is live.')
      exit(0)
    case 'broken':
      console.error(`\nVERDICT: FAIL (${info.rng_cause}). The hardware RNG repeated itself across a`)
      console.error('reboot. This is the Coldcard failure mode: treat every key this board')
      console.error('generated as reproducible, and generate nothing more on it.')
      exit(1)
    case 'needs-reboot':
      if (afterReboot) {
        console.error('\nNo verdict: the board rebooted but still had no proof to compare against,')
        console.error('so the proof is not surviving a reboot. Check NVS is writable. The board')
        console.error('refuses to generate keys in this state, so nothing new is at risk.')
        exit(2)
      }
      return
    case 'storage':
      console.error(`\nNo verdict on the RNG (${info.rng_cause}): a storage fault stopped the`)
      console.error('comparison. This is NOT evidence the RNG is broken. The board refuses to')
      console.error('generate keys until it clears.')
      exit(2)
    case 'not-run':
      console.error('\nNo verdict: the self-test has not run this boot. Try again in a moment.')
      exit(2)
    case 'unsupported':
      console.error(`\nNo verdict: firmware ${info?.version ?? '(unknown)'} does not report the RNG self-test.`)
      console.error('Its result was only ever logged, and the log console is compiled out on')
      console.error('every board, so there is nothing to read. Flash firmware that reports')
      console.error('rng/rng_cause in FIRMWARE_INFO, then re-run. Its first boot compares')
      console.error('against the proof this firmware has been storing, so no wipe is needed.')
      exit(2)
    default:
      console.error(`\nNo verdict: unrecognised rng_cause "${info.rng_cause}". Update this script.`)
      exit(2)
  }
}

const path = await resolvePath()
console.log(`Reading ${path}...`)

const first = await readInfo(path)
if (!first) {
  console.error('The board did not answer FIRMWARE_INFO. Check the port, then re-run.')
  exit(2)
}
console.log(`now:    ${describe(first)}`)
settle(first, { afterReboot: false })

// First boot after a flash or a wipe: one reboot gives the comparison.
console.log('\nThis boot had no previous draw to compare against (first boot after a flash')
console.log('or a wipe). One reboot is enough to get a verdict.')
stdout.write('\nPress RST (not PRG) on the board once. Do NOT factory reset. Waiting...')

const deadline = Date.now() + REBOOT_WAIT_MS
for (;;) {
  if (Date.now() > deadline) {
    console.error(`\n\nNo reboot seen in ${REBOOT_WAIT_MS / 1000}s — no verdict.`)
    exit(2)
  }
  await sleep(2_000)
  const info = await readInfo(path, 5_000)
  // A reboot shows as uptime going backwards. last_reset cannot tell an RST
  // press from a power cycle on these boards — both read "power-on".
  if (info && info.uptime_s < first.uptime_s) {
    console.log(`\nafter:  ${describe(info)}`)
    settle(info, { afterReboot: true })
  }
}
