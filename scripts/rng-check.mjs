#!/usr/bin/env node
// scripts/rng-check.mjs
//
// Checklist section 22 item 4, as one command: does this board's hardware RNG
// produce a DIFFERENT 32-byte draw on each boot?
//
// This is the only question the firmware cannot answer for you. The boot
// self-test compares each boot's draw against a hash of the previous boot's,
// so a stuck RNG is provable only across two boots with no wipe between them —
// a wipe erases the stored proof, which is exactly the hole the gate now
// closes. Run this BEFORE trusting any key a board has generated.
//
// Passive tap: opens the port without touching DTR/RTS, so it cannot itself
// reset the board or disturb a live signing session. It only reads.
//
// Usage:
//   node scripts/rng-check.mjs                 # auto-detect the port, two boots
//   node scripts/rng-check.mjs --port /dev/cu.usbmodem1101
//   node scripts/rng-check.mjs --once          # report this boot only, no reset
//
// Exit codes: 0 the RNG moved between boots, 1 it did not (or the board
// refused), 2 could not run the check.

import { argv, env, exit, stdout } from 'node:process'

import { classify } from './lib/rng-log.mjs'

const args = argv.slice(2)
const flag = (name) => {
  const i = args.indexOf(name)
  return i === -1 ? null : (args[i + 1] ?? '')
}
const ONCE = args.includes('--once')
const PORT_ARG = flag('--port')
const BOOT_WAIT_MS = Number(flag('--timeout') ?? 45_000)

const SerialPort = await (async () => {
  const candidates = [
    'serialport',
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../', import.meta.url)).href,
  ]
  for (const candidate of candidates) {
    try {
      return (await import(candidate)).SerialPort
    } catch {
      // try the next candidate
    }
  }
  console.error('cannot resolve node-serialport; set SAPWOOD_DIR to a checkout that has it')
  exit(2)
})()

async function resolvePort() {
  if (PORT_ARG) return PORT_ARG
  const ports = await SerialPort.list()
  // The S3's native USB-Serial-JTAG and the V3's CP2102 bridge both show up as
  // usbmodem/usbserial; Bluetooth and wlan-debug never do.
  const likely = ports.filter((p) => /usbmodem|usbserial|ttyACM|ttyUSB/.test(p.path))
  if (likely.length === 1) return likely[0].path
  if (likely.length === 0) {
    console.error('No serial device found. Plug the signer in, then re-run.')
    console.error('Ports seen: ' + (ports.map((p) => p.path).join(', ') || 'none'))
    exit(2)
  }
  console.error('Several serial devices found; pass one with --port:')
  for (const p of likely) console.error(`  ${p.path}  ${p.manufacturer ?? ''}`)
  exit(2)
}

/** Read lines until one classifies, or the deadline passes. */
function awaitBootLine(port, deadlineMs) {
  return new Promise((resolve) => {
    let buffer = ''
    const timer = setTimeout(() => {
      port.off('data', onData)
      resolve(null)
    }, deadlineMs)
    const onData = (chunk) => {
      buffer += chunk.toString('latin1')
      let nl
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).replace(/\r$/, '')
        buffer = buffer.slice(nl + 1)
        const hit = classify(line)
        if (hit) {
          clearTimeout(timer)
          port.off('data', onData)
          resolve(hit)
          return
        }
      }
      // A long line with no newline is almost certainly binary frame traffic.
      if (buffer.length > 4096) buffer = ''
    }
    port.on('data', onData)
  })
}

const path = await resolvePort()
const port = new SerialPort({ path, baudRate: 115200, autoOpen: false })
// Never assert the reset lines: this script must not be able to reboot a
// signer that is mid-ceremony.
await new Promise((resolve, reject) => {
  port.open((err) => (err ? reject(err) : resolve()))
}).catch((err) => {
  console.error(`cannot open ${path}: ${err.message}`)
  exit(2)
})
port.set({ dtr: false, rts: false }, () => {})

console.log(`Watching ${path}.`)
console.log('The self-test line is printed once per boot, so press RESET on the board now.')

const first = await awaitBootLine(port, BOOT_WAIT_MS)
if (!first) {
  console.error(`\nNo RNG self-test line in ${BOOT_WAIT_MS / 1000}s.`)
  console.error('Press RESET while this is running, or check the port and baud rate.')
  port.close(() => {})
  exit(2)
}
console.log(`\nboot 1: ${first.line}`)

if (first.verdict === 'constant') {
  console.error('\nVERDICT: the draw was a constant 32 bytes. The entropy source is dead.')
  console.error('Treat every key this board generated as reproducible.')
  port.close(() => {})
  exit(1)
}
if (first.verdict === 'repeated') {
  console.error('\nVERDICT: this boot repeated the previous boot\'s draw. The RNG is stuck.')
  console.error('Treat every key this board generated as reproducible.')
  port.close(() => {})
  exit(1)
}

if (first.verdict === 'failed') {
  console.error('\nVERDICT: the self-test refused on its own (see the line above). The board')
  console.error('will not generate keys this boot. Fix the stated cause, then re-run.')
  port.close(() => {})
  exit(1)
}

if (ONCE) {
  console.log('\n--once: stopping after one boot. This says nothing about continuity.')
  port.close(() => {})
  exit(0)
}

if (first.verdict === 'no-proof') {
  console.log('\nNo stored proof — this is the first boot after a flash or a wipe.')
  console.log('That is expected, and on current firmware it also means key generation')
  console.log('is refused until the next boot proves the draw changed.')
}

stdout.write('\nPress RESET again (do NOT factory reset in between)...')
const second = await awaitBootLine(port, BOOT_WAIT_MS)
if (!second) {
  console.error(`\n\nNo second self-test line in ${BOOT_WAIT_MS / 1000}s — inconclusive.`)
  port.close(() => {})
  exit(2)
}
console.log(`\nboot 2: ${second.line}`)
port.close(() => {})

if (second.verdict === 'repeated' || second.verdict === 'constant') {
  console.error('\nVERDICT: FAIL. The draw did not change across a reset.')
  console.error('This is the Coldcard failure mode. Treat every key this board')
  console.error('generated as reproducible, and do not generate more on it.')
  exit(1)
}
if (second.verdict === 'passed') {
  console.log('\nVERDICT: PASS. The draw changed across a reset, and the firmware')
  console.log('verified it against the stored proof. The RNG is live.')
  exit(0)
}
if (second.verdict === 'no-proof') {
  console.error('\nVERDICT: inconclusive. The second boot still had no proof to compare')
  console.error('against, which means the proof is not surviving a reboot. Check that')
  console.error('NVS is writable — a board that can never store the proof can never')
  console.error('prove its RNG moves, and current firmware refuses to generate keys.')
  exit(1)
}
if (second.verdict === 'failed') {
  console.error('\nVERDICT: the self-test refused on its own (see the line above). The board')
  console.error('will not generate keys this boot. Fix the stated cause, then re-run.')
  exit(1)
}
console.error(`\nVERDICT: inconclusive — unrecognised line: ${second.line}`)
exit(2)
