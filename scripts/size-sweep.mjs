#!/usr/bin/env node
// scripts/size-sweep.mjs
//
// Message-size sweep for the signing oracle. Drives sign-test at increasing
// content sizes and records where the device stops returning a signature, so
// per-board `max_sign_bytes` comes from measurement rather than inference.
//
// See docs/plans/2026-08-06-message-size-limits.md for why these sizes.
//
// This exercises the PLAINTEXT USB path (frame 0x02), which carries no NIP-44
// and no base64, so it isolates "what can the signer parse and sign" from
// "what can the signer transport". Its only ceiling is MAX_PAYLOAD_SIZE. The
// relay path is bound lower, by MAX_WS_FRAME plus response_transportable, and
// needs a paired auto-signing app to sweep without a button press per step.
//
// Every sign_event on this path opens an approval prompt on the device
// display, so a human must press the button once per size. Sizes are swept
// low to high and the run stops at the first hard failure.
//
// Usage:
//   node scripts/size-sweep.mjs --port /dev/cu.usbmodemXXXX [--out results.json]

import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { argv } from 'node:process'

function arg(name, fallback = null) {
  const i = argv.indexOf(name)
  return i === -1 ? fallback : argv[i + 1]
}

const PORT = arg('--port')
const OUT = arg('--out')
const BIN = arg('--bin', 'sign-test/target/release/heartwood-sign-test')

if (!PORT) {
  console.error('usage: node scripts/size-sweep.mjs --port /dev/cu.usbmodemXXXX')
  process.exit(2)
}

// NIP-44 padding steps, plus the points either side of the frame ceiling.
// The request wraps content in ~190 bytes of event and JSON-RPC scaffolding,
// and the response adds an id and a signature, so content of 32768 cannot fit
// a 32768-byte frame. 32000 is the last size that should.
const SIZES = [1024, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32000, 32768]

// Printable ASCII with no JSON escapes, so content bytes map 1:1 to wire bytes
// and the sizes below mean what they say. Escape-heavy content is a separate
// axis worth its own run.
function content(n) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789 '
  let s = ''
  while (s.length < n) s += alphabet
  return s.slice(0, n)
}

// sign-test prints two different shapes. Responses over 2048 bytes get
// print_large_response_summary()'s "content: N bytes" / "signature: present"
// lines; anything smaller is pretty-printed JSON instead, so the small sizes
// need the signed event dug out of the "result" string or they read as
// failures. Handle both.
function parse(stdout) {
  const requestBytes = /Request JSON \((\d+) bytes\)/.exec(stdout)?.[1]
  const responseBytes = /Response JSON \((\d+) bytes\)/.exec(stdout)?.[1]
  let contentBytes = /^content: (\d+) bytes$/m.exec(stdout)?.[1]
  let signature = /^signature: (\w+)$/m.exec(stdout)?.[1]
  let error = /^error: (.+)$/m.exec(stdout)?.[1]

  if (!signature && !error) {
    // Pretty-printed small response: recover the JSON body after the header.
    const body = stdout.slice(stdout.indexOf('{', stdout.indexOf('Response JSON')))
    try {
      const response = JSON.parse(body.slice(0, body.lastIndexOf('}') + 1))
      if (response.error) error = JSON.stringify(response.error)
      if (typeof response.result === 'string') {
        const event = JSON.parse(response.result)
        contentBytes = String(event.content?.length ?? 0)
        signature = event.sig?.length === 128 ? 'present' : 'missing'
      }
    } catch {
      // Leave the fields null; the caller treats that as no_signature.
    }
  }

  return {
    requestBytes: requestBytes ? Number(requestBytes) : null,
    responseBytes: responseBytes ? Number(responseBytes) : null,
    signedContentBytes: contentBytes ? Number(contentBytes) : null,
    signature: signature ?? null,
    error: error ?? null,
  }
}

const results = []
console.log(`port ${PORT}`)
console.log(`sizes ${SIZES.join(', ')}`)
console.log('press the device button to approve each request\n')

for (const size of SIZES) {
  process.stdout.write(`content ${String(size).padStart(6)} B ... `)
  let stdout = ''
  let outcome = 'ok'
  try {
    stdout = execFileSync(
      BIN,
      ['--port', PORT, '--method', 'sign_event', '--kind', '1', '--content', content(size)],
      { encoding: 'utf8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024 }
    )
  } catch (e) {
    stdout = `${e.stdout ?? ''}${e.stderr ?? ''}`
    outcome = e.killed ? 'timeout' : 'failed'
  }

  const parsed = parse(stdout)
  // A signature that came back covering exactly the bytes we sent is the only
  // outcome that counts as a pass. Everything else, including a well-formed
  // NIP-46 error, is a ceiling.
  const signed = parsed.signature === 'present' && parsed.signedContentBytes === size
  if (outcome === 'ok' && !signed) outcome = parsed.error ? 'device_error' : 'no_signature'

  // Name the two distinct ways this path fails, because they mean different
  // things. The request never leaving the host is a clean client-side bound.
  // A device timeout after an approved press is NOT: write_owned_frame
  // (protocol.rs:308) drops a response over MAX_PAYLOAD_SIZE with only a
  // log::warn, and that log goes to an unrouted console. So the device signed
  // the event, charged the user a button press, and discarded the result in
  // silence. Worth calling out separately in the results.
  if (/too large to fit in a serial frame/i.test(stdout)) outcome = 'request_too_large'
  else if (/Timeout waiting for response from device/i.test(stdout)) outcome = 'silent_drop'

  results.push({ size, outcome, ...parsed })
  console.log(
    outcome === 'ok'
      ? `signed  (req ${parsed.requestBytes} B, resp ${parsed.responseBytes} B)`
      : `${outcome}${parsed.error ? `: ${parsed.error}` : ''}`
  )

  // An unanswered approval prompt is a missing human, not a size ceiling.
  // Recording it as one would understate max_sign_bytes for the whole board,
  // so abort loudly instead of writing a false result.
  if (/timeout/i.test(parsed.error ?? '')) {
    console.log('\nAPPROVAL NOT ANSWERED: the device prompt expired unpressed.')
    console.log('This is not a size limit. Re-run with someone at the button.')
    process.exit(3)
  }

  if (outcome === 'failed' || outcome === 'timeout') {
    console.log('\nstopping at first hard failure')
    break
  }
}

const passed = results.filter((r) => r.outcome === 'ok')
const ceiling = passed.length ? passed[passed.length - 1].size : 0
console.log(`\nlargest signed content: ${ceiling} B`)
if (passed.length) {
  const last = passed[passed.length - 1]
  console.log(`at that size: request ${last.requestBytes} B, response ${last.responseBytes} B`)
}

if (OUT) {
  writeFileSync(OUT, JSON.stringify({ port: PORT, path: 'usb-plaintext-0x02', results }, null, 2))
  console.log(`wrote ${OUT}`)
}
