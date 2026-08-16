#!/usr/bin/env node
// Audible prompt for the steps that need a finger on the device.
//
// A bench run can sit for a minute before it wants anything, and the request
// only shows up as a line of console output and a card on a small OLED. If
// you are not watching the terminal at that moment the window expires and the
// step reads as a denial — which has cost this bench a false "denied" and a
// false "stuck button" already.
//
// So: chime, say it, and KEEP saying it until the request is answered. A
// one-shot prompt is no good if you are in another room when it fires.
//
// Also runnable directly, for any flow that will need a press:
//   node scripts/press-prompt.mjs "the sign request"
//   node scripts/press-prompt.mjs --repeat "the sign request"   (ctrl-c stops)
//
// Best effort by design: no sound must ever fail a bench step, so every
// player is fire-and-forget and a machine without one just gets the text.

import { spawn } from 'node:child_process'
import { argv, platform } from 'node:process'

/** Seconds between reminders while a window is open. Long enough not to
 *  nag, short enough to catch you inside a 30-second approval window. */
const REPEAT_MS = 8000

/** Fire and forget — never throws, never blocks, never fails a step. */
function play(command, args) {
  try {
    const child = spawn(command, args, { stdio: 'ignore', detached: true })
    child.on('error', () => {})
    child.unref()
  } catch {
    /* no audio here; the printed prompt still stands */
  }
}

/** A short attention sound, and the words if the platform can speak. */
export function chime(spoken) {
  if (platform === 'darwin') {
    play('afplay', ['/System/Library/Sounds/Glass.aiff'])
    if (spoken) play('say', ['-v', 'Daniel', spoken])
    return
  }
  if (platform === 'linux') {
    play('paplay', ['/usr/share/sounds/freedesktop/stereo/complete.oga'])
    if (spoken) play('spd-say', [spoken])
  }
}

/**
 * Ask for a physical press, once.
 *
 * `what` is the on-screen decision, e.g. "the sign request".
 */
export function promptForPress(what, { hold = '2 s' } = {}) {
  console.log(`\n>>> APPROVE ON THE DEVICE: ${what} — hold the button ${hold}\n`)
  chime(`Approve on the device: ${what}`)
}

/**
 * Ask for a press and keep asking until the caller says it landed.
 *
 * Returns a `stop()` — call it the moment the request is answered, however it
 * was answered, so a denial or an expiry silences the prompt too.
 */
export function startPressPrompt(what, { hold = '2 s', intervalMs = REPEAT_MS } = {}) {
  promptForPress(what, { hold })
  const timer = setInterval(() => chime('Still waiting for your approval'), intervalMs)
  // Never hold the process open on the reminder alone.
  timer.unref?.()
  let stopped = false
  return () => {
    if (stopped) return
    stopped = true
    clearInterval(timer)
  }
}

// Direct invocation: sound the prompt for anything that is about to need one.
if (import.meta.url === `file://${process.argv[1]}`) {
  const repeat = argv.includes('--repeat')
  const what = argv.slice(2).filter((a) => a !== '--repeat').join(' ') || 'the pending request'
  if (repeat) {
    const stop = startPressPrompt(what)
    process.on('SIGINT', () => {
      stop()
      process.exit(0)
    })
    // Hold the process open so the reminders keep coming.
    setInterval(() => {}, 1 << 30)
  } else {
    promptForPress(what)
  }
}
