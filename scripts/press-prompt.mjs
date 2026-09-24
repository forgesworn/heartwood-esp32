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
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { argv, env, platform } from 'node:process'

/** Seconds between reminders while a window is open. Long enough not to
 *  nag, short enough to catch you inside a 30-second approval window. */
const REPEAT_MS = 8000

/** A card's window is 30 s. A "wait, then press" plan must leave the owner
 *  most of it: being asked with 10 s left is a scramble, not a press. */
const CARD_WINDOW_S = 30
const MIN_TIME_TO_PRESS_S = 20

/** Recorded prompts, if present: `<dir>/<clip>.mp3` (HEARTWOOD_VOICE_DIR,
 *  default ~/heartwood-bench/voice). Anything missing falls back to `say`. */
const VOICE_DIR = env.HEARTWOOD_VOICE_DIR ?? join(homedir(), 'heartwood-bench', 'voice')

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

/** A short attention sound, then the words: the recorded `clip` when there
 *  is one, otherwise whatever the platform can speak. */
export function chime(spoken, clip) {
  if (platform === 'darwin') {
    const recorded = clip && join(VOICE_DIR, `${clip}.mp3`)
    if (recorded && existsSync(recorded)) {
      play('sh', ['-c', 'afplay /System/Library/Sounds/Glass.aiff; afplay "$0"', recorded])
      return
    }
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
  chime(`Approve on the device: ${what}`, 'approve')
}

/**
 * Ask for a press and keep asking until the caller says it landed.
 *
 * Returns a `stop()` — call it the moment the request is answered, however it
 * was answered, so a denial or an expiry silences the prompt too.
 */
export function startPressPrompt(what, { hold = '2 s', intervalMs = REPEAT_MS } = {}) {
  promptForPress(what, { hold })
  const timer = setInterval(() => chime('Still waiting for your approval', 'still-waiting'), intervalMs)
  // Never hold the process open on the reminder alone.
  timer.unref?.()
  let stopped = false
  return () => {
    if (stopped) return
    stopped = true
    clearInterval(timer)
  }
}

/**
 * Say what the finger on the device should do, per `--press` style plans:
 *   'now'   ask straight away (the default, as before)
 *   'never' say NOT to press, and keep saying it: the card is meant to be
 *           left alone (an expiry bench, or a card another step must cancel)
 *   <n>     say "card coming, don't press yet", then ask after n seconds,
 *           for a bench that has to do something while the card is up
 *
 * Returns `stop()`, as startPressPrompt does.
 */
export function startPressPlan(what, plan = 'now', { hold = '2 s', intervalMs = REPEAT_MS } = {}) {
  if (plan === 'now') return startPressPrompt(what, { hold, intervalMs })
  if (plan === 'never') {
    console.log(`\n>>> DO NOT APPROVE ON THE DEVICE: ${what} — leave the card alone\n`)
    chime(`Do not approve on the device. Leave ${what} alone`, 'do-not-press')
    const timer = setInterval(() => chime('Still do not press', 'still-do-not-press'), intervalMs)
    timer.unref?.()
    return () => clearInterval(timer)
  }
  const seconds = Number(plan)
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error(`press plan must be now, never or a number of seconds, not ${plan}`)
  }
  if (seconds > CARD_WINDOW_S - MIN_TIME_TO_PRESS_S) {
    throw new Error(
      `a ${seconds} s wait leaves ${CARD_WINDOW_S - seconds} s of the card window to press in; ` +
        `ask within ${CARD_WINDOW_S - MIN_TIME_TO_PRESS_S} s and do the bench's own step sooner`,
    )
  }
  console.log(`\n>>> DO NOT PRESS YET: ${what} — you will be asked in ${seconds} s\n`)
  chime("Card coming. Don't press yet", 'dont-press-yet')
  let stopInner = () => {}
  let stopped = false
  const timer = setTimeout(() => {
    if (!stopped) stopInner = startPressPrompt(what, { hold, intervalMs })
  }, seconds * 1000)
  timer.unref?.()
  return () => {
    stopped = true
    clearTimeout(timer)
    stopInner()
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
