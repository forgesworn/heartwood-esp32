// Audible prompt for the steps that need a finger on the device.
//
// A bench run can sit for a minute before it wants anything, and the request
// only shows up as a line of console output and a card on a small OLED. If
// you are not watching the terminal at that moment the window expires and the
// step reads as a denial — which has cost this bench a false "denied" and a
// false "stuck button" already. So say it out loud.
//
// Best effort by design: no sound must ever fail a bench step, so every
// player is fire-and-forget and a machine without one just gets the text.

import { spawn } from 'node:child_process'
import { platform } from 'node:process'

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
    if (spoken) play('say', [spoken])
    return
  }
  if (platform === 'linux') {
    play('paplay', ['/usr/share/sounds/freedesktop/stereo/complete.oga'])
    return
  }
  process.stdout.write('')
}

/**
 * Ask for a physical press: prints the instruction, sounds the chime, and
 * says it. `what` is the on-screen decision, e.g. "the sign request".
 */
export function promptForPress(what, { hold = '2 s' } = {}) {
  const line = `>>> APPROVE ON THE DEVICE: ${what} — hold the button ${hold}`
  console.log(`\n${line}\n`)
  chime('Approve on the device')
}
