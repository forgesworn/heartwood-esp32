// scripts/lib/rng-verdict.mjs
//
// Turn a board's FIRMWARE_INFO into a verdict on its hardware RNG.
//
// The boot self-test's result is read from FIRMWARE_INFO's `rng` and
// `rng_cause`, not from the log. The log console is compiled out on every
// board — log bytes would interleave with the frame protocol on the same USB
// port — so `RNG self-test passed` never reaches anyone. An earlier version of
// rng-check.mjs listened for exactly that line and could never have heard it.
//
// Every boot compares its draw against the previous boot's stored proof, so
// ONE reading from a boot that had a proof to compare against is already a
// verdict. Only a boot with no proof (first after a flash or a wipe) needs a
// reboot before it can say anything.
//
// Tested against common/src/entropy.rs itself (rng-verdict.test.mjs): a cause
// the firmware adds that this file does not know fails that test rather than
// reading as "unknown" at the bench.

/** Causes that mean the hardware RNG itself is broken. */
const BROKEN = new Set(['draw_repeated', 'constant_draw'])
/** Causes that mean the check could not run: storage faults, RNG unknown. */
const STORAGE = new Set(['proof_unreadable', 'proof_write_failed'])

/**
 * @param {Record<string, unknown>} info  Parsed FIRMWARE_INFO JSON.
 * @returns {{kind: 'pass'|'broken'|'needs-reboot'|'storage'|'not-run'|'unsupported'|'unknown', cause: string|null}}
 */
export function rngVerdict(info) {
  const cause = typeof info?.rng_cause === 'string' ? info.rng_cause : null
  if (cause === null) return { kind: 'unsupported', cause }
  if (cause === 'draw_moved') return { kind: 'pass', cause }
  if (BROKEN.has(cause)) return { kind: 'broken', cause }
  if (cause === 'no_previous_draw') return { kind: 'needs-reboot', cause }
  if (STORAGE.has(cause)) return { kind: 'storage', cause }
  if (cause === 'not_run') return { kind: 'not-run', cause }
  return { kind: 'unknown', cause }
}

/** Every cause this file assigns a meaning to. Exported for the drift test. */
export const KNOWN_CAUSES = new Set([
  'draw_moved',
  'no_previous_draw',
  'not_run',
  ...BROKEN,
  ...STORAGE,
])

/** The causes treated as a broken RNG. Exported for the drift test. */
export const BROKEN_CAUSES = BROKEN
