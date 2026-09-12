// scripts/lib/rng-log.mjs
//
// Classify the firmware's boot RNG self-test line.
//
// Split out of rng-check.mjs so it can be tested against the strings
// firmware/src/entropy.rs actually emits — see rng-log.test.mjs, which reads
// that source rather than trusting a copy kept in step by hand. A classifier
// that silently stops recognising "draw identical to last boot" would report a
// stuck RNG as inconclusive, which is the wrong way round to be wrong.
//
// The pre-2026-09-12 wording is still recognised so the script is useful on a
// board that has not been reflashed yet.

/**
 * @param {string} line
 * @returns {{verdict: 'passed'|'no-proof'|'repeated'|'constant'|'failed'|'unknown', line: string}|null}
 *   null when the line is not a self-test line at all.
 */
export function classify(line) {
  if (!/RNG self-test/i.test(line)) return null
  if (/FAILED/.test(line)) {
    if (/identical to last boot/i.test(line)) return { verdict: 'repeated', line }
    if (/constant draw/i.test(line)) return { verdict: 'constant', line }
    return { verdict: 'failed', line }
  }
  if (/passed/i.test(line)) return { verdict: 'passed', line }
  // Both wordings for "nothing to compare against yet".
  if (/no previous draw/i.test(line)) return { verdict: 'no-proof', line }
  return { verdict: 'unknown', line }
}

/** Verdicts that mean the board must not be trusted to generate key material. */
export const FATAL_VERDICTS = new Set(['repeated', 'constant'])
