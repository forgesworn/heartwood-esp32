//! One-button BIP-39 word entry for on-device recovery-phrase restore.
//!
//! Restoring an existing identity must happen ON the device — the phrase must
//! never be typed into the browser (same rule as on-device generation: the
//! secret never touches the host). The board has a single button, so a word is
//! entered by cycling a highlight through a small set of *choices* and
//! committing one at a time.
//!
//! The clever part is that the BIP-39 English wordlist is lexicographically
//! sorted, so [`words_by_prefix`](bip39::Language::words_by_prefix) returns a
//! contiguous slice and the set of valid *next* letters after any prefix is
//! tiny — usually a handful. Because no BIP-39 word's first four letters are a
//! prefix of another's, a word resolves uniquely within at most four letters
//! (often fewer), at which point the only remaining choice is to accept it. So
//! a whole word costs a few single-clicks to position the highlight and one
//! double-click to commit, never the 26-letter slog of a naive picker.
//!
//! This module is pure logic — no button, no display, no I/O — so the whole
//! state machine is unit-tested on the host; the firmware layers the gesture
//! detector and the OLED on top.

use bip39::Language;

const LANG: Language = Language::English;

/// One selectable option at the current entry step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Append this letter to the prefix.
    Letter(char),
    /// Accept this complete word — the prefix has resolved to it.
    Word(&'static str),
}

/// In-progress entry of a single BIP-39 word, identified by the prefix typed so
/// far. The empty prefix matches the whole wordlist.
#[derive(Debug, Clone, Default)]
pub struct WordEntry {
    prefix: String,
}

impl WordEntry {
    pub fn new() -> Self {
        Self { prefix: String::new() }
    }

    /// The letters committed so far (lowercase ASCII).
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn is_empty(&self) -> bool {
        self.prefix.is_empty()
    }

    /// The BIP-39 words still matching the current prefix — a contiguous,
    /// lexicographically sorted slice (empty prefix ⇒ all 2048 words). The
    /// slice borrows `self`, but each element is a `'static` wordlist entry, so
    /// individual words copy out freely into [`Choice::Word`].
    pub fn matches(&self) -> &[&'static str] {
        LANG.words_by_prefix(&self.prefix)
    }

    /// How many words still match. Reaches 1 within at most four letters.
    pub fn candidate_count(&self) -> usize {
        self.matches().len()
    }

    /// The ordered choices to present at this step:
    ///
    /// - if exactly one word matches, the sole choice is to **accept** it (the
    ///   owner needn't type the remaining letters);
    /// - otherwise, the distinct valid **next letters**, preceded by an accept
    ///   option when the prefix is *itself* a complete word (e.g. accept "act"
    ///   while "action"/"actor" also match).
    ///
    /// Letters appear in sorted order because the wordlist is sorted. Returns
    /// empty only for a prefix that matches nothing, which the entry flow never
    /// produces (it only ever commits letters drawn from this list).
    pub fn choices(&self) -> Vec<Choice> {
        let matches = self.matches();
        if matches.is_empty() {
            return Vec::new();
        }
        if matches.len() == 1 {
            return vec![Choice::Word(matches[0])];
        }

        let mut out = Vec::new();

        // If the prefix is already a complete word, it is the first (shortest)
        // entry of the sorted match slice — offer it as an explicit accept so
        // short words that are also prefixes ("act" vs "action") are reachable.
        if let Some(exact) = matches.iter().find(|w| **w == self.prefix) {
            out.push(Choice::Word(*exact));
        }

        // Distinct next byte across the matches (wordlist is ASCII).
        let at = self.prefix.len();
        let mut last: Option<u8> = None;
        for w in matches {
            if let Some(&b) = w.as_bytes().get(at) {
                if Some(b) != last {
                    out.push(Choice::Letter(b as char));
                    last = Some(b);
                }
            }
        }
        out
    }

    /// Commit a letter (expected to come from a [`Choice::Letter`]).
    pub fn push(&mut self, c: char) {
        self.prefix.push(c);
    }

    /// Remove the last committed letter. Returns `false` if the prefix was
    /// already empty (the caller then treats it as "step back a word").
    pub fn backspace(&mut self) -> bool {
        self.prefix.pop().is_some()
    }
}

/// Validate a space-joined recovery phrase's BIP-39 checksum and derive its
/// tree-root secret. `Err` means the words don't form a valid mnemonic — a
/// mistyped word or a wrong checksum word — which the device surfaces before
/// storing anything. Reuses the exact derivation used for generation so a
/// restored phrase reproduces the identical key (and npub).
pub fn restore_root(phrase: &str) -> Result<[u8; 32], String> {
    crate::mnemonic::derive_root_secret(phrase, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_prefix_matches_whole_list() {
        let e = WordEntry::new();
        assert_eq!(e.candidate_count(), 2048);
        assert!(e.is_empty());
    }

    #[test]
    fn next_letters_are_distinct_and_sorted() {
        let mut e = WordEntry::new();
        e.push('a');
        e.push('b');
        let letters: Vec<char> = e
            .choices()
            .into_iter()
            .filter_map(|c| match c {
                Choice::Letter(ch) => Some(ch),
                Choice::Word(_) => None,
            })
            .collect();
        // abandon/ability/able/about/above/absent.../abuse → a,i,l,o,s,u
        assert_eq!(letters, vec!['a', 'i', 'l', 'o', 's', 'u']);
        // sorted + unique
        let mut sorted = letters.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(letters, sorted);
    }

    #[test]
    fn resolves_unique_within_four_letters() {
        // "aban" matches only "abandon".
        let mut e = WordEntry::new();
        for c in "aban".chars() {
            e.push(c);
        }
        assert_eq!(e.candidate_count(), 1);
        assert_eq!(e.choices(), vec![Choice::Word("abandon")]);
    }

    #[test]
    fn backspace_reports_emptiness() {
        let mut e = WordEntry::new();
        assert!(!e.backspace()); // already empty
        e.push('z');
        assert!(e.backspace());
        assert!(e.is_empty());
    }

    #[test]
    fn short_word_that_prefixes_others_is_acceptable() {
        // Scan the real wordlist for any word that is a strict prefix of a
        // longer word; for each, the picker must offer accepting the short word
        // as well as continuing. If BIP-39 has no such pair this passes vacuously.
        let list = Language::English.word_list();
        let mut checked = 0usize;
        for &short in list.iter() {
            let longer_exists = list
                .iter()
                .any(|w| *w != short && w.starts_with(short));
            if !longer_exists {
                continue;
            }
            checked += 1;
            let mut e = WordEntry::new();
            for c in short.chars() {
                e.push(c);
            }
            assert!(
                e.choices().contains(&Choice::Word(short)),
                "short word {short} not offered as an accept choice"
            );
            assert!(
                e.choices().len() > 1,
                "{short} prefixes others but offered no continuation"
            );
        }
        // Sanity: the wordlist genuinely contains such pairs.
        assert!(checked > 0, "expected at least one prefix pair in BIP-39");
    }

    #[test]
    fn every_word_is_reachable_and_acceptable() {
        // The real guarantee: drive each of the 2048 words through the state
        // machine using only the offered choices, and confirm it can always be
        // entered and accepted. This catches any prefix the picker can't form.
        for &target in Language::English.word_list().iter() {
            let mut e = WordEntry::new();
            loop {
                let choices = e.choices();
                if choices.contains(&Choice::Word(target)) {
                    break;
                }
                let next = target.as_bytes()[e.prefix().len()] as char;
                assert!(
                    choices.contains(&Choice::Letter(next)),
                    "word {target}: letter '{next}' missing at prefix '{}'",
                    e.prefix()
                );
                e.push(next);
            }
        }
    }

    #[test]
    fn restore_root_accepts_valid_phrase() {
        // Canonical all-zero vector, shared with mnemonic::generate.
        const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let root = restore_root(ZERO_PHRASE).expect("valid phrase");
        let expected = crate::mnemonic::generate(&[0u8; 16]).unwrap().1;
        assert_eq!(root, expected);
    }

    #[test]
    fn restore_root_rejects_bad_checksum() {
        // Valid words, wrong checksum word (last "about" → "abandon").
        const BAD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(restore_root(BAD).is_err());
    }

    #[test]
    fn restore_root_rejects_unknown_word() {
        const BAD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzzz";
        assert!(restore_root(BAD).is_err());
    }
}
