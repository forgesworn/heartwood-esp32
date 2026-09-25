// common/src/spoken_words.rs
//
// spoken-token's en-v1 word list (forgesworn/spoken-token, MIT), the list its
// `format: 'words'` encoding and KithMoot use: 2048 words of 3 to 8 lower-case
// letters, chosen to be told apart when read aloud. Kept once, as a plain file
// (spoken_words.txt, one word a line), so the Node bench library reads the
// same bytes this crate compiles in.
//
// spoken-token's word encoding: word i of a token is
// WORDLIST[uint16_be(bytes[2i], bytes[2i+1]) % 2048], so each word carries 11
// bits of the digest and uses two of its bytes.

/// The list, one word a line. SHA-256 of its words joined with "\n" (no
/// trailing newline) is pinned below against spoken-token 2.0.4 and 2.1.0.
const WORDS: &str = include_str!("spoken_words.txt");

/// How many words the list holds.
pub const WORDLIST_LEN: usize = 2048;
/// The longest word, in letters: what a card line must fit twice.
pub const WORDLIST_MAX_LEN: usize = 8;

/// Word `index % 2048`.
pub fn word(index: usize) -> &'static str {
    WORDS
        .lines()
        .nth(index % WORDLIST_LEN)
        .expect("the list holds 2048 words")
}

/// The word two digest bytes encode, as spoken-token's `encodeAsWords` does.
pub fn word_for(pair: &[u8]) -> &'static str {
    word(usize::from(u16::from_be_bytes([pair[0], pair[1]])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_list_is_spoken_tokens_en_v1() {
        let words: alloc::vec::Vec<&str> = WORDS.lines().collect();
        assert_eq!(words.len(), WORDLIST_LEN);
        assert!(WORDS.ends_with('\n'), "one word a line, newline-terminated");
        assert!(words.iter().all(|w| (3..=WORDLIST_MAX_LEN).contains(&w.len())
            && w.bytes().all(|b| b.is_ascii_lowercase())));
        assert_eq!(words.iter().map(|w| w.len()).max(), Some(WORDLIST_MAX_LEN));
        let mut unique = words.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), WORDLIST_LEN, "no word twice");
        let digest = Sha256::digest(words.join("\n").as_bytes());
        let hex: alloc::string::String = digest.iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(hex, "0334930ebdfbc76e81ec914515d7567ca85738a6bf3069249d97df951d44661c");
        assert_eq!(word(0), "ability");
        assert_eq!(word(2048), "ability", "indices wrap as spoken-token's modulo does");
    }

    #[test]
    fn two_bytes_pick_a_word_by_their_low_eleven_bits() {
        assert_eq!(word_for(&[0x00, 0x00]), word(0));
        assert_eq!(word_for(&[0x08, 0x01]), word(1), "0x0801 % 2048 = 1");
        assert_eq!(word_for(&[0xFF, 0xFF]), word(2047));
    }
}
