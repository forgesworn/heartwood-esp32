// sprite-gen/src/main.rs
//
// Reads ASCII art sprite component files (body, tail variants, leg variants)
// and generates firmware/src/cat_sprites.rs with pre-assembled const frames.

use std::fs;
use std::path::Path;

const TAIL_ROWS: usize = 14;
const BODY_ROWS: usize = 27;
const LEGS_ROWS: usize = 15;
const TOTAL_ROWS: usize = TAIL_ROWS + BODY_ROWS + LEGS_ROWS; // 56
const COLS: usize = 56;

/// Parse an ASCII art file into a Vec of u64.
/// '#' = on (bit set), '.' = off (bit clear).
/// Bit 55 = leftmost column, bit 0 = rightmost column.
fn parse_art(content: &str) -> Vec<u64> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut row: u64 = 0;
            for (col, ch) in line.chars().enumerate() {
                if col >= COLS {
                    break;
                }
                if ch == '#' {
                    row |= 1u64 << (COLS - 1 - col);
                }
            }
            row
        })
        .collect()
}

fn main() {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_art_simple() {
        let art = "#..#\n.##.\n";
        let rows = parse_art(art);
        assert_eq!(rows.len(), 2);
        // col 0 = '#' -> bit 55, col 3 = '#' -> bit 52
        assert_eq!(rows[0], (1u64 << 55) | (1u64 << 52));
        // col 1 = '#' -> bit 54, col 2 = '#' -> bit 53
        assert_eq!(rows[1], (1u64 << 54) | (1u64 << 53));
    }

    #[test]
    fn test_parse_art_full_row() {
        let art = &"#".repeat(56);
        let rows = parse_art(art);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], (1u64 << 56) - 1);
    }

    #[test]
    fn test_parse_art_empty_row() {
        let art = &".".repeat(56);
        let rows = parse_art(art);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], 0);
    }

    #[test]
    fn test_parse_art_skips_blank_lines() {
        let art = "#...\n\n.#..\n";
        let rows = parse_art(art);
        assert_eq!(rows.len(), 2);
    }
}
