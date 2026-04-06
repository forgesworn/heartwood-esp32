# HD Cat Boot Animation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the text-character cat boot animation with a pixel-art silhouette using composable sprite frames at 1:1 pixel scale on the SSD1306 OLED.

**Architecture:** Standalone `sprite-gen` crate reads ASCII art source files (body + 2 tail variants + 4 leg variants), assembles 8 frame combinations (2 tails x 4 legs), and generates `firmware/src/cat_sprites.rs` with flat `const [u64; 56]` arrays. Firmware draws frames pixel-by-pixel using embedded-graphics `Pixel` primitives.

**Tech Stack:** Rust (sprite-gen: std only; firmware: esp-idf-svc, embedded-graphics 0.8, ssd1306 0.9)

**Spec:** `docs/superpowers/specs/2026-04-06-hd-cat-boot-animation-design.md`

**Note:** The spec estimated body=30 rows, legs=12 rows. Analysis of the reference art shows the leg separation starts at row 42, giving body=27, legs=15. The plan uses the precise split: tail=14, body=27, legs=15 (total=56).

---

## File structure

| File | Action | Purpose |
|------|--------|---------|
| `scripts/extract-sprites.py` | Create | One-time script to split reference art into components |
| `docs/sprites/body.txt` | Create (generated) | 27-row constant body section |
| `docs/sprites/tail-up.txt` | Create (generated) | 14-row tail curled upward |
| `docs/sprites/tail-down.txt` | Create | 14-row tail relaxed/lower |
| `docs/sprites/legs-stride-1.txt` | Create (generated) | 15-row reference leg pose |
| `docs/sprites/legs-stride-2.txt` | Create | 15-row legs passing (vertical) |
| `docs/sprites/legs-stride-3.txt` | Create | 15-row opposite stride |
| `docs/sprites/legs-stride-4.txt` | Create | 15-row passing (other direction) |
| `sprite-gen/Cargo.toml` | Create | Converter tool manifest |
| `sprite-gen/src/main.rs` | Create | Converter: parse, assemble, generate Rust code |
| `firmware/src/cat_sprites.rs` | Create (generated) | 8 pre-assembled `[u64; 56]` sprite frames |
| `firmware/src/oled.rs` | Modify | Replace text-char animation with pixel-based HD animation |
| `firmware/src/main.rs` | Modify | Add `mod cat_sprites;` |

---

### Task 1: Extract reference art into component files

**Files:**
- Create: `scripts/extract-sprites.py`
- Create: `docs/sprites/body.txt` (generated)
- Create: `docs/sprites/tail-up.txt` (generated)
- Create: `docs/sprites/legs-stride-1.txt` (generated)
- Read: `docs/cat-sprite-reference.txt`

- [ ] **Step 1: Create docs/sprites/ directory**

```bash
mkdir -p docs/sprites
```

- [ ] **Step 2: Write the extraction script**

Create `scripts/extract-sprites.py`:

```python
#!/usr/bin/env python3
"""Extract cat sprite reference into composable component files.

Reads docs/cat-sprite-reference.txt, splits into tail/body/legs zones,
converts Unicode block chars to ASCII (#/.), writes to docs/sprites/.
"""

import os

TAIL_ROWS = 14
BODY_ROWS = 27
LEGS_ROWS = 15
TOTAL_ROWS = TAIL_ROWS + BODY_ROWS + LEGS_ROWS  # 56
COLS = 56


def main():
    with open('docs/cat-sprite-reference.txt', encoding='utf-8') as f:
        lines = f.readlines()

    # Collect sprite rows (lines containing only middle-dot and full-block).
    sprite_rows = []
    for line in lines:
        stripped = line.rstrip('\n')
        if not stripped:
            continue
        # Skip header lines that contain ASCII letters/digits/colons.
        if any(c.isascii() and c.isalpha() for c in stripped):
            continue
        # Convert: full-block -> #, middle-dot -> .
        converted = stripped.replace('\u2588', '#').replace('\u00B7', '.')
        # Pad or trim to COLS columns.
        converted = converted.ljust(COLS, '.')[:COLS]
        sprite_rows.append(converted)

    if len(sprite_rows) != TOTAL_ROWS:
        raise ValueError(
            f'Expected {TOTAL_ROWS} sprite rows, got {len(sprite_rows)}'
        )

    os.makedirs('docs/sprites', exist_ok=True)

    # Tail: rows 0..14
    with open('docs/sprites/tail-up.txt', 'w') as f:
        f.write('\n'.join(sprite_rows[:TAIL_ROWS]) + '\n')

    # Body: rows 14..41
    with open('docs/sprites/body.txt', 'w') as f:
        f.write('\n'.join(sprite_rows[TAIL_ROWS:TAIL_ROWS + BODY_ROWS]) + '\n')

    # Legs: rows 41..56
    with open('docs/sprites/legs-stride-1.txt', 'w') as f:
        f.write('\n'.join(sprite_rows[TAIL_ROWS + BODY_ROWS:]) + '\n')

    print(f'Extracted {len(sprite_rows)} rows into docs/sprites/:')
    print(f'  tail-up.txt:       {TAIL_ROWS} rows')
    print(f'  body.txt:          {BODY_ROWS} rows')
    print(f'  legs-stride-1.txt: {LEGS_ROWS} rows')


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: Run the extraction script**

```bash
python3 scripts/extract-sprites.py
```

Expected output:
```
Extracted 56 rows into docs/sprites/:
  tail-up.txt:       14 rows
  body.txt:          27 rows
  legs-stride-1.txt: 15 rows
```

- [ ] **Step 4: Verify the extracted files**

```bash
wc -l docs/sprites/tail-up.txt docs/sprites/body.txt docs/sprites/legs-stride-1.txt
```

Expected: 14, 27, 15 lines respectively. Visually inspect each file to confirm the art looks correct (all `#` and `.` characters, 56 columns wide).

- [ ] **Step 5: Commit**

```bash
git add scripts/extract-sprites.py docs/sprites/body.txt docs/sprites/tail-up.txt docs/sprites/legs-stride-1.txt
git commit -m "feat: extract cat sprite reference into composable component files"
```

---

### Task 2: Create tail-down variant

**Files:**
- Create: `docs/sprites/tail-down.txt`

The tail-down variant has the tail relaxed and lower. The tip starts at row 5 instead of row 1. The connecting rows (11-14) match tail-up since that's where the tail joins the body.

- [ ] **Step 1: Create tail-down.txt**

Create `docs/sprites/tail-down.txt`. This is the tail-up art with the upper portion shifted down 4 rows (4 blank rows inserted at top, curve adjusted). Rows 11-14 stay identical to tail-up.txt since they connect to the body:

```
........................................................
........................................................
........................................................
........................................................
..####..................................................
..####..................................................
..######................................................
...#####................................................
....#####...............................................
...######...............................................
...####.................................................
...####.................................................
...####.................................................
.#####..................................................
```

Open `docs/sprites/tail-up.txt` for reference while editing. Rows 11-14 of tail-down MUST match rows 11-14 of tail-up exactly (these are the body junction rows).

- [ ] **Step 2: Verify row count and width**

```bash
wc -l docs/sprites/tail-down.txt
awk '{ print length }' docs/sprites/tail-down.txt | sort -u
```

Expected: 14 lines, all 56 characters wide.

- [ ] **Step 3: Commit**

```bash
git add docs/sprites/tail-down.txt
git commit -m "feat: create tail-down sprite variant"
```

---

### Task 3: Create leg stride variants

**Files:**
- Create: `docs/sprites/legs-stride-2.txt`
- Create: `docs/sprites/legs-stride-3.txt`
- Create: `docs/sprites/legs-stride-4.txt`

Study the reference images on the Desktop (`Screenshot 2026-04-06 at 2.10.16 AM.png` and `2.11.19 AM.png`) and the extracted `legs-stride-1.txt` before creating these. The cat faces right (head on right, tail on left). The reference pose shows a full stride. All variant files must be 15 rows x 56 columns.

**Walk cycle phases:**
- stride-1: full extension (reference pose) -- front-left and back-right forward
- stride-2: legs gathering toward vertical, transitioning from stride-1 to stride-3
- stride-3: full extension opposite -- front-right and back-left forward (roughly mirrored leg angles from stride-1)
- stride-4: legs gathering toward vertical, transitioning from stride-3 back to stride-1

**Critical constraint:** Row 1 of each legs file must align with the last row of body.txt (where the body mass transitions into separated legs). Match the horizontal extent of the upper leg rows to the body's bottom edge.

- [ ] **Step 1: Create legs-stride-2.txt (passing)**

The legs are more vertical and gathered under the body. Less horizontal spread than stride-1. The four legs are closer together, nearly vertical:

```
....##############..##################.................
...###############.....##############..................
..############.#####.....############..................
..###########..#####.....######..######................
..##########...#####.....######...#####................
...########...######.....######...#####................
....######....######......#####....#####...............
.....#####....######......#####.....####...............
.....#####.....#####......####......####...............
......####.....#####.....#####......####...............
......####......####.....#####.......####..............
......####......#####....#####.......####..............
.......####.....#####.....####.......#####.............
.......####......####.....#####.......####.............
.......####......####......####.......####.............
```

- [ ] **Step 2: Create legs-stride-3.txt (opposite stride)**

Opposite leg extension from stride-1. The legs that were angled forward in stride-1 are now angled backward, and vice versa. Study stride-1.txt and swap which legs extend forward vs back:

```
....##############..##################.................
...###############.....###############.................
..#########.########......##########.#####.............
..########..########.......######...######..............
..########....######........######....#######..........
...#######...#######........######....########.........
....######..########.........#####.....########........
.....####..########..........#####......########.......
......####..#######..........####........#######.......
......####...######..........#####.......########......
.......####...######.........#####........########.....
.......#####...######........#####.........#######.....
........#####...######........####..........######.....
.........#####...#####.......######..........######....
..........####....#####......######...........#####....
```

- [ ] **Step 3: Create legs-stride-4.txt (passing, other direction)**

Similar to stride-2 but the legs are transitioning from stride-3 back to stride-1. Slightly different from stride-2 to avoid a mechanical ping-pong feel. The legs are gathered but with a slight lean in the opposite direction from stride-2:

```
....##############..##################.................
...###############.....##############..................
..############.######....############..................
..###########...#####....######..######................
...#########....#####....######...#####................
...########....######....######....#####...............
....######.....######.....#####....#####...............
....######.....######.....#####.....####...............
.....#####.....#####......####......####...............
.....#####......#####.....#####.....#####..............
......####......#####.....#####......####..............
......####......#####.....#####......#####.............
......#####......####......####......#####.............
.......####......#####.....#####......####.............
.......####......####......#####......####.............
```

- [ ] **Step 4: Verify all leg files**

```bash
wc -l docs/sprites/legs-stride-{2,3,4}.txt
awk '{ print length }' docs/sprites/legs-stride-{1,2,3,4}.txt | sort -u
```

Expected: 15 lines each, all 56 characters wide.

- [ ] **Step 5: Visual sanity check**

Concatenate tail-up + body + each leg variant and eyeball the result:

```bash
for i in 1 2 3 4; do
  echo "=== stride-$i ==="
  cat docs/sprites/tail-up.txt docs/sprites/body.txt "docs/sprites/legs-stride-$i.txt"
  echo ""
done
```

The four assembled cats should show a plausible walk cycle: extended stride -> gathering -> opposite stride -> gathering.

- [ ] **Step 6: Commit**

```bash
git add docs/sprites/legs-stride-2.txt docs/sprites/legs-stride-3.txt docs/sprites/legs-stride-4.txt
git commit -m "feat: create walking leg sprite variants (4 stride phases)"
```

---

### Task 4: Build sprite-gen crate with parser and tests

**Files:**
- Create: `sprite-gen/Cargo.toml`
- Create: `sprite-gen/src/main.rs`

- [ ] **Step 1: Create Cargo.toml**

Create `sprite-gen/Cargo.toml`:

```toml
[package]
name = "sprite-gen"
version = "0.1.0"
edition = "2021"
description = "Build-time converter: ASCII art sprites to Rust const u64 arrays"
```

- [ ] **Step 2: Write failing test for parse_art**

Create `sprite-gen/src/main.rs` with the test and a stub:

```rust
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

/// Parse an ASCII art file into a Vec<u64>.
/// '#' = on (bit set), '.' = off (bit clear).
/// Bit 55 = leftmost column, bit 0 = rightmost column.
fn parse_art(_content: &str) -> Vec<u64> {
    todo!()
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
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd sprite-gen && cargo test 2>&1 | head -20
```

Expected: compilation error from `todo!()`.

- [ ] **Step 4: Implement parse_art**

Replace the `parse_art` stub in `sprite-gen/src/main.rs`:

```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd sprite-gen && cargo test
```

Expected: all 4 tests pass.

- [ ] **Step 6: Commit**

```bash
cd sprite-gen && git add Cargo.toml src/main.rs && git commit -m "feat: sprite-gen crate with ASCII art parser"
```

---

### Task 5: Add frame assembly, code generation, and generate sprites

**Files:**
- Modify: `sprite-gen/src/main.rs`
- Create: `firmware/src/cat_sprites.rs` (generated output)

- [ ] **Step 1: Write failing test for assemble_frame**

Add to the `tests` module in `sprite-gen/src/main.rs`:

```rust
    #[test]
    fn test_assemble_frame() {
        let tail = vec![1u64; TAIL_ROWS];
        let body = vec![2u64; BODY_ROWS];
        let legs = vec![3u64; LEGS_ROWS];
        let frame = assemble_frame(&tail, &body, &legs);
        assert_eq!(frame.len(), TOTAL_ROWS);
        assert!(frame[..TAIL_ROWS].iter().all(|&r| r == 1));
        assert!(frame[TAIL_ROWS..TAIL_ROWS + BODY_ROWS].iter().all(|&r| r == 2));
        assert!(frame[TAIL_ROWS + BODY_ROWS..].iter().all(|&r| r == 3));
    }
```

Add a stub above `main()`:

```rust
fn assemble_frame(_tail: &[u64], _body: &[u64], _legs: &[u64]) -> [u64; TOTAL_ROWS] {
    todo!()
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd sprite-gen && cargo test test_assemble_frame
```

Expected: panic from `todo!()`.

- [ ] **Step 3: Implement assemble_frame**

Replace the stub:

```rust
fn assemble_frame(tail: &[u64], body: &[u64], legs: &[u64]) -> [u64; TOTAL_ROWS] {
    assert_eq!(tail.len(), TAIL_ROWS, "tail must be {TAIL_ROWS} rows");
    assert_eq!(body.len(), BODY_ROWS, "body must be {BODY_ROWS} rows");
    assert_eq!(legs.len(), LEGS_ROWS, "legs must be {LEGS_ROWS} rows");

    let mut frame = [0u64; TOTAL_ROWS];
    frame[..TAIL_ROWS].copy_from_slice(tail);
    frame[TAIL_ROWS..TAIL_ROWS + BODY_ROWS].copy_from_slice(body);
    frame[TAIL_ROWS + BODY_ROWS..].copy_from_slice(legs);
    frame
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd sprite-gen && cargo test test_assemble_frame
```

Expected: PASS.

- [ ] **Step 5: Write failing test for generate_rust**

Add to the `tests` module:

```rust
    #[test]
    fn test_generate_rust_format() {
        let frames = vec![[0u64; TOTAL_ROWS]; 2];
        let code = generate_rust(&frames);
        assert!(code.contains("pub const FRAME_ROWS: usize = 56;"));
        assert!(code.contains("pub const FRAME_COLS: usize = 56;"));
        assert!(code.contains("pub const FRAME_COUNT: usize = 2;"));
        assert!(code.contains("pub const FRAMES:"));
        assert!(code.contains("0x00000000000000,"));
    }
```

Add a stub:

```rust
fn generate_rust(_frames: &[[u64; TOTAL_ROWS]]) -> String {
    todo!()
}
```

- [ ] **Step 6: Implement generate_rust**

Replace the stub:

```rust
fn generate_rust(frames: &[[u64; TOTAL_ROWS]]) -> String {
    let mut out = String::new();
    out.push_str("/// Auto-generated by sprite-gen. Do not edit by hand.\n");
    out.push_str("/// Source: docs/sprites/{body,tail-*,legs-*}.txt\n\n");
    out.push_str(&format!("pub const FRAME_ROWS: usize = {TOTAL_ROWS};\n"));
    out.push_str(&format!("pub const FRAME_COLS: usize = {COLS};\n"));
    out.push_str(&format!(
        "pub const FRAME_COUNT: usize = {};\n\n",
        frames.len()
    ));
    out.push_str("/// Frames 0-3: tail up + 4 leg poses.\n");
    out.push_str("/// Frames 4-7: tail down + 4 leg poses.\n");
    out.push_str("pub const FRAMES: [[u64; FRAME_ROWS]; FRAME_COUNT] = [\n");

    for (i, frame) in frames.iter().enumerate() {
        out.push_str(&format!("    [ // frame {i}\n"));
        for row in frame {
            out.push_str(&format!("        0x{row:014X},\n"));
        }
        out.push_str("    ],\n");
    }

    out.push_str("];\n");
    out
}
```

- [ ] **Step 7: Run all tests**

```bash
cd sprite-gen && cargo test
```

Expected: all 6 tests pass.

- [ ] **Step 8: Implement main()**

Replace the `main()` stub:

```rust
fn main() {
    let sprites_dir = Path::new("docs/sprites");
    let output_path = Path::new("firmware/src/cat_sprites.rs");

    let body = parse_art(
        &fs::read_to_string(sprites_dir.join("body.txt")).expect("failed to read body.txt"),
    );
    let tail_up = parse_art(
        &fs::read_to_string(sprites_dir.join("tail-up.txt")).expect("failed to read tail-up.txt"),
    );
    let tail_down = parse_art(
        &fs::read_to_string(sprites_dir.join("tail-down.txt"))
            .expect("failed to read tail-down.txt"),
    );

    let legs: Vec<Vec<u64>> = (1..=4)
        .map(|i| {
            let path = sprites_dir.join(format!("legs-stride-{i}.txt"));
            parse_art(
                &fs::read_to_string(&path)
                    .unwrap_or_else(|_| panic!("failed to read {}", path.display())),
            )
        })
        .collect();

    let tails = [&tail_up, &tail_down];
    let mut frames = Vec::new();
    for tail in &tails {
        for leg in &legs {
            frames.push(assemble_frame(tail, &body, leg));
        }
    }

    let rust_code = generate_rust(&frames);
    fs::write(output_path, &rust_code).expect("failed to write cat_sprites.rs");

    println!(
        "Generated {} with {} frames ({TOTAL_ROWS} rows each)",
        output_path.display(),
        frames.len()
    );
}
```

- [ ] **Step 9: Run sprite-gen to generate cat_sprites.rs**

Run from the repo root (sprite-gen reads paths relative to cwd):

```bash
cd /path/to/heartwood-esp32 && cargo run --manifest-path sprite-gen/Cargo.toml
```

Expected output:
```
Generated firmware/src/cat_sprites.rs with 8 frames (56 rows each)
```

- [ ] **Step 10: Verify the generated file**

```bash
head -20 firmware/src/cat_sprites.rs
grep -c "0x" firmware/src/cat_sprites.rs
```

Expected: header comment, const declarations, and 448 hex values (8 frames x 56 rows).

- [ ] **Step 11: Commit**

```bash
git add sprite-gen/src/main.rs firmware/src/cat_sprites.rs
git commit -m "feat: sprite-gen frame assembly and code generation"
```

---

### Task 6: Update firmware boot animation

**Files:**
- Modify: `firmware/src/main.rs:20` (add module)
- Modify: `firmware/src/oled.rs:5` (add Pixel import)
- Modify: `firmware/src/oled.rs:670-885` (replace boot animation + draw_sprite)

- [ ] **Step 1: Add cat_sprites module to main.rs**

In `firmware/src/main.rs`, add after line 20 (`mod oled;`):

```rust
mod cat_sprites;
```

- [ ] **Step 2: Add Pixel import to oled.rs**

In `firmware/src/oled.rs`, add after line 9 (`use embedded_graphics::prelude::*;`):

```rust
use embedded_graphics::Pixel;
```

If the compiler says `Pixel` is already in scope via the prelude glob import, remove this line.

- [ ] **Step 3: Replace show_boot_animation and add draw_sprite_hd**

In `firmware/src/oled.rs`, replace the entire block from line 670 (`// Boot animation`) through line 885 (end of `draw_sprite`) AND lines 887-909 (the `_unused` function) with:

```rust
// Boot animation
// ---------------------------------------------------------------------------

/// Boot animation: HD pixel-art cat + decrypt reveal.
///
/// Phase 1: A cat silhouette walks across the screen at 1:1 pixel scale.
/// At centre screen it "glitches" (deja vu -- ghost cat behind). Like The Matrix.
/// Phase 2: Screen clears, HEARTWOOD decrypts letter by letter.
pub fn show_boot_animation(display: &mut Display<'_>) {
    let mut lfsr: u16 = 0xACE1;
    let mut next_byte = |lfsr: &mut u16| -> u8 {
        let bit = *lfsr & 1;
        *lfsr >>= 1;
        if bit != 0 { *lfsr ^= 0xB400; }
        (*lfsr & 0xFF) as u8
    };

    use crate::cat_sprites::{FRAMES, FRAME_COUNT, FRAME_COLS};

    // Deja vu triggers when the cat's midpoint reaches screen centre (px 64).
    let glitch_x: i32 = 64 - (FRAME_COLS as i32 / 2); // ~36

    // Lead-in: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    let mut x: i32 = -(FRAME_COLS as i32);
    let mut step: u32 = 0;

    while x < 128 {
        display.clear_buffer();

        let frame_idx = (step as usize) % FRAME_COUNT;
        draw_sprite_hd(display, &FRAMES[frame_idx], x, 0);

        // Deja vu glitch: ghost cat appears 40px behind for 3 frames.
        if x >= glitch_x && x <= glitch_x + 6 {
            let ghost_idx = ((step as usize) + 4) % FRAME_COUNT;
            draw_sprite_hd(display, &FRAMES[ghost_idx], x - 40, 0);
        }

        // Moving ground: scrolling dashes at the bottom.
        let ground_y = 63;
        let ground_offset = (step as i32 * 3) % 6;
        for px in (0..128).step_by(6) {
            let gx = px - ground_offset;
            if gx >= 0 && gx < 128 {
                use embedded_graphics::primitives::{Line, PrimitiveStyle};
                Line::new(Point::new(gx, ground_y), Point::new(gx + 2, ground_y))
                    .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
                    .draw(display).ok();
            }
        }

        display.flush().ok();
        step += 1;
        x += 2;
        FreeRtos::delay_ms(45);
    }

    // Lead-out: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    // Phase 2: HEARTWOOD decrypt reveal (unchanged).
    const TITLE: &[u8] = b"HEARTWOOD";
    const LEN: usize = 9;
    const START_X: i32 = 19;
    const Y: i32 = 35;

    let big_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let sub_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let mut resolved: usize = 0;

    for frame in 0u32..25 {
        display.clear_buffer();

        if frame >= 3 && frame % 2 == 1 && resolved < LEN {
            resolved += 1;
        }

        for i in 0..LEN {
            let ch = if i < resolved {
                TITLE[i]
            } else {
                0x21 + (next_byte(&mut lfsr) % 94)
            };
            let buf = [ch];
            let s = core::str::from_utf8(&buf).unwrap_or("?");
            let x = START_X + (i as i32 * 10);
            Text::new(s, Point::new(x, Y), big_style).draw(display).ok();
        }

        if resolved >= LEN {
            let version = concat!("v", env!("CARGO_PKG_VERSION"));
            let vx = ((128 - version.len() as i32 * 6) / 2).max(0);
            Text::new(version, Point::new(vx, 56), sub_style).draw(display).ok();
        }

        display.flush().ok();
        FreeRtos::delay_ms(60);
    }
}

/// Draw a 56x56 pixel sprite at the given pixel offset.
/// Bits are packed as u64 per row: bit 55 = leftmost column, bit 0 = rightmost.
fn draw_sprite_hd(
    display: &mut Display<'_>,
    frame: &[u64; 56],
    x_offset: i32,
    y_offset: i32,
) {
    for row in 0..56i32 {
        let bits = frame[row as usize];
        if bits == 0 { continue; }
        let py = y_offset + row;
        if py < 0 || py >= 64 { continue; }
        for col in 0..56i32 {
            if (bits >> (55 - col)) & 1 == 1 {
                let px = x_offset + col;
                if px >= 0 && px < 128 {
                    Pixel(Point::new(px, py), BinaryColor::On)
                        .draw(display).ok();
                }
            }
        }
    }
}
```

- [ ] **Step 4: Build the firmware to verify compilation**

```bash
cd firmware && cargo build 2>&1 | tail -5
```

Expected: successful build (or warnings only, no errors). If `Pixel` import conflicts with the prelude, remove the explicit `use embedded_graphics::Pixel;` line.

Note: this only checks compilation. Visual verification requires flashing to the device, which is a manual step outside this plan.

- [ ] **Step 5: Commit**

```bash
git add firmware/src/main.rs firmware/src/oled.rs firmware/src/cat_sprites.rs
git commit -m "feat: HD pixel-art cat boot animation"
```

---

### Task 7: Clean up and final verification

**Files:**
- Delete: `scripts/extract-sprites.py` (optional -- one-time tool, safe to keep or remove)

- [ ] **Step 1: Verify no dead code warnings**

```bash
cd firmware && cargo build 2>&1 | grep "warning"
```

If there are warnings about unused imports (e.g. `FONT_5X8` is still imported but only used elsewhere -- this is fine), leave them. If the old `draw_sprite` or `CAT` arrays somehow survived, remove them.

- [ ] **Step 2: Run sprite-gen tests**

```bash
cd sprite-gen && cargo test
```

Expected: all tests pass.

- [ ] **Step 3: Commit any cleanup**

Only if changes were needed:

```bash
git add -u && git commit -m "chore: clean up dead code from animation upgrade"
```

- [ ] **Step 4: Flash to device and verify visually (manual)**

This is a manual step. Flash the firmware to the Heltec V4 and observe the boot animation:

```bash
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Or via OTA if the device is on the Pi:
```bash
cd firmware && espflash save-image --chip esp32s3 target/xtensa-esp32s3-espidf/debug/heartwood-esp32 /tmp/heartwood.bin
# Then scp to Pi and run ota tool
```

Check:
- Cat silhouette walks smoothly across the screen
- Deja vu glitch appears at centre screen
- Ground line scrolls
- HEARTWOOD decrypt reveal plays after
- Walk cycle looks natural (legs animate, tail sways)

If the leg art doesn't look right, edit the `docs/sprites/legs-stride-*.txt` files and re-run `cargo run --manifest-path sprite-gen/Cargo.toml` to regenerate.
