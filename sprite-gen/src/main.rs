// sprite-gen/src/main.rs
//
// Procedural cat walk animation generator.
//
// Body (27 rows) is read from ASCII art (constant across frames).
// Tail (14 rows) and legs (15 rows) are generated procedurally:
//   - Tail: Bezier curve that sways sinusoidally.
//   - Legs: 4 limbs with 3 segments each, driven by a diagonal gait cycle.
//     Front legs: shoulder->elbow(back)->carpal(forward)->paw (Z-shape).
//     Back legs: hip->knee(forward)->ankle/hock(back)->paw (S-shape).
//
// The top HAUNCH_ROWS of the legs section are overlaid from the reference
// art to preserve the body-to-leg transition mass.

use std::f64::consts::PI;
use std::fs;
use std::path::Path;

const TAIL_ROWS: usize = 14;
const BODY_ROWS: usize = 27;
const LEGS_ROWS: usize = 15;
const TOTAL_ROWS: usize = TAIL_ROWS + BODY_ROWS + LEGS_ROWS; // 56
const COLS: usize = 56;
const TOTAL_FRAMES: usize = 16;

// Rows of procedural haunch fill (tapers from body width to individual legs).
const HAUNCH_FILL: usize = 4;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn parse_art(content: &str) -> Vec<u64> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut row: u64 = 0;
            for (col, ch) in line.chars().enumerate() {
                if col >= COLS { break; }
                if ch == '#' {
                    row |= 1u64 << (COLS - 1 - col);
                }
            }
            row
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pixel drawing helpers
// ---------------------------------------------------------------------------

fn set_pixel(rows: &mut [u64], col: i32, row: i32, max_rows: usize) {
    if col >= 0 && col < COLS as i32 && row >= 0 && (row as usize) < max_rows {
        rows[row as usize] |= 1u64 << (COLS - 1 - col as usize);
    }
}

fn draw_thick_line(rows: &mut [u64], max_rows: usize,
                   x0: f64, y0: f64, x1: f64, y1: f64, thickness: f64) {
    let dx = x1 - x0;
    let dy = y1 - y0;
    let len = (dx * dx + dy * dy).sqrt();
    let steps = (len * 3.0).max(1.0) as usize;
    let half = thickness / 2.0;

    for i in 0..=steps {
        let t = i as f64 / steps as f64;
        let cx = x0 + dx * t;
        let cy = y0 + dy * t;
        let min_x = (cx - half).floor() as i32;
        let max_x = (cx + half).ceil() as i32;
        let min_y = (cy - half).floor() as i32;
        let max_y = (cy + half).ceil() as i32;
        for py in min_y..=max_y {
            for px in min_x..=max_x {
                set_pixel(rows, px, py, max_rows);
            }
        }
    }
}

fn draw_bezier(rows: &mut [u64], max_rows: usize,
               p0: (f64, f64), p1: (f64, f64), p2: (f64, f64),
               base_thickness: f64) {
    let steps = 48usize;
    for i in 0..steps {
        let t0 = i as f64 / steps as f64;
        let t1 = (i + 1) as f64 / steps as f64;

        let pt = |t: f64| -> (f64, f64) {
            let u = 1.0 - t;
            (u * u * p0.0 + 2.0 * u * t * p1.0 + t * t * p2.0,
             u * u * p0.1 + 2.0 * u * t * p1.1 + t * t * p2.1)
        };

        let a = pt(t0);
        let b = pt(t1);
        // Taper from base to tip (steeper taper for sleeker tail).
        let th = base_thickness * (1.0 - t0 * 0.7);
        draw_thick_line(rows, max_rows, a.0, a.1, b.0, b.1, th);
    }
}

// ---------------------------------------------------------------------------
// Procedural tail
// ---------------------------------------------------------------------------

fn generate_tail(frame: usize) -> Vec<u64> {
    let mut rows = vec![0u64; TAIL_ROWS];
    let phase = frame as f64 / TOTAL_FRAMES as f64;
    let angle = 2.0 * PI * phase;

    // Anchor: bottom of tail, connects to body (col ~4, row 13).
    let anchor = (4.5, 13.0);
    // Control: mid-curve, sways 2px.
    let control = (3.5 + 2.0 * angle.sin(), 7.0 + 0.5 * angle.cos());
    // Tip: top of tail, big sway (5px side to side).
    let tip = (6.0 + 4.0 * angle.sin(), 0.5 + 1.0 * angle.cos());

    draw_bezier(&mut rows, TAIL_ROWS, anchor, control, tip, 3.0);

    // Ensure junction to body: tail rows 12-13 must include cols 1-5
    // to connect with body row 1 which starts .#####...
    for col in 1..=5 {
        set_pixel(&mut rows, col, 13, TAIL_ROWS);
    }
    for col in 2..=5 {
        set_pixel(&mut rows, col, 12, TAIL_ROWS);
    }
    for col in 2..=4 {
        set_pixel(&mut rows, col, 11, TAIL_ROWS);
    }

    rows
}

// ---------------------------------------------------------------------------
// Procedural legs
// ---------------------------------------------------------------------------

/// Foot position in the walk cycle.
/// Stance (0-0.5): foot on ground, slides from ahead to behind.
/// Swing (0.5-1.0): foot lifts in arc, moves forward.
fn foot_position(phase: f64, anchor_col: f64, stride: f64, ground_row: f64) -> (f64, f64) {
    let p = phase % 1.0;
    if p < 0.5 {
        let t = p / 0.5;
        let col = anchor_col + stride * (1.0 - 2.0 * t);
        (col, ground_row)
    } else {
        let t = (p - 0.5) / 0.5;
        let col = anchor_col - stride + 2.0 * stride * t;
        let lift = 4.0 * (PI * t).sin();
        (col, ground_row - lift)
    }
}

fn generate_legs(frame: usize, _haunch_template: &[u64]) -> Vec<u64> {
    let mut rows = vec![0u64; LEGS_ROWS];

    let phase = frame as f64 / TOTAL_FRAMES as f64;
    let ground = (LEGS_ROWS - 1) as f64;

    // Body bottom edge spans cols 4-41. Back haunch ~4-21, front shoulder ~24-41.
    // Procedural haunch fill: smoothly narrows from body width to individual legs.
    // Rows 0-3: filled blocks that taper from body width to leg pair width.
    for r in 0..4 {
        let taper = r as f64 / 4.0; // 0.0 at top, 0.75 at row 3
        // Back haunch: narrows from cols 4-21 toward the two back leg anchors (5, 15)
        let bl = (4.0 + taper * 1.0) as i32;
        let br = (21.0 - taper * 3.0) as i32;
        for col in bl..=br {
            set_pixel(&mut rows, col, r as i32, LEGS_ROWS);
        }
        // Front shoulder: narrows from cols 24-41 toward the two front leg anchors (30, 39)
        let fl = (24.0 + taper * 3.0) as i32;
        let fr = (41.0 - taper * 1.0) as i32;
        for col in fl..=fr {
            set_pixel(&mut rows, col, r as i32, LEGS_ROWS);
        }
    }

    struct Leg {
        anchor_col: f64,
        stride: f64,
        phase_offset: f64,
        thickness: f64,
    }

    let legs = [
        Leg { anchor_col:  7.0, stride: 7.0, phase_offset: 0.0,  thickness: 3.5 }, // back-far
        Leg { anchor_col: 16.0, stride: 5.0, phase_offset: 0.5,  thickness: 3.0 }, // back-near
        Leg { anchor_col: 30.0, stride: 5.0, phase_offset: 0.5,  thickness: 3.0 }, // front-near
        Leg { anchor_col: 38.0, stride: 7.0, phase_offset: 0.0,  thickness: 3.5 }, // front-far
    ];

    let anchor_row = 3.0; // legs emerge from the haunch fill

    for leg in &legs {
        let leg_phase = (phase + leg.phase_offset) % 1.0;
        let (paw_col, paw_row) = foot_position(leg_phase, leg.anchor_col, leg.stride, ground);

        // Single clean line from anchor to just above paw, tapering.
        let above_paw_row = paw_row - 1.0;
        draw_thick_line(&mut rows, LEGS_ROWS,
            leg.anchor_col, anchor_row, paw_col, above_paw_row,
            leg.thickness);

        // Paw pad: small filled rectangle where the foot meets the ground.
        if paw_row >= ground - 0.5 {
            // Stance: paw on ground, 3px wide pad.
            let pad_left = (paw_col - 1.0).round() as i32;
            let pad_right = (paw_col + 1.0).round() as i32;
            for col in pad_left..=pad_right {
                set_pixel(&mut rows, col, paw_row.round() as i32, LEGS_ROWS);
                set_pixel(&mut rows, col, (paw_row - 1.0).round() as i32, LEGS_ROWS);
            }
        } else {
            // Swing: foot lifted, just draw the leg endpoint.
            let px = paw_col.round() as i32;
            let py = paw_row.round() as i32;
            set_pixel(&mut rows, px, py, LEGS_ROWS);
            set_pixel(&mut rows, px + 1, py, LEGS_ROWS);
        }
    }

    rows
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

fn assemble_frame(tail: &[u64], body: &[u64], legs: &[u64]) -> [u64; TOTAL_ROWS] {
    assert_eq!(tail.len(), TAIL_ROWS);
    assert_eq!(body.len(), BODY_ROWS);
    assert_eq!(legs.len(), LEGS_ROWS);

    let mut frame = [0u64; TOTAL_ROWS];
    frame[..TAIL_ROWS].copy_from_slice(tail);
    frame[TAIL_ROWS..TAIL_ROWS + BODY_ROWS].copy_from_slice(body);
    frame[TAIL_ROWS + BODY_ROWS..].copy_from_slice(legs);
    frame
}

fn generate_rust(frames: &[[u64; TOTAL_ROWS]]) -> String {
    let mut out = String::new();
    out.push_str("/// Auto-generated by sprite-gen. Do not edit by hand.\n");
    out.push_str("/// Procedural 3-segment legs (diagonal gait) and Bezier tail.\n\n");
    out.push_str(&format!("pub const FRAME_ROWS: usize = {TOTAL_ROWS};\n"));
    out.push_str(&format!("pub const FRAME_COLS: usize = {COLS};\n"));
    out.push_str(&format!("pub const FRAME_COUNT: usize = {};\n\n", frames.len()));
    out.push_str(&format!("/// {} procedural walk cycle frames.\n", frames.len()));
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let sprites_dir = Path::new("docs/sprites");
    let output_path = Path::new("firmware/src/cat_sprites.rs");

    let body = parse_art(
        &fs::read_to_string(sprites_dir.join("body.txt")).expect("failed to read body.txt"),
    );
    let stride_ref = parse_art(
        &fs::read_to_string(sprites_dir.join("legs-stride-1.txt"))
            .expect("failed to read legs-stride-1.txt"),
    );

    let mut frames = Vec::new();
    for f in 0..TOTAL_FRAMES {
        let tail = generate_tail(f);
        let legs = generate_legs(f, &stride_ref);
        frames.push(assemble_frame(&tail, &body, &legs));
    }

    let rust_code = generate_rust(&frames);
    fs::write(output_path, &rust_code).expect("failed to write cat_sprites.rs");

    println!("Generated {} with {} frames ({TOTAL_ROWS} rows each)",
        output_path.display(), frames.len());

    // Text preview of first and mid-cycle frames (legs only).
    for &f in &[0, 4, 8, 12] {
        println!("\nFrame {f} legs:");
        let frame = &frames[f];
        for row in TAIL_ROWS + BODY_ROWS..TOTAL_ROWS {
            let bits = frame[row];
            let line: String = (0..COLS)
                .map(|c| if (bits >> (COLS - 1 - c)) & 1 == 1 { '#' } else { '.' })
                .collect();
            println!("  {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_art_simple() {
        let art = "#..#\n.##.\n";
        let rows = parse_art(art);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], (1u64 << 55) | (1u64 << 52));
        assert_eq!(rows[1], (1u64 << 54) | (1u64 << 53));
    }

    #[test]
    fn test_parse_art_full_row() {
        let art = &"#".repeat(56);
        let rows = parse_art(art);
        assert_eq!(rows[0], (1u64 << 56) - 1);
    }

    #[test]
    fn test_parse_art_skips_blank_lines() {
        let art = "#...\n\n.#..\n";
        let rows = parse_art(art);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn test_generate_tail_junction() {
        let tail = generate_tail(0);
        assert_eq!(tail.len(), TAIL_ROWS);
        // Junction rows must have pixels for body connection.
        assert_ne!(tail[13], 0);
        assert_ne!(tail[12], 0);
    }

    #[test]
    fn test_generate_legs_ground_contact() {
        let haunch = vec![0xFFu64; LEGS_ROWS];
        let legs = generate_legs(0, &haunch);
        assert_eq!(legs.len(), LEGS_ROWS);
        // Ground row should have foot pixels.
        assert_ne!(legs[LEGS_ROWS - 1], 0);
    }

    #[test]
    fn test_haunch_fill() {
        // Top rows should have pixels (procedural haunch fill).
        let haunch = vec![0u64; LEGS_ROWS];
        let legs = generate_legs(0, &haunch);
        assert_ne!(legs[0], 0, "row 0 should have haunch fill");
        assert_ne!(legs[1], 0, "row 1 should have haunch fill");
    }

    #[test]
    fn test_total_frame_count() {
        let body = vec![0u64; BODY_ROWS];
        let haunch = vec![0u64; LEGS_ROWS];
        let mut frames = Vec::new();
        for f in 0..TOTAL_FRAMES {
            let tail = generate_tail(f);
            let legs = generate_legs(f, &haunch);
            frames.push(assemble_frame(&tail, &body, &legs));
        }
        assert_eq!(frames.len(), TOTAL_FRAMES);
    }

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
}
