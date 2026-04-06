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
