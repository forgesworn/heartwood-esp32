"""Render the Heartwood boot animation as a looping GIF, frame for frame from
firmware/src/oled.rs::show_boot_animation at the 128x64 OLED layout (sc=1).
Colours follow the site's amber OLED plate for the walk, and the firmware's
true RAINBOW palette for the HEARTWOOD decrypt."""
import os
import re
from PIL import Image, ImageDraw, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = f"{REPO}/site"
VERSION = "v" + re.search(
    r'^version\s*=\s*"([^"]+)"',
    open(f"{REPO}/firmware/Cargo.toml").read(), re.M).group(1)

W, H = 128, 64
SC = 1
COLS = ROWS = 56

# ---- colours ----
BG = (6, 4, 2)          # matches .oled background #060402
AMBER = (232, 168, 56)  # site accent, the cat
GHOST = (110, 76, 26)   # dim amber ghost
GROUND = (150, 106, 36)
MUTED = (115, 113, 115)         # Rgb565 (14,28,14)
NOSTR = (139, 93, 246)          # Rgb565 (17,23,30)
RAINBOW = [                     # Rgb565 -> Rgb888, from oled.rs
    (255, 0, 0), (255, 97, 0), (255, 222, 0), (0, 202, 65), (0, 210, 255),
    (49, 80, 255), (98, 32, 230), (139, 93, 246), (255, 24, 213),
]

# ---- parse the 16 sprite frames from cat_sprites.rs ----
src = open(f"{REPO}/firmware/src/cat_sprites.rs").read()
hexes = re.findall(r"0x([0-9A-Fa-f]{14}),", src)
assert len(hexes) == 16 * 56, len(hexes)
FRAMES = []
for f in range(16):
    rows = [int(hexes[f * 56 + r], 16) for r in range(56)]
    FRAMES.append(rows)

def draw_sprite(px, rows, ox, oy, colour):
    for r, v in enumerate(rows):
        y = oy + r
        if not (0 <= y < H) or v == 0:
            continue
        for c in range(COLS):
            if v >> (55 - c) & 1:
                x = ox + c
                if 0 <= x < W:
                    px[x, y] = colour

# ---- fonts (thresholded to 1-bit so they read as OLED pixels) ----
BIG = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 17, index=0)
SMALL = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 10, index=0)

def draw_glyph(img, ch, cell_x, cell_y, cell_w, cell_h, colour, font, thresh=110):
    tile = Image.new("L", (cell_w + 8, cell_h + 8), 0)
    d = ImageDraw.Draw(tile)
    d.text((4, 4), ch, fill=255, font=font)
    bbox = tile.getbbox()
    if bbox is None:
        return
    # horizontal centre in cell; vertical: common baseline from font metrics
    ascent, _ = font.getmetrics()
    gw = bbox[2] - bbox[0]
    dst_x = cell_x + (cell_w - gw) // 2 - bbox[0]
    dst_y = cell_y + (cell_h - ascent) // 2
    px = img.load()
    tp = tile.load()
    for ty in range(tile.height):
        for tx in range(tile.width):
            if tp[tx, ty] > thresh:
                x, y = dst_x + tx, dst_y + ty
                if 0 <= x < W and 0 <= y < H:
                    px[x, y] = colour

# ---- LFSR, exactly as oled.rs ----
class Lfsr:
    def __init__(self):
        self.s = 0xACE1
    def next_byte(self):
        bit = self.s & 1
        self.s >>= 1
        if bit:
            self.s ^= 0xB400
        return self.s & 0xFF

# 3x5 pixel font for the version line (authentic OLED look at this scale)
PIXFONT = {
    "v": ["101", "101", "101", "101", "010"],
    "0": ["111", "101", "101", "101", "111"],
    "1": ["010", "110", "010", "010", "111"],
    "2": ["111", "001", "111", "100", "111"],
    "3": ["111", "001", "011", "001", "111"],
    "4": ["101", "101", "111", "001", "001"],
    "5": ["111", "100", "111", "001", "111"],
    "6": ["111", "100", "111", "101", "111"],
    "7": ["111", "001", "010", "010", "010"],
    "8": ["111", "101", "111", "101", "111"],
    "9": ["111", "101", "111", "001", "111"],
    ".": ["000", "000", "000", "000", "010"],
}

def draw_pixel_text(img, text, x0, y0, colour):
    if x0 is None:
        x0 = (W - (len(text) * 4 - 1)) // 2
    px = img.load()
    for j, ch in enumerate(text):
        for r, row in enumerate(PIXFONT[ch]):
            for c, bit in enumerate(row):
                if bit == "1":
                    x, y = x0 + j * 4 + c, y0 + r
                    if 0 <= x < W and 0 <= y < H:
                        px[x, y] = colour

def blank():
    return Image.new("RGB", (W, H), BG)

frames, durations = [], []

def emit(img, ms):
    frames.append(img)
    durations.append(ms)

# ---- phase 1: the walk (oled.rs lines 1711-1759) ----
cat_y_base = max((H - ROWS) // 2 - SC, 0)          # 3
ground_y = min(cat_y_base + ROWS + SC, H - 1)      # 60
glitch_x = W // 2 - COLS // 2                      # 36
ghost_off = 40

emit(blank(), 50)
emit(blank(), 50)

x = -COLS
step = 0
while x < W:
    img = blank()
    px = img.load()
    frame_idx = step % 16
    y_pos = cat_y_base + (SC if step % 2 == 0 else 0)
    sway = 0 if (step // 4) % 2 == 0 else SC
    if glitch_x <= x <= glitch_x + 6 * SC:
        ghost_idx = (step + 8) % 16
        ghost_y = cat_y_base + (SC if (step + 1) % 2 == 0 else 0)
        draw_sprite(px, FRAMES[ghost_idx], x - ghost_off, ghost_y, GHOST)
    draw_sprite(px, FRAMES[frame_idx], x + sway, y_pos, AMBER)
    dash_gap = 6 * SC
    dash_scroll = (step * 3 * SC) % dash_gap
    gx = -dash_scroll
    while gx < W:
        for dx in range(2 * SC):
            gxx = gx + dx
            if 0 <= gxx < W:
                px[gxx, ground_y] = GROUND
        gx += dash_gap
    emit(img, 40 if step % 2 else 50)  # averages the firmware's 45ms
    step += 1
    x += 2 * SC

emit(blank(), 50)
emit(blank(), 50)

# ---- phase 2: HEARTWOOD decrypt (oled.rs lines 1768-1834) ----
TITLE = "HEARTWOOD"
GLYPH_W, GLYPH_H = 10, 20
title_x0 = (W - len(TITLE) * GLYPH_W) // 2         # 19
title_y0 = (H - GLYPH_H) // 2                      # 22
lfsr = Lfsr()
resolved = 0
for frame in range(25):
    img = blank()
    if frame >= 3 and frame % 2 == 1 and resolved < len(TITLE):
        resolved += 1
    for i, ch in enumerate(TITLE):
        if i < resolved:
            glyph, colour = ch, RAINBOW[i]
        else:
            glyph, colour = chr(0x21 + lfsr.next_byte() % 94), MUTED
        draw_glyph(img, glyph, title_x0 + i * GLYPH_W, title_y0,
                   GLYPH_W, GLYPH_H, colour, BIG)
    if resolved >= len(TITLE):
        draw_pixel_text(img, VERSION, None, 55, NOSTR)
    emit(img, 60)

# hold the resolved title, then loop
emit(frames[-1].copy(), 1800)

# ---- write ----
frames[0].save(
    f"{OUT}/boot.gif", save_all=True, append_images=frames[1:],
    duration=durations, loop=0, optimize=True, disposal=1,
)

# reduced-motion still: cat mid-screen with ground, step chosen for a nice pose
img = blank()
px = img.load()
draw_sprite(px, FRAMES[4], 36, 3, AMBER)
gx = 0
while gx < W:
    for dx in range(2):
        if gx + dx < W:
            px[gx + dx, ground_y] = GROUND
    gx += 6
img.save(f"{OUT}/boot-still.png", optimize=True)

print("version:", VERSION)
print("frames:", len(frames))
print("boot.gif:", os.path.getsize(f"{OUT}/boot.gif"), "bytes")
print("boot-still.png:", os.path.getsize(f"{OUT}/boot-still.png"), "bytes")
