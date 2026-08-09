"""Render the entropy game as a looping GIF, frame for frame from
firmware/src/entropy_game.rs at the 128x64 OLED layout (sc=1): intro screen,
a stretch of play with the press counter climbing, one honest collision, then
the ENTROPY BANKED card. Colours follow the site's amber OLED plate, matching
gen-boot-gif.py. Physics constants are copied from the firmware, not invented:
gravity +1/frame clamped to 6, jump impulse -9, obstacles 2 px/frame, spawn
window every 30 frames, ground_y 54, 8x8 player at x=12, 6x10 obstacles."""
import os
import random
from PIL import Image, ImageDraw, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = f"{REPO}/site"

W, H = 128, 64

# ---- colours (amber OLED plate, as gen-boot-gif.py) ----
BG = (6, 4, 2)            # matches .oled background #060402
AMBER = (232, 168, 56)    # site accent -> firmware ACCENT (obstacles, headers)
FGC = (232, 244, 248)     # firmware FG #e8f4f8 (player, primary text)
MUTED = (115, 113, 115)   # firmware MUTED (ground, progress counter)

# ---- firmware constants (entropy_game.rs) ----
TARGET_PRESSES = 64
GROUND_Y = 54
PLAYER_X = 12
JUMP_VY = -9
GRAVITY_CLAMP = 6
OBSTACLE_SPEED = 2
SPAWN_EVERY = 30

# ---- fonts (thresholded to 1-bit so they read as OLED pixels) ----
HEADER = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13, index=0)
SMALL = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 10, index=0)
TINY = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 9, index=0)


def draw_text(img, text, x0, baseline, colour, font, thresh=110):
    """Threshold-blit `text` left-aligned with its baseline at `baseline`,
    mirroring how embedded-graphics positions Text (baseline coords)."""
    tile = Image.new("L", (W + 16, H + 16), 0)
    d = ImageDraw.Draw(tile)
    ascent, _ = font.getmetrics()
    d.text((4, 4), text, fill=255, font=font)
    px = img.load()
    tp = tile.load()
    for ty in range(tile.height):
        for tx in range(tile.width):
            if tp[tx, ty] > thresh:
                x = x0 + tx - 4
                y = baseline - ascent + ty - 4
                if 0 <= x < W and 0 <= y < H:
                    px[x, y] = colour


def rect(img, x, y, w, h, colour):
    px = img.load()
    for yy in range(y, y + h):
        if not 0 <= yy < H:
            continue
        for xx in range(x, x + w):
            if 0 <= xx < W:
                px[xx, yy] = colour


def blank():
    return Image.new("RGB", (W, H), BG)


frames, durations = [], []


def emit(img, ms):
    frames.append(img)
    durations.append(ms)


# ---- intro screen (entropy_game.rs::intro) ----
img = blank()
draw_text(img, "ADD YOUR", 28, 10, AMBER, HEADER)
draw_text(img, "RANDOMNESS", 24, 22, AMBER, HEADER)
draw_text(img, "tap: jump the blocks", 2, 40, FGC, TINY)
draw_text(img, "hold: skip (chip RNG)", 2, 50, FGC, TINY)
draw_text(img, "timing becomes entropy", 2, 62, MUTED, TINY)
emit(img, 2200)


def game_frame(player_y, obstacles, count, flash):
    img = blank()
    rect(img, 0, GROUND_Y + 6, W, 1, MUTED)                      # ground line
    for ox, active in obstacles:                                  # obstacles
        if active:
            rect(img, ox - 3, GROUND_Y - 4, 6, 10, AMBER)
    rect(img, PLAYER_X - 4, player_y - 8, 8, 8,                   # player
         AMBER if flash else FGC)
    draw_text(img, f"{count}/{TARGET_PRESSES}", 2, 8, MUTED, SMALL)
    if flash:                                                     # hit bar
        rect(img, 0, 0, W, 2, FGC)
    return img


# ---- gameplay (entropy_game.rs::run, scripted player) ----
# Seed chosen so the firmware's own spawn distribution (a 1-in-3 roll every
# 30 frames) gives a lively stretch rather than an empty one.
PLAY_FRAMES = 260


def spawn_count(seed):
    r = random.Random(seed)
    return sum(1 for step in range(PLAY_FRAMES)
               if step % SPAWN_EVERY == 0 and r.randrange(3) == 0)


seed = next(s for s in range(1000) if spawn_count(s) >= 5)
rng = random.Random(seed)

player_y = GROUND_Y
vy = 0
obstacles = [[-40, False] for _ in range(4)]
count = 21          # join mid-session, as Fig. 1 joins the boot mid-walk
flash_frames = 0
obstacles_seen = 0
idle_beat = 0

for step in range(PLAY_FRAMES):
    vy = min(vy + 1, GRAVITY_CLAMP)
    player_y = min(player_y + vy, GROUND_Y)

    if step % SPAWN_EVERY == 0 and rng.randrange(3) == 0:
        for o in obstacles:
            if not o[1]:
                o[0], o[1] = W, True
                obstacles_seen += 1
                break
    for o in obstacles:
        if o[1]:
            o[0] -= OBSTACLE_SPEED
            if o[0] < -12:
                o[1] = False

    # The scripted thumb. Every press on the ground jumps (firmware rule), so
    # a player harvesting presses bounces between blocks too; and one block is
    # let through, because the game keeps your timing whether or not you clear
    # it -- the when is harvested, never the whether.
    nearest = min((o[0] for o in obstacles if o[1] and o[0] >= PLAYER_X - 8),
                  default=None)
    if player_y >= GROUND_Y:
        pressed = False
        if nearest is not None and 14 <= nearest - PLAYER_X <= 20:
            pressed = obstacles_seen != 2  # miss the second block on purpose
        elif nearest is None or nearest - PLAYER_X > 60:
            idle_beat += 1
            if idle_beat >= 16:   # a lazy bounce roughly every half second
                idle_beat = 0
                pressed = True
        if pressed:
            vy = JUMP_VY
            count = min(count + 1, TARGET_PRESSES)

    if (player_y >= GROUND_Y - 4
            and any(a and PLAYER_X - 8 <= x < PLAYER_X + 8
                    for x, a in obstacles)):
        flash_frames = 5

    emit(game_frame(player_y, obstacles, count, flash_frames > 0), 33)
    if flash_frames:
        flash_frames -= 1

# ---- done card (entropy_game.rs::show_done) ----
img = blank()
draw_text(img, "ENTROPY BANKED", 6, 20, AMBER, HEADER)
draw_text(img, "64 presses mixed", 2, 44, FGC, SMALL)
draw_text(img, "with chip RNG", 2, 56, FGC, SMALL)
emit(img, 2600)

frames[0].save(
    f"{OUT}/entropy-game.gif", save_all=True, append_images=frames[1:],
    duration=durations, loop=0, optimize=True, disposal=1,
)

# ---- reduced-motion still: mid-jump over a block, counter well along ----
img = game_frame(player_y=36, obstacles=[[14, True], [92, True],
                                         [-40, False], [-40, False]],
                 count=37, flash=False)
img.save(f"{OUT}/entropy-game-still.png", optimize=True)

print("frames:", len(frames))
print("entropy-game.gif:", os.path.getsize(f"{OUT}/entropy-game.gif"), "bytes")
print("entropy-game-still.png:",
      os.path.getsize(f"{OUT}/entropy-game-still.png"), "bytes")
