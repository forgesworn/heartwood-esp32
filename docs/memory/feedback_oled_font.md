---
name: Bigger OLED font
description: User finds small fonts unreadable on the Heltec V4 OLED - use FONT_7X14 or larger
type: feedback
---

FONT_5X8 and FONT_6X10 are both too small on the 128x64 SSD1306. FONT_7X14 (18 chars/line, 4 lines) is the minimum for comfortable reading.

**Why:** User tested on hardware and said text was too small to read, twice (first with FONT_5X8, then again with FONT_6X10).

**How to apply:** Use `embedded_graphics::mono_font::ascii::FONT_7X14` in oled.rs. 18 chars/line, line spacing 16px, Y positions: 14, 30, 46, 62. Npubs split across 4 lines (63 chars / 18 = 4 lines). Do not go smaller than FONT_7X14.
