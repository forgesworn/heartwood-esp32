---
name: OLED diagnostics for ESP32 debugging
description: When serial port is occupied, use OLED step labels to pinpoint hangs — don't guess at crypto
type: feedback
---

When debugging ESP32 firmware issues where the serial port is occupied by the test tool, use OLED-based diagnostics (show a step label on screen before each operation) to pinpoint where code hangs. This found the TX buffer issue instantly after 5 failed guesses at crypto/threading/heap.

**Why:** The USB-Serial-JTAG port is shared between log output and the frame protocol. When sign-test holds the port, serial logs are invisible. The OLED is always visible.

**How to apply:** Before each suspect operation, call `show_error(display, "D:step_name")`. The step that stays on screen is where it's stuck. Remove diagnostic labels after the issue is resolved.
