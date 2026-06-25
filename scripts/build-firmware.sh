#!/usr/bin/env bash
#
# Build the Heartwood ESP32 firmware for a specific board variant.
#
# Usage: scripts/build-firmware.sh {v3|v4|tdisplay|c6} [cargo args...]
#
# Boards differ in chip, display, host transport and flash:
#
#   v3       -- Heltec WiFi LoRa 32 V3: ESP32-S3, SSD1306 OLED, CP2102 UART0.
#   v4       -- Heltec WiFi LoRa 32 V4: ESP32-S3, SSD1306 OLED, native USB-JTAG.
#   tdisplay -- LilyGO / TENSTAR T-Display: classic ESP32, ST7789 colour TFT,
#               CH9102 UART0. Built for the xtensa-esp32-espidf target.
#   c6       -- Waveshare ESP32-C6-LCD-1.47: ESP32-C6 (RISC-V), ST7789 172x320
#               portrait TFT, native USB-JTAG. Built for riscv32imac-esp-espidf.
#
# Compile-time board selection is via mutually-exclusive cargo features plus a
# matching sdkconfig fragment, target triple and MCU -- all set here together
# so they cannot drift apart.
#
# Artifacts are copied to target/heartwood-<board>.elf so you can distribute
# them alongside the right hardware and never flash the wrong binary.
#
# Examples:
#
#   scripts/build-firmware.sh v4
#   scripts/build-firmware.sh v3 --release
#   scripts/build-firmware.sh tdisplay --release
#   scripts/build-firmware.sh c6 --release

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 {v3|v4|tdisplay|c6} [cargo args...]" >&2
    exit 2
fi

BOARD="$1"
shift

case "$BOARD" in
    v3|V3|heltec-v3)
        FEATURE="heltec-v3"; TARGET="xtensa-esp32s3-espidf"; MCU="esp32s3"
        ;;
    v4|V4|heltec-v4)
        FEATURE="heltec-v4"; TARGET="xtensa-esp32s3-espidf"; MCU="esp32s3"
        ;;
    tdisplay|TDISPLAY|t-display)
        FEATURE="tdisplay"; TARGET="xtensa-esp32-espidf"; MCU="esp32"
        ;;
    c6|C6|esp32c6)
        FEATURE="c6"; TARGET="riscv32imac-esp-espidf"; MCU="esp32c6"
        ;;
    *)
        echo "error: unknown board '$BOARD' (expected v3, v4, tdisplay, or c6)" >&2
        exit 2
        ;;
esac

FIRMWARE_DIR="$(cd "$(dirname "$0")/../firmware" && pwd)"
cd "$FIRMWARE_DIR"

# `force = false` on the [env] entries in .cargo/config.toml means these shell
# exports win, so MCU/sdkconfig follow the chosen board rather than the S3
# default baked into the config file.
export ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.${FEATURE}"
export MCU

echo "==> Building heartwood-esp32 for ${FEATURE}"
echo "    target                     = ${TARGET}"
echo "    MCU                        = ${MCU}"
echo "    ESP_IDF_SDKCONFIG_DEFAULTS = ${ESP_IDF_SDKCONFIG_DEFAULTS}"

cargo build --target "$TARGET" --no-default-features --features "$FEATURE" "$@"

# Copy the compiled ELF next to a board-tagged name so the operator cannot
# accidentally flash one board's binary onto another. The ELF path depends on
# whether --release was passed; inspect the args.
PROFILE="debug"
for arg in "$@"; do
    if [[ "$arg" == "--release" ]]; then
        PROFILE="release"
    fi
done

SRC="target/${TARGET}/${PROFILE}/heartwood-esp32"
DST="target/heartwood-${BOARD}.elf"

if [[ -f "$SRC" ]]; then
    cp "$SRC" "$DST"
    echo "==> Copied ${SRC} -> ${DST}"
fi
