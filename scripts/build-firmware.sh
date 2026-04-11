#!/usr/bin/env bash
#
# Build the Heartwood ESP32 firmware for a specific Heltec board variant.
#
# Usage: scripts/build-firmware.sh {v3|v4} [cargo args...]
#
# The two Heltec boards wire USB-C differently:
#
#   V4 -- USB-C goes to the ESP32-S3 native USB pins (GPIO19/20), driving
#         the chip's USB-Serial-JTAG peripheral.
#
#   V3 -- USB-C goes through a CP2102 USB-to-UART bridge to the ESP32-S3's
#         UART0 (GPIO43 TX / GPIO44 RX).
#
# Compile-time selection is via mutually-exclusive cargo features
# (heltec-v3, heltec-v4) and a matching sdkconfig fragment pointed to by
# ESP_IDF_SDKCONFIG_DEFAULTS. This script sets both in one go so they cannot
# drift apart.
#
# Artifacts are copied to target/heartwood-v3.bin or target/heartwood-v4.bin
# so you can distribute them alongside the right hardware and never flash
# the wrong binary.
#
# Examples:
#
#   scripts/build-firmware.sh v4
#   scripts/build-firmware.sh v3 --release
#   scripts/build-firmware.sh v4 --release -- --features some-extra

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 {v3|v4} [cargo args...]" >&2
    exit 2
fi

BOARD="$1"
shift

case "$BOARD" in
    v3|V3|heltec-v3)
        FEATURE="heltec-v3"
        ;;
    v4|V4|heltec-v4)
        FEATURE="heltec-v4"
        ;;
    *)
        echo "error: unknown board '$BOARD' (expected v3 or v4)" >&2
        exit 2
        ;;
esac

FIRMWARE_DIR="$(cd "$(dirname "$0")/../firmware" && pwd)"
cd "$FIRMWARE_DIR"

export ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.${FEATURE}"

echo "==> Building heartwood-esp32 for Heltec ${BOARD^^}"
echo "    feature                    = ${FEATURE}"
echo "    ESP_IDF_SDKCONFIG_DEFAULTS = ${ESP_IDF_SDKCONFIG_DEFAULTS}"

cargo build --no-default-features --features "$FEATURE" "$@"

# Copy the compiled ELF next to a board-tagged name so the operator cannot
# accidentally espflash a V3 binary onto a V4 or vice versa. The ELF path
# depends on whether --release was passed; inspect the args.
PROFILE="debug"
for arg in "$@"; do
    if [[ "$arg" == "--release" ]]; then
        PROFILE="release"
    fi
done

SRC="target/xtensa-esp32s3-espidf/${PROFILE}/heartwood-esp32"
DST="target/heartwood-${BOARD}.elf"

if [[ -f "$SRC" ]]; then
    cp "$SRC" "$DST"
    echo "==> Copied ${SRC} -> ${DST}"
fi
