#!/usr/bin/env bash
# Build and measure opt-in QR firmware locally. Never flash or open a port.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$HOME/export-esp.sh" ]]; then
    source "$HOME/export-esp.sh"
fi
for riscv_bin in "$root/firmware/.embuild/espressif/tools/riscv32-esp-elf/"*/riscv32-esp-elf/bin; do
    if [[ -d "$riscv_bin" ]]; then export PATH="$riscv_bin:$PATH"; fi
done
if [[ $# -eq 0 ]]; then
    set -- tdisplay-reference tdisplay-compact tdisplay-optimal v4-reference v4-compact c6-reference c6-compact
fi
cd "$root/firmware"
mkdir -p target/qr-evaluation
for label in "$@"; do
    board="${label%-*}"
    mode="${label##*-}"
    case "$board" in
        tdisplay) feature=tdisplay; chip=esp32; target=xtensa-esp32-espidf; objdump=xtensa-esp32-elf-objdump ;;
        v4) feature=heltec-v4; chip=esp32s3; target=xtensa-esp32s3-espidf; objdump=xtensa-esp32s3-elf-objdump ;;
        c6) feature=c6; chip=esp32c6; target=riscv32imac-esp-espidf; objdump=riscv32-esp-elf-objdump ;;
        *) echo "Unknown evaluation board: $board" >&2; exit 2 ;;
    esac
    features="$feature"
    case "$mode" in
        reference) ;;
        compact) features+=,qr-compact ;;
        optimal) features+=,qr-optimal ;;
        *) echo "Unknown evaluation mode: $mode" >&2; exit 2 ;;
    esac
    export MCU="$chip"
    export ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.$feature"
    log="target/qr-evaluation/$label.log"
    echo "Building $label ($features)"
    if ! cargo +esp build --locked --offline --release --target "$target" --no-default-features --features "$features" --bin heartwood-esp32 -j 2 > "$log" 2>&1; then
        tail -n 50 "$log"
        exit 1
    fi
    cp "target/$target/release/heartwood-esp32" "target/qr-evaluation/$label.elf"
    tail -n 2 "$log"
    python3 "$root/scripts/measure-note-qr.py" "$label" --elf "target/qr-evaluation/$label.elf" --chip "$chip" --objdump "$objdump" --report "$root/docs/qr-evaluation-2026-11-17.json"
done
