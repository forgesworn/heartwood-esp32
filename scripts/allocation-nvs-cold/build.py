"""Build the offline pinned SDK worker in an explicitly owned scratch folder."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

SDK = "9d7f2d69f50d1288526d4f1027108e314e8c879f"
MBEDTLS = "98fcfd6d2cea90d306e8fde8e5bffd6087c9cda8"
CORE = ["nvs_types", "nvs_api", "nvs_page", "nvs_pagemanager", "nvs_storage", "nvs_item_hash_list", "nvs_handle_simple", "nvs_handle_locked", "nvs_partition_manager", "nvs_partition", "nvs_encrypted_partition", "nvs_cxx_api", "nvs_platform"]
SPARSE = ["components/nvs_flash", "components/esp_rom", "components/log", "components/esp_common", "components/esp32", "components/mbedtls", "components/spi_flash", "components/esp_partition", "components/hal", "components/xtensa", "components/soc/linux", "tools/catch"]


def run(args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def text(args, cwd):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    root = args.scratch.resolve()
    assert root.is_relative_to(Path.home() / "WebstormProjects/.worktrees"), "explicit owned scratch only"
    assert not args.scratch.is_symlink()
    root.mkdir(parents=True, exist_ok=False)
    sdk = root / "sdk"
    run(["git", "clone", "--filter=blob:none", "--depth", "1", "--branch", "v5.3.2", "--sparse", "https://github.com/espressif/esp-idf.git", str(sdk)])
    run(["git", "sparse-checkout", "set", *SPARSE], sdk)
    assert text(["git", "rev-parse", "HEAD"], sdk) == SDK
    run(["git", "submodule", "update", "--init", "--depth", "1", "components/mbedtls/mbedtls"], sdk)
    mbedtls = sdk / "components/mbedtls/mbedtls"
    assert text(["git", "rev-parse", "HEAD"], mbedtls) == MBEDTLS
    fingerprints = []
    for checkout, prefix in [(sdk, "sdk/"), (mbedtls, "sdk/components/mbedtls/mbedtls/")]:
        run(["git", "diff", "--exit-code", "HEAD"], checkout)
        for name in text(["git", "ls-files"], checkout).splitlines():
            p = checkout / name
            if p.is_file() and not p.is_symlink():
                fingerprints.append({"path": prefix + name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    build = root / "build"
    build.mkdir()
    source = Path(__file__).with_name("worker.cpp")
    shutil.copyfile(source, build / "worker.cpp")
    sources = " ".join("../src/" + name + ".cpp" for name in CORE) + " spi_flash_emulation.cpp " + str(build / "worker.cpp")
    flags = "-DLINUX_TARGET -DLINUX_HOST_LEGACY_TEST -fsanitize=address,undefined"
    link = "-lstdc++ -Wall -fprofile-arcs -ftest-coverage -fsanitize=address,undefined"
    if platform.system() == "Linux":
        link += " -lbsd"
    command = ["make", "-j4", "CC=clang", "CXX=clang++", "SOURCE_FILES=" + sources, "TEST_PROGRAM=" + str(build / "allocation-nvs-cold"), "CXXFLAGS=-std=c++11 -Wall -Werror " + flags, "CFLAGS=" + flags, "LDFLAGS=" + link]
    # Narrow host init_custom seam. No driver, page, storage, GC, C API or SDK
    # tracked source changes; no production nvs_flash_init_partition_ptr claim.
    run(command, sdk / "components/nvs_flash/test_nvs_host")
    run(["git", "diff", "--exit-code", "HEAD"], sdk)
    run(["git", "diff", "--exit-code", "HEAD"], mbedtls)
    proof = {"sdkCommit": SDK, "mbedtlsCommit": MBEDTLS, "sourceFingerprints": fingerprints, "workerSHA256": hashlib.sha256(source.read_bytes()).hexdigest(), "binarySHA256": hashlib.sha256((build / "allocation-nvs-cold").read_bytes()).hexdigest(), "toolchain": text(["clang", "--version"], root), "command": command, "asan": True, "ubsan": True, "trackedSDKUnchanged": True, "productionInitPointerExercised": False, "capacityAuthority": False, "physicalAcceptance": False}
    (build / "build-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(build / "allocation-nvs-cold")


if __name__ == "__main__":
    main()
