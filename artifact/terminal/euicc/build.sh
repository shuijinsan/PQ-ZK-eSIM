#!/bin/bash
# Build PQ-ZK-eSIM for artifact evaluation.
#   - build/arm64/   : ARM64 cross-compile (aarch64-linux-gnu), run under QEMU
#                      for the timing claims (Fig 5/7/8/9).
#   - build_debug/   : native x86 Debug (-O0) for the Callgrind claim (Fig 6).
# Run once before running any claim.
set -e
cd "$(dirname "$0")"

command -v aarch64-linux-gnu-gcc >/dev/null || { echo "aarch64-linux-gnu-gcc not found; install gcc-aarch64-linux-gnu."; exit 1; }
command -v qemu-aarch64-static >/dev/null || { echo "qemu-aarch64-static not found; install qemu-user-static."; exit 1; }

echo "== ARM64 cross-compile (QEMU) =="
cmake -S . -B build/arm64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 --target bench_pqzkesim bench_pqzkesim_comprehensive -j"$(nproc)"

echo "== Native x86 Debug (Callgrind) =="
cmake -S . -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug --target bench_pqzkesim -j"$(nproc)"

echo "Build complete. Binaries are in build/arm64/ and build_debug/."
