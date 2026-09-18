#!/bin/bash
# Claim 3: Figure 8 / Appendix E DoS early-reject speedup (QEMU ARM64).
# Usage: bash claims/claim3_dos_early_reject/run.sh
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim3_dos_early_reject/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu artifact/terminal/euicc/build/arm64/bench_pqzkesim --dos
cp dos_results.csv claims/claim3_dos_early_reject/results/
echo "Done. See claims/claim3_dos_early_reject/results/dos_results.csv"
