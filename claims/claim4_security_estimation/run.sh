#!/bin/bash
# Claim 4: Figure 9 / Appendix D DoS early-reject speedup (QEMU ARM64).
# Usage: bash claims/claim4/run.sh [--quick|--full]   (both equivalent; fast)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim4_security_estimation/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu artifact/terminal/euicc/build/arm64/bench_pqzkesim --dos
cp dos_results.csv claims/claim4_security_estimation/results/
echo "Done. See claims/claim4_security_estimation/results/dos_results.csv"
