#!/bin/bash
# Claim 4: Figure 6 / Appendix D sliding-window resynchronization (QEMU ARM64).
# Usage: bash claims/claim4_sliding_window/run.sh [--quick|--full]   (both equivalent)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim4_sliding_window/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    artifact/terminal/euicc/build/arm64/bench_pqzkesim_comprehensive --only sliding
cp sliding_window_resync_results.csv claims/claim4_sliding_window/results/
echo "Done. See claims/claim4_sliding_window/results/sliding_window_resync_results.csv"
