#!/bin/bash
# Claim 5: Figure 7 / Appendix D sliding-window resynchronization (QEMU ARM64).
# Usage: bash claims/claim5/run.sh [--quick|--full]   (both equivalent)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim5_desync_dos/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    artifact/terminal/euicc/build/arm64/bench_pqzkesim_comprehensive --only sliding
cp sliding_window_resync_results.csv claims/claim5_desync_dos/results/
echo "Done. See claims/claim5_desync_dos/results/sliding_window_resync_results.csv"
