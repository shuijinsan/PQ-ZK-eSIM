#!/bin/bash
# Claim 1: Figure 5 / Section 7.2 per-phase timing (QEMU ARM64 emulation).
# Usage: bash claims/claim1/run.sh [--quick|--full]   (both equivalent)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim1_qemu_performance/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    artifact/terminal/euicc/build/arm64/bench_pqzkesim_comprehensive --only phase
cp phase_timing_results.csv claims/claim1_qemu_performance/results/
echo "Done. See claims/claim1_qemu_performance/results/phase_timing_results.csv"
