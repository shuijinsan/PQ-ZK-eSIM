#!/bin/bash
# Claim 6: Figure 8 / Appendix D sparse-noise degradation detection (QEMU ARM64).
# Usage: bash claims/claim6/run.sh [--quick|--full]   (both equivalent)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim6_sparse_noise/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    artifact/terminal/euicc/build/arm64/bench_pqzkesim_comprehensive --only sparse
cp sparse_noise_attack_results.csv claims/claim6_sparse_noise/results/
echo "Done. See claims/claim6_sparse_noise/results/sparse_noise_attack_results.csv"
