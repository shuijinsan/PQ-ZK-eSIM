#!/bin/bash
# Claim 5: Figure 7 / Appendix E sparse-noise degradation detection (QEMU ARM64).
# Usage: bash claims/claim5_sparse_noise/run.sh
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p claims/claim5_sparse_noise/results
qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    artifact/terminal/euicc/build/arm64/bench_pqzkesim_comprehensive --only sparse
cp sparse_noise_attack_results.csv claims/claim5_sparse_noise/results/
rm -f sparse_noise_attack_results.csv
echo "Done. See claims/claim5_sparse_noise/results/sparse_noise_attack_results.csv"
