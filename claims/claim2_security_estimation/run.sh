#!/bin/bash
# Claim 2: Figure 4 HNF-MSIS lattice-estimator sweep.
# Usage: bash claims/claim2_security_estimation/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/claims/claim2_security_estimation"

export PYTHONPATH="${LATTICE_ESTIMATOR:-$HOME/lattice-estimator}"

mkdir -p results

python3 run_sweep.py
python3 plot_sweep.py

echo "Done. See claims/claim2_security_estimation/results/"