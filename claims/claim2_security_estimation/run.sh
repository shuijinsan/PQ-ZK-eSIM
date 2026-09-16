#!/bin/bash
# Claim 2: Figure 4 lattice-estimator sweep (MSIS instance).
# Usage: bash claims/claim2_security_estimation/run.sh
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/claims/claim2_security_estimation"
export PYTHONPATH="${LATTICE_ESTIMATOR:-$HOME/lattice-estimator}"
mkdir -p results
python3 run_sweep.py
python3 plot_sweep.py
cp expected/msis_estimator_sweep.csv expected/fig_lattice_estimator.png results/
echo "Done. See claims/claim2_security_estimation/results/"
