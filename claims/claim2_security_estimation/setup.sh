#!/bin/bash
# Claim 2: one-time heavyweight dependency setup (SageMath + lattice-estimator).
# Deliberately kept out of the core install.sh: SageMath needs several GB of
# disk space and would slow down the quick evaluation path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPS_DIR="$ROOT/.deps"
ESTIMATOR_DIR="$DEPS_DIR/lattice-estimator"
ESTIMATOR_COMMIT="6019056"
MIN_SAGE_MAJOR=10

echo "== Claim 2 dependency setup =="
echo "This step installs SageMath and downloads the lattice-estimator."
echo "Expect several minutes and several GB of disk space."

if ! command -v sage >/dev/null 2>&1; then
    echo "== Installing SageMath =="
    sudo apt-get update
    sudo apt-get install -y ca-certificates git sagemath
fi

if ! command -v sage >/dev/null 2>&1; then
    echo "ERROR: SageMath installation failed; 'sage' is not on PATH." >&2
    exit 2
fi

SAGE_MAJOR="$(sage --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\)\..*/\1/p')"
echo "Detected SageMath major version: ${SAGE_MAJOR:-unknown}"
if [ -z "$SAGE_MAJOR" ] || [ "$SAGE_MAJOR" -lt "$MIN_SAGE_MAJOR" ]; then
    echo "ERROR: SageMath >= ${MIN_SAGE_MAJOR}.x is required for lattice-estimator ${ESTIMATOR_COMMIT}." >&2
    echo "Ubuntu 22.04 ships SageMath 9.x, which is too old for this estimator revision." >&2
    echo "Use a newer Ubuntu release, or install SageMath ${MIN_SAGE_MAJOR}.x (e.g. conda-forge) and re-run." >&2
    exit 2
fi

mkdir -p "$DEPS_DIR"

if [ ! -d "$ESTIMATOR_DIR/.git" ]; then
    echo "== Cloning lattice-estimator =="
    git clone https://github.com/malb/lattice-estimator.git "$ESTIMATOR_DIR"
fi

echo "== Pinning lattice-estimator to ${ESTIMATOR_COMMIT} =="
git -C "$ESTIMATOR_DIR" fetch origin
git -C "$ESTIMATOR_DIR" checkout "$ESTIMATOR_COMMIT"

# `sage -c` works across Sage distributions (apt/source and conda-forge),
# unlike `sage -python`, which conda-forge builds do not accept.
echo "== Verifying imports =="
PYTHONPATH="$ESTIMATOR_DIR" sage -c '
import fpylll
from sage.all import oo
from estimator import SIS
from estimator.reduction import RC
print("fpylll: OK   sage: OK   estimator: OK")
'

echo "== Claim 2 dependencies ready =="
echo "Run: bash claims/claim2_security_estimation/run.sh"
