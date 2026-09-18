#!/bin/bash
# Claim 2: one-time heavyweight dependency setup (SageMath + lattice-estimator).
# Deliberately kept out of the core install.sh: SageMath needs several GB of
# disk space and would slow down the quick evaluation path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPS_DIR="$ROOT/.deps"
ESTIMATOR_DIR="$DEPS_DIR/lattice-estimator"
SAGE_ENV_DIR="$DEPS_DIR/sage-env"
SAGE_REQUIREMENT="sage=10"
ESTIMATOR_COMMIT="6019056"
MIN_SAGE_MAJOR=10

# Prefer a SageMath already on PATH when it is new enough.
SAGE_BIN=""
if command -v sage >/dev/null 2>&1; then
    m="$(sage --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\)\..*/\1/p')"
    if [ -n "$m" ] && [ "$m" -ge "$MIN_SAGE_MAJOR" ]; then
        SAGE_BIN="$(command -v sage)"
        echo "Using the SageMath already on PATH (version ${m}.x)."
    else
        echo "SageMath on PATH is ${m:-unknown}.x; ${MIN_SAGE_MAJOR}.x or newer is required."
    fi
fi

echo "== Claim 2 dependency setup =="
echo "This step installs SageMath and downloads the lattice-estimator."
echo "Expect several minutes and several GB of disk space."

mkdir -p "$DEPS_DIR"

if [ -z "$SAGE_BIN" ]; then
    # The distribution package is not usable everywhere: Ubuntu 22.04 ships
    # SageMath 9.x, which is too old for lattice-estimator 6019056, and some
    # later releases do not ship the package at all. Install a self-contained
    # SageMath from conda-forge into .deps/ instead.
    if ! command -v conda >/dev/null 2>&1; then
        echo "ERROR: SageMath >= ${MIN_SAGE_MAJOR}.x is required and conda was not found." >&2
        echo "Install it from conda-forge and re-run this script:" >&2
        echo "  conda create -y -p \"$SAGE_ENV_DIR\" -c conda-forge \"$SAGE_REQUIREMENT\" fpylll" >&2
        exit 2
    fi

    if [ ! -x "$SAGE_ENV_DIR/bin/sage" ]; then
        echo "== Creating conda environment with SageMath (the slow step) =="
        conda create -y -p "$SAGE_ENV_DIR" -c conda-forge "$SAGE_REQUIREMENT" fpylll
    fi
    SAGE_BIN="$SAGE_ENV_DIR/bin/sage"
fi

if [ ! -x "$SAGE_BIN" ]; then
    echo "ERROR: no usable SageMath executable was found." >&2
    exit 2
fi
export PATH="$(dirname "$SAGE_BIN"):$PATH"

if [ ! -d "$ESTIMATOR_DIR/.git" ]; then
    echo "== Cloning lattice-estimator =="
    git clone https://github.com/malb/lattice-estimator.git "$ESTIMATOR_DIR"
fi

echo "== Pinning lattice-estimator to ${ESTIMATOR_COMMIT} =="
git -C "$ESTIMATOR_DIR" fetch origin
git -C "$ESTIMATOR_DIR" checkout "$ESTIMATOR_COMMIT"

# `sage -c` works across Sage distributions (conda-forge and distro builds),
# unlike `sage -python`, which conda-forge builds do not accept.
echo "== Verifying imports =="
PYTHONPATH="$ESTIMATOR_DIR" "$SAGE_BIN" -c '
import fpylll
from sage.all import oo
from estimator import SIS
from estimator.reduction import RC
print("fpylll: OK   sage: OK   estimator: OK")
'

echo "== Claim 2 dependencies ready =="
echo "Run: bash claims/claim2_security_estimation/run.sh"
