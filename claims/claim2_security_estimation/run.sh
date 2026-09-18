#!/bin/bash
# Claim 2: Figure 4 HNF-MSIS lattice-estimator sweep.
# Requires the one-time setup: bash claims/claim2_security_estimation/setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/claims/claim2_security_estimation"
ESTIMATOR_DIR="${LATTICE_ESTIMATOR:-$ROOT/.deps/lattice-estimator}"
EXPECTED_COMMIT="6019056"

# SageMath installed by setup.sh lives in a conda prefix under .deps/.
if [ -x "$ROOT/.deps/sage-env/bin/sage" ]; then
    export PATH="$ROOT/.deps/sage-env/bin:$PATH"
fi

cd "$HERE"
mkdir -p results

if ! command -v sage >/dev/null 2>&1; then
    echo "ERROR: SageMath is required for Claim 2 but was not found on PATH." >&2
    echo "Run: bash claims/claim2_security_estimation/setup.sh" >&2
    exit 2
fi

if [ ! -d "$ESTIMATOR_DIR/.git" ]; then
    echo "ERROR: lattice-estimator not found at $ESTIMATOR_DIR" >&2
    echo "Run: bash claims/claim2_security_estimation/setup.sh" >&2
    exit 2
fi

ACTUAL_COMMIT="$(git -C "$ESTIMATOR_DIR" rev-parse --short=7 HEAD)"
if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "ERROR: lattice-estimator commit mismatch (expected $EXPECTED_COMMIT, got $ACTUAL_COMMIT)." >&2
    echo "Run: bash claims/claim2_security_estimation/setup.sh" >&2
    exit 2
fi

export PYTHONPATH="$ESTIMATOR_DIR"

# Sage installations differ in how the bundled Python is invoked: distro builds
# accept `sage -python`, conda-forge builds do not.
run_sage_python() {
    if sage -python -c "pass" >/dev/null 2>&1; then
        sage -python "$@"
    elif sage --python -c "pass" >/dev/null 2>&1; then
        sage --python "$@"
    else
        local d
        d="$(dirname "$(command -v sage)")"
        if [ -x "$d/python3" ]; then
            "$d/python3" "$@"
        else
            "$d/python" "$@"
        fi
    fi
}

echo "== HNF-MSIS estimator sweep =="
run_sage_python run_sweep.py

echo "== Figure 4 =="
python3 plot_sweep.py

echo "Done. See claims/claim2_security_estimation/results/"
