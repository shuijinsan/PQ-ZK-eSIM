#!/bin/bash
# Claim 2: Figure 4 HNF-MSIS lattice-estimator sweep.
# Requires the one-time setup: bash claims/claim2_security_estimation/setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/claims/claim2_security_estimation"
ESTIMATOR_DIR="${LATTICE_ESTIMATOR:-$ROOT/.deps/lattice-estimator}"
EXPECTED_COMMIT="6019056"

cd "$HERE"
mkdir -p results

# setup.sh records the SageMath interpreter it selected, so this runs from a
# fresh non-interactive shell without activating conda or editing PATH.
SAGE_BIN=""
if [ -f "$ROOT/.deps/sage-bin" ]; then
    read -r SAGE_BIN < "$ROOT/.deps/sage-bin"
fi
if [ -z "$SAGE_BIN" ] || [ ! -x "$SAGE_BIN" ]; then
    if [ -x "$ROOT/.deps/sage-env/bin/sage" ]; then
        SAGE_BIN="$ROOT/.deps/sage-env/bin/sage"
    elif command -v sage >/dev/null 2>&1; then
        SAGE_BIN="$(command -v sage)"
    fi
fi

if [ -z "$SAGE_BIN" ] || [ ! -x "$SAGE_BIN" ]; then
    echo "ERROR: SageMath is required for Claim 2 but was not found." >&2
    echo "Run: bash claims/claim2_security_estimation/setup.sh" >&2
    exit 2
fi
export PATH="$(dirname "$SAGE_BIN"):$PATH"

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
    if "$SAGE_BIN" -python -c "pass" >/dev/null 2>&1; then
        "$SAGE_BIN" -python "$@"
    elif "$SAGE_BIN" --python -c "pass" >/dev/null 2>&1; then
        "$SAGE_BIN" --python "$@"
    else
        local d
        d="$(dirname "$SAGE_BIN")"
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
