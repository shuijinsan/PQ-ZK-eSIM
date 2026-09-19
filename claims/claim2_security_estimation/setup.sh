#!/bin/bash
# Claim 2: one-time heavyweight dependency setup (SageMath + lattice-estimator).
#
# Kept out of the core install.sh: SageMath needs several GB of disk space and
# would slow down the quick evaluation path.
#
# This script is self-contained and non-interactive. It reuses a SageMath that
# is already available when possible, and otherwise bootstraps conda and
# installs SageMath from conda-forge. Nothing here depends on the caller's
# shell configuration: no .bashrc edit, no `conda activate`, no manual PATH
# export, and no interactive channel terms-of-service prompt.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPS_DIR="$ROOT/.deps"
ESTIMATOR_DIR="$DEPS_DIR/lattice-estimator"
CONDA_DIR="$DEPS_DIR/miniforge3"
SAGE_ENV_DIR="$DEPS_DIR/sage-env"
SAGE_BIN_FILE="$DEPS_DIR/sage-bin"
CONDA_CHANNEL="conda-forge"
SAGE_REQUIREMENT="sage=10"
ESTIMATOR_COMMIT="6019056"
MIN_SAGE_MAJOR=10
MINIFORGE_URL="https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh"

sage_major() {
    # `sage` resolves Singular and the rest of the Sage stack from its own bin
    # directory, so put that on PATH first. Distributions print the version
    # either as "SageMath version 10.6, ..." or as a bare "10.6".
    PATH="$(dirname "$1"):$PATH" "$1" --version 2>/dev/null \
        | sed -n 's/^\([0-9][0-9]*\)\..*/\1/p; s/.*version \([0-9][0-9]*\)\..*/\1/p' | head -n 1
}

usable_sage() {
    [ -n "${1:-}" ] && [ -x "$1" ] || return 1
    local m
    m="$(sage_major "$1")"
    [ -n "$m" ] && [ "$m" -ge "$MIN_SAGE_MAJOR" ]
}

echo "== Claim 2 dependency setup =="
echo "This step prepares SageMath and downloads the lattice-estimator."
echo "It needs network access and several GB of free disk space."
echo

command -v git >/dev/null 2>&1 || { echo "ERROR: git is required." >&2; exit 2; }

mkdir -p "$DEPS_DIR"
SAGE_BIN=""

# 1. Reuse a SageMath that is already on PATH.
if command -v sage >/dev/null 2>&1 && usable_sage "$(command -v sage)"; then
    SAGE_BIN="$(command -v sage)"
    echo "Reusing the SageMath found on PATH: $SAGE_BIN"
fi

# 2. Reuse the environment a previous run of this script created.
if [ -z "$SAGE_BIN" ] && usable_sage "$SAGE_ENV_DIR/bin/sage"; then
    SAGE_BIN="$SAGE_ENV_DIR/bin/sage"
    echo "Reusing the SageMath in $SAGE_ENV_DIR"
fi

if [ -z "$SAGE_BIN" ]; then
    # 3. Find a conda to use. `conda` is normally a shell function defined in
    #    ~/.bashrc, which a non-interactive shell does not load, so look at the
    #    usual install locations as well.
    CONDA_EXE=""
    for candidate in \
        "$CONDA_DIR/bin/conda" \
        "$HOME/miniforge3/bin/conda" \
        "$HOME/miniconda3/bin/conda" \
        "$HOME/anaconda3/bin/conda" \
        "$(command -v conda 2>/dev/null || true)"
    do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            CONDA_EXE="$candidate"
            break
        fi
    done

    if [ -z "$CONDA_EXE" ]; then
        command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required to install Miniforge." >&2; exit 2; }
        echo "== No conda found; installing Miniforge into $CONDA_DIR =="
        curl -fsSL -o "$DEPS_DIR/miniforge.sh" "$MINIFORGE_URL"
        bash "$DEPS_DIR/miniforge.sh" -b -p "$CONDA_DIR"
        rm -f "$DEPS_DIR/miniforge.sh"
        CONDA_EXE="$CONDA_DIR/bin/conda"
    fi
    echo "Using conda: $CONDA_EXE"

    if [ ! -x "$SAGE_ENV_DIR/bin/sage" ]; then
        echo "== Creating the SageMath environment (this is the slow step) =="
        # conda-forge only. Consulting the defaults channel requires accepting
        # its terms of service, which a non-interactive run cannot do.
        "$CONDA_EXE" create -y \
            --override-channels -c "$CONDA_CHANNEL" \
            -p "$SAGE_ENV_DIR" \
            "$SAGE_REQUIREMENT" fpylll
    fi
    SAGE_BIN="$SAGE_ENV_DIR/bin/sage"
fi

if ! usable_sage "$SAGE_BIN"; then
    echo "ERROR: SageMath ${MIN_SAGE_MAJOR}.x or newer is required but is not usable: $SAGE_BIN" >&2
    exit 2
fi

# Record the chosen interpreter so run.sh finds it from a fresh shell.
printf '%s\n' "$SAGE_BIN" > "$SAGE_BIN_FILE"
echo "SageMath ready: $SAGE_BIN"

echo
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

echo
echo "== Claim 2 dependencies ready =="
echo "Run: bash claims/claim2_security_estimation/run.sh"
