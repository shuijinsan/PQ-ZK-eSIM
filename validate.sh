#!/bin/bash
# Compare each claim's results/ against expected/ (tolerances in claim.txt).
#
#   --quick   Claim 1, 3, 4, 5 (default). These need only the core install.sh.
#   --full    All five claims, including the SageMath-based Claim 2. Requires
#             running claims/claim2_security_estimation/setup.sh first.
#
# Explicit claim names override the mode, e.g.:
#   bash validate.sh claim4_sliding_window
#
# Usage: bash validate.sh [--quick|--full] [claim ...]
set -e
cd "$(dirname "$0")"

QUICK_CLAIMS=(
    claim1_qemu_performance
    claim3_dos_early_reject
    claim4_sliding_window
    claim5_sparse_noise
)
FULL_CLAIMS=(
    claim1_qemu_performance
    claim2_security_estimation
    claim3_dos_early_reject
    claim4_sliding_window
    claim5_sparse_noise
)

MODE="--quick"
if [ $# -gt 0 ]; then
    case "$1" in
        --quick|--full) MODE="$1"; shift ;;
    esac
fi

if [ $# -gt 0 ]; then
    python3 validate.py "$@"
elif [ "$MODE" = "--full" ]; then
    python3 validate.py "${FULL_CLAIMS[@]}"
else
    python3 validate.py "${QUICK_CLAIMS[@]}"
fi
