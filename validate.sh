#!/bin/bash
# Compare each claim's results/ against expected/ (tolerances in claim.txt).
# Usage: bash validate.sh [claim1 claim4 ...]   (no args = all claims)
set -e
cd "$(dirname "$0")"
python3 validate.py "$@"
