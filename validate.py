#!/usr/bin/env python3
"""Validate AE results/ against expected/ for PQ-ZK-eSIM claims.

Usage: python3 validate.py [claim ...]

Each claim directory contains:
  claim.txt   - human-readable claim description
  run.sh      - produces the CSVs under results/
  expected/   - reference CSVs (this repo's recorded outputs)
  results/    - CSVs produced by run.sh on the reviewer's machine

Comparison rules (from each claim's Tolerance section):
  - "key"     column identifies rows; must match exactly (set and order).
  - "exact"   columns must match exactly (counts, integers).
  - "rate"    columns must match within 1e-3 (0.0/1.0 success/detection).
  - "timing"  columns must match within +-50% of the reference value.
  - "speedup" a named row/column must exceed a minimum (e.g. Speedup > 1).
"""

import csv
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
TIMING_TOL = 0.50
RATE_TOL = 1e-3

# Per-claim file spec. "rowcount" files only check header + row count
# (raw per-trial latency traces are timing-only and too noisy to compare).
CLAIMS = {
    "claim1_qemu_performance": {
        "phase_timing_results.csv": {
            "rowcount": True,
        },
    },
    "claim3_dos_early_reject": {
        "dos_results.csv": {
            "key": "test",
            "timing": ["avg_us"],
            "skip_timing": ["Speedup"],
            "speedup": {"row": "Speedup", "col": "avg_us", "min": 1.0},
        },
    },
    "claim4_sliding_window": {
        "sliding_window_resync_results.csv": {
            "key": ["window_size", "sync_depth"],
            "rate": ["success_rate"],
            "timing": ["avg_mac_us", "avg_total_us"],
        },
    },
    "claim5_sparse_noise": {
        "sparse_noise_attack_results.csv": {
            "key": "rho",
            "rate": ["false_reject_rate"],
            "detection": "detection_rate",
            "timing": ["avg_total_us"],
        },
    },
}


def read_csv(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = [dict(r) for r in reader]
    return fieldnames, rows


def num(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return None


def within_tol(a, b, tol):
    fa, fb = num(a), num(b)
    if fa is None or fb is None:
        return str(a).strip() == str(b).strip()
    if fa == fb:
        return True
    denom = max(abs(fa), abs(fb))
    if denom == 0:
        return True
    return abs(fa - fb) / denom <= tol


def key_of(row, key):
    if isinstance(key, list):
        return tuple(row[k] for k in key)
    return row[key]


def compare_file(claim, name, spec):
    exp_path = os.path.join(ROOT, "claims", claim, "expected", name)
    res_path = os.path.join(ROOT, "claims", claim, "results", name)

    if not os.path.exists(res_path):
        print(f"  [{name}] MISSING results file (run: bash claims/{claim}/run.sh)")
        return False
    if not os.path.exists(exp_path):
        print(f"  [{name}] MISSING expected file")
        return False

    exp_fields, exp_rows = read_csv(exp_path)
    res_fields, res_rows = read_csv(res_path)

    if exp_fields != res_fields:
        print(f"  [{name}] header mismatch:\n    expected={exp_fields}\n    actual  ={res_fields}")
        return False

    if spec.get("rowcount"):
        if len(exp_rows) != len(res_rows):
            print(f"  [{name}] row count mismatch: expected {len(exp_rows)}, got {len(res_rows)}")
            return False
        print(f"  [{name}] OK (header + {len(res_rows)} rows; latency is timing-only)")
        return True

    key = spec["key"]
    exp_keys = [key_of(r, key) for r in exp_rows]
    res_keys = [key_of(r, key) for r in res_rows]
    if exp_keys != res_keys:
        print(f"  [{name}] row key mismatch:\n    expected={exp_keys}\n    actual  ={res_keys}")
        return False

    ok = True
    for er in exp_rows:
        rr = res_rows[exp_keys.index(key_of(er, key))]
        k = key_of(er, key)
        for col in spec.get("exact", []):
            if str(er[col]).strip() != str(rr[col]).strip():
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]}")
                ok = False
        for col in spec.get("rate", []):
            if not within_tol(er[col], rr[col], RATE_TOL):
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]}")
                ok = False
        det = spec.get("detection")
        if det:
            rho = float(k)
            val = float(rr[det])
            if rho <= 0.75 and val < 0.95:
                print(f"  [{name}] {det} (rho={rho}) expected ~1.0, got {val}")
                ok = False
            elif rho >= 0.999 and val > 0.05:
                print(f"  [{name}] {det} (rho={rho}) expected ~0.0, got {val}")
                ok = False
        for col in spec.get("timing", []):
            if k in spec.get("skip_timing", []):
                continue
            if not within_tol(er[col], rr[col], TIMING_TOL):
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]} (out of +-50%)")
                ok = False

    sp = spec.get("speedup")
    if sp:
        for rr in res_rows:
            if key_of(rr, key) == sp["row"]:
                val = num(rr[sp["col"]])
                if val is not None and val <= sp["min"]:
                    print(f"  [{name}] {sp['col']} (row {sp['row']}) expected > {sp['min']}, got {val}")
                    ok = False

    if ok:
        print(f"  [{name}] OK")
    return ok


def main():
    args = sys.argv[1:]
    claims = args or list(CLAIMS.keys())
    unknown = [c for c in claims if c not in CLAIMS]
    if unknown:
        print(f"Unknown claim(s): {unknown}")
        sys.exit(2)

    all_ok = True
    for claim in claims:
        print(f"== {claim} ==")
        for name, spec in CLAIMS[claim].items():
            if not compare_file(claim, name, spec):
                all_ok = False
        print()

    if all_ok:
        print("ALL CLAIMS PASSED")
        sys.exit(0)
    else:
        print("SOME CLAIMS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
