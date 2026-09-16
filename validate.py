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
  - "timing"  columns are machine-dependent: a FASTER machine (lower
              latency) always passes; a slower machine passes up to
              TIMING_SLOW_TOL (100% slower, i.e. <= 2x).
  - "speedup" a named row/column must exceed a minimum (e.g. Speedup > 1).
"""

import csv
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
RATE_TOL = 1e-3
# Asymmetric timing tolerance (QEMU emulation speed varies across machines):
#   - faster  (got <= expected): always accepted -- a faster host is never a fail
#   - slower  (got >  expected): accepted up to 100% slower (<= 2x)
TIMING_SLOW_TOL = 1.0

# Per-claim file spec. "rowcount" files only check header + row count
# (raw per-trial latency traces are timing-only and too noisy to compare).
CLAIMS = {
    "claim1_qemu_performance": {
    "phase_timing_results.csv": {
        "rowcount": True,
        "mean_timing": [
            "lpa_precompute_us",
            "euicc_commit_us",
            "challenge_gen_us",
            "tee_authtoken_us",
            "euicc_mask_us",
            "lpa_aggregate_us",
            "server_verify_us",
            "total_us",
            ],
        },
    },
    "claim2_security_estimation": {
        "msis_estimator_sweep.csv": {
            "key": "length_bound",
            "exact": ["bkz_block_size"],
            "rate": ["classical_bits", "quantum_bits"],
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
            "detection": "detection_rate",
            "honest_frr": {"rho": 1.0, "col": "false_reject_rate", "max": 0.05},
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


def within_timing_tol(expected, got):
    """Asymmetric timing tolerance (see TIMING_SLOW_TOL)."""
    fe, fg = num(expected), num(got)
    if fe is None or fg is None:
        return str(expected).strip() == str(got).strip()
    if fg <= fe:
        return True                       # faster or equal: always OK
    if fe <= 0:
        return False                      # reference <= 0 but got is slower
    return (fg - fe) / fe <= TIMING_SLOW_TOL


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

        ok = True
        for col in spec.get("mean_timing", []):
            exp_mean = sum(float(r[col]) for r in exp_rows) / len(exp_rows)
            res_mean = sum(float(r[col]) for r in res_rows) / len(res_rows)

            if not within_timing_tol(exp_mean, res_mean):
                print(
                    f"  [{name}] mean {col}: "
                    f"expected {exp_mean:.2f}, got {res_mean:.2f} "
                    f"(slower by > {int(TIMING_SLOW_TOL*100)}%)"
                )
                ok = False

        if ok:
            print(f"  [{name}] OK (header + {len(res_rows)} rows + phase means)")
        return ok

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
            if not within_timing_tol(er[col], rr[col]):
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]} (slower by > {int(TIMING_SLOW_TOL*100)}%)")
                ok = False

    honest_frr = spec.get("honest_frr")
    if honest_frr:
        target = honest_frr["rho"]
        col = honest_frr["col"]
        max_val = honest_frr["max"]
        for rr in res_rows:
            if abs(float(rr["rho"]) - target) < 1e-9:
                val = float(rr[col])
                if val > max_val:
                    print(f"  [{name}] {col} (rho={target}) expected <= {max_val}, got {val}")
                    ok = False
                break

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
