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
  - "rate"    columns must match within 1e-3 (0.0/1.0 success/detection)
              and must lie in [0, 1].
  - "timing"  columns are machine-dependent: a FASTER machine (lower
              latency) always passes; a slower machine passes up to
              TIMING_SLOW_TOL (100% slower, i.e. <= 2x). Timings must be
              positive finite numbers.
  - "speedup" is recomputed from the two named timing rows and checked
              against the value written in the file.

A value that is not a finite number (text, NaN, +/-inf) never passes, and a
ratio outside [0, 1] is a failure rather than a pass.
"""

import csv
import math
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
RATE_TOL = 1e-3
# Asymmetric timing tolerance (QEMU emulation speed varies across machines):
#   - faster  (got <= expected): always accepted -- a faster host is never a fail
#   - slower  (got >  expected): accepted up to 100% slower (<= 2x)
TIMING_SLOW_TOL = 1.0
# A "Speedup" row must agree with the ratio recomputed from its two timing
# rows to within this relative tolerance.
RATIO_TOL = 0.05

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
            "speedup": {
                "row": "Speedup", "col": "avg_us", "min": 1.0,
                "fast_row": "MAC_W_Verification",
                "slow_row": "Full_Lattice_Verification",
            },
        },
    },
    "claim4_sliding_window": {
        "sliding_window_resync_results.csv": {
            "key": ["window_size", "sync_depth"],
            "ratio": ["success_rate"],
            "timing": ["avg_mac_us", "avg_total_us"],
        },
    },
    "claim5_sparse_noise": {
        "sparse_noise_attack_results.csv": {
            "key": "rho",
            "detection": "detection_rate",
            "ratio": ["false_reject_rate"],
            "honest_frr": {"rho": 1.0, "col": "false_reject_rate", "max": 0.05},
            "timing": ["avg_total_us"],
        },
        # Per-norm breakdown. Figure 7A plots the ell_1 lower-bound rate, which
        # is l1_low_rate; detection_rate in the file above is the union of the
        # ell_2-low, ell_2-high, ell_inf and ell_1 checks. The rho = 0.90 row
        # sits in the transition band, so only the threshold rule is applied.
        "sparse_noise_norm_breakdown.csv": {
            "key": "rho",
            "rules_only": True,
            "detection": "l1_low_rate",
            "range": ["l2_low_rate", "l2_high_rate", "linf_rate",
                      "l1_low_rate", "verify_reject_rate"],
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
    """Parse a finite float; anything else (text, NaN, +/-inf) yields None."""
    try:
        v = float(x)
    except (ValueError, TypeError):
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v


def detection_ok(rows, spec, name, ok):
    """Apply the acceptance threshold stated in the claim's Tolerance section."""
    det = spec.get("detection")
    if not det:
        return ok
    for rr in rows:
        k = rr[spec["key"]]
        rho = num(k)
        val = num(rr[det])
        if rho is None or not rate_ok(rr[det]):
            print(f"  [{name}] {det} (rho={k}) is not a ratio in [0, 1]: {rr[det]!r}")
            ok = False
        elif rho <= 0.75 and val < 0.95:
            print(f"  [{name}] {det} (rho={rho}) expected ~1.0, got {val}")
            ok = False
        elif rho >= 0.999 and val > 0.05:
            print(f"  [{name}] {det} (rho={rho}) expected ~0.0, got {val}")
            ok = False
    return ok


def range_ok(rows, spec, name, ok):
    """Columns listed under "range" must be ratios in [0, 1] (no comparison)."""
    for col in spec.get("range", []):
        for rr in rows:
            if not rate_ok(rr[col]):
                print(f"  [{name}] {col} (row {rr[spec['key']]}) is not a ratio in [0, 1]: {rr[col]!r}")
                ok = False
    return ok


def rate_ok(x):
    """A ratio must be a finite number inside [0, 1]."""
    v = num(x)
    return v is not None and 0.0 <= v <= 1.0


def within_tol(a, b, tol):
    fa, fb = num(a), num(b)
    if fa is None or fb is None:
        return False                      # a non-numeric value never matches
    if fa == fb:
        return True
    denom = max(abs(fa), abs(fb))
    if denom == 0:
        return True
    return abs(fa - fb) / denom <= tol


def within_timing_tol(expected, got):
    """Asymmetric timing tolerance (see TIMING_SLOW_TOL).

    Both values must be positive finite numbers: a negative or non-numeric
    latency is a failure, not something that is merely "not slower".
    """
    fe, fg = num(expected), num(got)
    if fe is None or fg is None:
        return False
    if fe <= 0 or fg <= 0:
        return False
    if fg <= fe:
        return True                       # faster or equal: always OK
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
    if spec.get("rules_only"):
        # No stored reference: the file is judged only against the acceptance
        # rules stated in the claim's Tolerance section. Used for outputs whose
        # non-extreme rows legitimately vary between runs.
        _, res_rows = read_csv(res_path)
        ok = True
        ok = detection_ok(res_rows, spec, name, ok)
        ok = range_ok(res_rows, spec, name, ok)
        if ok:
            print(f"  [{name}] OK (checked against the acceptance rules)")
        return ok

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
        for col in spec.get("ratio", []):
            if not rate_ok(rr[col]):
                print(f"  [{name}] {col} (row {k}) is not a ratio in [0, 1]: {rr[col]!r}")
                ok = False
            elif not within_tol(er[col], rr[col], RATE_TOL):
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]}")
                ok = False
        for col in spec.get("rate", []):
            if not within_tol(er[col], rr[col], RATE_TOL):
                print(f"  [{name}] {col} (row {k}) expected {er[col]}, got {rr[col]}")
                ok = False
        if spec.get("detection"):
            ok = detection_ok([er, rr], spec, name, ok)
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
        found = False
        for rr in res_rows:
            rho = num(rr["rho"])
            if rho is not None and abs(rho - target) < 1e-9:
                found = True
                if not rate_ok(rr[col]):
                    print(f"  [{name}] {col} (rho={target}) is not a ratio in [0, 1]: {rr[col]!r}")
                    ok = False
                elif num(rr[col]) > max_val:
                    print(f"  [{name}] {col} (rho={target}) expected <= {max_val}, got {rr[col]}")
                    ok = False
                break
        if not found:
            print(f"  [{name}] no honest row with rho={target}")
            ok = False

    sp = spec.get("speedup")
    if sp:
        # Recompute the ratio from the two timing rows rather than trusting the
        # value written into the file.
        by_row = {key_of(rr, key): rr for rr in res_rows}
        col = sp["col"]
        fast = num(by_row.get(sp["fast_row"], {}).get(col))
        slow = num(by_row.get(sp["slow_row"], {}).get(col))
        reported = num(by_row.get(sp["row"], {}).get(col))
        if fast is None or slow is None or fast <= 0 or slow <= 0:
            print(f"  [{name}] cannot recompute {sp['row']}: missing or invalid timings")
            ok = False
        else:
            ratio = slow / fast
            if ratio <= sp["min"]:
                print(f"  [{name}] recomputed {sp['row']} = {ratio:.2f}, expected > {sp['min']}")
                ok = False
            if reported is None or abs(reported - ratio) > RATIO_TOL * ratio:
                print(f"  [{name}] {sp['row']} row reads "
                      f"{by_row.get(sp['row'], {}).get(col)!r}, recomputed {ratio:.2f}")
                ok = False

    ok = range_ok(res_rows, spec, name, ok)

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
