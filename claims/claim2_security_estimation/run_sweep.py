#!/usr/bin/env python3
"""MSIS estimator sweep for the PQ-ZK-eSIM parameter set (Figure 4).

Sweeps the infinity-norm length bound with the lattice-estimator
(github.com/malb/lattice-estimator, commit 6019056) and reports the
classical (MATZOV) and quantum (LaaMosPol14) attack cost of the extraction
instance used in Theorem 4.

Instance (N=256, q=8380417, k=3, m=8): coefficient view with
n = k*N = 768 rows and m = (m+1)*N = 2304 columns, norm = infinity.

Writes expected/msis_estimator_sweep.csv. Figure 4 is rendered separately
by plot_sweep.py from that CSV.
"""
import csv
import math
import os

from sage.all import oo
from estimator import SIS
from estimator.reduction import RC

Q = 8380417
N_ROWS = 768
M_COLS = 2304
BETAS = [40000, 50000, 60000, 70000, 71400, 80000, 90000, 100000,
         120000, 140000, 160000, 200000]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected")

rows = []
for b in BETAS:
    p = SIS.Parameters(n=N_ROWS, q=Q, length_bound=b, m=M_COLS, norm=oo)
    c = SIS.estimate(p, red_cost_model=RC.MATZOV, quiet=True)["lattice"]
    qq = SIS.estimate(p, red_cost_model=RC.LaaMosPol14, quiet=True)["lattice"]
    cl = math.log2(float(c["rop"]))
    qu = math.log2(float(qq["rop"]))
    rows.append((b, cl, qu, int(c["beta"])))
    print("  bound=%7d  classical=%6.1f  quantum=%6.1f  BKZ-beta=%d"
          % (b, cl, qu, int(c["beta"])), flush=True)

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "msis_estimator_sweep.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["length_bound", "classical_bits", "quantum_bits", "bkz_block_size"])
    w.writerows(rows)

print("Wrote", os.path.join(OUT, "msis_estimator_sweep.csv"))
