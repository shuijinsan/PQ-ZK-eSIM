#!/usr/bin/env python3
"""HNF-MSIS estimator sweep for the PQ-ZK-eSIM parameter set (Figure 4).

Sweeps the HNF-MSIS infinity-norm length bound with the lattice-estimator
(github.com/malb/lattice-estimator, commit 6019056) and reports the
classical (MATZOV) and quantum (LaaMosPol14) security of the extraction
instance used in Theorem 4.

Instance (N=256, q=8380417, k=3, m=8): coefficient view with
n = k*N = 768 rows and m = (m+1)*N = 2304 columns, norm = infinity.
"""
import csv
import math
import os

from sage.all import oo
from matplotlib import pyplot as plt
from estimator import SIS
from estimator.reduction import RC

Q = 8380417
N_ROWS = 768
M_COLS = 2304
BETAS = [40000, 50000, 60000, 70000, 71400, 80000, 90000, 100000,
         120000, 140000, 160000, 200000]
HIGHLIGHT = 71400       # HNF-MSIS extraction bound
NIST = {1: 143, 3: 207, 5: 272}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

rows = []
for b in BETAS:
    p = SIS.Parameters(n=N_ROWS, q=Q, length_bound=b, m=M_COLS, norm=oo)
    c = SIS.estimate(p, red_cost_model=RC.MATZOV, quiet=True)["lattice"]
    qq = SIS.estimate(p, red_cost_model=RC.LaaMosPol14, quiet=True)["lattice"]
    cl = math.log2(float(c["rop"]))
    qu = math.log2(float(qq["rop"]))
    rows.append((b, cl, qu, int(c["beta"])))
    print("  bound=%7d  classical=%6.1f  quantum=%6.1f  BKZ-beta=%d" % (b, cl, qu, int(c["beta"])), flush=True)

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "msis_estimator_sweep.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["length_bound", "classical_bits", "quantum_bits", "bkz_block_size"])
    w.writerows(rows)

xs = [r[0] for r in rows]
cl = [r[1] for r in rows]
qu = [r[2] for r in rows]
bkz = [r[3] for r in rows]
h = [r for r in rows if r[0] == HIGHLIGHT][0]

fig, (a, b) = plt.subplots(1, 2, figsize=(15, 6.5))
fig.suptitle("HNF-MSIS Security Estimation (lattice-estimator)", fontweight="bold", fontsize=17)

a.plot(xs, cl, "o-", color="#1f77b4", linewidth=2, markersize=6, label="Classical (MATZOV)")
a.plot(xs, qu, "s-", color="#ff7f0e", linewidth=2, markersize=6, label="Quantum (LaaMosPol14)")
for lvl, val, st in [(1, 143, ":"), (3, 207, "--"), (5, 272, "-.")]:
    a.axhline(val, color="k", linestyle=st, linewidth=1, alpha=0.6,
              label="NIST Level %d (%d bits)" % (lvl, val))
a.axvline(HIGHLIGHT, color="#d62728", linestyle="--", linewidth=1.5,
          label="bound = %d" % HIGHLIGHT)
a.annotate("%.1f classical\n%.1f quantum\nBKZ-beta=%d" % (h[1], h[2], h[3]),
           xy=(h[0], h[1]), xytext=(95000, 175), color="#d62728", fontweight="bold",
           fontsize=10, arrowprops=dict(arrowstyle="->", color="#d62728"))
a.set_xlabel("length_bound (HNF-MSIS, norm = infinity)", fontsize=12)
a.set_ylabel("Security (bits)", fontsize=12)
a.set_title("(A) Security Level vs length_bound", fontsize=13)
a.set_ylim(120, 290)
a.legend(fontsize=9, loc="upper right", framealpha=0.9)
a.grid(alpha=0.3)

b.plot(xs, bkz, "o-", color="#d62728", linewidth=2, markersize=6)
b.axvline(HIGHLIGHT, color="#d62728", linestyle="--", linewidth=1.5,
          label="bound = %d" % HIGHLIGHT)
b.set_xlabel("length_bound (HNF-MSIS, norm = infinity)", fontsize=12)
b.set_ylabel("BKZ block size beta", fontsize=12)
b.set_title("(B) Required BKZ-beta vs length_bound", fontsize=13)
b.legend(fontsize=9, loc="upper right", framealpha=0.9)
b.grid(alpha=0.3)

fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig_lattice_estimator.png"), dpi=160)
print("Wrote", OUT)
