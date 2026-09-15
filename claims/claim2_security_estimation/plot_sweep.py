#!/usr/bin/env python3
"""Plot the HNF-MSIS estimator sweep (Figure 4) from the CSV written by run_sweep.py."""
import csv
import os

from matplotlib import pyplot as plt
from matplotlib.ticker import FuncFormatter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "expected")
HIGHLIGHT = 71400       # HNF-MSIS extraction bound
MLWE_QUANTUM = 162.9     # verified: dual_hybrid, LaaMosPol14
NIST = {1: 143, 3: 207, 5: 272}

rows = []
with open(os.path.join(OUT, "msis_estimator_sweep.csv")) as f:
    for r in csv.DictReader(f):
        rows.append((int(r["length_bound"]), float(r["classical_bits"]),
                     float(r["quantum_bits"]), int(r["bkz_block_size"])))
xs = [r[0] for r in rows]
cl = [r[1] for r in rows]
qu = [r[2] for r in rows]
bkz = [r[3] for r in rows]
h = [r for r in rows if r[0] == HIGHLIGHT][0]

lo = min(min(qu), min(cl)) - 8
hi = max(max(qu), max(cl), *(NIST.values())) + 8

fig, (a, b) = plt.subplots(1, 2, figsize=(15, 6.5))
fig.suptitle("HNF-MSIS Security Estimation (lattice-estimator)", fontweight="bold", fontsize=17)

a.plot(xs, cl, "o-", color="#1f77b4", linewidth=2, markersize=6, label="Classical (MATZOV)")
a.plot(xs, qu, "s-", color="#ff7f0e", linewidth=2, markersize=6, label="Quantum (LaaMosPol14)")
for lvl, val, st in [(1, 143, ":"), (3, 207, "--"), (5, 272, "-.")]:
    a.axhline(val, color="k", linestyle=st, linewidth=1, alpha=0.6,
              label="NIST Level %d (%d bits)" % (lvl, val))
if MLWE_QUANTUM:
    a.axhline(MLWE_QUANTUM, color="#7f7f7f", linestyle="-.", linewidth=1.5,
              label="MLWE quantum (%.1f)" % MLWE_QUANTUM)
a.axvline(HIGHLIGHT, color="#d62728", linestyle="--", linewidth=1.5,
          label="chosen bound = %d" % HIGHLIGHT)
a.annotate("%.1f classical\n%.1f quantum\nBKZ-beta=%d" % (h[1], h[2], h[3]),
           xy=(h[0], qu[rows.index(h)]), xytext=(96000, 178), color="#d62728",
           fontweight="bold", fontsize=10,
           arrowprops=dict(arrowstyle="->", color="#d62728"))
a.set_xlabel("length_bound (HNF-MSIS, norm = infinity)", fontsize=12)
a.set_ylabel("Security (bits)", fontsize=12)
a.set_title("(A) Security Level vs length_bound", fontsize=13)
a.set_ylim(lo, hi)
a.legend(fontsize=9, loc="upper right", framealpha=0.9)
a.grid(alpha=0.3)

b.plot(xs, bkz, "o-", color="#d62728", linewidth=2, markersize=6)
b.axvline(HIGHLIGHT, color="#d62728", linestyle="--", linewidth=1.5,
          label="chosen bound = %d" % HIGHLIGHT)
b.set_xlabel("length_bound (HNF-MSIS, norm = infinity)", fontsize=12)
b.set_ylabel("BKZ block size beta", fontsize=12)
b.set_title("(B) Required BKZ-beta vs length_bound", fontsize=13)
b.legend(fontsize=9, loc="upper right", framealpha=0.9)
b.grid(alpha=0.3)

for ax in (a, b):
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, p: "%dk" % round(v / 1000.0)))

fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig_lattice_estimator.png"), dpi=160)
print("Wrote", os.path.join(OUT, "fig_lattice_estimator.png"))
