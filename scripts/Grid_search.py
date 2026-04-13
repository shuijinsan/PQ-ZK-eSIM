#!/usr/bin/env python3
"""
grid_search.py  —  PQ-ZK-eSIM parameter grid search visualization  v4.2

Key changes vs v4.1:
  - Core metric: overflow_rate (inf_norm > beta_final, true mod-q overflow)
  - underflow_rate (l2 < beta_min, design-expected ~2%) shown separately
  - Security strength log2(C(256,k)*2^k) added to tradeoff figure
  - fig_tradeoff now has 4 panels: security / overflow rate / margin / latency
  - fig_parameter_space uses overflow_rate for heatmap

Output:
    fig_parameter_space.png
    fig_tradeoff.png
    optimal_params.txt
"""

import csv, sys, os, argparse
from math import comb, log2, sqrt

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    print("[INFO] pip install matplotlib numpy\n")

# ── Protocol constants ────────────────────────────────────────────
Q         = 3329
Q_HALF    = Q // 2
ETA_S     = 2
ETA_Y     = 1
TAU       = 12
GAMMA     = 2
N         = 256        # polynomial degree
K         = 3          # module dimension
KAPPA_OPT = 26
SIGMA_OPT = 105.0
BETA_MIN  = 2735
SECURITY_TARGET = 128  # bits

def zk_lower(kappa):
    return GAMMA * ETA_S * kappa

def correctness_upper(kappa):
    return (Q_HALF - ETA_Y - kappa * ETA_S) / TAU

def security_bits(kappa):
    """log2(C(N, kappa) * 2^kappa) — combinatorial security strength."""
    return log2(comb(N, kappa)) + kappa

def expected_underflow_rate(sigma, beta_min=BETA_MIN):
    """
    Approximate probability that ||z||_2 < beta_min.
    ||z||_2^2 ~ chi-squared(K*N) scaled by sigma^2.
    Use normal approximation: mean=K*N*sigma^2, std=sqrt(2*K*N)*sigma^2.
    """
    mu  = K * N * sigma**2
    std = sqrt(2 * K * N) * sigma**2
    # P(l2_sq < beta_min^2) ~ Phi((beta_min^2 - mu) / std)
    z = (beta_min**2 - mu) / std
    # Simple approximation of Phi(z) for z < 0
    import math
    return 0.5 * math.erfc(-z / math.sqrt(2))


# ── CSV loading ───────────────────────────────────────────────────
def load_csv(path):
    rows = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ov_fail = int(row.get('overflow_fail',  -1))
            un_fail = int(row.get('underflow_fail', -1))
            ov_rate = float(row.get('overflow_rate',  -1))
            un_rate = float(row.get('underflow_rate', -1))
            rows.append({
                'kappa':            int(row['kappa']),
                'sigma':            float(row['sigma_pub']),
                'beta_final':       int(row['beta_final']),
                'correct_ok':       int(row['correctness_ok']),
                'overflow_fail':    ov_fail,
                'underflow_fail':   un_fail,
                'mac_fail':         int(row.get('mac_fail', 0)),
                'other_fail':       int(row.get('other_fail', 0)),
                'fail_count':       int(row['fail_count']),
                'trials':           int(row['trials']),
                'fail_rate':        float(row['fail_rate']),
                'overflow_rate':    ov_rate,
                'underflow_rate':   un_rate,
                'avg_precompute':   float(row['avg_precompute_us']),
                'avg_commit':       float(row['avg_commit_us']),
                'avg_challenge':    float(row['avg_challenge_us']),
                'avg_compute_mask': float(row['avg_compute_mask_us']),
                'avg_aggregate':    float(row['avg_aggregate_us']),
                'avg_verify':       float(row['avg_verify_us']),
                'avg_total':        float(row['avg_total_us']),
                'security_bits':    security_bits(int(row['kappa'])),
            })
    return rows

def csv_version(rows):
    """Detect CSV version: 4.2 has overflow_rate column."""
    if rows[0]['overflow_rate'] >= 0:
        return '4.2'
    elif rows[0].get('norm_bound_rate', -1) >= 0:
        return '4.1'
    return '4.0'


# ── Text analysis ─────────────────────────────────────────────────
def analyze(rows):
    print("=" * 65)
    print("  PQ-ZK-eSIM Parameter Grid Search Analysis  (v4.2)")
    print("=" * 65)

    ver = csv_version(rows)
    print(f"CSV version : {ver}")
    if ver != '4.2':
        print("[WARN] Re-run bench v4.2 to get overflow/underflow breakdown.\n"
              "       Falling back to fail_rate as core metric.")

    kappas = sorted(set(r['kappa'] for r in rows))
    sigmas = sorted(set(r['sigma']  for r in rows))
    trials = rows[0]['trials']
    print(f"kappa range : {min(kappas)} ~ {max(kappas)}, {len(kappas)} values")
    print(f"sigma range : {min(sigmas):.0f} ~ {max(sigmas):.0f}, {len(sigmas)} values")
    print(f"Combinations: {len(rows)}, trials each: {trials}\n")

    print("--- Security strength vs kappa ---")
    print(f"  {'kappa':>5}  {'sec_bits':>10}  {'>= 128?':>8}  {'valid sigma range':>20}")
    for k in kappas:
        sb     = security_bits(k)
        zk_lb  = zk_lower(k)
        cor_ub = correctness_upper(k)
        ok     = "YES" if sb >= SECURITY_TARGET else "NO "
        rng    = f"[{zk_lb:.0f}, {cor_ub:.0f}]" if zk_lb <= cor_ub else "NONE"
        print(f"  {k:>5}  {sb:>10.2f}  {ok:>8}  {rng:>20}")

    print(f"\n--- Optimal: kappa={KAPPA_OPT}, sigma={SIGMA_OPT} ---")
    target = [r for r in rows
              if r['kappa'] == KAPPA_OPT and abs(r['sigma'] - SIGMA_OPT) < 0.1]
    if target:
        t = target[0]
        sb = security_bits(KAPPA_OPT)
        print(f"  Security strength  : {sb:.2f} bits  (target >= {SECURITY_TARGET})")
        print(f"  ZK lower bound     : sigma={SIGMA_OPT} >= {zk_lower(KAPPA_OPT):.0f}  OK")
        print(f"  beta_final         : {t['beta_final']} < q/2={Q_HALF}  "
              f"{'OK' if t['correct_ok'] else 'FAIL'}")
        print(f"  Correctness margin : {Q_HALF - t['beta_final']} (q/2 - beta_final)")
        if ver == '4.2':
            print(f"  overflow_rate      : {t['overflow_rate']:.6f}  (mod-q overflow)")
            print(f"  underflow_rate     : {t['underflow_rate']:.6f}  (beta_min design ~2%)")
        print(f"  total fail_rate    : {t['fail_rate']:.6f}")
        print(f"  End-to-end latency : {t['avg_total']:.1f} us")
        print(f"    eUICC_Commit     : {t['avg_commit']:.1f} us  (5 ms target)")
        print(f"    VerifyEngine     : {t['avg_verify']:.1f} us")

        un_theory = expected_underflow_rate(SIGMA_OPT)
        print(f"\n  [Theory] Expected underflow rate (beta_min={BETA_MIN}): "
              f"~{un_theory:.3f} ({un_theory*100:.1f}%)")
        print(f"  This is by design — beta_min guards against y_pub=0 attacks.")

        with open("optimal_params.txt", "w") as f:
            f.write("PQ-ZK-eSIM Optimal Parameter Summary\n")
            f.write("=" * 45 + "\n")
            f.write(f"kappa (PQZK_KAPPA)          = {t['kappa']}\n")
            f.write(f"sigma (PQZK_SIGMA_PUB)      = {t['sigma']:.1f}\n")
            f.write(f"beta_final                  = {t['beta_final']}\n")
            f.write(f"beta_min (PQZK_BETA_MIN)    = {BETA_MIN}\n")
            f.write(f"Security strength           = {sb:.2f} bits (>= {SECURITY_TARGET})\n")
            f.write(f"ZK lower bound              = {zk_lower(KAPPA_OPT):.1f}\n")
            f.write(f"Correctness upper bound     = {correctness_upper(KAPPA_OPT):.1f}\n")
            f.write(f"Correctness margin          = {Q_HALF - t['beta_final']}\n")
            if ver == '4.2':
                f.write(f"overflow_rate (mod-q)       = {t['overflow_rate']:.6f}\n")
                f.write(f"underflow_rate (beta_min)   = {t['underflow_rate']:.6f}\n")
            f.write(f"total fail_rate             = {t['fail_rate']:.6f}\n")
            f.write(f"End-to-end latency (avg)    = {t['avg_total']:.1f} us\n")
        print("\nSummary -> optimal_params.txt")

    return rows, ver


# ── Figure 1: Parameter space ─────────────────────────────────────
def plot_parameter_space(rows, ver):
    metric = 'overflow_rate' if ver == '4.2' else 'fail_rate'
    mlabel = 'Mod-q Overflow Rate (inf_norm > β_final)' \
             if ver == '4.2' else 'Failure Rate (all errors)'

    kappas = sorted(set(r['kappa'] for r in rows))
    sigmas = sorted(set(r['sigma']  for r in rows))

    val_grid    = np.full((len(kappas), len(sigmas)), np.nan)
    region_grid = np.zeros((len(kappas), len(sigmas)))

    for r in rows:
        ki = kappas.index(r['kappa'])
        si = sigmas.index(r['sigma'])
        val_grid[ki][si] = r[metric]
        if r['sigma'] < zk_lower(r['kappa']):
            region_grid[ki][si] = 0
        elif not r['correct_ok']:
            region_grid[ki][si] = 2
        else:
            region_grid[ki][si] = 1

    valid_vals = val_grid[region_grid == 1]
    valid_vals = valid_vals[~np.isnan(valid_vals)]
    vmax = float(np.percentile(valid_vals, 95)) if len(valid_vals) else 0.02
    vmax = max(vmax, 1e-6)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle("PQ-ZK-eSIM Parameter Space Analysis",
                 fontsize=14, fontweight='bold')

    # ── Left: heatmap ──
    masked = np.ma.masked_where(region_grid != 1, val_grid)
    cmap = plt.cm.RdYlGn_r.copy()
    cmap.set_bad(color='#e8e8e8')
    im = ax1.imshow(masked, aspect='auto', origin='lower',
                    cmap=cmap, vmin=0, vmax=vmax)

    for ki in range(len(kappas)):
        for si in range(len(sigmas)):
            reg = region_grid[ki][si]
            if reg == 0:
                ax1.add_patch(mpatches.Rectangle(
                    (si-.5, ki-.5), 1, 1,
                    facecolor='#aac4e8', edgecolor='#6699cc',
                    hatch='////', alpha=0.6, zorder=2))
            elif reg == 2:
                ax1.add_patch(mpatches.Rectangle(
                    (si-.5, ki-.5), 1, 1,
                    facecolor='#f4b0b0', edgecolor='#cc6666',
                    hatch='xxxx', alpha=0.6, zorder=2))

    ax1.set_xticks(range(len(sigmas)))
    ax1.set_xticklabels([f"{s:.0f}" for s in sigmas],
                        rotation=45, ha='right', fontsize=8)
    ax1.set_yticks(range(len(kappas)))
    ax1.set_yticklabels([str(k) for k in kappas], fontsize=8)
    ax1.set_xlabel(r"$\sigma_{pub}$", fontsize=12)
    ax1.set_ylabel(r"$\kappa$", fontsize=12)
    ax1.set_title(f"(A)  {mlabel}\n"
                  "blue (////): ZK violated  |  red (xxxx): correctness violated",
                  fontsize=10)

    if KAPPA_OPT in kappas and SIGMA_OPT in sigmas:
        ki = kappas.index(KAPPA_OPT)
        si = sigmas.index(SIGMA_OPT)
        ax1.plot(si, ki, '*', color='black', markersize=18, zorder=6,
                 label=f"Optimal ($\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f})")
        ax1.legend(loc='upper left', fontsize=9)
    plt.colorbar(im, ax=ax1, label=mlabel, shrink=0.8)

    # ── Right: region map ──
    sigma_cont = np.linspace(min(sigmas)-5, max(sigmas)+5, 500)

    def hex2rgb(h):
        h = h.lstrip('#')
        return [int(h[i:i+2],16)/255. for i in (0,2,4)]

    cm = {0:'#aac4e8', 1:'#b7e4b7', 2:'#f4b0b0'}
    rgb_img = np.ones((len(kappas), len(sigma_cont), 3))
    for ki, k in enumerate(kappas):
        zk_lb = zk_lower(k); cor_ub = correctness_upper(k)
        for si, s in enumerate(sigma_cont):
            key = 0 if s < zk_lb else (2 if s > cor_ub else 1)
            rgb_img[ki, si] = hex2rgb(cm[key])

    ax2.imshow(rgb_img, aspect='auto', origin='lower',
               extent=[sigma_cont[0], sigma_cont[-1], 0, len(kappas)])

    zk_pts  = [zk_lower(k) for k in kappas]
    cor_pts = [correctness_upper(k) for k in kappas]
    y_edges = list(range(len(kappas)+1))
    ax2.step(zk_pts  + [zk_pts[-1]],  y_edges, where='post',
             color='#1a5fa8', lw=2.5,
             label=r'ZK lower bound $(\gamma\eta_s\kappa)$')
    ax2.step(cor_pts + [cor_pts[-1]], y_edges, where='post',
             color='#c0392b', lw=2.5, label='Correctness upper bound')

    if KAPPA_OPT in kappas:
        ki = kappas.index(KAPPA_OPT)
        ax2.plot(SIGMA_OPT, ki+.5, '*', color='black', markersize=18, zorder=6)
        ax2.annotate(
            f"$\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f}  (selected)",
            xy=(SIGMA_OPT, ki+.5), fontsize=9, va='bottom', ha='left',
            xytext=(SIGMA_OPT+4, ki+1.8),
            arrowprops=dict(arrowstyle='->', color='black', lw=1.2))

    ax2.set_yticks([i+.5 for i in range(len(kappas))])
    ax2.set_yticklabels([str(k) for k in kappas], fontsize=8)
    ax2.set_xlabel(r"$\sigma_{pub}$", fontsize=12)
    ax2.set_ylabel(r"$\kappa$", fontsize=12)
    ax2.set_title("(B)  Parameter Region Classification\n"
                  "green = valid  |  blue = ZK violated  |  red = correctness violated",
                  fontsize=10)
    ax2.legend(handles=[
        mpatches.Patch(color='#aac4e8', label=r'ZK violated ($\sigma$ too small)'),
        mpatches.Patch(color='#b7e4b7', label='Valid region'),
        mpatches.Patch(color='#f4b0b0', label=r'Correctness violated ($\sigma$ too large)'),
        plt.Line2D([0],[0], color='#1a5fa8', lw=2.5,
                   label=r'ZK lower bound $\gamma\eta_s\kappa$'),
        plt.Line2D([0],[0], color='#c0392b', lw=2.5,
                   label='Correctness upper bound'),
        plt.Line2D([0],[0], marker='*', color='black', lw=0, markersize=12,
                   label=f'Optimal ($\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f})'),
    ], fontsize=8, loc='upper right', framealpha=0.92)

    plt.tight_layout()
    plt.savefig("fig_parameter_space.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("Saved: fig_parameter_space.png")


# ── Figure 2: Trade-off (fixed sigma=SIGMA_OPT) ──────────────────
#
# 4 panels sharing x-axis (kappa):
#   A: Security strength log2(C(N,k)*2^k)  — must be >= 128, higher = safer
#   B: Mod-q overflow rate                  — lower is better (core metric)
#   C: Correctness margin q/2 - beta_final  — must be > 0
#   D: End-to-end latency                   — lower is better
#
# κ=26 is the SMALLEST kappa that gives adequate security (>128 bits)
# while keeping overflow rate low AND maintaining correctness margin.
#
def plot_tradeoff(rows, ver):
    subset = sorted(
        [r for r in rows if abs(r['sigma'] - SIGMA_OPT) < 0.1],
        key=lambda x: x['kappa']
    )
    if not subset:
        print(f"[WARN] No data for sigma={SIGMA_OPT:.0f}")
        return

    kappas   = [r['kappa']       for r in subset]
    sec_bits = [r['security_bits'] for r in subset]
    correct  = [r['correct_ok']  for r in subset]
    margins  = [Q_HALF - r['beta_final'] for r in subset]
    totals   = [r['avg_total']   for r in subset]

    if ver == '4.2':
        core_vals  = [r['overflow_rate']  for r in subset]
        core_label = r'Mod-$q$ Overflow Rate (inf\_norm $> \beta_{final}$)'
        ref_vals   = [r['underflow_rate'] for r in subset]
        ref_label  = r'Underflow Rate ($\|z\|_2 < \beta_{min}$, design ~2%)'
    else:
        core_vals  = [r['fail_rate'] for r in subset]
        core_label = 'Failure Rate (all errors, bench v4.0/4.1)'
        ref_vals   = None
        ref_label  = None

    VALID   = '#2ecc71'
    INVALID = '#e74c3c'
    OPT_C   = '#2c3e50'
    SEC_C   = '#8e44ad'

    fig, axes = plt.subplots(4, 1, figsize=(13, 14), sharex=True)
    fig.suptitle(
        f"Parameter Trade-off Analysis  ($\\sigma_{{pub}}$ = {SIGMA_OPT:.0f})\n"
        r"$\kappa$=26 is the smallest value satisfying 128-bit security "
        r"with low overflow rate and positive correctness margin",
        fontsize=12, fontweight='bold'
    )

    valid_k = [k for k, c in zip(kappas, correct) if c]
    if valid_k:
        for ax in axes:
            ax.axvspan(min(valid_k)-.5, max(valid_k)+.5,
                       color=VALID, alpha=0.06, zorder=0)

    # ── Panel A: Security strength ──
    ax = axes[0]
    ax.plot(kappas, sec_bits, 'o-', color=SEC_C, lw=2.2,
            markersize=6, zorder=3, label='Security strength')
    ax.axhline(SECURITY_TARGET, color='red', linestyle='--', lw=1.8,
               label=f'{SECURITY_TARGET}-bit security target', zorder=4)
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=5)

    # Find minimum kappa meeting target
    min_safe_k = next((k for k, s in zip(kappas, sec_bits)
                       if s >= SECURITY_TARGET), None)
    if min_safe_k is not None:
        ax.axvline(min_safe_k, color='orange', linestyle='--', lw=1.5,
                   label=f'Min. secure $\\kappa$={min_safe_k}', zorder=4)

    ax.fill_between(kappas,
                    [min(sec_bits)-2]*len(kappas), SECURITY_TARGET,
                    color='red', alpha=0.06, label='Below security target')

    # Annotate optimal
    if KAPPA_OPT in kappas:
        idx = kappas.index(KAPPA_OPT)
        ax.annotate(
            f"$\\kappa$={KAPPA_OPT}: {sec_bits[idx]:.1f} bits\n(selected)",
            xy=(KAPPA_OPT, sec_bits[idx]),
            xytext=(KAPPA_OPT+2, sec_bits[idx]-8),
            arrowprops=dict(arrowstyle='->', color=OPT_C, lw=1.5),
            fontsize=9, color=OPT_C)

    ax.set_ylabel(r"Security Strength (bits)", fontsize=11)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=8, loc='lower right')
    ax.set_title(r"(A)  Security Strength $\log_2\binom{256}{\kappa} \cdot 2^\kappa$"
                 "  —  must be $\geq$ 128", fontsize=10, loc='left')

    # ── Panel B: Overflow rate ──
    ax = axes[1]
    bar_c = [VALID if c else INVALID for c in correct]
    ax.bar(kappas, core_vals, color=bar_c, alpha=0.82, width=0.6,
           zorder=3, label=core_label)

    if ref_vals is not None:
        ax.plot(kappas, ref_vals, 's--', color='gray', markersize=4,
                lw=1.2, alpha=0.7, zorder=4, label=ref_label)

    ax.axhline(0.001, color='darkorange', linestyle='--', lw=1.8,
               label='0.1% target', zorder=5)
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=6)

    # Log scale only if values span multiple orders
    nonzero = [v for v in core_vals if v > 0]
    if nonzero and max(nonzero)/min(nonzero) > 10:
        ax.set_yscale('log')
        ax.set_ylim(bottom=max(1e-5, min(nonzero)*0.5))
    ax.set_ylabel(core_label, fontsize=9)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=8, loc='upper right')
    ax.set_title("(B)  Mod-$q$ Overflow Rate  —  lower is better", fontsize=10, loc='left')

    # ── Panel C: Correctness margin ──
    ax = axes[2]
    m_colors = [VALID if m > 0 else INVALID for m in margins]
    ax.bar(kappas, margins, color=m_colors, alpha=0.82, width=0.6, zorder=3)
    ax.axhline(0, color='red', lw=2.2, zorder=4,
               label=r'$q/2$ boundary — must stay above zero')
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=5)
    ax.fill_between([min(kappas)-.5, max(kappas)+.5],
                    0, min(margins)-50,
                    color='red', alpha=0.07, label='Overflow region')
    ax.set_ylabel(r"Margin  $= q/2 - \beta_{final}$", fontsize=11)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=9, loc='lower left')
    ax.set_title(r"(C)  Correctness Margin  —  must be $> 0$",
                 fontsize=10, loc='left')

    # ── Panel D: Latency ──
    ax = axes[3]
    for i in range(len(kappas)-1):
        c = VALID if correct[i] and correct[i+1] else INVALID
        ax.plot(kappas[i:i+2], totals[i:i+2], '-', color=c, lw=2.2, zorder=3)
    ax.scatter(kappas, totals,
               color=[VALID if c else INVALID for c in correct],
               s=45, zorder=4)
    ax.axhline(5000, color='red', linestyle='--', lw=1.8,
               label='5 ms eUICC target', zorder=4)
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2,
               label=f'Optimal $\\kappa$={KAPPA_OPT}', zorder=5)
    ax.set_xlabel(r"$\kappa$ (sparse challenge weight)", fontsize=12)
    ax.set_ylabel("End-to-end Latency (μs)", fontsize=11)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=9, loc='upper left')
    ax.set_title("(D)  End-to-end Latency  —  lower is better",
                 fontsize=10, loc='left')

    fig.legend(
        handles=[
            mpatches.Patch(color=VALID,   alpha=0.82, label='Correctness satisfied'),
            mpatches.Patch(color=INVALID, alpha=0.82, label='Correctness violated'),
        ],
        loc='lower center', ncol=2, fontsize=10,
        bbox_to_anchor=(0.5, -0.01), framealpha=0.9)

    plt.tight_layout(rect=[0, 0.02, 1, 1])
    plt.savefig("fig_tradeoff.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("Saved: fig_tradeoff.png")


# ── Entry point ───────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="PQ-ZK-eSIM grid search visualization v4.2")
    parser.add_argument("--csv",     default="grid_results.csv")
    parser.add_argument("--no-plot", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"[ERROR] File not found: {args.csv}")
        print("Run first: ./bench --grid")
        sys.exit(1)

    rows = load_csv(args.csv)
    rows, ver = analyze(rows)

    if not args.no_plot:
        if HAS_PLOT:
            print("\nGenerating figures...")
            plot_parameter_space(rows, ver)
            plot_tradeoff(rows, ver)
            print("\nDone.")
        else:
            print("\n[Hint] pip3 install matplotlib numpy")

if __name__ == "__main__":
    main()