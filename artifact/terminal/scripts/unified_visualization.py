#!/usr/bin/env python3
"""
unified_visualization.py — PQ-ZK-eSIM unified visualization v1.0

Unified visualization:
  1. Sparse noise attack
  2. Sliding window resync
  3. Operator switch
  4. NVM wear
  5. Phase timing
  6. Memory usage
  7. DoS prevention
  8. Constant time
  9. Environment breakdown
  10. Component memory
"""

import os
import sys
import csv
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

matplotlib.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 28,
    'axes.titlesize': 34,
    'axes.labelsize': 30,
    'xtick.labelsize': 26,
    'ytick.labelsize': 26,
    'legend.fontsize': 28,
    'figure.dpi': 150,
    'savefig.dpi': 200,
    'savefig.bbox': 'tight',
})

OUTPUT_DIR = "../build"

# ================================================================
# ================================================================

def load_csv(filename):
    path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(path):
        print(f"  [Warning] File not found: {path}")
        return None
    try:
        df = pd.read_csv(path)
        return df
    except Exception as e:
        print(f"  [Error] read failed: {e}")
        return None

def save_fig(fig, name):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, bbox_inches='tight')
    print(f"  -> Saved: {path}")
    plt.close(fig)

# ================================================================
# ================================================================

def plot_sparse_noise_attack():
    df = load_csv("sparse_noise_attack_results.csv")
    if df is None:
        return

    fig, axes = plt.subplots(1, 3, figsize=(36, 14))
    fig.suptitle("Sparse Noise Degradation Attack Analysis",
                 fontweight='bold', fontsize=56, y=0.98)

    rho = df["rho"].values * 100

    ax = axes[0]
    colors_a = ['#d62728' if r < 100 else '#2ca02c' for r in rho]
    bars = ax.bar(rho, df["detection_rate"] * 100, color=colors_a,
                  width=8, alpha=0.85, edgecolor='white', linewidth=2)
    for bar, v in zip(bars, df["detection_rate"] * 100):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{v:.0f}%', ha='center', va='bottom', 
                fontsize=32, fontweight='bold', color='black')
    ax.axhline(y=99, color='#1f77b4', linestyle='--', linewidth=3)
    ax.set_xlabel("Non-zero coefficient ratio ρ (%)", fontsize=42)
    ax.set_ylabel("L1 Check Detection Rate (%)", fontsize=42)
    ax.set_title("(A) Attack Detection Rate vs ρ", fontsize=44, pad=5)
    ax.set_ylim(0, 108)
    ax.set_xticks(rho)
    ax.tick_params(axis='both', labelsize=38)

    ax = axes[1]
    honest_mask = df["rho"] >= 1.0
    if honest_mask.any():
        false_reject = df[honest_mask]["false_reject_rate"].values[0] * 100
        ax.bar([0], [false_reject],
               color='#2ca02c', alpha=0.85, width=0.6, edgecolor='white', linewidth=2)
        ax.axhline(y=0.01, color='#d62728', linestyle='--', linewidth=2,
                   label=f'2⁻¹²⁸ target (≈0%)')
        ax.text(0, false_reject + 0.3, f'{false_reject:.2f}%',
                ha='center', fontsize=38, fontweight='bold')
    ax.set_ylabel("False Rejection Rate (%)", fontsize=42)
    ax.set_title("(B) Honest Authentication\nFalse Rejection Rate", fontsize=44, pad=5)
    ax.set_ylim(0, max(6, false_reject * 2 + 1.5) if honest_mask.any() else 6)
    ax.legend(fontsize=38)
    ax.set_xticks([])
    ax.tick_params(axis='y', labelsize=38)

    ax = axes[2]
    ax.plot(rho, df["avg_total_us"] / 1000, 'o-',
            color='#1f77b4', linewidth=4, markersize=16)
    ax.set_xlabel("Non-zero coefficient ratio ρ (%)", fontsize=42)
    ax.set_ylabel("End-to-End Latency (ms)", fontsize=42)
    ax.set_title("(C) End-to-End Latency vs ρ", fontsize=44, pad=5)
    ax.set_xticks(rho)
    ax.tick_params(axis='both', labelsize=38)

    red_patch = mpatches.Patch(color='#d62728', alpha=0.85, label='Attack (ρ < 100%)')
    green_patch = mpatches.Patch(color='#2ca02c', alpha=0.85, label='Honest (ρ = 100%)')
    fig.legend(handles=[red_patch, green_patch], fontsize=36, 
               loc='upper center', bbox_to_anchor=(0.5, 0.92), 
               ncol=2, handlelength=2, columnspacing=2)

    plt.tight_layout(pad=2.0)
    save_fig(fig, "fig_sparse_noise_attack_v2.png")

# ================================================================
# ================================================================

def plot_sliding_window_resync():
    df = load_csv("sliding_window_resync_results.csv")
    if df is None:
        return

    fig = plt.figure(figsize=(36, 14))
    fig.suptitle("Sliding Window Resync Analysis",
                 fontweight='bold', fontsize=56, y=1.02)
    gs = GridSpec(1, 3, figure=fig, wspace=0.4)

    windows = sorted(df["window_size"].unique())
    depths = sorted(df["sync_depth"].unique())

    ax_a = fig.add_subplot(gs[0])
    matrix = np.zeros((len(windows), len(depths)))
    for i, w in enumerate(windows):
        for j, d in enumerate(depths):
            row = df[(df["window_size"] == w) & (df["sync_depth"] == d)]
            if not row.empty:
                matrix[i, j] = row["success_rate"].values[0] * 100

    im = ax_a.imshow(matrix, aspect='auto', cmap='RdYlGn',
                     vmin=0, vmax=100,
                     extent=[-0.5, len(depths)-0.5, len(windows)-0.5, -0.5])
    cb = plt.colorbar(im, ax=ax_a, label='Success Rate (%)')
    cb.ax.tick_params(labelsize=32)
    cb.set_label('Success Rate (%)', fontsize=38)
    ax_a.set_xticks(range(len(depths)))
    ax_a.set_xticklabels(depths, fontsize=38)
    ax_a.set_yticks(range(len(windows)))
    ax_a.set_yticklabels(windows, fontsize=38)
    ax_a.set_xlabel("Sync Depth Δ", fontsize=42)
    ax_a.set_ylabel("Window Size W", fontsize=42)
    ax_a.set_title("(A) Success Rate Heatmap\n(green=success, red=fail)", fontsize=44)

    for i in range(len(windows)):
        for j in range(len(depths)):
            v = matrix[i, j]
            color = 'white' if v < 50 or v > 90 else 'black'
            ax_a.text(j, i, f'{v:.0f}', ha='center', va='center',
                      fontsize=26, color=color, fontweight='bold')  # reduce font, remove %

    ax_b = fig.add_subplot(gs[1])
    worst_case_mac = []
    for w in windows:
        row = df[(df["window_size"] == w) & (df["sync_depth"] == w)]
        if row.empty:
            row = df[df["window_size"] == w].sort_values("sync_depth").tail(1)
        if not row.empty:
            worst_case_mac.append(row["avg_mac_us"].values[0])
        else:
            worst_case_mac.append(0)

    theoretical = [w * 2.82 for w in windows]

    ax_b.plot(windows, worst_case_mac, 'o-', color='#d62728',
              linewidth=4, markersize=16, label='Measured (worst case)')
    ax_b.plot(windows, theoretical, 's--', color='#1f77b4',
              linewidth=3, markersize=14, label='Theoretical (W×2.82μs)')
    ax_b.set_xlabel("Window Size W", fontsize=42)
    ax_b.set_ylabel("MAC Search Time (μs)", fontsize=42)
    ax_b.set_title("(B) MAC Search Latency\n(worst case: Δ=W)", fontsize=44)
    ax_b.legend(fontsize=38)
    ax_b.set_xticks(windows)
    ax_b.tick_params(axis='both', labelsize=38)

    ax_c = fig.add_subplot(gs[2])
    w_target = max(windows)
    df_w = df[df["window_size"] == w_target].sort_values("sync_depth")
    if not df_w.empty:
        ax_c.plot(df_w["sync_depth"], df_w["avg_total_us"] / 1000,
                  'D-', color='#2ca02c', linewidth=4, markersize=16,
                  label=f'W={w_target}')
        ax_c.axvline(x=w_target, color='#d62728', linestyle='--',
                     linewidth=3, label=f'Window limit (W={w_target})')
        ax_c.fill_betweenx([0, df_w["avg_total_us"].max()/1000 * 1.1],
                            0, w_target, alpha=0.08, color='#2ca02c',
                            label='Sync success zone')

    ax_c.set_xlabel("Sync Depth Δ", fontsize=42)
    ax_c.set_ylabel("Total Latency (ms)", fontsize=42)
    ax_c.set_title(f"(C) Total Latency vs Sync Depth\n(W={w_target})", fontsize=44)
    ax_c.legend(fontsize=38)
    ax_c.tick_params(axis='both', labelsize=38)

    plt.tight_layout(pad=3.0)
    save_fig(fig, "fig_sliding_window_resync_v2.png")

# ================================================================
# ================================================================

def plot_operator_switching():
    df = load_csv("operator_switching_results.csv")
    if df is None:
        return

    fig, axes = plt.subplots(1, 2, figsize=(18, 9))
    fig.suptitle("Operator Switching Analysis",
                 fontweight='bold', fontsize=26, y=1.02)

    colors_dir = {
        'h2h': '#1f77b4',
        'h2r': '#ff7f0e',
        'r2h': '#2ca02c',
        'r2r': '#9467bd'
    }

    ax = axes[0]
    for _, row in df.iterrows():
        color = colors_dir.get(row["direction"], '#7f7f7f')
        alpha = 0.9 if row["success"] else 0.4
        ax.bar(row["trial"], row["switch_time_us"],
               color=color, alpha=alpha, edgecolor='white', width=0.7)
        if not row["success"]:
            ax.text(row["trial"], row["switch_time_us"] + 200,
                    '✗', ha='center', fontsize=20, color='red')

    avg_time = df["switch_time_us"].mean()
    ax.axhline(y=avg_time, color='red', linestyle='--', linewidth=2,
               label=f'Avg: {avg_time:.1f} μs')

    first_row = df.iloc[0]
    if first_row["switch_time_us"] > avg_time * 2:
        ax.annotate("ML-KEM\ncold start",
                    xy=(first_row["trial"], first_row["switch_time_us"]),
                    xytext=(first_row["trial"] + 2, first_row["switch_time_us"] * 0.85),
                    arrowprops=dict(arrowstyle='->', color='gray'),
                    fontsize=14, color='gray')

    patches = [mpatches.Patch(color=c, label=d)
               for d, c in colors_dir.items() if d in df["direction"].values]
    patches.append(mpatches.Patch(color='gray', alpha=0.4, label='Failed'))
    ax.legend(handles=patches, fontsize=16)
    ax.set_xlabel("Trial", fontsize=20)
    ax.set_ylabel("Switch Time (μs)", fontsize=20)
    ax.set_title("(A) Operator Switching Time per Trial", fontsize=22)

    ax = axes[1]
    success_rate = df["success"].mean() * 100
    total = len(df)
    success_count = df["success"].sum()
    fail_count = total - success_count

    wedges, texts, autotexts = ax.pie(
        [success_count, fail_count],
        labels=[f'Success\n({success_count}/{total})',
                f'Failed\n({fail_count}/{total})'],
        colors=['#2ca02c', '#d62728'],
        autopct='%1.1f%%',
        startangle=90,
        explode=(0.05, 0),
        textprops={'fontsize': 18}
    )
    ax.set_title(f"(B) Overall Success Rate: {success_rate:.1f}%", fontsize=22)

    if success_count > 0:
        success_times = df[df["success"] == 1]["switch_time_us"]
        ax.text(0, -1.4,
                f'Success stats: mean={success_times.mean():.0f}μs, '
                f'std={success_times.std():.0f}μs',
                ha='center', fontsize=16, transform=ax.transData)

    plt.tight_layout()
    save_fig(fig, "fig_operator_switching_v2.png")

# ================================================================
# ================================================================

def plot_nvm_wear():
    df = load_csv("nvm_wear_results.csv")
    if df is None:
        return

    df = df[df["operation"] != "total"].copy()

    fig, axes = plt.subplots(1, 3, figsize=(22, 8))
    fig.suptitle("NVM Wear Analysis",
                 fontweight='bold', fontsize=26, y=1.02)

    ops = df["operation"].tolist()
    colors = ['#8e44ad', '#1abc9c']

    ax = axes[0]
    bars = ax.bar(ops, df["nvram_writes"], color=colors, alpha=0.85,
                  edgecolor='white', width=0.5)
    for bar, v, s in zip(bars, df["nvram_writes"], df["success_count"]):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.05,
                f'{int(v)} writes\n{s} trials', ha='center', va='bottom', fontsize=16)
    ax.set_ylabel("NVM Write Count", fontsize=20)
    ax.set_title("(A) NVM Write Count per Operation", fontsize=22)
    ax.set_ylim(0, df["nvram_writes"].max() * 1.3 + 1)

    ax = axes[1]
    avg_times_ms = df["total_time_us"] / 1000 / df["nvram_writes"]
    bars = ax.bar(ops, avg_times_ms, color=colors, alpha=0.85,
                  edgecolor='white', width=0.5)
    for bar, v, s in zip(bars, avg_times_ms, df["nvram_writes"]):
        label = f'{v:.1f}ms\n({int(s)} writes)'
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + avg_times_ms.max() * 0.02,
                label, ha='center', va='bottom', fontsize=16)
    ax.set_ylabel("Average Time per NVM Write (ms)", fontsize=20)
    ax.set_title("(B) Average Time per NVM Write", fontsize=22)

    ax = axes[2]
    NVM_LIFETIME_WRITES = 200_000
    auth_per_day = 20
    switch_per_year = 12

    auth_row = df[df["operation"] == "authentication"]
    switch_row = df[df["operation"] == "operator_switching"]

    if not auth_row.empty and not switch_row.empty:
        writes_per_auth = auth_row["nvram_writes"].values[0] / auth_row["success_count"].values[0]
        writes_per_switch = switch_row["nvram_writes"].values[0] / switch_row["success_count"].values[0]

        auth_writes_per_year = writes_per_auth * auth_per_day * 365
        switch_writes_per_year = writes_per_switch * switch_per_year
        total_writes_per_year = auth_writes_per_year + switch_writes_per_year
        lifetime_years = NVM_LIFETIME_WRITES / total_writes_per_year if total_writes_per_year > 0 else float('inf')

        categories = ["Auth\n(yearly)", "Switching\n(yearly)", "Total\n(yearly)", "NVM\nLifetime"]
        values = [auth_writes_per_year, switch_writes_per_year, total_writes_per_year, NVM_LIFETIME_WRITES]
        bar_colors = ['#8e44ad', '#1abc9c', '#e67e22', '#2c3e50']

        bars = ax.bar(categories, values, color=bar_colors, alpha=0.85, edgecolor='white')
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + NVM_LIFETIME_WRITES * 0.005,
                    f'{int(v):,}', ha='center', va='bottom', fontsize=14)

        ax.set_ylabel("NVM Writes", fontsize=20)
        ax.set_title(f"(C) Lifetime Estimate\n(≈{auth_per_day}/day auth, ≈{switch_per_year}/year switch)\nEst. lifetime: {lifetime_years:.1f} years", fontsize=22)
    elif not auth_row.empty:
        writes_per_auth = auth_row["nvram_writes"].values[0] / auth_row["success_count"].values[0]
        auth_writes_per_year = writes_per_auth * auth_per_day * 365
        lifetime_years = NVM_LIFETIME_WRITES / auth_writes_per_year if auth_writes_per_year > 0 else float('inf')
        categories = ["Writes\nper Auth", "Yearly\nWrites", "Chip\nCapacity"]
        values = [writes_per_auth, auth_writes_per_year, NVM_LIFETIME_WRITES]
        bar_colors = ['#8e44ad', '#e67e22', '#2c3e50']
        bars = ax.bar(categories, values, color=bar_colors, alpha=0.85, edgecolor='white', width=0.5)
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.02,
                    f'{v:,.0f}', ha='center', va='bottom', fontsize=14)
        ax.set_ylabel("NVM Writes", fontsize=16)
        ax.set_title(f"(C) Lifetime Estimate\n{auth_per_day} auth/day -> {lifetime_years:.1f} years", fontsize=18)
    else:
        ax.text(0.5, 0.5, "Insufficient data\nfor lifetime estimate",
                ha='center', va='center', transform=ax.transAxes, fontsize=18)

    plt.tight_layout()
    save_fig(fig, "fig_nvm_wear_v2.png")

# ================================================================
# ================================================================

def plot_phase_timing():
    df = load_csv("phase_timing_results.csv")
    if df is None:
        return

    phase_cols = ["lpa_precompute_us", "euicc_commit_us", "challenge_gen_us",
                  "tee_authtoken_us", "euicc_mask_us", "lpa_aggregate_us", "server_verify_us"]
    phase_names = ["LPA\nPreCompute", "eUICC\nCommit", "Challenge\nGen",
                   "TEE\nAuthToken", "eUICC\nMask", "LPA\nAggregate", "Server\nVerify"]
    entity_colors = {
        "lpa_precompute_us": '#ff7f0e',
        "euicc_commit_us": '#1f77b4',
        "challenge_gen_us": '#9467bd',
        "tee_authtoken_us": '#8c564b',
        "euicc_mask_us": '#1f77b4',
        "lpa_aggregate_us": '#ff7f0e',
        "server_verify_us": '#2ca02c',
    }

    missing = [c for c in phase_cols if c not in df.columns]
    if missing:
        print(f"  [Warning] phase_timing CSV missing: {missing}")
        return

    fig = plt.figure(figsize=(72, 40))
    fig.suptitle("Per-Phase Timing Analysis", fontweight='bold', fontsize=120, y=0.985)
    gs = GridSpec(2, 2, figure=fig, hspace=0.5, wspace=0.35)

    ax_a = fig.add_subplot(gs[0, :])
    means = df[phase_cols].mean()
    stds = df[phase_cols].std()
    colors_bar = [entity_colors[c] for c in phase_cols]
    
    bars = ax_a.bar(range(len(phase_cols)), means, yerr=stds, capsize=30,
                    color=colors_bar, alpha=0.85, edgecolor='white', width=0.7)
    
    for bar, m, s in zip(bars, means, stds):
        ax_a.text(bar.get_x() + bar.get_width()/2,
                  bar.get_height() + s + max(means)*0.02,
                  f'{m:.0f}μs', ha='center', va='bottom', fontsize=90, fontweight='bold')
    
    ax_a.set_xticks(range(len(phase_cols)))
    ax_a.set_xticklabels(phase_names, rotation=0, ha='center', fontsize=48)
    ax_a.set_ylabel("Time (μs)", fontsize=102)
    ax_a.set_title("(A) Per-Phase Latency (mean ± std)", fontsize=95, fontweight='bold', pad=15)
    ax_a.tick_params(axis='y', labelsize=86)

    legend_patches = [
        mpatches.Patch(color='#1f77b4', label='eUICC'),
        mpatches.Patch(color='#ff7f0e', label='LPA'),
        mpatches.Patch(color='#8c564b', label='TEE'),
        mpatches.Patch(color='#2ca02c', label='Server'),
        mpatches.Patch(color='#9467bd', label='Shared'),
    ]
    ax_a.legend(handles=legend_patches, fontsize=72, loc='upper right')

    ax_b = fig.add_subplot(gs[1, 0])
    data_for_box = [df[c].dropna().values for c in phase_cols]
    bp = ax_b.boxplot(data_for_box, patch_artist=True, notch=False,
                      medianprops=dict(color='red', linewidth=8),
                      flierprops=dict(marker='o', markerfacecolor='red', markersize=24, linestyle='none'))
    
    for patch, color in zip(bp['boxes'], colors_bar):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax_b.set_xticks(range(1, len(phase_names)+1))
    ax_b.set_xticklabels(phase_names, rotation=0, ha='center', fontsize=48)
    ax_b.set_ylabel("Time (μs)", fontsize=92)
    ax_b.set_title("(B) Per-Phase Latency Distribution", fontsize=85, fontweight='bold', pad=15)
    ax_b.legend([mpatches.Patch(color='red', alpha=0.5)], ['Outliers'], fontsize=72, loc='upper right')
    ax_b.tick_params(axis='y', labelsize=72)
    
    all_data = np.concatenate(data_for_box)
    q1 = np.percentile(all_data, 25)
    q3 = np.percentile(all_data, 75)
    iqr = q3 - q1
    y_min = max(0, q1 - 1.5 * iqr)
    y_max = q3 + 2 * iqr
    ax_b.set_ylim(y_min, y_max)

    ax_c = fig.add_subplot(gs[1, 1])
    if "total_us" in df.columns:
        total = df["total_us"].values
    else:
        total = df[[c for c in phase_cols if c in df.columns]].sum(axis=1).values
    
    sorted_total = np.sort(total)
    if len(sorted_total) > 3:
        max_val = sorted_total[-1]
        second_max = sorted_total[-2]
        if max_val > second_max * 1.5:
            filtered_total = total[total != max_val]
            filtered_indices = np.where(total != max_val)[0]
        else:
            filtered_total = total
            filtered_indices = np.arange(len(total))
    else:
        filtered_total = total
        filtered_indices = np.arange(len(total))
    
    ax_c.plot(filtered_indices, filtered_total, alpha=0.7, color='#2c3e50', linewidth=6, marker='o', markersize=16)
    ax_c.axhline(y=np.mean(filtered_total), color='red', linestyle='--',
                 linewidth=6, label=f'Mean: {np.mean(filtered_total):.0f}μs')
    ax_c.fill_between(filtered_indices,
                      np.mean(filtered_total) - np.std(filtered_total),
                      np.mean(filtered_total) + np.std(filtered_total),
                      alpha=0.15, color='red', label='±1σ')
    ax_c.set_xlabel("Trial", fontsize=82)
    ax_c.set_ylabel("Total Time (μs)", fontsize=82)
    ax_c.set_title("(C) End-to-End Latency\nTime Series", fontsize=80, fontweight='bold', pad=15)
    ax_c.legend(fontsize=68)
    ax_c.tick_params(axis='both', labelsize=72)
    
    t_min = max(0, filtered_total.min() * 0.9)
    t_max = filtered_total.max() * 1.1
    ax_c.set_ylim(t_min, t_max)

    plt.tight_layout(rect=[0, 0.02, 1, 0.96])
    save_fig(fig, "fig_phase_timing_v2.png")

# ================================================================
# ================================================================

def plot_memory_usage():
    df = load_csv("memory_usage_results.csv")
    if df is None:
        return

    phases = ["init", "precompute", "commit", "challenge",
              "authtoken", "mask", "aggregate", "verify"]
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728',
              '#9467bd', '#8c564b', '#e377c2', '#7f7f7f']

    fig, axes = plt.subplots(1, 2, figsize=(20, 10))
    fig.suptitle("Memory Usage Analysis", fontweight='bold', fontsize=26, y=1.02)

    ax = axes[0]
    deltas = []
    for phase in phases:
        delta_col = f"{phase}_delta_kb"
        if delta_col in df.columns:
            deltas.append(df[delta_col].mean())
        else:
            deltas.append(0)

    bars = ax.barh(phases, deltas, color=colors, alpha=0.85, edgecolor='white')
    for bar, v in zip(bars, deltas):
        ax.text(v + (0.3 if v >= 0 else -0.3),
                bar.get_y() + bar.get_height()/2,
                f'{v:+.1f} KB', va='center', ha='left' if v >= 0 else 'right',
                fontsize=16)
    ax.axvline(x=0, color='black', linewidth=1)
    ax.set_xlabel("RSS Delta (KB)", fontsize=20)
    ax.set_title("(A) Memory Delta per Phase", fontsize=22)

    ax = axes[1]
    rss_values = []
    for phase in phases:
        rss_col = f"{phase}_rss_kb"
        if rss_col in df.columns:
            rss_values.append(df[rss_col].mean())
        else:
            rss_values.append(0)

    ax.plot(range(len(phases)), rss_values, 'o-', color='#1f77b4',
            linewidth=3, markersize=12)
    ax.fill_between(range(len(phases)), rss_values, alpha=0.2, color='#1f77b4')
    ax.axhline(y=64, color='#d62728', linestyle='--', linewidth=2,
               label='eUICC limit: 64 KB')

    ax.set_xticks(range(len(phases)))
    ax.set_xticklabels([p.replace('_', '\n') for p in phases], fontsize=16)
    ax.set_ylabel("RSS (KB)", fontsize=20)
    ax.set_title("(B) Absolute RSS vs Phase", fontsize=22)
    ax.legend(fontsize=16)

    plt.tight_layout()
    save_fig(fig, "fig_memory_usage_v2.png")

# ================================================================
# ================================================================

def load_dos_results(csv_path):
    path = os.path.join(OUTPUT_DIR, csv_path)
    if not os.path.exists(path):
        print(f"  [Warning] File not found: {path}")
        return None
    
    data = {}
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            test = row['test']
            avg_us = float(row['avg_us'])
            data[test] = avg_us
    return data

def plot_dos_prevention():
    dos_data = load_dos_results("dos_results.csv")
    if not dos_data:
        dos_data = load_dos_results("dos_results_qemu.csv")
    
    if not dos_data:
        return

    tests = []
    times = []
    
    if 'MAC_W_Verification' in dos_data:
        tests.append('MAC_W Verification')
        times.append(dos_data['MAC_W_Verification'])
    
    if 'Full_Lattice_Verification' in dos_data:
        tests.append('Full Lattice Verification')
        times.append(dos_data['Full_Lattice_Verification'])
    
    if not tests:
        print("  [Warning] No valid DoS test data found")
        return

    fig, ax = plt.subplots(figsize=(14, 10))
    y_pos = np.arange(len(tests))

    ax.barh(y_pos, times, color=['#4CAF50', '#F44336'], height=0.6)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(tests, fontsize=20)
    ax.set_xlabel('Execution Time (μs)', fontsize=22)
    ax.set_title('DoS Prevention: Verification Time Comparison', fontsize=26, fontweight='bold')
    ax.set_xscale('log')

    for i, v in enumerate(times):
        ax.text(v * 1.1, i, f'{v:.2f} μs', va='center', fontsize=18)

    if len(times) == 2:
        speedup = times[1] / times[0]
        ax.text(0.5, -0.15, f'Speedup: {speedup:.1f}x faster', 
                ha='center', va='center', transform=ax.transAxes, 
                fontweight='bold', color='#2196F3', fontsize=20)

    plt.tight_layout()
    save_fig(fig, "fig_dos_prevention.png")

# ================================================================
# ================================================================

def load_constant_time_results(csv_path):
    path = os.path.join(OUTPUT_DIR, csv_path)
    if not os.path.exists(path):
        print(f"  [Warning] File not found: {path}")
        return None
    
    times = []
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            times.append(float(row['execution_time_us']))
    return times

def plot_constant_time():
    constant_times = load_constant_time_results("constant_time_results.csv")
    if not constant_times:
        constant_times = load_constant_time_results("constant_time_results_qemu.csv")
    
    if not constant_times:
        return

    fig, ax = plt.subplots(figsize=(14, 10))

    x = range(len(constant_times))
    ax.scatter(x, constant_times, alpha=0.6, s=20, color='#2196F3')

    mean_time = np.mean(constant_times)
    ax.axhline(y=mean_time, color='red', linestyle='--', linewidth=2,
               label=f'Mean: {mean_time:.2f} μs')

    ax.set_xlabel('Trial', fontsize=22)
    ax.set_ylabel('Execution Time (μs)', fontsize=22)
    ax.set_title('Constant Time Execution: Core Algebraic Response Generation', fontsize=26, fontweight='bold')
    ax.legend(fontsize=18)

    std_dev = np.std(constant_times)
    variance = np.var(constant_times)
    min_time = np.min(constant_times)
    max_time = np.max(constant_times)
    
    stats_text = f"Statistics:\n"
    stats_text += f"Mean: {mean_time:.2f} μs\n"
    stats_text += f"Std Dev: {std_dev:.2f} μs\n"
    stats_text += f"Variance: {variance:.2f} μs²\n"
    stats_text += f"Min: {min_time:.2f} μs\n"
    stats_text += f"Max: {max_time:.2f} μs"
    
    ax.text(0.05, 0.95, stats_text, transform=ax.transAxes, 
            verticalalignment='top', bbox=dict(boxstyle='round', alpha=0.1), 
            fontsize=16)

    plt.tight_layout()
    save_fig(fig, "fig_constant_time.png")

# ================================================================
# ================================================================

def plot_callgrind_top_functions():
    csv_path = os.path.join(OUTPUT_DIR, "callgrind_top_functions.csv")
    if not os.path.exists(csv_path):
        csv_path = os.path.join(os.path.dirname(OUTPUT_DIR), "callgrind_top_functions.csv")
    if not os.path.exists(csv_path):
        print(f"  [Warning] callgrind_top_functions.csv not found")
        return

    df = load_csv("callgrind_top_functions.csv")
    if df is None:
        return

    if "function" not in df.columns or "instructions" not in df.columns:
        return

    top_df = df.sort_values("instructions", ascending=False).head(10)

    fig = plt.figure(figsize=(13.4, 9.7))
    fig.suptitle("Callgrind Top Functions Analysis", fontweight='bold', fontsize=28, y=0.97)

    ax = fig.add_subplot(111)

    vals = top_df["instructions"].values.astype(int)
    funcs = top_df["function"].values

    short_names = {
        'pqzk_mat_vec_mul': 'mat_vec_mul',
        'pqzk_vec_scalar_mul': 'vec_scalar_mul',
        'pqzk_gen_matrix_A': 'gen_matrix_A',
        'pqzk_sample_gauss_vec': 'sample_gauss_vec',
        'PQC_eUICC_Commit': 'eUICC_Commit',
        'PQC_ComputeZ_and_Mask': 'ComputeZ_and_Mask',
        'PQC_GenKeyPair.part.0': 'GenKeyPair',
        'PQC_PreCompute': 'PreCompute',
        'PQC_eUICC_Init': 'eUICC_Init',
        'pqzk_parse_poly_vec': 'parse_poly_vec',
    }
    func_labels = [short_names.get(f, f) for f in funcs]

    y_pos = np.arange(len(func_labels))
    bars = ax.barh(y_pos, vals, height=0.55,
                   color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
                          '#8c564b', '#17becf', '#bcbd22', '#7f7f7f', '#e377c2'],
                   alpha=0.85, edgecolor='white')

    for bar, v in zip(bars, vals):
        label = f'{v/1e6:.0f} M' if v >= 1e6 else f'{v/1e6:.1f} M'
        ax.text(bar.get_width() + max(vals)*0.015,
                bar.get_y() + bar.get_height()/2,
                label, va='center', fontsize=22, fontweight='bold')

    from matplotlib.ticker import FuncFormatter
    def millions(x, pos):
        return f'{x/1e6:.0f} M'
    ax.xaxis.set_major_formatter(FuncFormatter(millions))
    ax.tick_params(axis='x', labelsize=20)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(func_labels, fontsize=22)
    ax.set_xlabel("Instruction Count (Ir)", fontsize=24)
    ax.set_title("Top 10 Functions by Instruction Count", fontsize=24, fontweight='bold', pad=15)
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    ax.set_xlim(0, max(vals)*1.15)
    ax.invert_yaxis()

    plt.tight_layout(rect=[0, 0.02, 1, 0.95])
    save_fig(fig, "callgrind_top_functions.png")

# ================================================================
# ================================================================

def plot_environment_breakdown():
    csv_path = os.path.join(OUTPUT_DIR, "perf_results.csv")
    if not os.path.exists(csv_path):
        print(f"  [Warning] File not found: {csv_path}")
        return

    data = {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['function'] in ['eUICC_total', 'LPA_total', 'Server_total']:
                data[row['function']] = float(row['avg_us'])

    if not data:
        print("  [Warning] No environment breakdown data found")
        return

    labels = ['eUICC\n(resource-constrained)', 'LPA\n(high-power)', 'Server']
    values = []
    colors = ['#FF9800', '#4CAF50', '#2196F3']
    
    for label in labels:
        if 'eUICC' in label:
            values.append(data.get('eUICC_total', 0))
        elif 'LPA' in label:
            values.append(data.get('LPA_total', 0))
        elif 'Server' in label:
            values.append(data.get('Server_total', 0))

    fig, ax = plt.subplots(figsize=(12, 10))
    
    bars = ax.bar(labels, values, color=colors, alpha=0.85, edgecolor='white', width=0.7)
    
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.02,
                f'{v:.1f} μs', ha='center', va='bottom', fontsize=36, fontweight='bold')
    
    total = sum(values)
    for bar, v, label in zip(bars, values, labels):
        percentage = (v / total) * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 0.5,
                f'{percentage:.1f}%', ha='center', va='center', fontsize=32, color='white', fontweight='bold')

    ax.set_ylabel("Average Time (μs)", fontsize=42)
    ax.set_xlabel("Component", fontsize=42)
    ax.set_title('Computational Load Distribution', fontsize=50, fontweight='bold')
    ax.tick_params(axis='both', labelsize=38)
    plt.tight_layout()
    save_fig(fig, "fig_environment_breakdown.png")

# ================================================================
# ================================================================

def plot_component_memory():
    lpa_df = load_csv("lpa_memory_results.csv")
    euicc_df = load_csv("euicc_memory_results.csv")
    server_df = load_csv("server_memory_results.csv")

    if lpa_df is None and euicc_df is None and server_df is None:
        print("  [Warning] Missing component memory CSV")
        return

    components = []
    memory_values = []
    colors = []

    if lpa_df is not None and 'memory_kb' in lpa_df.columns:
        lpa_memory = lpa_df['memory_kb'].mean()
        components.append('LPA')
        memory_values.append(lpa_memory)
        colors.append('#ff7f0e')

    if euicc_df is not None and 'memory_kb' in euicc_df.columns:
        euicc_memory = euicc_df['memory_kb'].mean()
        components.append('eUICC')
        memory_values.append(euicc_memory)
        colors.append('#1f77b4')

    if server_df is not None and 'memory_kb' in server_df.columns:
        server_memory = server_df['memory_kb'].mean()
        components.append('Server')
        memory_values.append(server_memory)
        colors.append('#2ca02c')

    if not components:
        print("  [Warning] no valid memory data")
        return

    fig, ax = plt.subplots(figsize=(12, 10))
    fig.suptitle("Component Memory Comparison", fontweight='bold', fontsize=26, y=1.02)

    bars = ax.bar(components, memory_values, color=colors, alpha=0.85,
                  edgecolor='white', width=0.6)
    
    for bar, v in zip(bars, memory_values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(memory_values)*0.03,
                f'{v:.1f} KB', ha='center', va='bottom', fontsize=20, fontweight='bold')
    
    total = sum(memory_values)
    for bar, v, label in zip(bars, memory_values, components):
        percentage = (v / total) * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 0.5,
                f'{percentage:.1f}%', ha='center', va='center', fontsize=18, color='white', fontweight='bold')

    ax.set_ylabel("Memory Usage (KB)", fontsize=22)
    ax.set_title("Memory Usage per Component", fontsize=24)
    ax.set_ylim(0, max(memory_values) * 1.2)

    plt.tight_layout()
    save_fig(fig, "fig_component_memory.png")

# ================================================================
# ================================================================

# ================================================================
# ================================================================

def plot_parameter_space():
    csv_path = os.path.join(OUTPUT_DIR, "grid_results.csv")
    if not os.path.exists(csv_path):
        print("  [Warning] File not found: grid_results.csv")
        return

    import csv
    from math import comb, log2, sqrt

    Q = 3329
    Q_HALF = Q // 2
    ETA_S = 2
    ETA_Y = 1
    TAU = 12
    GAMMA = 2
    N = 256
    K = 3
    KAPPA_OPT = 30
    SIGMA_OPT = 120.0
    BETA_MIN = 3159
    SECURITY_TARGET = 128

    def zk_lower(kappa):
        return GAMMA * ETA_S * kappa

    def correctness_upper(kappa):
        return (Q_HALF - ETA_Y - kappa * ETA_S) / TAU

    def security_bits(kappa):
        return log2(comb(N, kappa)) + kappa

    rows = []
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            avg_total_val = row.get('avg_total_us', '0')
            if avg_total_val is None or avg_total_val.strip() == '':
                avg_total_val = '0'
            
            ov_fail_val = row.get('overflow_fail', '-1')
            if ov_fail_val is None or ov_fail_val.strip() == '':
                ov_fail_val = '-1'
            
            un_fail_val = row.get('underflow_fail', '-1')
            if un_fail_val is None or un_fail_val.strip() == '':
                un_fail_val = '-1'
            
            ov_rate_val = row.get('overflow_rate', '-1')
            if ov_rate_val is None or ov_rate_val.strip() == '':
                ov_rate_val = '-1'
            
            un_rate_val = row.get('underflow_rate', '-1')
            if un_rate_val is None or un_rate_val.strip() == '':
                un_rate_val = '-1'
            
            rows.append({
                'kappa': int(row['kappa']),
                'sigma': float(row['sigma_pub']),
                'beta_final': int(row['beta_final']),
                'correct_ok': int(row['correctness_ok']),
                'overflow_fail': int(ov_fail_val),
                'underflow_fail': int(un_fail_val),
                'fail_count': int(row['fail_count']),
                'trials': int(row['trials']),
                'fail_rate': float(row['fail_rate']),
                'overflow_rate': float(ov_rate_val),
                'underflow_rate': float(un_rate_val),
                'avg_total': float(avg_total_val),
                'security_bits': security_bits(int(row['kappa'])),
            })

    ver = '4.2' if rows[0]['overflow_rate'] >= 0 else '4.1'
    metric = 'overflow_rate' if ver == '4.2' else 'fail_rate'

    kappas = sorted(set(r['kappa'] for r in rows))
    sigmas = sorted(set(r['sigma'] for r in rows))

    val_grid = np.full((len(kappas), len(sigmas)), np.nan)
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

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(50, 25))
    plt.rcParams.update({'font.size': 36})
    fig.suptitle("PQ-ZK-eSIM Parameter Space Analysis",
                 fontsize=60, fontweight='bold', y=0.99)

    # Left: heatmap
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
                        rotation=45, ha='right', fontsize=40)
    ax1.set_yticks(range(len(kappas)))
    ax1.set_yticklabels([str(k) for k in kappas], fontsize=40)
    ax1.set_xlabel(r"$\sigma_{pub}$", fontsize=48)
    ax1.set_ylabel(r"$\kappa$", fontsize=48)
    ax1.set_title("(A)  Overflow Rate\n"
                  "blue (////): ZK violated  |  red (xxxx): correctness violated",
                  fontsize=44)

    if KAPPA_OPT in kappas and SIGMA_OPT in sigmas:
        ki = kappas.index(KAPPA_OPT)
        si = sigmas.index(SIGMA_OPT)
        ax1.plot(si, ki, '*', color='black', markersize=48, zorder=6,
                 label=f"Optimal ($\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f})")
        ax1.legend(loc='upper left', fontsize=40)
    cbar = plt.colorbar(im, ax=ax1, label='Overflow Rate', shrink=0.8)
    cbar.ax.tick_params(labelsize=40)
    cbar.set_label('Overflow Rate', fontsize=40)

    # Right: region map
    sigma_cont = np.linspace(min(sigmas)-5, max(sigmas)+5, 500)

    def hex2rgb(h):
        h = h.lstrip('#')
        return [int(h[i:i+2], 16)/255. for i in (0, 2, 4)]

    cm = {0: '#aac4e8', 1: '#b7e4b7', 2: '#f4b0b0'}
    rgb_img = np.ones((len(kappas), len(sigma_cont), 3))
    for ki, k in enumerate(kappas):
        zk_lb = zk_lower(k)
        cor_ub = correctness_upper(k)
        for si, s in enumerate(sigma_cont):
            key = 0 if s < zk_lb else (2 if s > cor_ub else 1)
            rgb_img[ki, si] = hex2rgb(cm[key])

    ax2.imshow(rgb_img, aspect='auto', origin='lower',
               extent=[sigma_cont[0], sigma_cont[-1], 0, len(kappas)])

    zk_pts = [zk_lower(k) for k in kappas]
    cor_pts = [correctness_upper(k) for k in kappas]
    y_edges = list(range(len(kappas)+1))
    ax2.step(zk_pts + [zk_pts[-1]], y_edges, where='post',
             color='#1a5fa8', lw=2.5,
             label=r'ZK lower bound $(\gamma\eta_s\kappa)$')
    ax2.step(cor_pts + [cor_pts[-1]], y_edges, where='post',
             color='#c0392b', lw=2.5, label='Correctness upper bound')

    if KAPPA_OPT in kappas:
        ki = kappas.index(KAPPA_OPT)
        ax2.plot(SIGMA_OPT, ki+.5, '*', color='black', markersize=36, zorder=6)
        ax2.annotate(
            f"$\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f}  (selected)",
            xy=(SIGMA_OPT, ki+.5), fontsize=36, va='bottom', ha='left',
            xytext=(SIGMA_OPT+4, ki+1.8),
            arrowprops=dict(arrowstyle='->', color='black', lw=3))

    ax2.set_yticks([i+.5 for i in range(len(kappas))])
    ax2.set_yticklabels([str(k) for k in kappas], fontsize=40)
    ax2.set_xlabel(r"$\sigma_{pub}$", fontsize=48)
    ax2.set_ylabel(r"$\kappa$", fontsize=48)
    ax2.set_title("(B)  Parameter Region Classification\n"
                  "green = valid  |  blue = ZK violated  |  red = correctness violated",
                  fontsize=44)
    ax2.legend(handles=[
        mpatches.Patch(color='#aac4e8', label=r'ZK violated ($\sigma$ too small)'),
        mpatches.Patch(color='#b7e4b7', label='Valid region'),
        mpatches.Patch(color='#f4b0b0', label=r'Correctness violated ($\sigma$ too large)'),
        plt.Line2D([0], [0], color='#1a5fa8', lw=2.5,
                   label=r'ZK lower bound $\gamma\eta_s\kappa$'),
        plt.Line2D([0], [0], color='#c0392b', lw=2.5,
                   label='Correctness upper bound'),
        plt.Line2D([0], [0], marker='*', color='black', lw=0, markersize=36,
                   label=f'Optimal ($\\kappa$={KAPPA_OPT}, $\\sigma$={SIGMA_OPT:.0f})'),
    ], fontsize=36, loc='upper right', framealpha=0.92)

    plt.tight_layout()
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_parameter_space.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  -> Saved: {os.path.join(OUTPUT_DIR, 'fig_parameter_space.png')}")

# ================================================================
# ================================================================

def plot_tradeoff():
    csv_path = os.path.join(OUTPUT_DIR, "grid_results.csv")
    if not os.path.exists(csv_path):
        print("  [Warning] File not found: grid_results.csv")
        return

    import csv
    from math import comb, log2, sqrt

    Q = 3329
    Q_HALF = Q // 2
    KAPPA_OPT = 30
    SIGMA_OPT = 120.0
    SECURITY_TARGET = 128

    def security_bits(kappa):
        return log2(comb(256, kappa)) + kappa

    rows = []
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            avg_total_val = row.get('avg_total_us', '0')
            if avg_total_val is None or avg_total_val.strip() == '':
                avg_total_val = '0'
            
            ov_rate_val = row.get('overflow_rate', '-1')
            if ov_rate_val is None or ov_rate_val.strip() == '':
                ov_rate_val = '-1'
            
            un_rate_val = row.get('underflow_rate', '-1')
            if un_rate_val is None or un_rate_val.strip() == '':
                un_rate_val = '-1'
            
            rows.append({
                'kappa': int(row['kappa']),
                'sigma': float(row['sigma_pub']),
                'beta_final': int(row['beta_final']),
                'correct_ok': int(row['correctness_ok']),
                'fail_rate': float(row['fail_rate']),
                'overflow_rate': float(ov_rate_val),
                'underflow_rate': float(un_rate_val),
                'avg_total': float(avg_total_val),
                'security_bits': security_bits(int(row['kappa'])),
            })

    ver = '4.2' if rows[0]['overflow_rate'] >= 0 else '4.1'
    subset = sorted(
        [r for r in rows if abs(r['sigma'] - SIGMA_OPT) < 0.1],
        key=lambda x: x['kappa']
    )
    if not subset:
        print(f"  [Warning] No data for sigma={SIGMA_OPT:.0f}")
        return

    kappas = [r['kappa'] for r in subset]
    sec_bits = [r['security_bits'] for r in subset]
    correct = [r['correct_ok'] for r in subset]
    margins = [Q_HALF - r['beta_final'] for r in subset]
    totals = [r['avg_total'] for r in subset]

    if ver == '4.2':
        core_vals = [r['overflow_rate'] for r in subset]
        ref_vals = [r['underflow_rate'] for r in subset]
    else:
        core_vals = [r['fail_rate'] for r in subset]
        ref_vals = None

    VALID = '#2ecc71'
    INVALID = '#e74c3c'
    OPT_C = '#2c3e50'
    SEC_C = '#8e44ad'

    fig, axes = plt.subplots(4, 1, figsize=(20, 24), sharex=True)
    plt.rcParams.update({'font.size': 18})
    fig.suptitle(
        f"Parameter Trade-off Analysis  ($\sigma_{{pub}}$ = {SIGMA_OPT:.0f})\n"
        r"$\kappa$=30 is the optimal value with low overflow rate "
        r"and positive correctness margin",
        fontsize=24, fontweight='bold'
    )

    valid_k = [k for k, c in zip(kappas, correct) if c]
    if valid_k:
        for ax in axes:
            ax.axvspan(min(valid_k)-.5, max(valid_k)+.5,
                       color=VALID, alpha=0.06, zorder=0)

    # Panel A: Security strength
    ax = axes[0]
    ax.plot(kappas, sec_bits, 'o-', color=SEC_C, lw=2.2,
            markersize=6, zorder=3, label='Security strength')
    ax.axhline(SECURITY_TARGET, color='red', linestyle='--', lw=1.8,
               label=f'{SECURITY_TARGET}-bit security target', zorder=4)
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=5)

    min_safe_k = next((k for k, s in zip(kappas, sec_bits) if s >= SECURITY_TARGET), None)
    if min_safe_k is not None:
        ax.axvline(min_safe_k, color='orange', linestyle='--', lw=1.5,
                   label=f'Min. secure $\\kappa$={min_safe_k}', zorder=4)

    ax.fill_between(kappas, [min(sec_bits)-2]*len(kappas), SECURITY_TARGET,
                    color='red', alpha=0.06, label='Below security target')

    if KAPPA_OPT in kappas:
        idx = kappas.index(KAPPA_OPT)
        ax.annotate(
            f"$\\kappa$={KAPPA_OPT}: {sec_bits[idx]:.1f} bits\n(selected)",
            xy=(KAPPA_OPT, sec_bits[idx]),
            xytext=(KAPPA_OPT+2, sec_bits[idx]-8),
            arrowprops=dict(arrowstyle='->', color=OPT_C, lw=1.5),
            fontsize=16, color=OPT_C)

    ax.set_ylabel(r"Security Strength (bits)", fontsize=22)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=18, loc='lower right')
    ax.tick_params(axis='both', labelsize=16)
    ax.set_title(r"(A)  Security Strength $\log_2\binom{256}{\kappa} \cdot 2^\kappa$"
                 "  —  must be $\geq$ 128", fontsize=20, loc='left')

    # Panel B: Overflow rate
    ax = axes[1]
    valid_kappas = [k for k, c in zip(kappas, correct) if c]
    valid_core_vals = [v for v, c in zip(core_vals, correct) if c]
    invalid_kappas = [k for k, c in zip(kappas, correct) if not c]
    invalid_core_vals = [v for v, c in zip(core_vals, correct) if not c]

    ax.plot(valid_kappas, valid_core_vals, 'o-', color=VALID, lw=2.2, markersize=6,
            zorder=3, label='Correctness satisfied')
    ax.plot(invalid_kappas, invalid_core_vals, 'o-', color=INVALID, lw=2.2, markersize=6,
            zorder=3, label='Correctness violated')

    if ref_vals is not None:
        ax.plot(kappas, ref_vals, 's--', color='gray', markersize=4,
                lw=1.2, alpha=0.7, zorder=4, label=r'Underflow Rate ($\|z\|_2 < \beta_{min}$)')

    ax.axhline(0.001, color='darkorange', linestyle='--', lw=1.8,
               label='0.1% target', zorder=5)
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=6)

    nonzero = [v for v in core_vals if v > 0]
    if nonzero and max(nonzero)/min(nonzero) > 10:
        ax.set_yscale('log')
        ax.set_ylim(bottom=max(1e-5, min(nonzero)*0.5))
    ax.set_ylabel(r'Mod-$q$ Overflow Rate', fontsize=20)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=16, loc='upper right')
    ax.tick_params(axis='both', labelsize=16)
    ax.set_title("(B)  Mod-$q$ Overflow Rate  —  lower is better", fontsize=20, loc='left')

    # Panel C: Correctness margin
    ax = axes[2]
    m_colors = [VALID if m > 0 else INVALID for m in margins]
    ax.bar(kappas, margins, color=m_colors, alpha=0.82, width=0.6, zorder=3)
    ax.axhline(0, color='red', lw=2.2, zorder=4,
               label=r'$q/2$ boundary — must stay above zero')
    ax.axvline(KAPPA_OPT, color=OPT_C, linestyle=':', lw=2.2, zorder=5)
    ax.fill_between([min(kappas)-.5, max(kappas)+.5], 0, min(margins)-50,
                    color='red', alpha=0.07, label='Overflow region')
    ax.set_ylabel(r"Margin  $= q/2 - \beta_{final}$", fontsize=22)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=16, loc='lower left')
    ax.tick_params(axis='both', labelsize=16)
    ax.set_title(r"(C)  Correctness Margin  —  must be $> 0$", fontsize=20, loc='left')

    # Panel D: Latency
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
    ax.set_xlabel(r"$\kappa$ (sparse challenge weight)", fontsize=22)
    ax.set_ylabel("End-to-end Latency (μs)", fontsize=22)
    ax.grid(axis='y', linestyle=':', alpha=0.45)
    ax.legend(fontsize=16, loc='upper left')
    ax.tick_params(axis='both', labelsize=16)
    ax.set_title("(D)  End-to-end Latency  —  lower is better", fontsize=20, loc='left')

    fig.legend(
        handles=[
            mpatches.Patch(color=VALID, alpha=0.82, label='Correctness satisfied'),
            mpatches.Patch(color=INVALID, alpha=0.82, label='Correctness violated'),
        ],
        loc='lower center', ncol=2, fontsize=12,
        bbox_to_anchor=(0.5, -0.01), framealpha=0.9)

    plt.tight_layout(rect=[0, 0.02, 1, 1])
    fig.savefig(os.path.join(OUTPUT_DIR, "fig_tradeoff.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  -> Saved: {os.path.join(OUTPUT_DIR, 'fig_tradeoff.png')}")

# ================================================================
# ================================================================

def main():
    print("=" * 60)
    print("  PQ-ZK-eSIM unified visualization v1.0")
    print("=" * 60)

    plot_functions = [
        ("Sparse noise attack", plot_sparse_noise_attack),
        ("Sliding window resync", plot_sliding_window_resync),
        ("Operator switch", plot_operator_switching),
        ("NVM wear", plot_nvm_wear),
        ("Phase timing", plot_phase_timing),
        ("Memory usage", plot_memory_usage),
        ("DoS prevention", plot_dos_prevention),
        ("Constant time", plot_constant_time),
        ("Callgrind Top Functions", plot_callgrind_top_functions),
        ("Environment breakdown", plot_environment_breakdown),
        ("Component memory", plot_component_memory),
        ("Parameter space", plot_parameter_space),
        ("Parameter tradeoff", plot_tradeoff),
    ]

    for i, (name, func) in enumerate(plot_functions, 1):
        print(f"\n[{i}/{len(plot_functions)}] {name}...")
        try:
            func()
        except Exception as e:
            print(f"  [Error]  {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print("  Done, charts saved to build/")
    print("=" * 60)

if __name__ == "__main__":
    main()