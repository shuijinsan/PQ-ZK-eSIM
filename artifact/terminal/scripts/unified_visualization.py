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
