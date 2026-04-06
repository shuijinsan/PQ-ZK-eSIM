#!/usr/bin/env python3
"""
grid_search.py
读取 bench_pqzkesim 输出的 grid_results.csv，生成论文图表

用法：
    python3 grid_search.py                        # 读 grid_results.csv
    python3 grid_search.py --csv other.csv        # 指定 CSV 文件
    python3 grid_search.py --no-plot              # 只打印统计，不画图

输出：
    fig_fail_rate_heatmap.png   失败率热力图（κ × σ）
    fig_fail_rate_kappa.png     固定σ=104，失败率随κ变化曲线
    fig_fail_rate_sigma.png     固定κ=26，失败率随σ变化曲线
    fig_timing_breakdown.png    各阶段耗时分布（最优参数点）
    optimal_params.txt          最优参数点摘要
"""

import csv
import sys
import os
import argparse
from collections import defaultdict

# ── 可选 matplotlib（无则只输出文本）──────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    print("[INFO] matplotlib 未安装，跳过图表生成，只输出文本统计")
    print("       pip install matplotlib 后重新运行可生成图表\n")

# ── 协议参数常量（与 params.h 对齐）──────────────────────────────
Q          = 3329
Q_HALF     = Q // 2       # 1664
ETA_S      = 2
TAU        = 12
KAPPA_OPT  = 26
SIGMA_OPT  = 104.0

def load_csv(path: str):
    rows = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                'kappa':         int(row['kappa']),
                'sigma':         float(row['sigma_pub']),
                'beta_final':    int(row['beta_final']),
                'beta_pub':      int(row['beta_pub']),
                'correct_ok':    int(row['correctness_ok']),
                'fail_count':    int(row['fail_count']),
                'trials':        int(row['trials']),
                'fail_rate':     float(row['fail_rate']),
                'avg_precompute':   float(row['avg_precompute_us']),
                'avg_commit':       float(row['avg_commit_us']),
                'avg_challenge':    float(row['avg_challenge_us']),
                'avg_compute_mask': float(row['avg_compute_mask_us']),
                'avg_aggregate':    float(row['avg_aggregate_us']),
                'avg_verify':       float(row['avg_verify_us']),
                'avg_total':        float(row['avg_total_us']),
            })
    return rows

# ── 统计分析 ─────────────────────────────────────────────────────

def analyze(rows):
    print("=" * 60)
    print("  PQ-ZK-eSIM 参数网格搜索结果分析")
    print("=" * 60)

    kappas = sorted(set(r['kappa'] for r in rows))
    sigmas = sorted(set(r['sigma']  for r in rows))
    print(f"κ 范围: {min(kappas)} ~ {max(kappas)}，共 {len(kappas)} 个值")
    print(f"σ 范围: {min(sigmas):.0f} ~ {max(sigmas):.0f}，共 {len(sigmas)} 个值")
    print(f"总组合数: {len(rows)}，每组试验次数: {rows[0]['trials']}\n")

    # ── 溢出边界分析 ────────────────────────────────────────────
    print("--- 正确性约束（β_final < q/2 = 1664）---")
    overflow_kappas = set()
    for r in rows:
        if not r['correct_ok']:
            overflow_kappas.add(r['kappa'])
    if overflow_kappas:
        print(f"  β_final ≥ q/2 的 κ 值（σ=104）: "
              f"{sorted(overflow_kappas)}")
    else:
        print("  所有参数组合均满足正确性约束")

    # ── 最优参数点 ───────────────────────────────────────────────
    print("\n--- 最优参数点（论文推荐值）---")
    target = [r for r in rows
              if r['kappa'] == KAPPA_OPT and abs(r['sigma'] - SIGMA_OPT) < 0.1]
    if target:
        t = target[0]
        print(f"  κ={t['kappa']}, σ={t['sigma']:.1f}")
        print(f"  β_final = {t['beta_final']} < q/2=1664: "
              f"{'✓' if t['correct_ok'] else '✗'}")
        print(f"  失败率: {t['fail_count']}/{t['trials']} = {t['fail_rate']:.6f}"
              f"  ≈ 2^{{{-round(-t['fail_rate'].bit_length() if t['fail_rate']>0 else 0)}}}")
        print(f"  端到端耗时: {t['avg_total']:.1f} μs")
        print(f"    PreCompute:   {t['avg_precompute']:.1f} μs")
        print(f"    eUICC_Commit: {t['avg_commit']:.1f} μs  ← 5ms 目标关键")
        print(f"    VerifyEngine: {t['avg_verify']:.1f} μs")

    # ── 失败率分布（固定σ=104）──────────────────────────────────
    print(f"\n--- 失败率随 κ 变化（σ={SIGMA_OPT:.0f}）---")
    print(f"{'κ':>4}  {'β_final':>7}  {'ok?':>4}  {'fail/trials':>12}  {'fail_rate':>10}")
    for r in sorted(rows, key=lambda x: x['kappa']):
        if abs(r['sigma'] - SIGMA_OPT) < 0.1:
            ok_str = "✓" if r['correct_ok'] else "✗溢出"
            print(f"{r['kappa']:>4}  {r['beta_final']:>7}  {ok_str:>4}  "
                  f"{r['fail_count']:>5}/{r['trials']:<5}  {r['fail_rate']:>10.6f}")

    # ── 写最优参数摘要 ───────────────────────────────────────────
    with open("optimal_params.txt", "w") as f:
        f.write("PQ-ZK-eSIM 最优参数摘要\n")
        f.write("=" * 40 + "\n")
        if target:
            t = target[0]
            f.write(f"κ (PQZK_KAPPA)       = {t['kappa']}\n")
            f.write(f"σ (PQZK_SIGMA_PUB)   = {t['sigma']:.1f}\n")
            f.write(f"β_final              = {t['beta_final']}\n")
            f.write(f"β_min (PQZK_BETA_MIN)= {PQZK_BETA_MIN}\n")
            f.write(f"失败率               = {t['fail_rate']:.6f}\n")
            f.write(f"端到端耗时 (avg)     = {t['avg_total']:.1f} μs\n")
    print("\n最优参数摘要写入 optimal_params.txt")

    return rows

PQZK_BETA_MIN = 2735  # 与 params.h 对齐

# ── 可视化 ───────────────────────────────────────────────────────

def plot_heatmap(rows):
    """失败率热力图：x轴=σ，y轴=κ"""
    kappas = sorted(set(r['kappa'] for r in rows))
    sigmas = sorted(set(r['sigma']  for r in rows))

    data = [[0.0]*len(sigmas) for _ in range(len(kappas))]
    for r in rows:
        ki = kappas.index(r['kappa'])
        si = sigmas.index(r['sigma'])
        data[ki][si] = r['fail_rate']

    fig, ax = plt.subplots(figsize=(12, 6))
    im = ax.imshow(data, aspect='auto', origin='lower',
                   cmap='RdYlGn_r', vmin=0, vmax=0.1)

    ax.set_xticks(range(len(sigmas)))
    ax.set_xticklabels([f"{s:.0f}" for s in sigmas], rotation=45, ha='right')
    ax.set_yticks(range(len(kappas)))
    ax.set_yticklabels([str(k) for k in kappas])
    ax.set_xlabel("σ_pub（外部盲化因子标准差）", fontsize=12)
    ax.set_ylabel("κ（稀疏挑战权重）", fontsize=12)
    ax.set_title("PQ-ZK-eSIM 模 q 溢出失败率热力图\n"
                 "（绿色=低失败率，红色=高失败率，白色边界=β_final≥q/2溢出区）",
                 fontsize=12)

    # 标记最优点
    if KAPPA_OPT in kappas and SIGMA_OPT in sigmas:
        ki = kappas.index(KAPPA_OPT)
        si = sigmas.index(SIGMA_OPT)
        ax.plot(si, ki, 'b*', markersize=15, label=f"最优点 κ={KAPPA_OPT},σ={SIGMA_OPT:.0f}")
        ax.legend(loc='upper left')

    # 标记溢出边界（β_final ≥ q/2）
    for r in rows:
        if not r['correct_ok']:
            ki = kappas.index(r['kappa'])
            si = sigmas.index(r['sigma'])
            ax.add_patch(plt.Rectangle((si-0.5, ki-0.5), 1, 1,
                         fill=False, edgecolor='white', linewidth=2))

    plt.colorbar(im, ax=ax, label="失败率")
    plt.tight_layout()
    plt.savefig("fig_fail_rate_heatmap.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("图表保存: fig_fail_rate_heatmap.png")


def plot_fail_vs_kappa(rows):
    """固定σ=104，失败率随κ的变化"""
    subset = sorted(
        [r for r in rows if abs(r['sigma'] - SIGMA_OPT) < 0.1],
        key=lambda x: x['kappa']
    )
    if not subset:
        return

    kappas     = [r['kappa']     for r in subset]
    fail_rates = [r['fail_rate'] for r in subset]
    correct    = [r['correct_ok'] for r in subset]

    fig, ax1 = plt.subplots(figsize=(10, 5))

    # 失败率（左轴）
    colors = ['green' if c else 'red' for c in correct]
    bars = ax1.bar(kappas, fail_rates, color=colors, alpha=0.7, width=0.6)
    ax1.set_xlabel("κ（稀疏挑战权重）", fontsize=12)
    ax1.set_ylabel("失败率", fontsize=12, color='darkgreen')
    ax1.axhline(0.001, color='orange', linestyle='--',
                label='目标失败率 0.1%')
    ax1.axvline(KAPPA_OPT, color='blue', linestyle=':',
                label=f'最优点 κ={KAPPA_OPT}')

    # β_final（右轴）
    ax2 = ax1.twinx()
    beta_finals = [r['beta_final'] for r in subset]
    ax2.plot(kappas, beta_finals, 'b--o', markersize=4, label='β_final')
    ax2.axhline(Q_HALF, color='red', linestyle='-', linewidth=2,
                label=f'q/2={Q_HALF}（溢出边界）')
    ax2.set_ylabel("β_final", fontsize=12, color='blue')

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    ax1.set_title(f"失败率与 β_final 随 κ 的变化（σ={SIGMA_OPT:.0f}）\n"
                  "绿柱=满足正确性约束，红柱=β_final≥q/2溢出区",
                  fontsize=12)
    plt.tight_layout()
    plt.savefig("fig_fail_rate_kappa.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("图表保存: fig_fail_rate_kappa.png")


def plot_fail_vs_sigma(rows):
    """固定κ=26，失败率随σ的变化"""
    subset = sorted(
        [r for r in rows if r['kappa'] == KAPPA_OPT],
        key=lambda x: x['sigma']
    )
    if not subset:
        return

    sigmas     = [r['sigma']     for r in subset]
    fail_rates = [r['fail_rate'] for r in subset]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(sigmas, fail_rates, 'go-', markersize=5)
    ax.fill_between(sigmas, 0, fail_rates, alpha=0.2, color='green')
    ax.axvline(SIGMA_OPT, color='blue', linestyle='--',
               label=f'最优点 σ={SIGMA_OPT:.0f}')
    ax.axhline(0.001, color='orange', linestyle='--',
               label='目标失败率 0.1%')
    ax.axvline(TAU * ETA_S * KAPPA_OPT, color='red', linestyle=':',
               label=f'Rényi 下界 σ_min={TAU*ETA_S*KAPPA_OPT}')

    ax.set_xlabel("σ_pub（外部盲化因子标准差）", fontsize=12)
    ax.set_ylabel("失败率", fontsize=12)
    ax.set_title(f"失败率随 σ_pub 的变化（κ={KAPPA_OPT}）\n"
                 "σ 越大失败率越低，但增大参数规模",
                 fontsize=12)
    ax.legend()
    ax.set_yscale('log')  # 对数坐标更直观
    plt.tight_layout()
    plt.savefig("fig_fail_rate_sigma.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("图表保存: fig_fail_rate_sigma.png")


def plot_timing_breakdown(rows):
    """最优参数点各阶段耗时分布"""
    target = [r for r in rows
              if r['kappa'] == KAPPA_OPT and abs(r['sigma'] - SIGMA_OPT) < 0.1]
    if not target:
        return
    t = target[0]

    labels = [
        'PreCompute\n(LPA)',
        'eUICC_Commit\n(eUICC)',
        'GenChallenge\n(LPA)',
        'ComputeZ\n(eUICC)',
        'Aggregate\n(LPA)',
        'Verify\n(Server)',
    ]
    values = [
        t['avg_precompute'],
        t['avg_commit'],
        t['avg_challenge'],
        t['avg_compute_mask'],
        t['avg_aggregate'],
        t['avg_verify'],
    ]
    colors = ['#4C72B0','#DD8452','#55A868','#C44E52','#8172B3','#937860']

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(labels, values, color=colors, alpha=0.85)

    # 在柱子上标注数值
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{val:.1f}μs', ha='center', va='bottom', fontsize=9)

    ax.set_ylabel("平均耗时（μs）", fontsize=12)
    ax.set_title(f"各阶段 API 耗时分布（κ={KAPPA_OPT}, σ={SIGMA_OPT:.0f}）\n"
                 f"端到端合计：{t['avg_total']:.1f} μs",
                 fontsize=12)

    # 标注 5ms eUICC 目标
    ax.axhline(5000, color='red', linestyle='--', linewidth=1,
               label='5ms eUICC 目标')
    ax.legend()
    plt.tight_layout()
    plt.savefig("fig_timing_breakdown.png", dpi=150, bbox_inches='tight')
    plt.close()
    print("图表保存: fig_timing_breakdown.png")


# ── 主入口 ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PQ-ZK-eSIM 网格搜索结果可视化")
    parser.add_argument("--csv",      default="grid_results.csv",
                        help="CSV 文件路径（默认 grid_results.csv）")
    parser.add_argument("--no-plot",  action="store_true",
                        help="只输出文本统计，不生成图表")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"[ERROR] 找不到 {args.csv}")
        print("请先运行：./bench --grid")
        sys.exit(1)

    rows = load_csv(args.csv)
    analyze(rows)

    if not args.no_plot:
        if HAS_PLOT:
            print("\n生成图表...")
            plot_heatmap(rows)
            plot_fail_vs_kappa(rows)
            plot_fail_vs_sigma(rows)
            plot_timing_breakdown(rows)
            print("\n所有图表生成完毕，可直接用于论文 Evaluation 章节。")
        else:
            print("\n[提示] 安装 matplotlib 后可生成图表：")
            print("  pip3 install matplotlib")


if __name__ == "__main__":
    main()