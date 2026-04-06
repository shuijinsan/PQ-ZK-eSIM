/**
 * @file params.h
 * @brief PQ-ZK-eSIM 安全参数集中定义 (v3.0)
 *
 * 本文件是所有可调安全参数的唯一来源（Single Source of Truth）。
 * 修改任何参数前必须重新验证正确性条件（见下方推导注释）。
 * 网格搜索脚本（bench_pqzkesim.c / grid_search.py）通过
 * 覆盖 PQZK_KAPPA 和 PQZK_SIGMA_PUB 宏来扫描参数空间。
 *
 * ┌─────────────────────────────────────────────────────────┐
 * │  正确性约束（必须满足，否则验证引擎概率性失败）         │
 * │  β_pub + η_y + κ · η_s  <  q/2                         │
 * │  τ·σ   +  1  + κ·2     <  1664                         │
 * │  当前值：1248 + 1 + 52 = 1301 < 1664  ✓               │
 * └─────────────────────────────────────────────────────────┘
 *
 * 与 pq_zk_esim.h 的关系：
 *   - pq_zk_esim.h 定义协议结构和 API 签名（跨端宪法，不可改）
 *   - params.h     定义可调数值参数（实验调优入口）
 *   - 两者均被包含时，params.h 的定义通过 #ifndef 保护与 h 对齐
 */

#ifndef PQZK_PARAMS_H
#define PQZK_PARAMS_H

/* ================================================================
 * 第一层：从 pq_zk_esim.h 继承的固定系统参数（只读，不可覆盖）
 * ================================================================ */

#include "pq_zk_esim.h"

/* 以下来自 pq_zk_esim.h，此处仅作注释说明，不重复定义：
 *   PQ_ZK_N     = 256     多项式环阶数
 *   PQ_ZK_K     = 3       模块维度（Kyber-768）
 *   PQ_ZK_Q_VAL = 3329    模数 q（素数）
 *   PQ_ZK_ETA_S = 2       私钥 S 系数无穷范数上界 η_s
 */

/* ================================================================
 * 第二层：协议安全参数（可通过网格搜索调优）
 * ================================================================
 *
 * 参数推导链：
 *
 *   1. κ（挑战稀疏权重）
 *      - 影响抗伪造安全性：组合空间 C(N,κ)·2^κ
 *      - 影响正确性上界：κ·η_s 项
 *      - 论文实验范围：κ ∈ [20, 39]
 *      - 当前最优值：26（零知识性与正确性平衡点）
 *
 *   2. σ_pub（外部盲化因子高斯标准差）
 *      - 零知识性约束：σ_pub ≥ γ·η_s·κ = 2·2·26 = 104
 *      - 正确性约束：τ·σ_pub + 1 + κ·η_s < q/2 = 1664
 *        → σ_pub < (1664 - 1 - 52) / 12 = 1611/12 ≈ 134.25
 *        → σ_pub ∈ [104, 134]，取 104 最保守（论文实验范围 [80,150]）
 *
 *   3. τ（高斯截断参数）
 *      - Pr[|x| > τ·σ] ≤ 2^{-τ}，取 τ=12 → 概率 ≈ 2^{-12} ≈ 0.024%
 *      - β_pub = τ·σ_pub = 12·104 = 1248
 *
 *   4. β_final（验证引擎无穷范数上界）
 *      - β_final = β_pub + η_y + κ·η_s = 1248 + 1 + 52 = 1301
 *      - 必须 β_final < q/2 = 1664 → 安全余量 363 ✓
 *
 *   5. β_min（验证引擎欧几里得范数下界）
 *      - 基于期望 L2 范数：E[||y_pub||_2] = sqrt(K·N·σ²) ≈ 2882
 *      - 取 0.95 倍期望值（>99% 概率满足）：β_min = 2735
 *      - 作用：检测恶意 LPA 令 y_pub=0 的攻击（此时 ||z||_2 ≪ β_min）
 */

/* ---- 当前生产参数（κ=26，σ=104）---- */

#ifndef PQZK_KAPPA
/** 稀疏挑战多项式汉明权重 κ（非零系数个数）*/
#  define PQZK_KAPPA            26
#endif

#ifndef PQZK_SIGMA_PUB
/** 外部盲化因子 y_pub 的离散高斯标准差 */
#  define PQZK_SIGMA_PUB        104.0
#endif

/** 高斯截断参数 τ（Pr[越界] ≈ 2^{-τ}）*/
#define PQZK_TAU                12

/** Rényi 散度安全系数 γ（满足 σ_pub ≥ γ·η_s·κ）*/
#define PQZK_RENYI_GAMMA        2

/* ================================================================
 * 第三层：派生参数（由上层参数自动推导，请勿手动修改）
 * ================================================================ */

/** β_pub = τ · σ_pub，y_pub 系数高置信上界 */
#define PQZK_BETA_PUB           ((int32_t)(PQZK_TAU * (int32_t)PQZK_SIGMA_PUB))

/**
 * β_final：验证引擎无穷范数上界（防模 q 溢出）
 * β_final = β_pub + η_y + κ·η_s
 *         = τ·σ + 1 + κ·η_s
 *
 * 【正确性红线】β_final 必须严格小于 q/2 = 1664
 * 当前值：1248 + 1 + 52 = 1301 < 1664 ✓
 */
#define PQZK_BETA_FINAL         ((int32_t)(                     \
    PQZK_BETA_PUB                                               \
    + 1                          /* η_y = 1（三进制 y_sec）*/   \
    + PQZK_KAPPA * PQ_ZK_ETA_S  /* κ · η_s */                  \
))

/**
 * β_min：验证引擎欧几里得范数下界（防 y_pub=0 攻击）
 * E[||y_pub||_2²] = K·N·σ²，取 0.95 倍期望的平方根
 *
 * 静态计算（避免浮点宏）：
 *   sqrt(0.95 · 3 · 256 · 104²) = sqrt(0.95 · 8306688) ≈ 2810
 * 保守取整为 2735（留余量防参数漂移）
 */
#define PQZK_BETA_MIN           2735

/**
 * 单次认证解密失败率估算（论文 Evaluation 数据）
 * 失败 = z 的某系数绝对值超过 β_final（发生模 q 环绕）
 * 当前参数下失败率 ≈ 2^{-10}（约 0.1%），蜂窝网络可接受
 *
 * 注意：此宏仅用于注释和断言，不参与计算
 */
#define PQZK_EXPECTED_FAIL_RATE_LOG2  (-10)   /* 约 2^{-10} */

/* ================================================================
 * 第四层：网格搜索边界（bench_pqzkesim.c 使用）
 * ================================================================ */

/** 网格搜索 κ 最小值 */
#define PQZK_GRID_KAPPA_MIN     20

/** 网格搜索 κ 最大值（κ=39 时 β_final > q/2，属于预期溢出区）*/
#define PQZK_GRID_KAPPA_MAX     39

/** 网格搜索 σ_pub 最小值 */
#define PQZK_GRID_SIGMA_MIN     80.0

/** 网格搜索 σ_pub 最大值 */
#define PQZK_GRID_SIGMA_MAX     150.0

/** 网格搜索 σ_pub 步长 */
#define PQZK_GRID_SIGMA_STEP    5.0

/** 每个参数组合的重复采样次数（统计失败率用）*/
#define PQZK_GRID_TRIALS        1000

/* ================================================================
 * 第五层：编译期正确性断言
 * ================================================================
 *
 * 如果参数不满足约束，编译时直接报错，而非运行时才发现问题。
 */

/* β_final < q/2 = 1664 */
_Static_assert(
    PQZK_BETA_FINAL < 1664,
    "PQZK_BETA_FINAL 必须小于 q/2=1664，请检查 PQZK_KAPPA 和 PQZK_SIGMA_PUB"
);

/* σ_pub ≥ γ·η_s·κ（零知识性下界） */
_Static_assert(
    (int)(PQZK_SIGMA_PUB) >= PQZK_RENYI_GAMMA * PQ_ZK_ETA_S * PQZK_KAPPA,
    "PQZK_SIGMA_PUB 不满足 Rényi 散度零知识性下界 γ·η_s·κ"
);

/* κ 在有效范围内 */
_Static_assert(
    PQZK_KAPPA >= 1 && PQZK_KAPPA <= PQ_ZK_N / 2,
    "PQZK_KAPPA 必须在 [1, N/2] 范围内"
);

/* ================================================================
 * 第六层：运行时参数初始化宏（供 VerifyEngine 调用方使用）
 * ================================================================ */

/**
 * PQZK_DEFAULT_BETA_PARAMS
 * 用默认参数初始化 beta_params_t 结构体
 *
 * 用法：
 *   beta_params_t p = PQZK_DEFAULT_BETA_PARAMS;
 *   PQC_VerifyEngine(..., &p);
 */
#define PQZK_DEFAULT_BETA_PARAMS  \
    { (uint16_t)PQZK_BETA_FINAL, (uint16_t)PQZK_BETA_MIN }

/**
 * PQZK_MAKE_BETA_PARAMS(kappa, sigma)
 * 网格搜索时动态计算 beta_params_t
 *
 * 用法（bench_pqzkesim.c）：
 *   beta_params_t p = PQZK_MAKE_BETA_PARAMS(30, 120.0);
 */
#define PQZK_MAKE_BETA_PARAMS(kappa_, sigma_)  {                            \
    (uint16_t)((int32_t)(PQZK_TAU * (int32_t)(sigma_))                     \
               + 1 + (kappa_) * PQ_ZK_ETA_S),   /* beta_final */           \
    (uint16_t)(2735)                              /* beta_min 固定 */       \
}

#endif /* PQZK_PARAMS_H */