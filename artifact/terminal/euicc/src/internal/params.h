/**
 * @file params.h
 * @brief PQ-ZK-eSIM security parameter definitions (v5.2 — sigma=5000, kappa=35)
 *
 * This file is the Single Source of Truth for all tunable security parameters.
 * All changes must be re-verified against the proof conditions in the paper.
 *
 * Relationship to pq_zk_esim.h:
 *   - pq_zk_esim.h defines protocol structures and API signatures
 *   - params.h      defines tunable numerical parameters (experiment tuning entry)
 *   - Both are included; params.h uses #ifndef guards to align with header
 */

#ifndef PQZK_PARAMS_H
#define PQZK_PARAMS_H

#include "pq_zk_esim.h"

/* ================================================================
 * Layer 1: Fixed system parameters inherited from pq_zk_esim.h
 * ================================================================
 *
 *   PQ_ZK_N     = 256     polynomial ring degree
 *   PQ_ZK_K     = 3       matrix rows (commitment dim)
 *   PQ_ZK_M     = 8       matrix cols (witness dim)
 *   PQ_ZK_Q_VAL = 8380417 modulus q = 2^23 - 2^13 + 1 (NTT-friendly)
 *   PQ_ZK_ETA_S = 1       secret S coefficient l_inf bound (ternary)
 */

#ifndef PQ_ZK_Q_VAL
#define PQ_ZK_Q_VAL 8380417
#endif

/* ================================================================
 * Layer 2: Protocol security parameters (Paper Table 3, Theorem 3/4)
 * ================================================================
 *
 * Derivation chain (sigma=5000, kappa=35):
 *
 *   1. kappa = 35 (challenge sparsity weight)
 *      - log2(C(256,35)*2^35) = 178.6 bit gives about 178.6 challenge bits
 *      - Soundness uses the ROM forking reduction in the paper
 *
 *   2. sigma_pub = 5000 (Gaussian flooding std deviation)
 *      - Finite-parameter Renyi accounting is reported separately from the asymptotic UC condition
 *      - R_16 <= exp(16*||b||^2 / (2*sigma^2)) = exp(16*97960/(2*25e6))
 *        = exp(0.0314) = 1.032  (paper: per-transcript loss R_16^(15/16) = 1.030)
 *      - Per-transcript loss L = R_16^(15/16) = 1.030
 *
 *   3. beta_inf = 35700 (verifier l_inf bound)
 *      - tau = beta_inf / sigma = 35700/5000 = 7.14
 *      - Pr[|coeff| > beta_inf] = erfc(7.14/sqrt(2)) ~ 10^{-12} per coeff
 *      - Union bound over mN=2048 coeffs: ~ 2 * 10^{-9}
 *
 *   4. beta_final = 260000 (z_unmasked l_2 upper bound)
 *      - E[||y_pub||_2] = sigma*sqrt(M*N) = 5000*45.25 = 226,274
 *      - radial standard deviation is approximately sigma/sqrt(2)
 *      - beta_final is about 9.54 radial standard deviations above the reference scale
 *      - beta_final = 260000 << q/2 = 4,190,208  OK
 *
 *   5. beta_min = 200000 (l_2 lower bound, sparse noise defense)
 *      - E[||y_pub||_2] = 226,274
 *      - beta_min is about 7.43 radial standard deviations below the reference scale
 *
 *   6. beta_L1 = 7,400,000 (L1 lower bound)
 *      - E[||y_pub||_1] = M*N*sigma*sqrt(2/pi) = 2048*5000*0.7979 = 8,170,338
 *      - Std[||y_pub||_1] ~ sigma*sqrt(M*N*(1-2/pi)) = 5000*27.3 = 136,500
 *      - beta_L1 = 8,170,338 - 5*136,500 = 7,487,838 ~ 7,400,000
 */

#ifndef PQZK_KAPPA
#define PQZK_KAPPA            35
#endif

#ifndef PQ_ZK_SIGMA_PUB
#define PQ_ZK_SIGMA_PUB        5000.0
#endif

#define PQ_ZK_TAU               7.14
#define PQ_ZK_BETA_INF          35700

/* ================================================================
 * Layer 3: Derived parameters (auto-derived, do not modify manually)
 * ================================================================ */

// beta_final = 260000: about 9.54 radial reference standard deviations above sigma*sqrt(mN)
// Actual z_unmasked norm: ||y_pub||_2 dominates, chi distribution
#define PQZK_BETA_FINAL        260000

// beta_min = 200000: lower acceptance bound used in the paper's finite accounting
#define PQZK_BETA_MIN           200000

// beta_L1 = 7,400,000: L1 lower bound for sparse noise defense
#define PQZK_BETA_L1            7400000

/* ================================================================
 * Layer 4: Grid search bounds (q=8.38M, correctness no longer bottleneck)
 * ================================================================ */


/* ================================================================
 * Layer 5: Compile-time correctness assertions
 * ================================================================ */

_Static_assert(
    PQZK_BETA_FINAL < 4190209,
    "PQZK_BETA_FINAL must be < q/2 = 4,190,208"
);

_Static_assert(
    PQ_ZK_BETA_INF >= (int)(PQ_ZK_TAU * PQ_ZK_SIGMA_PUB),
    "PQ_ZK_BETA_INF must be >= tau * sigma_pub"
);

_Static_assert(
    PQZK_KAPPA >= 1 && PQZK_KAPPA <= PQ_ZK_N / 2,
    "PQZK_KAPPA must be in [1, N/2]"
);

_Static_assert(
    PQ_ZK_M > PQ_ZK_K,
    "Rectangular matrix requires M > K (witness dim > commitment dim)"
);

/* ================================================================
 * Layer 6: Runtime parameter initialization macros
 * ================================================================ */

#ifndef PQZK_DEFAULT_BETA_PARAMS
#define PQZK_DEFAULT_BETA_PARAMS      { (uint32_t)PQZK_BETA_FINAL, (uint32_t)PQZK_BETA_MIN, (uint32_t)PQZK_BETA_L1 }

#define PQZK_MAKE_BETA_PARAMS(kappa_, sigma_)  { \
    (uint32_t)PQZK_BETA_FINAL, \
    (uint32_t)PQZK_BETA_MIN,   \
    (uint32_t)PQZK_BETA_L1     \
}

#endif /* PQZK_PARAMS_H */
#endif
