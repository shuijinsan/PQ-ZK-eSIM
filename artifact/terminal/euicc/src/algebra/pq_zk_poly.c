/*
 * pqzk_poly.c — v5.2
 * Polynomial arithmetic in R_q = Z_q[X]/(X^N+1)
 */

#include "pqzk_internal.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

/* ================================================================
 * poly_mul_scalar_coeff: single poly x sparse challenge coefficient
 * result += coeff_val * (a * X^pos) mod (X^N+1, q)
 * ================================================================ */
static void poly_mul_scalar_coeff(const int32_t *a, int pos, int coeff_val,
                                   int32_t *result)
{
    for (int j = 0; j < PQ_ZK_N; j++) {
        int src = j - pos;
        int32_t contrib;
        if (src >= 0) {
            contrib = (int32_t)coeff_val * a[src];
        } else {
            contrib = -(int32_t)coeff_val * a[src + PQ_ZK_N];
        }
        int32_t r = (int32_t)result[j] + contrib;
        r %= PQ_ZK_Q_VAL;
        if (r < 0) r += PQ_ZK_Q_VAL;
        result[j] = (int32_t)r;
    }
}

/* ================================================================
 * SampleInBall_kappa: deterministic sparse challenge generation
 * kappa=35, coefficients in {-1,0,1}
 * ================================================================ */
void pqzk_sample_in_ball(const uint8_t hash[32], poly_t *c)
{
    /*
     * FIPS-204 / ML-DSA-style SampleInBall with the protocol-specific
     * weight kappa=35.  SHAKE256 is treated as an XOF stream: the first
     * 64 bits provide signs and subsequent bytes select positions using
     * rejection sampling exactly as in the reference poly_challenge path.
     */
    size_t cap = 512;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) {
        memset(c->coeffs, 0, sizeof(c->coeffs));
        return;
    }
    if (pqzk_shake256(hash, 32, buf, cap) != 0) {
        memset(c->coeffs, 0, sizeof(c->coeffs));
        free(buf);
        return;
    }

    memset(c->coeffs, 0, sizeof(c->coeffs));
    uint64_t signs = read_le64(buf);
    size_t pos = 8;

    for (int i = PQ_ZK_N - PQ_ZK_CHALLENGE_WEIGHT; i < PQ_ZK_N; i++) {
        uint8_t b;
        do {
            if (pos >= cap) {
                size_t new_cap = cap * 2;
                uint8_t *new_buf = (uint8_t *)realloc(buf, new_cap);
                if (!new_buf) {
                    secure_zero(buf, cap);
                    free(buf);
                    memset(c->coeffs, 0, sizeof(c->coeffs));
                    return;
                }
                buf = new_buf;
                if (pqzk_shake256(hash, 32, buf, new_cap) != 0) {
                    secure_zero(buf, new_cap);
                    free(buf);
                    memset(c->coeffs, 0, sizeof(c->coeffs));
                    return;
                }
                cap = new_cap;
            }
            b = buf[pos++];
        } while (b > (uint8_t)i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1u);
        signs >>= 1;
    }

    secure_zero(buf, cap);
    free(buf);
}

/* ================================================================
 * approx_normal: Box-Muller helper for discrete Gaussian
 * ================================================================ */
static double approx_normal(uint64_t r1, uint64_t r2)
{
    double u1 = (double)(r1 & 0x001FFFFF) / (double)0x00200000 + 1e-10;
    double u2 = (double)(r2 & 0x001FFFFF) / (double)0x00200000;
    double mag = -2.0 * log(u1);
    if (mag < 0) mag = -mag;
    return sqrt(mag) * cos(6.283185307 * u2);
}

/* ================================================================
 * SampleGauss_sigma: Gaussian sampling for y_pub
 * M=8 polynomials, sigma=5000; verifier applies beta_inf=35700
 * NOTE: Box-Muller continuous Gaussian + rounding is an approximation
 *       of a discrete Gaussian sampler (not a rigorous CDT/Knuth-Yao
 *       sampler). This is consistent with the paper, whose finite
 *       flooding calculations are stated as illustrative rather than
 *       instantiating the asymptotic negligible-distance condition.
 * ================================================================ */
void pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,
                             poly_vec_t *out)
{
    size_t needed = (size_t)PQ_ZK_M * PQ_ZK_N * 16;
    uint8_t *buf = (uint8_t *)malloc(needed);
    if (!buf) return;

    pqzk_shake256(seed, seed_len, buf, needed);

    int total = PQ_ZK_M * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        uint64_t r1, r2;
        memcpy(&r1, buf + i * 16,     8);
        memcpy(&r2, buf + i * 16 + 8, 8);

        double g = approx_normal(r1, r2) * PQ_ZK_SIGMA_PUB;
        int32_t v = (int32_t)round(g);

        v = v % PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        out->coeffs[i] = (int32_t)v;
    }

    secure_zero(buf, needed);
    free(buf);
}

/* ================================================================
 * Parse_R_q^m: PRF stream -> uniform poly vector (M_mask).
 * Parse 23-bit blocks (ceil(log2 q)=23) and rejection-sample v<q.
 * Callers provide 128 spare candidates; exhaustion is fail-closed to zero.
 * ================================================================ */
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,
                          poly_vec_t *out)
{
    size_t pos = 0;
    int total = PQ_ZK_M * PQ_ZK_N;
    int filled = 0;
    while (filled < total) {
        if (pos + 3 > stream_len) {
            memset(&out->coeffs[filled], 0,
                   (size_t)(total - filled) * sizeof(out->coeffs[0]));
            return;
        }
        uint32_t v = ((uint32_t)stream[pos]
                    | ((uint32_t)stream[pos + 1] << 8)
                    | ((uint32_t)stream[pos + 2] << 16)) & 0x7FFFFFu;
        pos += 3;
        if (v >= PQ_ZK_Q_VAL) continue;
        out->coeffs[filled++] = (int32_t)v;
    }
}
/* ================================================================
 * gen_matrix_A: systematic public matrix A=[Abar|I_k].
 * Abar is k x (m-k), expanded uniformly with 23-bit rejection sampling.
 * ================================================================ */
static void sample_uniform_matrix_poly(const uint8_t seed[32], int row, int col,
                                       int32_t out[PQ_ZK_N])
{
    /* Seed-expand one matrix polynomial with SHAKE128, then apply the
     * same 23-bit rejection rule used for q=8380417. */
    uint8_t domain[34];
    size_t cap = 1024;
    uint8_t *buf = (uint8_t *)malloc(cap);
    int filled = 0;
    size_t pos = 0;

    memcpy(domain, seed, 32);
    domain[32] = (uint8_t)row;
    domain[33] = (uint8_t)col;
    if (!buf || pqzk_shake128(domain, sizeof(domain), buf, cap) != 0) {
        if (buf) free(buf);
        memset(out, 0, (size_t)PQ_ZK_N * sizeof(out[0]));
        return;
    }

    while (filled < PQ_ZK_N) {
        if (pos + 3 > cap) {
            size_t new_cap = cap * 2;
            uint8_t *new_buf = (uint8_t *)realloc(buf, new_cap);
            if (!new_buf) {
                secure_zero(buf, cap);
                free(buf);
                memset(out, 0, (size_t)PQ_ZK_N * sizeof(out[0]));
                return;
            }
            buf = new_buf;
            if (pqzk_shake128(domain, sizeof(domain), buf, new_cap) != 0) {
                secure_zero(buf, new_cap);
                free(buf);
                memset(out, 0, (size_t)PQ_ZK_N * sizeof(out[0]));
                return;
            }
            cap = new_cap;
        }
        uint32_t v = ((uint32_t)buf[pos]
                    | ((uint32_t)buf[pos + 1] << 8)
                    | ((uint32_t)buf[pos + 2] << 16)) & 0x7FFFFFu;
        pos += 3;
        if (v >= PQ_ZK_Q_VAL) continue;
        out[filled++] = (int32_t)v;
    }

    secure_zero(domain, sizeof(domain));
    secure_zero(buf, cap);
    free(buf);
}

void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows,
                        int k_rows, int m_cols)
{
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        memset(A_rows[i].coeffs, 0, sizeof(A_rows[i].coeffs));
        for (int j = 0; j < r; j++)
            sample_uniform_matrix_poly(seed, i, j,
                                       &A_rows[i].coeffs[j * PQ_ZK_N]);
        /* Identity polynomial in column r+i: constant coefficient 1. */
        A_rows[i].coeffs[(r + i) * PQ_ZK_N] = 1;
    }
}
/* ================================================================
 * mat_vec_mul: result=[Abar|I_k]v, schoolbook/ternary-friendly path.
 * Only the first r=m-k columns need polynomial convolution.
 * ================================================================ */
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v,
                       poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        int32_t *r_i = &result->coeffs[i * PQ_ZK_N];
        for (int j = 0; j < r; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            for (int p = 0; p < PQ_ZK_N; p++) {
                if (v_j[p] == 0) continue;
                for (int qq = 0; qq < PQ_ZK_N; qq++) {
                    int dst = p + qq;
                    int64_t contrib = (int64_t)a_ij[qq] * (int64_t)v_j[p];
                    int idx = (dst >= PQ_ZK_N) ? dst - PQ_ZK_N : dst;
                    int64_t cur = (int64_t)r_i[idx] +
                                  ((dst >= PQ_ZK_N) ? -contrib : contrib);
                    cur %= PQ_ZK_Q_VAL;
                    if (cur < 0) cur += PQ_ZK_Q_VAL;
                    r_i[idx] = (int32_t)cur;
                }
            }
        }
        /* Identity block contributes v_{r+i} coefficient-wise. */
        const int32_t *v_id = &v->coeffs[(r + i) * PQ_ZK_N];
        for (int t = 0; t < PQ_ZK_N; t++) {
            int64_t cur = (int64_t)r_i[t] + v_id[t];
            cur %= PQ_ZK_Q_VAL;
            if (cur < 0) cur += PQ_ZK_Q_VAL;
            r_i[t] = (int32_t)cur;
        }
    }
}
/* ================================================================
 * vec_scalar_mul: result = S * c mod q
 * S: vec_dim polynomials, c: scalar (sparse ternary challenge)
 * eUICC: O(kappa * vec_dim * N) additions, no multiplier
 * ================================================================ */
void pqzk_vec_scalar_mul(const poly_vec_t *S, const poly_t *c,
                          poly_vec_t *result, int vec_dim)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));

    for (int pos = 0; pos < PQ_ZK_N; pos++) {
        int coeff = c->coeffs[pos];
        if (coeff == 0) continue;

        for (int k = 0; k < vec_dim; k++) {
            const int32_t *s_k = &S->coeffs[k * PQ_ZK_N];
            int32_t       *r_k = &result->coeffs[k * PQ_ZK_N];
            poly_mul_scalar_coeff(s_k, pos, coeff, r_k);
        }
    }
}

/* ================================================================
 * vec_add / vec_sub: dimension-parameterized vector ops
 * ================================================================ */
void pqzk_vec_add(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result, int vec_dim)
{
    int total = vec_dim * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        int32_t v = (int32_t)a->coeffs[i] + (int32_t)b->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        result->coeffs[i] = (int32_t)v;
    }
}

void pqzk_vec_sub(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result, int vec_dim)
{
    int total = vec_dim * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        int32_t v = (int32_t)a->coeffs[i] - (int32_t)b->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        result->coeffs[i] = (int32_t)v;
    }
}

/* ================================================================
 * NTT (Number Theoretic Transform) for R_q = Z_q[X]/(X^256+1)
 * q = 8380417 (2^23 - 2^13 + 1), N = 256  -- Dilithium ring
 * psi   = 1921994  (primitive 512-th root, psi^256 = -1)
 * omega = 6644104  (= psi^2, primitive 256-th root)
 * ninv  = 8347681  (= N^{-1} mod q)
 * Negacyclic multiply via twist + cyclic-NTT + untwist.
 * ================================================================ */

#define PQZK_NTT_PSI    1921994
#define PQZK_NTT_OMEGA  6644104
#define PQZK_NTT_NINV   8347681

static int32_t ntt_mod(int64_t x) {
    x %= PQ_ZK_Q_VAL;
    if (x < 0) x += PQ_ZK_Q_VAL;
    return (int32_t)x;
}

static int32_t ntt_modpow(int32_t base, int32_t exp) {
    int64_t r = 1, b = base;
    while (exp > 0) {
        if (exp & 1) r = r * b % PQ_ZK_Q_VAL;
        b = b * b % PQ_ZK_Q_VAL;
        exp >>= 1;
    }
    return (int32_t)r;
}

static int32_t psi_pow[PQ_ZK_N];
static int32_t psi_inv_pow[PQ_ZK_N];
static int32_t omega_inv;
static int ntt_ready = 0;

static void ntt_init(void) {
    if (ntt_ready) return;
    psi_pow[0] = 1;
    for (int i = 1; i < PQ_ZK_N; i++)
        psi_pow[i] = (int32_t)((int64_t)psi_pow[i - 1] * PQZK_NTT_PSI % PQ_ZK_Q_VAL);
    psi_inv_pow[0] = 1;
    for (int i = 1; i < PQ_ZK_N; i++)
        psi_inv_pow[i] = ntt_mod(-(int64_t)psi_pow[PQ_ZK_N - i]);
    omega_inv = ntt_modpow(PQZK_NTT_OMEGA, PQ_ZK_Q_VAL - 2);
    ntt_ready = 1;
}

static void ntt_core(int32_t *a, int32_t root) {
    int j = 0;
    for (int i = 1; i < PQ_ZK_N; i++) {
        int bit = PQ_ZK_N >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j ^= bit;
        if (i < j) { int32_t t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (int len = 2; len <= PQ_ZK_N; len <<= 1) {
        int32_t wlen = ntt_modpow(root, PQ_ZK_N / len);
        for (int i = 0; i < PQ_ZK_N; i += len) {
            int32_t w = 1;
            for (int jj = 0; jj < len / 2; jj++) {
                int32_t u = a[i + jj];
                int32_t v = (int32_t)((int64_t)a[i + jj + len / 2] * w % PQ_ZK_Q_VAL);
                a[i + jj] = ntt_mod((int64_t)u + v);
                a[i + jj + len / 2] = ntt_mod((int64_t)u - v);
                w = (int32_t)((int64_t)w * wlen % PQ_ZK_Q_VAL);
            }
        }
    }
}

/* negacyclic product c = a*b mod (X^N+1) */
static void ntt_poly_mul(const int32_t *a, const int32_t *b, int32_t *c) {
    ntt_init();
    int32_t at[PQ_ZK_N], bt[PQ_ZK_N];
    for (int i = 0; i < PQ_ZK_N; i++) {
        at[i] = (int32_t)((int64_t)a[i] * psi_pow[i] % PQ_ZK_Q_VAL);
        bt[i] = (int32_t)((int64_t)b[i] * psi_pow[i] % PQ_ZK_Q_VAL);
    }
    ntt_core(at, PQZK_NTT_OMEGA);
    ntt_core(bt, PQZK_NTT_OMEGA);
    for (int i = 0; i < PQ_ZK_N; i++)
        at[i] = (int32_t)((int64_t)at[i] * bt[i] % PQ_ZK_Q_VAL);
    ntt_core(at, omega_inv);
    for (int i = 0; i < PQ_ZK_N; i++)
        at[i] = (int32_t)((int64_t)at[i] * PQZK_NTT_NINV % PQ_ZK_Q_VAL);
    for (int i = 0; i < PQ_ZK_N; i++)
        c[i] = (int32_t)((int64_t)at[i] * psi_inv_pow[i] % PQ_ZK_Q_VAL);
}

/* matrix-vector multiply result=[Abar|I_k]v using NTT on Abar only */
void pqzk_mat_vec_mul_ntt(const poly_vec_t *A_rows, const poly_vec_t *v,
                           poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));
    const int r = m_cols - k_rows;
    for (int i = 0; i < k_rows; i++) {
        int32_t *r_i = &result->coeffs[i * PQ_ZK_N];
        for (int j = 0; j < r; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            int32_t prod[PQ_ZK_N];
            ntt_poly_mul(a_ij, v_j, prod);
            for (int t = 0; t < PQ_ZK_N; t++)
                r_i[t] = ntt_mod((int64_t)r_i[t] + prod[t]);
        }
        const int32_t *v_id = &v->coeffs[(r + i) * PQ_ZK_N];
        for (int t = 0; t < PQ_ZK_N; t++)
            r_i[t] = ntt_mod((int64_t)r_i[t] + v_id[t]);
    }
}
