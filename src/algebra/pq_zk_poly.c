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
 * kappa=25, coefficients in {-1,0,1}
 * ================================================================ */
void pqzk_sample_in_ball(const uint8_t hash[32], poly_t *c)
{
    uint8_t buf[PQ_ZK_N * 3];
    pqzk_shake256(hash, 32, buf, sizeof(buf));
    memset(c->coeffs, 0, sizeof(c->coeffs));

    int32_t perm[PQ_ZK_N];
    for (int i = 0; i < PQ_ZK_N; i++) perm[i] = (int32_t)i;

    size_t pos_off  = 0;
    size_t sign_off = (size_t)(2 * PQ_ZK_N);

    for (int i = PQ_ZK_N - 1; i >= PQ_ZK_N - PQ_ZK_CHALLENGE_WEIGHT; i--) {
        uint32_t rv;
        uint32_t threshold = (uint32_t)(0x10000 / (uint32_t)(i + 1))
                             * (uint32_t)(i + 1);
        do {
            if (pos_off + 1 >= sizeof(buf)) pos_off = 0;
            rv = (uint32_t)buf[pos_off]
               | ((uint32_t)buf[pos_off + 1] << 8);
            pos_off += 2;
        } while (rv >= threshold);

        int j = (int)(rv % (uint32_t)(i + 1));
        int32_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;

        if (sign_off >= sizeof(buf)) sign_off = PQ_ZK_N;
        int32_t sign = (buf[sign_off] & 0x01) ? 1 : -1;
        sign_off++;
        c->coeffs[perm[i]] = sign;
    }
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
 * SampleGauss_sigma: discrete Gaussian sampling for y_pub
 * M=8 polynomials, sigma=2800, truncation at beta_inf=20000
 * ================================================================ */
void pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,
                             poly_vec_t *out)
{
    size_t needed = (size_t)PQ_ZK_M * PQ_ZK_N * 16;
    uint8_t *buf = (uint8_t *)malloc(needed);
    if (!buf) return;

    pqzk_shake256(seed, seed_len, buf, needed);

    int total = PQ_ZK_M * PQ_ZK_N;
    double tau_bound = (double)PQ_ZK_BETA_INF;

    for (int i = 0; i < total; i++) {
        uint64_t r1, r2;
        memcpy(&r1, buf + i * 16,     8);
        memcpy(&r2, buf + i * 16 + 8, 8);

        double g = approx_normal(r1, r2) * PQ_ZK_SIGMA_PUB;
        int32_t v = (int32_t)round(g);
        if (v >  (int32_t)tau_bound) v =  (int32_t)tau_bound;
        if (v < -(int32_t)tau_bound) v = -(int32_t)tau_bound;

        v = v % PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        out->coeffs[i] = (int32_t)v;
    }

    secure_zero(buf, needed);
    free(buf);
}

/* ================================================================
 * Parse_R_q^m: PRF stream -> uniform poly vector (M_mask)
 * M=8 polynomials, 24-bit packing (q=8.38M < 2^24)
 * ================================================================ */
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,
                          poly_vec_t *out)
{
    size_t pos = 0;
    int total = PQ_ZK_M * PQ_ZK_N;

    for (int i = 0; i < total; i++) {
        uint32_t v;
        do {
            if (pos + 3 >= stream_len) pos = 0;
            v = (uint32_t)stream[pos]
              | ((uint32_t)stream[pos + 1] << 8)
              | ((uint32_t)stream[pos + 2] << 16);
            pos += 3;
        } while (v >= PQ_ZK_Q_VAL);

        out->coeffs[i] = (int32_t)((int32_t)v);
    }
}

/* ================================================================
 * gen_matrix_A: K x M rectangular matrix (6 x 8)
 * A_rows[i].coeffs[j*N .. j*N+N-1] = A[i][j]
 * i=0..K-1, j=0..M-1
 * ================================================================ */
void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows,
                        int k_rows, int m_cols)
{
    for (int i = 0; i < k_rows; i++) {
        for (int j = 0; j < m_cols; j++) {
            uint8_t domain[34];
            memcpy(domain, seed, 32);
            domain[32] = (uint8_t)i;
            domain[33] = (uint8_t)j;

            uint8_t buf[PQ_ZK_N * 3];
            pqzk_shake256(domain, 34, buf, sizeof(buf));

            size_t pos = 0;
            for (int k = 0; k < PQ_ZK_N; k++) {
                uint32_t v;
                do {
                    if (pos + 3 >= sizeof(buf)) pos = 0;
                    v = (uint32_t)buf[pos]
                      | ((uint32_t)buf[pos + 1] << 8)
                      | ((uint32_t)buf[pos + 2] << 16);
                    pos += 3;
                } while (v >= PQ_ZK_Q_VAL);

                A_rows[i].coeffs[j * PQ_ZK_N + k] = (int32_t)((int32_t)v);
            }
        }
    }
}

/* ================================================================
 * mat_vec_mul: result = A * v mod q
 * A: KxM, v: M-dim, result: K-dim (first K*N positions)
 * ================================================================ */
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v,
                       poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));

    for (int i = 0; i < k_rows; i++) {
        for (int j = 0; j < m_cols; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            int32_t       *r_i  = &result->coeffs[i * PQ_ZK_N];

            for (int p = 0; p < PQ_ZK_N; p++) {
                if (v_j[p] == 0) continue;
                for (int q = 0; q < PQ_ZK_N; q++) {
                    int dst = p + q;
                    int64_t contrib = (int64_t)a_ij[q] * (int64_t)v_j[p];
                    if (dst >= PQ_ZK_N) {
                        int64_t cur = (int64_t)r_i[dst - PQ_ZK_N] - contrib;
                        cur %= PQ_ZK_Q_VAL;
                        if (cur < 0) cur += PQ_ZK_Q_VAL;
                        r_i[dst - PQ_ZK_N] = (int32_t)(cur % PQ_ZK_Q_VAL);
                    } else {
                        int64_t cur = (int64_t)r_i[dst] + contrib;
                        cur %= PQ_ZK_Q_VAL;
                        if (cur < 0) cur += PQ_ZK_Q_VAL;
                        r_i[dst] = (int32_t)(cur % PQ_ZK_Q_VAL);
                    }
                }
            }
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

/* matrix-vector multiply result = A * v using NTT (dense inputs) */
void pqzk_mat_vec_mul_ntt(const poly_vec_t *A_rows, const poly_vec_t *v,
                           poly_vec_t *result, int k_rows, int m_cols)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));
    for (int i = 0; i < k_rows; i++) {
        for (int j = 0; j < m_cols; j++) {
            const int32_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int32_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            int32_t       *r_i  = &result->coeffs[i * PQ_ZK_N];
            int32_t prod[PQ_ZK_N];
            ntt_poly_mul(a_ij, v_j, prod);
            for (int k = 0; k < PQ_ZK_N; k++)
                r_i[k] = ntt_mod((int64_t)r_i[k] + prod[k]);
        }
    }
}
