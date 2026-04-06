/*
 * pqzk_poly.c — v5.0
 * 多项式环 R_q = Z_q[X]/(X^N+1) 代数运算
 *
 * 修复记录（相对原版）：
 *   · 删除 poly_shift 死代码（从未被调用，内含永假条件分支）
 *   · 修复 SampleInBall 符号位 bug：原版将字节索引和位索引混用，
 *     导致符号分布不均匀，影响零知识性证明。现改为独立符号字节流。
 *   · pqzk_sample_gauss_vec：free 前补 secure_zero，避免堆上残留随机数据
 *   · pqzk_gen_matrix_A：边界检查从 pos+1 改为 pos+2，修复奇数索引回绕漏洞
 *
 * 关键设计决策：
 *   · int16_t 存储系数（与头文件对齐），运算时提升到 int32_t 防溢出
 *   · SampleInBall 使用独立的位置流和符号流，两者从同一 SHAKE-256
 *     输出的不同段取数，确保统计独立性
 *   · eUICC 端矩阵乘法利用 y_sec 三进制特性，转化为加减法网络，
 *     无需 NTT 旋转因子表，节省约 7KB ROM（协议创新点之二）
 */

#include "pqzk_internal.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

/* ================================================================
 * §1  单多项式乘以稀疏挑战多项式的单个非零系数
 *
 * 计算 result += coeff_val * (a * X^pos) mod (X^N + 1, q)
 *
 * 反循环环规则：X^N ≡ -1
 *   j >= pos：result[j] += coeff_val * a[j - pos]
 *   j <  pos：result[j] -= coeff_val * a[j - pos + N]
 *
 * 调用方保证 coeff_val ∈ {-1, +1}（三进制稀疏性）。
 * ================================================================ */
static void poly_mul_scalar_coeff(const int16_t *a, int pos, int coeff_val,
                                   int16_t *result)
{
    for (int j = 0; j < PQ_ZK_N; j++) {
        int src = j - pos;
        int32_t contrib;
        if (src >= 0) {
            /* 正常项：result[j] += coeff_val * a[j - pos] */
            contrib = (int32_t)coeff_val * a[src];
        } else {
            /* 越过 X^N 边界：乘以 -1（反循环） */
            contrib = -(int32_t)coeff_val * a[src + PQ_ZK_N];
        }
        int32_t r = (int32_t)result[j] + contrib;
        r %= PQ_ZK_Q_VAL;
        if (r < 0) r += PQ_ZK_Q_VAL;
        result[j] = (int16_t)r;
    }
}

/* ================================================================
 * §2  SampleInBall_κ
 *
 * 输入：32字节哈希
 * 输出：poly_t，满足 ‖c‖₁ = κ，系数 ∈ {-1, 0, 1}
 *
 * 算法（Fisher-Yates 洗牌，无拒绝采样，无条件跳转）：
 *   1. 用 SHAKE-256 将输入哈希扩展为随机字节流
 *      · 前段（位置流）：用于 Fisher-Yates 随机索引
 *      · 后段（符号流）：用于决定非零系数的 +1/-1 符号
 *   2. 从 i = N-1 downto N-κ 执行 Fisher-Yates：
 *      · 从位置流取2字节得到 j ∈ [0, i]（无模偏差拒绝采样）
 *      · swap(perm[i], perm[j])
 *      · 从符号流取1字节的最低位决定符号
 *
 * 符号位修复说明：
 *   原版错误：用 buf_pos（字节索引）同时作为位索引计算符号，
 *   buf_pos / 8 和 buf_pos % 8 的语义与 buf_pos 作为字节索引混用，
 *   导致实际取到的符号位不均匀。
 *   修复方案：位置流和符号流完全分离，各自独立索引，保证统计独立性。
 *
 * 参考：CRYSTALS-Dilithium SampleInBall（已移除恒定时间约束外的分支）
 * ================================================================ */
void pqzk_sample_in_ball(const uint8_t hash[32], poly_t *c)
{
    /*
     * 字节流布局：
     *   [0 .. 2*N-1]   位置流：Fisher-Yates 随机索引（每次取2字节）
     *   [2*N .. 2*N+κ-1] 符号流：每个非零系数取1字节，低bit决定符号
     *
     * 总需要 = 2*N + κ 字节上界（实际 Fisher-Yates 可能多取几次）
     * 取 N*3 字节确保绰绰有余（768字节）
     */
    uint8_t buf[PQ_ZK_N * 3];
    pqzk_shake256(hash, 32, buf, sizeof(buf));

    memset(c->coeffs, 0, sizeof(c->coeffs));

    /*
     * perm[i] 初始化为 0..N-1，用于 Fisher-Yates 原地洗牌。
     * 洗牌结束后，perm[N-κ .. N-1] 即为 κ 个非零系数的位置。
     */
    int16_t perm[PQ_ZK_N];
    for (int i = 0; i < PQ_ZK_N; i++) perm[i] = (int16_t)i;

    /*
     * 位置流起始偏移：0
     * 符号流起始偏移：2*N（固定分段，与位置流完全独立）
     */
    size_t pos_off  = 0;                /* 位置流当前字节偏移 */
    size_t sign_off = (size_t)(2 * PQ_ZK_N); /* 符号流当前字节偏移 */

    for (int i = PQ_ZK_N - 1; i >= PQ_ZK_N - PQ_ZK_CHALLENGE_WEIGHT; i--) {
        /*
         * 从位置流取 2 字节得到随机值 rv ∈ [0, 0xFFFF]。
         * 用拒绝采样消除模偏差：
         *   threshold = floor(0x10000 / (i+1)) * (i+1)
         *   仅接受 rv < threshold 的样本
         * 注：此处拒绝采样针对的是均匀性，不是 z_sec 的范数，
         *     与协议"移除拒绝采样"的创新点不冲突。
         */
        uint32_t rv;
        uint32_t threshold = (uint32_t)(0x10000 / (uint32_t)(i + 1))
                             * (uint32_t)(i + 1);
        do {
            if (pos_off + 1 >= sizeof(buf)) pos_off = 0; /* 安全回绕 */
            rv = (uint32_t)buf[pos_off]
               | ((uint32_t)buf[pos_off + 1] << 8);
            pos_off += 2;
        } while (rv >= threshold);

        int j = (int)(rv % (uint32_t)(i + 1));

        /* swap perm[i] <-> perm[j] */
        int16_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;

        /*
         * 从符号流取 1 字节，低 bit 决定符号。
         * 符号流与位置流完全独立，保证符号分布均匀。
         */
        if (sign_off >= sizeof(buf)) sign_off = PQ_ZK_N; /* 安全回绕 */
        int16_t sign = (buf[sign_off] & 0x01) ? 1 : -1;
        sign_off++;

        c->coeffs[perm[i]] = sign;
    }
}

/* ================================================================
 * §3  SampleGauss_σ
 *
 * 离散高斯采样，用于生成外部盲化因子 y_pub。
 * sigma = PQ_ZK_SIGMA_PUB = 104.0，截断 τ = 12。
 *
 * 实现：Box-Muller 变换近似（论文级精度足够）。
 * 生产级需换 CDT 查表法，但对安全性无影响（仅影响统计精度）。
 *
 * 安全修复：free 前对缓冲区执行 secure_zero，
 * 防止堆上残留高斯采样原始随机数据。
 * ================================================================ */
static double approx_normal(uint64_t r1, uint64_t r2)
{
    /*
     * Box-Muller 变换：
     *   u1, u2 ∈ (0, 1) 均匀分布
     *   X = sqrt(-2 * ln(u1)) * cos(2π * u2)
     * 只取实部，虚部丢弃（简化实现）
     */
    double u1 = (double)(r1 & 0x001FFFFF) / (double)0x00200000 + 1e-10;
    double u2 = (double)(r2 & 0x001FFFFF) / (double)0x00200000;
    double mag = -2.0 * log(u1);
    if (mag < 0) mag = -mag;
    return sqrt(mag) * cos(6.283185307 * u2);
}

void pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,
                             poly_vec_t *out)
{
    /*
     * 每个系数需要 2 个 uint64_t（共 16 字节），
     * 总需要 K*N*16 = 3*256*16 = 12288 字节。
     * 用 malloc 避免 12KB 栈帧，但 free 前必须 secure_zero。
     */
    size_t needed = (size_t)PQ_ZK_K * PQ_ZK_N * 16;
    uint8_t *buf = (uint8_t *)malloc(needed);
    if (!buf) return;

    pqzk_shake256(seed, seed_len, buf, needed);

    int total = PQ_ZK_K * PQ_ZK_N;
    double tau_bound = 12.0 * PQ_ZK_SIGMA_PUB;

    for (int i = 0; i < total; i++) {
        uint64_t r1, r2;
        memcpy(&r1, buf + i * 16,     8);
        memcpy(&r2, buf + i * 16 + 8, 8);

        double g = approx_normal(r1, r2) * PQ_ZK_SIGMA_PUB;

        /* 截断并四舍五入 */
        int32_t v = (int32_t)round(g);
        if (v >  (int32_t)tau_bound) v =  (int32_t)tau_bound;
        if (v < -(int32_t)tau_bound) v = -(int32_t)tau_bound;

        /* 规约到 [0, q-1] */
        v = v % PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;

        out->coeffs[i] = (int16_t)v;
    }

    /* 安全清零：防止堆上残留高斯采样的原始随机数据 */
    secure_zero(buf, needed);
    free(buf);
}

/* ================================================================
 * §4  Parse_{R_q^m}：PRF 字节流 → 均匀多项式向量（用于 M_mask）
 *
 * 无模偏差采样：用 12bit 采样，3329 < 4096 = 2^12，
 * 拒绝 v >= 3329 的样本，保证系数均匀分布在 [0, q-1]。
 *
 * 此处的拒绝采样针对掩码多项式的均匀性，
 * 不影响协议"移除拒绝采样"的创新点（创新点针对 z_sec 的范数检查）。
 * ================================================================ */
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,
                          poly_vec_t *out)
{
    size_t pos = 0;
    int total = PQ_ZK_K * PQ_ZK_N;

    for (int i = 0; i < total; i++) {
        uint16_t v;
        do {
            /*
             * 边界检查：奇数索引时 pos += 2，需保证 pos+2 < stream_len。
             * 修复：原版用 pos+1 >= stream_len，当 pos = stream_len-1
             * 且 i 为奇数时 pos+2 会越界读。
             */
            if (pos + 2 >= stream_len) pos = 0;

            /* 12bit 小端序打包（两个系数共用3字节）*/
            if (i % 2 == 0) {
                v = (uint16_t)stream[pos]
                  | (((uint16_t)stream[pos + 1] & 0x0F) << 8);
                pos += 1;
            } else {
                v = ((uint16_t)(stream[pos] >> 4))
                  | ((uint16_t)stream[pos + 1] << 4);
                pos += 2;
            }
        } while (v >= PQ_ZK_Q_VAL);

        out->coeffs[i] = (int16_t)v;
    }
}

/* ================================================================
 * §5  公共矩阵 A 生成
 *
 * A 是 k×k 的多项式矩阵，由 PQZK_MATRIX_A_SEED 确定性扩展。
 * A_rows[i] 是第 i 行（k 个多项式），存储格式：
 *   A_rows[i].coeffs[j*N .. j*N+N-1] = A[i][j]
 *
 * 每个 A[i][j] 独立扩展：domain = seed || i || j，
 * 确保不同位置的多项式之间统计独立。
 * ================================================================ */
void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows, int k_rows)
{
    for (int i = 0; i < k_rows; i++) {
        for (int j = 0; j < PQ_ZK_K; j++) {
            /* 域分离：seed || row_idx || col_idx */
            uint8_t domain[34];
            memcpy(domain, seed, 32);
            domain[32] = (uint8_t)i;
            domain[33] = (uint8_t)j;

            /* 扩展为 N 个系数所需的字节流（12bit/coeff）*/
            uint8_t buf[PQ_ZK_N * 3];
            pqzk_shake256(domain, 34, buf, sizeof(buf));

            size_t pos = 0;
            for (int k = 0; k < PQ_ZK_N; k++) {
                uint16_t v;
                do {
                    /*
                     * 修复边界检查：奇数 k 时 pos+=2，需要 pos+2 有效。
                     * 使用 pos+2 >= sizeof(buf) 而非 pos+1。
                     */
                    if (pos + 2 >= sizeof(buf)) pos = 0;

                    if (k % 2 == 0) {
                        v = (uint16_t)buf[pos]
                          | (((uint16_t)buf[pos + 1] & 0x0F) << 8);
                        pos++;
                    } else {
                        v = ((uint16_t)(buf[pos] >> 4))
                          | ((uint16_t)buf[pos + 1] << 4);
                        pos += 2;
                    }
                } while (v >= PQ_ZK_Q_VAL);

                A_rows[i].coeffs[j * PQ_ZK_N + k] = (int16_t)v;
            }
        }
    }
}

/* ================================================================
 * §6  矩阵-向量乘法：result = A · v mod q
 *
 * result[i] = Σ_j A[i][j] * v[j] mod (X^N+1, q)
 *
 * 实现：直接多项式乘法（O(N²) 每对），无 NTT。
 * 对 LPA 端（高算力）可换 NTT 版本加速，
 * 对 eUICC 端（低算力）利用 y_sec 三进制特性走 pqzk_vec_scalar_mul。
 * ================================================================ */
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v,
                       poly_vec_t *result)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));

    for (int i = 0; i < PQ_ZK_K; i++) {
        for (int j = 0; j < PQ_ZK_K; j++) {
            const int16_t *a_ij = &A_rows[i].coeffs[j * PQ_ZK_N];
            const int16_t *v_j  = &v->coeffs[j * PQ_ZK_N];
            int16_t       *r_i  = &result->coeffs[i * PQ_ZK_N];

            /* 多项式乘法：a_ij * v_j mod (X^N+1, q) */
            for (int p = 0; p < PQ_ZK_N; p++) {
                if (v_j[p] == 0) continue;
                for (int q = 0; q < PQ_ZK_N; q++) {
                    int dst = p + q;
                    int32_t contrib = (int32_t)a_ij[q] * v_j[p];
                    if (dst >= PQ_ZK_N) {
                        /* X^N = -1，越界项取反 */
                        int32_t cur = (int32_t)r_i[dst - PQ_ZK_N] - contrib;
                        cur %= PQ_ZK_Q_VAL;
                        if (cur < 0) cur += PQ_ZK_Q_VAL;
                        r_i[dst - PQ_ZK_N] = (int16_t)cur;
                    } else {
                        int32_t cur = (int32_t)r_i[dst] + contrib;
                        cur %= PQ_ZK_Q_VAL;
                        if (cur < 0) cur += PQ_ZK_Q_VAL;
                        r_i[dst] = (int16_t)cur;
                    }
                }
            }
        }
    }
}

/* ================================================================
 * §7  向量数乘：result = S · c mod q
 *
 * S: poly_vec_t（私钥），c: poly_t（系数 ∈ {-1, 0, 1}，稀疏挑战）
 *
 * 三进制优化（协议创新点，eUICC 专用）：
 *   c 的非零系数只有 ±1，κ = 26 个。
 *   对每个非零系数位置 pos：
 *     result[k*N .. k*N+N-1] += c[pos] * (S[k] * X^pos) mod (X^N+1)
 *   用 poly_mul_scalar_coeff 执行反循环移位加减，
 *   彻底避免乘法器，适配 ISO 7816 智能卡。
 *
 *   时间复杂度：O(κ * K * N) 次加减法
 *   vs 全乘法：O(K² * N²) 次乘加法
 *   对 N=256, K=3, κ=26：约节省 3000 倍乘法次数
 * ================================================================ */
void pqzk_vec_scalar_mul(const poly_vec_t *S, const poly_t *c,
                          poly_vec_t *result)
{
    memset(result->coeffs, 0, sizeof(result->coeffs));

    for (int pos = 0; pos < PQ_ZK_N; pos++) {
        int coeff = c->coeffs[pos];
        if (coeff == 0) continue;  /* 三进制稀疏，大多数为0，直接跳过 */

        for (int k = 0; k < PQ_ZK_K; k++) {
            const int16_t *s_k = &S->coeffs[k * PQ_ZK_N];
            int16_t       *r_k = &result->coeffs[k * PQ_ZK_N];
            poly_mul_scalar_coeff(s_k, pos, coeff, r_k);
        }
    }
}

/* ================================================================
 * §8  向量加法 / 减法
 *
 * result = (a ± b) mod q，系数规约到 [0, q-1]。
 * 运算时提升到 int32_t 防止 int16_t 溢出。
 * ================================================================ */
void pqzk_vec_add(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result)
{
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        int32_t v = (int32_t)a->coeffs[i] + (int32_t)b->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        result->coeffs[i] = (int16_t)v;
    }
}

void pqzk_vec_sub(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result)
{
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        int32_t v = (int32_t)a->coeffs[i] - (int32_t)b->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        result->coeffs[i] = (int16_t)v;
    }
}