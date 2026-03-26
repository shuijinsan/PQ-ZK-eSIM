/*
 * pq_zk_esim.c
 * PQ-ZK-eSIM 协议全阶段实现
 *
 * 实现顺序对应协议阶段：
 *   序列化工具   → PQC_EncodePolyVec / DecodePolyVec / SerializeContext
 *   阶段零       → PQC_GenKeyPair / PQC_eUICC_Init
 *   阶段一       → PQC_PreCompute / PQC_RegenerateYpub / PQC_eUICC_Commit
 *   阶段二       → PQC_GenChallenge
 *   阶段四       → PQC_ComputeZ_and_Mask  ← 核心黑盒
 *   阶段五       → PQC_LPA_Aggregate
 *   阶段六       → PQC_GenerateMask / PQC_VerifyEngine
 */

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/* nvram 魔数（与 pqzk_nvram.c 对齐） */
#define NVRAM_MAGIC "PQZK"

/* ================================================================
 * 内部辅助：生成三进制 y_sec（系数 ∈ {-1, 0, 1}）
 * 用 SHAKE-256 扩展随机种子，每2bit决定一个系数：
 *   00,01 → 0（大概率为0，保证稀疏性）
 *   10    → +1
 *   11    → -1
 * ================================================================ */

static void sample_ternary(const uint8_t seed[32], poly_vec_t *y_sec)
{
    uint8_t buf[PQ_ZK_K * PQ_ZK_N]; /* 每系数1字节，实际只用低2bit */
    pqzk_shake256(seed, 32, buf, sizeof(buf));

    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        uint8_t b = buf[i] & 0x03;
        if      (b == 2) y_sec->coeffs[i] =  1;
        else if (b == 3) y_sec->coeffs[i] = -1;
        else             y_sec->coeffs[i] =  0;
    }
}

/* ================================================================
 * 序列化工具
 * ================================================================ */

/*
 * PQC_EncodePolyVec
 * int16_t 系数直接按小端序展平为字节流
 * 每个系数 2 字节，总长 PQ_ZK_POLYVEC_BYTES = K*N*2 = 1536
 */
void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes)
{
    if (!in_poly || !out_bytes) return;
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        uint16_t v = (uint16_t)in_poly->coeffs[i];
        out_bytes[i * 2]     = (uint8_t)(v & 0xFF);        /* 低字节 */
        out_bytes[i * 2 + 1] = (uint8_t)((v >> 8) & 0xFF); /* 高字节 */
    }
}

void PQC_DecodePolyVec(const uint8_t *in_bytes, poly_vec_t *out_poly)
{
    if (!in_bytes || !out_poly) return;
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        uint16_t v = (uint16_t)in_bytes[i * 2]
                   | ((uint16_t)in_bytes[i * 2 + 1] << 8);
        out_poly->coeffs[i] = (int16_t)v;
    }
}

/*
 * PQC_EncodePoly / PQC_DecodePoly
 * 单多项式（poly_t），用于 c_agg
 * 每系数 2 字节，总长 PQ_ZK_POLY_BYTES = 512
 */
void PQC_EncodePoly(const poly_t *in_poly, uint8_t *out_bytes)
{
    if (!in_poly || !out_bytes) return;
    for (int i = 0; i < PQ_ZK_N; i++) {
        uint16_t v = (uint16_t)in_poly->coeffs[i];
        out_bytes[i * 2]     = (uint8_t)(v & 0xFF);
        out_bytes[i * 2 + 1] = (uint8_t)((v >> 8) & 0xFF);
    }
}

void PQC_DecodePoly(const uint8_t *in_bytes, poly_t *out_poly)
{
    if (!in_bytes || !out_poly) return;
    for (int i = 0; i < PQ_ZK_N; i++) {
        uint16_t v = (uint16_t)in_bytes[i * 2]
                   | ((uint16_t)in_bytes[i * 2 + 1] << 8);
        out_poly->coeffs[i] = (int16_t)v;
    }
}

/*
 * PQC_SerializeContext
 * 强制小端序逐字段位移序列化
 * 严禁直接对结构体指针哈希
 *
 * 输出格式（固定 PQ_ZK_CONTEXT_BYTES = 80 字节）：
 *   [0:8]   timestamp  uint64_t LE
 *   [8:12]  latitude   int32_t  LE
 *   [12:16] longitude  int32_t  LE
 *   [16:80] desc       64字节 UTF-8 原样拷贝
 */
void PQC_SerializeContext(const ContextData *ctx, uint8_t *ctx_bytes)
{
    if (!ctx || !ctx_bytes) return;
    memset(ctx_bytes, 0, PQ_ZK_CONTEXT_BYTES);

    /* timestamp：uint64_t 小端序 */
    ctx_bytes[0] = (uint8_t)(ctx->timestamp);
    ctx_bytes[1] = (uint8_t)(ctx->timestamp >> 8);
    ctx_bytes[2] = (uint8_t)(ctx->timestamp >> 16);
    ctx_bytes[3] = (uint8_t)(ctx->timestamp >> 24);
    ctx_bytes[4] = (uint8_t)(ctx->timestamp >> 32);
    ctx_bytes[5] = (uint8_t)(ctx->timestamp >> 40);
    ctx_bytes[6] = (uint8_t)(ctx->timestamp >> 48);
    ctx_bytes[7] = (uint8_t)(ctx->timestamp >> 56);

    /* latitude：int32_t 小端序（先转 uint32_t 避免符号位移 UB） */
    uint32_t lat = (uint32_t)ctx->latitude;
    ctx_bytes[8]  = (uint8_t)(lat);
    ctx_bytes[9]  = (uint8_t)(lat >> 8);
    ctx_bytes[10] = (uint8_t)(lat >> 16);
    ctx_bytes[11] = (uint8_t)(lat >> 24);

    /* longitude：int32_t 小端序 */
    uint32_t lon = (uint32_t)ctx->longitude;
    ctx_bytes[12] = (uint8_t)(lon);
    ctx_bytes[13] = (uint8_t)(lon >> 8);
    ctx_bytes[14] = (uint8_t)(lon >> 16);
    ctx_bytes[15] = (uint8_t)(lon >> 24);

    /* desc：直接拷贝64字节 */
    memcpy(ctx_bytes + 16, ctx->desc, 64);
}

/* ================================================================
 * 内部工具：12bit 压缩序列化（用于公钥 T）
 * 每2个系数打包成3字节，小端序
 * K*N=768个系数 → 768*12/8 = 1152 字节
 * 公钥 = 种子(32) + T_12bit(1152) = 1184 = PQ_ZK_PUBLICKEY_BYTES ✓
 * ================================================================ */

/* 768系数 → 1152字节 */
#define PQ_ZK_T_COMPRESSED_BYTES  ((PQ_ZK_K * PQ_ZK_N * 12) / 8)  /* 1152 */

static void encode_polyvec_12bit(const poly_vec_t *in, uint8_t *out)
{
    /* 每次处理2个系数，输出3字节 */
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i += 2) {
        uint16_t a = (uint16_t)((int32_t)in->coeffs[i]   % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
        uint16_t b = (uint16_t)((int32_t)in->coeffs[i+1] % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
        int j = (i / 2) * 3;
        out[j]   = (uint8_t)(a & 0xFF);
        out[j+1] = (uint8_t)(((a >> 8) & 0x0F) | ((b & 0x0F) << 4));
        out[j+2] = (uint8_t)((b >> 4) & 0xFF);
    }
}

static void decode_polyvec_12bit(const uint8_t *in, poly_vec_t *out)
{
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i += 2) {
        int j = (i / 2) * 3;
        uint16_t a = (uint16_t)in[j] | (((uint16_t)in[j+1] & 0x0F) << 8);
        uint16_t b = ((uint16_t)in[j+1] >> 4) | ((uint16_t)in[j+2] << 4);
        out->coeffs[i]   = (int16_t)(a & 0x0FFF);
        out->coeffs[i+1] = (int16_t)(b & 0x0FFF);
    }
}

/* ================================================================
 * 阶段零：密钥生成与初始化
 * ================================================================ */

/*
 * PQC_GenKeyPair
 * pk_t 格式（PQ_ZK_PUBLICKEY_BYTES = 1184字节）：
 *   [0:32]     矩阵 A 的生成种子（32字节）
 *   [32:1184]  T = A·S，12bit 压缩序列化（1152字节）
 *   合计：32 + 1152 = 1184 ✓
 */
void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s)
{
    if (!pk_t || !sk_s) return;

    /* 生成私钥 S（三进制短分布） */
    uint8_t sk_seed[32];
    pqzk_rand_bytes(sk_seed, 32);
    sample_ternary(sk_seed, sk_s);

    /* 公钥头部：矩阵 A 的种子 */
    memcpy(pk_t, PQZK_MATRIX_A_SEED, 32);

    /* 计算 T = A·S mod q */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K);
    poly_vec_t T;
    pqzk_mat_vec_mul(A_rows, sk_s, &T);

    /* T 用 12bit 压缩格式序列化到公钥后 1152 字节 */
    encode_polyvec_12bit(&T, pk_t + 32);

    secure_zero(sk_seed, sizeof(sk_seed));
    secure_zero(A_rows, sizeof(A_rows));
    secure_zero(&T, sizeof(T));
}

/*
 * PQC_eUICC_Init
 * 将所有核心凭证安全写入 nvram_dir
 */
void PQC_eUICC_Init(const char* nvram_dir,
                    const uint8_t* eid, size_t eid_len,
                    const poly_vec_t* sk_s,
                    const uint8_t* k_sym, size_t k_sym_len,
                    uint64_t initial_ctr,
                    const uint8_t* k_tee, size_t k_tee_len)
{
    if (!nvram_dir || !eid || !sk_s || !k_sym || !k_tee) return;
    if (eid_len > NVRAM_EID_LEN || k_sym_len > 32 || k_tee_len > 32) return;

    nvram_state_t state;
    memset(&state, 0, sizeof(state));

    memcpy(state.magic, NVRAM_MAGIC, 4);
    memcpy(state.eid,   eid,   eid_len);
    PQC_EncodePolyVec(sk_s, state.sk_s);   /* 序列化私钥 S */
    memcpy(state.k_sym, k_sym, k_sym_len);
    memcpy(state.k_tee, k_tee, k_tee_len);
    state.ctr_local   = initial_ctr;
    state.y_sec_valid = 0;

    /* d_seed：从 k_sym 派生，或随机生成（此处固定派生保证可重现） */
    pqzk_sha256(k_sym, k_sym_len, state.d_seed);

    nvram_write_atomic(nvram_dir, &state);
}

/* ================================================================
 * 阶段一：承诺生成
 * ================================================================ */

/*
 * PQC_PreCompute（LPA 端）
 * y_pub = SampleGauss(Expand(s_pub))
 * W_pub = A · y_pub mod q
 */
void PQC_PreCompute(poly_vec_t *W_pub, uint8_t seed_y[PQ_ZK_SEED_BYTES])
{
    if (!W_pub || !seed_y) return;

    /* 生成随机种子 s_pub */
    pqzk_rand_bytes(seed_y, PQ_ZK_SEED_BYTES);

    /* y_pub = SampleGauss(SHAKE-256(s_pub)) */
    poly_vec_t y_pub;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, &y_pub);

    /* W_pub = A · y_pub mod q */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K);
    pqzk_mat_vec_mul(A_rows, &y_pub, W_pub);

    secure_zero(&y_pub, sizeof(y_pub));
    secure_zero(A_rows, sizeof(A_rows));
}

/*
 * PQC_RegenerateYpub
 * 从种子确定性重新生成 y_pub（与 PreCompute 中完全一致）
 */
void PQC_RegenerateYpub(const uint8_t seed_y[PQ_ZK_SEED_BYTES], poly_vec_t *y_pub)
{
    if (!seed_y || !y_pub) return;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, y_pub);
}

/*
 * PQC_eUICC_Commit（eUICC 端）
 *
 * 1. 从 nvram 读取 K_sym 和 ctr_local
 * 2. 生成三进制 y_sec，持久化存储（严禁输出）
 * 3. W_sec = A · y_sec mod q
 * 4. MAC_W = HMAC-SHA256(K_sym, encode(W_sec) || ctr_le8)
 */
void PQC_eUICC_Commit(const char* nvram_dir, poly_vec_t *W_sec,
                      uint8_t MAC_W[PQ_ZK_MAC_BYTES])
{
    if (!nvram_dir || !W_sec || !MAC_W) return;

    /* 读取 nvram 状态 */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) return;

    /* 生成 y_sec（三进制随机） */
    uint8_t ysec_seed[32];
    pqzk_rand_bytes(ysec_seed, 32);
    poly_vec_t y_sec;
    sample_ternary(ysec_seed, &y_sec);
    secure_zero(ysec_seed, 32);

    /* W_sec = A · y_sec mod q */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K);
    pqzk_mat_vec_mul(A_rows, &y_sec, W_sec);
    secure_zero(A_rows, sizeof(A_rows));

    /* MAC_W = HMAC-SHA256(K_sym, encode(W_sec) || ctr_le8) */
    uint8_t wsec_bytes[PQ_ZK_POLYVEC_BYTES];
    uint8_t ctr_bytes[8];
    PQC_EncodePolyVec(W_sec, wsec_bytes);
    write_le64(ctr_bytes, state.ctr_local);

    pqzk_iov_t iov[] = {
        { wsec_bytes, PQ_ZK_POLYVEC_BYTES },
        { ctr_bytes,  8 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(state.k_sym, iov, MAC_W);

    /* 将 y_sec 持久化存储到 nvram（严禁输出） */
    PQC_EncodePolyVec(&y_sec, state.y_sec);
    state.y_sec_valid = 1;
    nvram_write_atomic(nvram_dir, &state);

    /* 安全清零所有敏感中间变量 */
    secure_zero(&y_sec, sizeof(y_sec));
    secure_zero(wsec_bytes, sizeof(wsec_bytes));
    secure_zero(&state, sizeof(state));
}

/* ================================================================
 * 阶段二：挑战生成
 * ================================================================ */

/*
 * PQC_GenChallenge（LPA 端）
 * c_agg = SampleInBall_κ(SHA256(c_seed || encode(W) || H_ctx))
 */
void PQC_GenChallenge(const poly_vec_t *comm_W,
                      const uint8_t nonce[PQ_ZK_SEED_BYTES],
                      const uint8_t H_ctx[PQ_ZK_SEED_BYTES],
                      poly_t *c_agg)
{
    if (!comm_W || !nonce || !H_ctx || !c_agg) return;

    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W, W_bytes);

    /* hash_input = c_seed || encode(W) || H_ctx */
    pqzk_iov_t iov[] = {
        { nonce,   PQ_ZK_SEED_BYTES    },
        { W_bytes, PQ_ZK_POLYVEC_BYTES },
        { H_ctx,   PQ_ZK_SEED_BYTES    },
        { NULL, 0 }
    };
    uint8_t hash[32];
    pqzk_sha256_iov(iov, hash);

    pqzk_sample_in_ball(hash, c_agg);
}

/* ================================================================
 * 阶段四：掩码协同计算（核心黑盒）
 * ================================================================ */

/*
 * PQC_ComputeZ_and_Mask
 *
 * 七步原子操作（安全禁区：y_sec 和 z_sec 永不离开此函数）：
 *
 *  1. 从 nvram 读取 ctr_local，验证 AuthToken
 *     AuthToken == HMAC(K_TEE, c_agg || ctr_le8 || H_ctx || hash_M2)
 *  2. 验证失败：返回 PQ_ZK_ERR_MAC_FAIL，计数器不变
 *  3. 验证成功：ctr_session = ctr_local，计数器 +1
 *  4. 稀疏性校验：c_agg 系数 ∈ {-1,0,1}，‖c_agg‖₁ = κ
 *  5. z_sec = y_sec + S·c_agg mod q
 *  6. M_mask = Parse(PRF(K_sym, c_seed||ctr_session||H_ctx))
 *  7. z_sec_masked = z_sec + M_mask mod q
 *     + 前向安全：K_sym_new = KDF(K_sym, d_seed, EID)
 *       计数器步进与密钥更新原子绑定（同一 nvram_write_atomic）
 */
PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(const char* nvram_dir,
                                        const poly_t *c_agg,
                                        const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                                        const uint8_t H_ctx[PQ_ZK_SEED_BYTES],
                                        const uint8_t hash_M2[PQ_ZK_MAC_BYTES],
                                        const uint8_t AuthToken[PQ_ZK_MAC_BYTES],
                                        poly_vec_t *z_sec_masked)
{
    if (!nvram_dir || !c_agg || !c_seed || !H_ctx ||
        !hash_M2  || !AuthToken || !z_sec_masked)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* ---- 步骤1：读取 nvram 状态 ---- */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* ---- 步骤1：验证 AuthToken ---- */
    /* AuthToken = HMAC(K_TEE, encode(c_agg) || ctr_le8 || H_ctx || hash_M2) */
    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(c_agg, cagg_bytes);
    uint8_t ctr_bytes[8];
    write_le64(ctr_bytes, state.ctr_local);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8                },
        { H_ctx,      PQ_ZK_SEED_BYTES },
        { hash_M2,    PQ_ZK_MAC_BYTES  },
        { NULL, 0 }
    };
    uint8_t expected_token[32];
    pqzk_hmac_sha256_iov(state.k_tee, auth_iov, expected_token);

    /* 恒定时间比较（防时序侧信道） */
    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected_token[i] ^ AuthToken[i]);

    if (mismatch) {
        /* ---- 步骤2：验证失败，计数器不变 ---- */
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_MAC_FAIL;
    }

    /* ---- 步骤3：锁存 ctr_session，计数器 +1 ---- */
    uint64_t ctr_session = state.ctr_local;

    /* ---- 步骤4：稀疏性校验 ---- */
    int ham_weight = 0;
    for (int i = 0; i < PQ_ZK_N; i++) {
        int16_t v = c_agg->coeffs[i];
        if (v != -1 && v != 0 && v != 1) {
            secure_zero(&state, sizeof(state));
            return PQ_ZK_ERR_CHALLENGE_WEIGHT;
        }
        if (v != 0) ham_weight++;
    }
    if (ham_weight != PQ_ZK_CHALLENGE_WEIGHT) {
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_CHALLENGE_WEIGHT;
    }

    /* ---- 步骤5：z_sec = y_sec + S·c_agg mod q ---- */
    if (!state.y_sec_valid) {
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    poly_vec_t y_sec, sk_s, S_c_agg, z_sec;
    PQC_DecodePolyVec(state.y_sec, &y_sec);
    PQC_DecodePolyVec(state.sk_s,  &sk_s);

    pqzk_vec_scalar_mul(&sk_s, c_agg, &S_c_agg);  /* S · c_agg */
    pqzk_vec_add(&y_sec, &S_c_agg, &z_sec);        /* z_sec = y_sec + S·c_agg */

    /* ---- 步骤6：M_mask = Parse(PRF(K_sym, c_seed||ctr_session||H_ctx)) ---- */
    /* PRF 输出足够长的字节流供 Parse 使用 */
    size_t mask_stream_len = (size_t)PQ_ZK_K * PQ_ZK_N * 3; /* 12bit/coeff 所需 */
    uint8_t *mask_stream = (uint8_t *)malloc(mask_stream_len);
    if (!mask_stream) {
        secure_zero(&state, sizeof(state));
        secure_zero(&y_sec, sizeof(y_sec));
        secure_zero(&z_sec, sizeof(z_sec));
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    pqzk_prf(state.k_sym, c_seed, ctr_session, H_ctx, mask_stream, mask_stream_len);

    poly_vec_t M_mask;
    pqzk_parse_poly_vec(mask_stream, mask_stream_len, &M_mask);
    free(mask_stream);

    /* ---- 步骤7：z_sec_masked = z_sec + M_mask mod q ---- */
    pqzk_vec_add(&z_sec, &M_mask, z_sec_masked);

    /* ---- 前向安全：计算新 K_sym ---- */
    uint8_t new_k_sym[32];
    pqzk_kdf(state.k_sym, state.d_seed, state.eid, NVRAM_EID_LEN, new_k_sym);

    /* ---- 原子更新：计数器+1 与 K_sym 更新同时落盘 ---- */
    state.ctr_local   = ctr_session + 1;
    state.y_sec_valid = 0;                    /* 清除 y_sec 有效标志 */
    memset(state.y_sec, 0, sizeof(state.y_sec));
    memcpy(state.k_sym, new_k_sym, 32);
    nvram_write_atomic(nvram_dir, &state);    /* tmpfile+fsync+rename */

    /* ---- 安全清零所有敏感中间量 ---- */
    secure_zero(&y_sec,   sizeof(y_sec));
    secure_zero(&sk_s,    sizeof(sk_s));
    secure_zero(&z_sec,   sizeof(z_sec));
    secure_zero(&S_c_agg, sizeof(S_c_agg));
    secure_zero(new_k_sym, 32);
    secure_zero(cagg_bytes, sizeof(cagg_bytes));
    secure_zero(&state, sizeof(state));

    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * 阶段五：LPA 聚合
 * ================================================================ */

void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked, const poly_vec_t *y_pub,
                       poly_vec_t *resp_z)
{
    if (!z_sec_masked || !y_pub || !resp_z) return;
    pqzk_vec_add(z_sec_masked, y_pub, resp_z);
}

/* ================================================================
 * 阶段六：掩码生成与验证引擎
 * ================================================================ */

void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES],
                      const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                      uint64_t ctr_session,
                      const uint8_t H_ctx[PQ_ZK_SEED_BYTES],
                      poly_vec_t *M_mask)
{
    if (!K_sym || !c_seed || !H_ctx || !M_mask) return;

    size_t stream_len = (size_t)PQ_ZK_K * PQ_ZK_N * 3;
    uint8_t *stream = (uint8_t *)malloc(stream_len);
    if (!stream) return;

    pqzk_prf(K_sym, c_seed, ctr_session, H_ctx, stream, stream_len);
    pqzk_parse_poly_vec(stream, stream_len, M_mask);
    free(stream);
}

/*
 * PQC_VerifyEngine
 *
 * 服务器端验证流程：
 *  1. 重构 c_agg = SampleInBall(SHA256(c_seed||W||H_ctx))
 *  2. z_unmasked = Lift((z - M_mask) mod q)    系数提升到 [-q/2, q/2)
 *  3. W' = A·z_unmasked - T·c_agg mod q
 *  4. 断言 W' == W
 *  5. ‖z_unmasked‖∞ ≤ β_final
 *  6. ‖z_unmasked‖₂ ≥ β_min
 */
PQ_ZK_ErrorCode PQC_VerifyEngine(const uint8_t mat_A_seed[32],
                                   const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
                                   const poly_vec_t *comm_W,
                                   const poly_vec_t *resp_z,
                                   const uint8_t nonce_s[32],
                                   const uint8_t H_ctx[32],
                                   const poly_vec_t *M_mask,
                                   const beta_params_t *beta_params)
{
    if (!mat_A_seed || !pk_t || !comm_W || !resp_z ||
        !nonce_s || !H_ctx || !M_mask || !beta_params)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* ---- 步骤1：重构 c_agg ---- */
    poly_t c_agg;
    PQC_GenChallenge(comm_W, nonce_s, H_ctx, &c_agg);

    /* ---- 步骤2：z_unmasked = Lift((z - M_mask) mod q) ---- */
    poly_vec_t z_minus_mask;
    pqzk_vec_sub(resp_z, M_mask, &z_minus_mask);

    /* Lift：将 [0,q-1] 提升到 [-q/2, q/2) */
    poly_vec_t z_unmasked;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = (int32_t)(uint16_t)z_minus_mask.coeffs[i];
        if (v > PQ_ZK_Q_VAL / 2) v -= PQ_ZK_Q_VAL;
        z_unmasked.coeffs[i] = (int16_t)v;
    }

    /* ---- 步骤5 提前：范数检查（省算力，失败直接返回）---- */
    int32_t inf_norm = 0;
    int64_t l2_sq    = 0;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v  = z_unmasked.coeffs[i];
        int32_t av = (v < 0) ? -v : v;
        if (av > inf_norm) inf_norm = av;
        l2_sq += (int64_t)v * v;
    }

    if (inf_norm > beta_params->beta_final) return PQ_ZK_ERR_NORM_BOUND;

    int64_t beta_min_sq = (int64_t)beta_params->beta_min * beta_params->beta_min;
    if (l2_sq < beta_min_sq) return PQ_ZK_ERR_NORM_BOUND;

    /* ---- 步骤3：W' = A·z_unmasked - T·c_agg ---- */
    /* 从公钥解析矩阵种子和 T */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(mat_A_seed, A_rows, PQ_ZK_K);

    poly_vec_t T_key;
    decode_polyvec_12bit(pk_t + 32, &T_key);  /* pk_t = seed(32) + T_12bit(1152) */

    /* A · z_unmasked */
    poly_vec_t Az;
    pqzk_mat_vec_mul(A_rows, &z_unmasked, &Az);

    /* T · c_agg（T 看作 poly_vec_t，c_agg 是标量多项式） */
    poly_vec_t Tc;
    pqzk_vec_scalar_mul(&T_key, &c_agg, &Tc);

    /* W' = Az - Tc */
    poly_vec_t W_prime;
    pqzk_vec_sub(&Az, &Tc, &W_prime);

    /* ---- 步骤4：断言 W' == W ---- */
    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES], Wp_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W, W_bytes);
    PQC_EncodePolyVec(&W_prime, Wp_bytes);

    volatile int diff = 0;
    for (int i = 0; i < PQ_ZK_POLYVEC_BYTES; i++)
        diff |= (W_bytes[i] ^ Wp_bytes[i]);

    if (diff) return PQ_ZK_ERR_MAC_FAIL; /* 代数关系不成立 */

    return PQ_ZK_SUCCESS;
}