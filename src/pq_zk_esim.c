/* pq_zk_esim.c
 * PQ-ZK-eSIM 协议全阶段实现 — v4.0
 *
 * v4.0 核心变化：
 *   - 删除 PQC_SerializeContext / ContextData（H_ctx 体系彻底废弃）
 *   - H_ctx 全面替换为 R_dynamic = Hash(R_bio || ctr_local)
 *   - PQC_GenChallenge：c_agg = SampleInBall(Hash(c_seed || W))
 *   - PQC_ComputeZ_and_Mask：掩码绑定 R_dynamic
 *   - PQC_GenerateMask / PQC_VerifyEngine：同步更新
 *
 * 文件结构（按协议阶段顺序）：
 *   §0  内部工具与宏
 *   §1  序列化 / 反序列化
 *   §2  阶段零：密钥生成与初始化
 *   §3  阶段一：承诺生成
 *   §4  阶段二：挑战生成
 *   §5  阶段三：TEE 生物鉴权与授权令牌签发
 *   §6  阶段四：掩码协同计算（核心黑盒）
 *   §7  阶段五：LPA 聚合
 *   §8  阶段六：掩码生成与验证引擎
 */

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/* ================================================================
 * §0  内部工具与宏
 * ================================================================ */

#define NVRAM_MAGIC "PQZK"

/*
 * PQZK_DEFAULT_BETA_PARAMS 已移至 pq_zk_esim.h，供所有端直接使用。
 */

/*
 * sample_ternary — 从随机种子生成三进制多项式向量
 *
 * y_sec 系数服从极小三进制分布 {-1, 0, 1}^N，
 * 用 SHAKE-256 扩展种子，每字节低2bit决定一个系数：
 *   00, 01 → 0（保证稀疏性，约50%为零）
 *   10     → +1
 *   11     → -1
 *
 * 对应协议 §1（阶段一）eUICC 内部盲化因子生成规范。
 */
static void sample_ternary(const uint8_t seed[32], poly_vec_t *y_sec)
{
    /* 每系数取1字节，仅用低2bit，避免位域操作的可移植性问题 */
    uint8_t buf[PQ_ZK_K * PQ_ZK_N];
    pqzk_shake256(seed, 32, buf, sizeof(buf));

    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        uint8_t b = buf[i] & 0x03;
        if      (b == 2) y_sec->coeffs[i] =  1;
        else if (b == 3) y_sec->coeffs[i] = -1;
        else             y_sec->coeffs[i] =  0;
    }

    /* 清零中间缓冲区，防止侧信道 */
    secure_zero(buf, sizeof(buf));
}

/* ================================================================
 * §1  序列化 / 反序列化
 * ================================================================ */

/*
 * PQC_EncodePolyVec — 多项式向量序列化
 *
 * int16_t 系数按小端序展平为字节流。
 * 每系数 2 字节，总长 PQ_ZK_POLYVEC_BYTES = K*N*2 = 1536。
 * 跨端一致性锚点：C/Python/Java 三端必须使用此接口，
 * 严禁对 poly_vec_t 结构体指针直接 memcpy 或哈希。
 */
void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes)
{
    if (!in_poly || !out_bytes) return;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        uint16_t v = (uint16_t)in_poly->coeffs[i];
        out_bytes[i * 2]     = (uint8_t)(v & 0xFF);
        out_bytes[i * 2 + 1] = (uint8_t)((v >> 8) & 0xFF);
    }
}

/*
 * PQC_DecodePolyVec — 多项式向量反序列化
 *
 * 将 JNI/Python 传入的小端序字节流无损重构为内部代数对象。
 * 长度必须为 PQ_ZK_POLYVEC_BYTES，调用方负责验证。
 */
void PQC_DecodePolyVec(const uint8_t *in_bytes, poly_vec_t *out_poly)
{
    if (!in_bytes || !out_poly) return;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        uint16_t v = (uint16_t)in_bytes[i * 2]
                   | ((uint16_t)in_bytes[i * 2 + 1] << 8);
        out_poly->coeffs[i] = (int16_t)v;
    }
}

/*
 * PQC_EncodePoly / PQC_DecodePoly — 单多项式序列化
 *
 * 专用于标量多项式 c_agg（poly_t），
 * 每系数 2 字节，总长 PQ_ZK_POLY_BYTES = 512。
 * TEE 计算 AuthToken 时对 c_agg 编码后作为 HMAC 输入。
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
 * encode_polyvec_12bit / decode_polyvec_12bit — 公钥 T 的压缩序列化
 *
 * 每2个系数打包成3字节（12bit × 2 = 24bit = 3字节），小端序。
 * K*N=768 个系数 → 768*12/8 = 1152 字节。
 * 公钥格式：种子(32B) + T_12bit(1152B) = 1184B = PQ_ZK_PUBLICKEY_BYTES。
 *
 * 注意：此函数仅用于公钥 T 的存储和传输，
 * 不用于协议中间变量（中间变量使用 16bit 全精度）。
 */
static void encode_polyvec_12bit(const poly_vec_t *in, uint8_t *out)
{
    int total = PQ_ZK_K * PQ_ZK_N;
    for (int i = 0; i < total; i += 2) {
        /* 系数归一化到 [0, q-1] 再截断到 12bit */
        uint16_t a = (uint16_t)((int32_t)in->coeffs[i]
                     % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
        uint16_t b = (uint16_t)((int32_t)in->coeffs[i+1]
                     % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
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
        uint16_t a = (uint16_t)in[j]
                   | (((uint16_t)in[j+1] & 0x0F) << 8);
        uint16_t b = ((uint16_t)in[j+1] >> 4)
                   | ((uint16_t)in[j+2] << 4);
        out->coeffs[i]   = (int16_t)(a & 0x0FFF);
        out->coeffs[i+1] = (int16_t)(b & 0x0FFF);
    }
}

/*
 * serialize_merkle_path — Merkle 路径序列化（内部工具）
 *
 * 将 merkle_path_t 序列化为跨端一致的字节流，
 * 用于计算 hash_M2 = SHA-256(Serialize(M2))。
 *
 * 格式（全部小端序）：
 *   [depth(4B)] [leaf_index(4B)]
 *   对每层 i in 0..depth-1：
 *     [sibling[i](32B)] [is_right_sibling[i](1B)]
 * 总长 = 8 + depth × 33 字节
 *
 * 返回：序列化后字节数，-1 表示参数错误或缓冲区不足
 */
#define PQZK_MERKLE_PATH_SERIAL_MAX \
    (8 + PQZK_MERKLE_MAX_DEPTH * (PQZK_MERKLE_HASH_BYTES + 1))  /* 8 + 6*33 = 206 */

static int serialize_merkle_path(const merkle_path_t *path,
                                  uint8_t *buf, size_t buf_len)
{
    if (!path || !buf) return -1;

    size_t needed = 8 + (size_t)path->depth * (PQZK_MERKLE_HASH_BYTES + 1);
    if (buf_len < needed) return -1;

    size_t off = 0;
    write_le32(buf + off, path->depth);       off += 4;
    write_le32(buf + off, path->leaf_index);  off += 4;

    for (uint32_t i = 0; i < path->depth; i++) {
        memcpy(buf + off, path->sibling[i], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        buf[off] = path->is_right_sibling[i];
        off += 1;
    }

    return (int)off;
}

/* ================================================================
 * §2  阶段零：密钥生成与初始化
 * ================================================================ */

/*
 * PQC_GenKeyPair — 生成长期公私钥对
 *
 * 私钥 S：三进制短系数向量，存储在 eUICC 内部安全区。
 * 公钥 T：T = A·S mod q，服务器注册时存储。
 *
 * pk_t 格式（1184字节）：
 *   [0:32]    矩阵 A 的生成种子（跨端固定值 PQZK_MATRIX_A_SEED）
 *   [32:1184] T = A·S，12bit 压缩序列化（1152字节）
 */
void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s)
{
    if (!pk_t || !sk_s) return;

    /* 生成私钥 S（三进制短分布） */
    uint8_t sk_seed[32];
    pqzk_rand_bytes(sk_seed, 32);
    sample_ternary(sk_seed, sk_s);

    /* 公钥头部：矩阵 A 的种子（跨端固定，确保服务器可重构 A） */
    memcpy(pk_t, PQZK_MATRIX_A_SEED, 32);

    /* 计算 T = A·S mod q */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K);
    poly_vec_t T;
    pqzk_mat_vec_mul(A_rows, sk_s, &T);

    /* T 用 12bit 压缩格式序列化写入公钥 */
    encode_polyvec_12bit(&T, pk_t + 32);

    /* 安全清零中间变量 */
    secure_zero(sk_seed, sizeof(sk_seed));
    secure_zero(A_rows, sizeof(A_rows));
    secure_zero(&T, sizeof(T));
}

/*
 * PQC_eUICC_Init — eUICC 状态初始化（阶段零 §0.3 SetupeUICC）
 *
 * 通过带外信道完成后调用，将所有核心凭证原子写入 nvram_dir：
 *   · EID（设备标识）
 *   · 私钥 S（长期密钥，三进制短向量）
 *   · K_sym（与服务器预共享的对称密钥，初始版本）
 *   · ctr_local（初始计数器，v4.0 支持随机初始值）
 *   · K_TEE-eUICC（TEE 与 eUICC 内部总线密钥）
 *   · d_seed（KDF 派生种子，由 K_sym 哈希派生保证确定性）
 *
 * 安全约束：
 *   · nvram_dir 必须是应用私有沙盒路径，外部不可访问
 *   · 写入通过 nvram_write_atomic 保证掉电安全
 */
void PQC_eUICC_Init(const char* nvram_dir,
                    const uint8_t* eid,   size_t eid_len,
                    const poly_vec_t* sk_s,
                    const uint8_t* k_sym, size_t k_sym_len,
                    uint64_t initial_ctr,
                    const uint8_t* k_tee, size_t k_tee_len,
                    const uint8_t* salt,                   
                    const uint8_t* cred_kyc, size_t cred_kyc_len )
{
    if (!nvram_dir || !eid || !sk_s || !k_sym || !k_tee) return;
    if (eid_len > NVRAM_EID_LEN || k_sym_len > 32 || k_tee_len > 32) return;

    nvram_state_t state;
    memset(&state, 0, sizeof(state));

    memcpy(state.magic, NVRAM_MAGIC, 4);
    memcpy(state.eid,   eid,   eid_len);
    PQC_EncodePolyVec(sk_s, state.sk_s);    /* 私钥序列化存储 */
    memcpy(state.k_sym, k_sym, k_sym_len);
    memcpy(state.k_tee, k_tee, k_tee_len);
    if (salt)      memcpy(state.salt,     salt,     32);
    if (cred_kyc)  memcpy(state.cred_kyc, cred_kyc,
                          cred_kyc_len > 64 ? 64 : cred_kyc_len);
    state.ctr_local   = initial_ctr;
    state.y_sec_valid = 0;                  /* 尚未生成 y_sec */

    /*
     * d_seed 派生：
     * 从初始 K_sym 哈希派生，保证设备唯一且可重现。
     * 服务器端 KDF 使用相同的 d_seed 演进密钥。
     */
    pqzk_sha256(k_sym, k_sym_len, state.d_seed);

    nvram_write_atomic(nvram_dir, &state);

    /* 清零敏感中间状态 */
    secure_zero(&state, sizeof(state));
}

/* ================================================================
 * §3  阶段一：承诺生成
 * ================================================================ */

/*
 * PQC_PreCompute — LPA 外部盲化因子预计算（阶段一 §1.1）
 *
 * LPA 在空闲时调用，执行重负载大矩阵乘法：
 *   s_pub  ← 随机种子（256bit）
 *   y_pub  ← SampleGauss(SHAKE-256(s_pub))，系数服从 N(0, σ_pub²)
 *   W_pub  ← A · y_pub mod q
 *
 * seed_y（即 s_pub）缓存于 REE 加密存储，供阶段五重新生成 y_pub。
 * y_pub 本身不存储，通过 PQC_RegenerateYpub 按需重建。
 */
void PQC_PreCompute(poly_vec_t *W_pub, uint8_t seed_y[PQ_ZK_SEED_BYTES])
{
    if (!W_pub || !seed_y) return;

    pqzk_rand_bytes(seed_y, PQ_ZK_SEED_BYTES);

    poly_vec_t y_pub;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, &y_pub);

    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K);
    pqzk_mat_vec_mul(A_rows, &y_pub, W_pub);

    secure_zero(&y_pub, sizeof(y_pub));
    secure_zero(A_rows, sizeof(A_rows));
}

/*
 * PQC_RegenerateYpub — 从种子重新生成 y_pub（阶段五调用）
 *
 * 与 PQC_PreCompute 内部使用相同的 SampleGauss 逻辑，
 * 确保确定性输出，避免 LPA 重复计算和存储庞大矩阵。
 */
void PQC_RegenerateYpub(const uint8_t seed_y[PQ_ZK_SEED_BYTES],
                         poly_vec_t *y_pub)
{
    if (!seed_y || !y_pub) return;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, y_pub);
}

/*
 * PQC_eUICC_Commit — eUICC 内部承诺生成（阶段一 §1.2）
 *
 * eUICC 执行轻量级运算（无 NTT，利用三进制稀疏性）：
 *   y_sec  ← SampleTernary(随机种子)，系数 ∈ {-1, 0, 1}
 *   W_sec  ← A · y_sec mod q
 *   MAC_W  ← HMAC-SHA256(K_sym, encode(W_sec) || ctr_le8)
 *
 * y_sec 持久化存储于 nvram（严禁输出给上层），
 * 供阶段四 PQC_ComputeZ_and_Mask 读取使用后立即清零。
 */
void PQC_eUICC_Commit(const char* nvram_dir,
                       poly_vec_t *W_sec,
                       uint8_t MAC_W[PQ_ZK_MAC_BYTES])
{
    if (!nvram_dir || !W_sec || !MAC_W) return;

    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) return;

    /* 生成三进制 y_sec */
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

    pqzk_iov_t mac_iov[] = {
        { wsec_bytes, PQ_ZK_POLYVEC_BYTES },
        { ctr_bytes,  8                   },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(state.k_sym, mac_iov, MAC_W);

    /* y_sec 持久化到 nvram（后续阶段四读取，严禁输出） */
    PQC_EncodePolyVec(&y_sec, state.y_sec);
    state.y_sec_valid = 1;
    nvram_write_atomic(nvram_dir, &state);

    /* 安全清零所有敏感中间变量 */
    secure_zero(&y_sec, sizeof(y_sec));
    secure_zero(wsec_bytes, sizeof(wsec_bytes));
    secure_zero(&state, sizeof(state));
}

/* ================================================================
 * §4  阶段二：挑战生成
 * ================================================================ */

/*
 * PQC_GenChallenge — 多维挑战折叠（阶段二 §2，LPA 端）— v4.0
 *
 * LPA 充当"多维挑战展开器"，将服务器的轻量级种子扩展为高维稀疏挑战：
 *   c_agg ← SampleInBall_κ(SHA-256(c_seed || encode(W)))
 *
 * v4.0 变更：删除 H_ctx 参数，承诺绑定改由 R_dynamic 在阶段三/四完成。
 * 生成的 c_agg 满足：系数 ∈ {-1, 0, 1}，‖c_agg‖₁ = κ = 26。
 */
void PQC_GenChallenge(const poly_vec_t *comm_W,
                      const uint8_t nonce[PQ_ZK_SEED_BYTES],
                      poly_t *c_agg)
{
    if (!comm_W || !nonce || !c_agg) return;

    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W, W_bytes);

    /* hash_input = c_seed || encode(W)（v4.0：不含 H_ctx） */
    pqzk_iov_t iov[] = {
        { nonce,   PQ_ZK_SEED_BYTES    },
        { W_bytes, PQ_ZK_POLYVEC_BYTES },
        { NULL, 0 }
    };
    uint8_t hash[32];
    pqzk_sha256_iov(iov, hash);

    pqzk_sample_in_ball(hash, c_agg);
}

/* ================================================================
 * §5  阶段三：TEE 生物鉴权与授权令牌签发
 * ================================================================ */

/*
 * TEE_GenerateAuthToken — TEE 阶段三主函数（v4.0）
 *
 * 协议流程：
 *   1. 从 nvram 读取 ctr_local（只读，不步进）
 *   2. R_dynamic ← SHA-256(R_bio || ctr_local_le8)
 *   3. M2 ← MerkleTree_GetPath(tree, M1)
 *   4. hash_M2 ← SHA-256(Serialize(M2))
 *   5. AuthToken ← HMAC-SHA256(K_TEE,
 *                    encode(c_agg) || ctr_le8 || R_dynamic || hash_M2)
 *   6. 输出 (R_dynamic, M2, AuthToken) 给 LPA
 *
 * 模拟环境说明：
 *   · 调用本函数即视为活体验证通过
 *   · 真实环境中活体验证由 Android BiometricPrompt 在调用前完成
 *   · K_TEE-eUICC 在真实环境由 StrongBox Keystore 保管，此处由参数传入
 *
 * 安全约束：
 *   · ctr_local 严禁由上层传入，必须从 nvram 内部读取
 *   · hash_M2 必须通过序列化整棵路径结构后哈希，确保跨端一致
 */
PQ_ZK_ErrorCode TEE_GenerateAuthToken(
    const char          *nvram_dir,
    const poly_t        *c_agg,
    const uint8_t        R_bio[PQZK_MERKLE_HASH_BYTES],
    const merkle_tree_t *tree,
    uint32_t             M1,
    const uint8_t        k_tee[PQ_ZK_TEE_KEY_BYTES],
    uint8_t              R_dynamic_out[PQ_ZK_SEED_BYTES],
    merkle_path_t       *M2_out,
    uint8_t              AuthToken_out[PQ_ZK_MAC_BYTES])
{
    if (!nvram_dir || !c_agg || !R_bio || !tree ||
        !k_tee || !R_dynamic_out || !M2_out || !AuthToken_out)
        return PQ_ZK_ERR_INVALID_PARAM;

    if (M1 >= tree->n_leaves)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* 步骤1：读取 ctr_local（只读，阶段三不步进计数器） */
    nvram_state_t nvram_st;
    if (nvram_read(nvram_dir, &nvram_st) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    uint8_t ctr_le8[8];
    write_le64(ctr_le8, nvram_st.ctr_local);

    /* 步骤2：R_dynamic = SHA-256(R_bio || ctr_local_le8)
     * 动态根绑定生物特征与计数器状态，每次认证唯一 */
    pqzk_iov_t rdyn_iov[] = {
        { R_bio,   PQZK_MERKLE_HASH_BYTES },
        { ctr_le8, 8                       },
        { NULL, 0 }
    };
    if (pqzk_sha256_iov(rdyn_iov, R_dynamic_out) != 0)
        return PQ_ZK_ERR_MAC_FAIL;

    /* 步骤3：按 M1 提取 Merkle 验证路径 M2 */
    if (PQC_MerkleTree_GetPath(tree, M1, M2_out) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* 步骤4：hash_M2 = SHA-256(Serialize(M2))
     * 序列化确保路径内容跨端哈希结果一致 */
    uint8_t m2_serial[PQZK_MERKLE_PATH_SERIAL_MAX];
    int m2_serial_len = serialize_merkle_path(M2_out, m2_serial,
                                               sizeof(m2_serial));
    if (m2_serial_len < 0)
        return PQ_ZK_ERR_MAC_FAIL;

    uint8_t hash_M2[32];
    if (pqzk_sha256(m2_serial, (size_t)m2_serial_len, hash_M2) != 0)
        return PQ_ZK_ERR_MAC_FAIL;

    /* 步骤5：encode(c_agg) 供 HMAC 输入 */
    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(c_agg, cagg_bytes);

    /* 步骤6：AuthToken = HMAC-SHA256(K_TEE,
     *          encode(c_agg) || ctr_le8 || R_dynamic || hash_M2)
     *
     * 四字段绑定语义：
     *   encode(c_agg) → 防挑战替换攻击
     *   ctr_le8       → 防重放攻击
     *   R_dynamic     → 绑定生物特征与会话
     *   hash_M2       → 防验证路径篡改
     */
    pqzk_iov_t auth_iov[] = {
        { cagg_bytes,    PQ_ZK_POLY_BYTES  },
        { ctr_le8,       8                 },
        { R_dynamic_out, PQ_ZK_SEED_BYTES  },
        { hash_M2,       32                },
        { NULL, 0 }
    };
    if (pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken_out) != 0)
        return PQ_ZK_ERR_MAC_FAIL;

    /* 清零 nvram 快照（含私钥等敏感数据） */
    secure_zero(&nvram_st, sizeof(nvram_st));
    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * §6  阶段四：掩码协同计算（核心黑盒）
 * ================================================================ */

/*
 * PQC_ComputeZ_and_Mask — eUICC 极速盲化（阶段四 §4）— v4.0
 *
 * 七步原子操作，所有敏感计算封闭在 C 层，严禁上层介入：
 *
 *   1. 读取 ctr_local，验证 AuthToken
 *      AuthToken ← HMAC(K_TEE, encode(c_agg)||ctr_le8||R_dynamic||hash_M2)
 *   2. 验证失败 → 返回 ERR_MAC_FAIL，计数器不变，终止会话
 *   3. 验证成功 → ctr_session = ctr_local，ctr_local += 1
 *   4. 稀疏性校验：c_agg 系数 ∈ {-1,0,1}，‖c_agg‖₁ = κ
 *   5. z_sec = y_sec + S·c_agg mod q（y_sec 从 nvram 读取）
 *   6. M_mask ← Parse(PRF(K_sym, c_seed||Serialize(ctr_session)||R_dynamic))
 *   7. z_sec_masked = z_sec + M_mask mod q
 *      + 前向安全：K_sym_new = KDF(K_sym, d_seed, EID)，与计数器步进原子绑定
 *
 * 安全红线：
 *   · z_sec 和 y_sec 永不暴露给上层
 *   · AuthToken 用恒定时间比较，防时序侧信道
 *   · 函数退出前所有敏感中间变量必须 secure_zero
 */
PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(
    const char*    nvram_dir,
    const poly_t  *c_agg,
    const uint8_t  c_seed[PQ_ZK_SEED_BYTES],
    const uint8_t  R_dynamic[PQ_ZK_SEED_BYTES],
    const uint8_t  hash_M2[PQ_ZK_MAC_BYTES],
    const uint8_t  AuthToken[PQ_ZK_MAC_BYTES],
    poly_vec_t    *z_sec_masked)
{
    if (!nvram_dir || !c_agg || !c_seed || !R_dynamic ||
        !hash_M2  || !AuthToken || !z_sec_masked)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* 步骤1：读取 nvram 状态 */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* 步骤1：重建期望 AuthToken 并恒定时间比较
     * v4.0: HMAC(K_TEE, encode(c_agg)||ctr_le8||R_dynamic||hash_M2) */
    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    uint8_t ctr_bytes[8];
    PQC_EncodePoly(c_agg, cagg_bytes);
    write_le64(ctr_bytes, state.ctr_local);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES  },
        { ctr_bytes,  8                 },
        { R_dynamic,  PQ_ZK_SEED_BYTES  },
        { hash_M2,    PQ_ZK_MAC_BYTES   },
        { NULL, 0 }
    };
    uint8_t expected_token[32];
    pqzk_hmac_sha256_iov(state.k_tee, auth_iov, expected_token);

    /* 恒定时间比较，防时序侧信道 */
    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected_token[i] ^ AuthToken[i]);

    if (mismatch) {
        secure_zero(&state, sizeof(state));
        secure_zero(expected_token, 32);
        return PQ_ZK_ERR_MAC_FAIL;
    }

    /* 步骤3：锁存 ctr_session，计数器 +1 */
    uint64_t ctr_session = state.ctr_local;

    /* 步骤4：稀疏性校验（系数域 + 汉明权重） */
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

    /* 步骤5：z_sec = y_sec + S·c_agg mod q
     * y_sec 从 nvram 读取，使用后立即清零 */
    if (!state.y_sec_valid) {
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    poly_vec_t y_sec, sk_s, S_c_agg, z_sec;
    PQC_DecodePolyVec(state.y_sec, &y_sec);
    PQC_DecodePolyVec(state.sk_s,  &sk_s);
    pqzk_vec_scalar_mul(&sk_s, c_agg, &S_c_agg);
    pqzk_vec_add(&y_sec, &S_c_agg, &z_sec);

    /* 步骤6：M_mask = Parse(PRF(K_sym, c_seed||ctr_session||R_dynamic))
     * v4.0: PRF 绑定 R_dynamic 而非 H_ctx */
    size_t mask_stream_len = (size_t)PQ_ZK_K * PQ_ZK_N * 3;
    uint8_t *mask_stream = (uint8_t *)malloc(mask_stream_len);
    if (!mask_stream) {
        secure_zero(&state, sizeof(state));
        secure_zero(&y_sec, sizeof(y_sec));
        secure_zero(&z_sec, sizeof(z_sec));
        secure_zero(&sk_s,  sizeof(sk_s));
        return PQ_ZK_ERR_INVALID_PARAM;
    }
    pqzk_prf(state.k_sym, c_seed, ctr_session, R_dynamic,
              mask_stream, mask_stream_len);

    poly_vec_t M_mask;
    pqzk_parse_poly_vec(mask_stream, mask_stream_len, &M_mask);
    free(mask_stream);

    /* 步骤7：z_sec_masked = z_sec + M_mask mod q */
    pqzk_vec_add(&z_sec, &M_mask, z_sec_masked);

    /* 前向安全密钥演进 + 计数器步进（原子写入 nvram）
     *
     * K_sym_new = KDF(K_sym, d_seed, EID)
     * 两者必须在同一 nvram_write_atomic 调用中生效，
     * 确保断电时同时回滚，维持防重放状态机严密性。
     */
    uint8_t new_k_sym[32];
    pqzk_kdf(state.k_sym, state.d_seed, state.eid, NVRAM_EID_LEN, new_k_sym);

    state.ctr_local   = ctr_session + 1;  /* 计数器步进 */
    state.y_sec_valid = 0;                /* y_sec 已使用，标记失效 */
    memset(state.y_sec, 0, sizeof(state.y_sec));
    memcpy(state.k_sym, new_k_sym, 32);   /* 密钥演进 */
    nvram_write_atomic(nvram_dir, &state); /* 原子写入，断电安全 */

    /* 安全清零所有敏感中间变量 */
    secure_zero(&y_sec,         sizeof(y_sec));
    secure_zero(&sk_s,          sizeof(sk_s));
    secure_zero(&z_sec,         sizeof(z_sec));
    secure_zero(&S_c_agg,       sizeof(S_c_agg));
    secure_zero(new_k_sym,      32);
    secure_zero(cagg_bytes,     sizeof(cagg_bytes));
    secure_zero(expected_token, 32);
    secure_zero(&state,         sizeof(state));

    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * §7  阶段五：LPA 大噪声聚合
 * ================================================================ */

/*
 * PQC_LPA_Aggregate — 大噪声淹没（阶段五 §5）
 *
 * LPA 将 eUICC 的掩码响应与自身的大方差盲化因子聚合：
 *   z = z_sec_masked + y_pub mod q
 *
 * 安全性依据 Rényi 散度：
 *   y_pub 的高斯噪声（σ_pub ≥ γ·η_s·κ）统计淹没了 z_sec 的分布特征，
 *   使 z 在计算上与均匀分布不可区分，实现统计零知识性。
 */
void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked,
                        const poly_vec_t *y_pub,
                        poly_vec_t *resp_z)
{
    if (!z_sec_masked || !y_pub || !resp_z) return;
    pqzk_vec_add(z_sec_masked, y_pub, resp_z);
}

/* ================================================================
 * §8  阶段六：掩码生成与验证引擎
 * ================================================================ */

/*
 * PQC_GenerateMask — 独立端到端掩码生成引擎（v4.0）
 *
 * 供服务器端（Python ctypes）调用，远端重建掩码多项式：
 *   M_mask ← Parse_Rq(PRF(K_sym, c_seed || Serialize(ctr_session) || R_dynamic))
 *
 * v4.0 变更：第四参数从 H_ctx 替换为 R_dynamic。
 * 调用方须保证 R_dynamic = Hash(R_bio || ctr_session)，
 * 与 eUICC 端计算时使用的 R_dynamic 严格一致。
 */
void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES],
                       const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                       uint64_t ctr_session,
                       const uint8_t R_dynamic[PQ_ZK_SEED_BYTES],
                       poly_vec_t *M_mask)
{
    if (!K_sym || !c_seed || !R_dynamic || !M_mask) return;

    size_t stream_len = (size_t)PQ_ZK_K * PQ_ZK_N * 3;
    uint8_t *stream = (uint8_t *)malloc(stream_len);
    if (!stream) return;

    pqzk_prf(K_sym, c_seed, ctr_session, R_dynamic, stream, stream_len);
    pqzk_parse_poly_vec(stream, stream_len, M_mask);
    free(stream);
}

/*
 * PQC_VerifyEngine — 服务器验证引擎（阶段六 §6）— v4.0
 *
 * 服务器端完整验证流程：
 *   1. c_agg ← SampleInBall(SHA-256(c_seed || encode(W)))  [v4.0: 无 H_ctx]
 *   2. z_unmasked ← Lift((z - M_mask) mod q)
 *   3. W' ← A·z_unmasked - T·c_agg mod q，断言 W' == W
 *   4. 无穷范数：‖z_unmasked‖∞ ≤ β_final（防溢出）
 *   5. 欧几里得范数：‖z_unmasked‖₂ ≥ β_min（防裸露）
 *
 * 注意：
 *   · R_dynamic 参数在本函数内不直接使用（仅用于参数签名对齐）
 *   · 服务器在调用本函数前须已独立完成：
 *     - Merkle 路径验证（R_bio' == R_bio）
 *     - 计数器滑动窗口匹配（MAC_W 校验）
 *     - R_dynamic 重构（Hash(R_bio || ctr_session)）
 *     详见规范 §6 前置条件说明
 */
PQ_ZK_ErrorCode PQC_VerifyEngine(
    const uint8_t    mat_A_seed[32],
    const uint8_t    pk_t[PQ_ZK_PUBLICKEY_BYTES],
    const poly_vec_t *comm_W,
    const poly_vec_t *resp_z,
    const uint8_t    nonce_s[32],
    const uint8_t    R_dynamic[32],
    const poly_vec_t *M_mask,
    const beta_params_t *beta_params)
{
    if (!mat_A_seed || !pk_t || !comm_W || !resp_z ||
        !nonce_s || !R_dynamic || !M_mask || !beta_params)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* 步骤1：重构 c_agg（v4.0 无 H_ctx） */
    poly_t c_agg;
    PQC_GenChallenge(comm_W, nonce_s, &c_agg);

    /* 步骤2：z_unmasked = Lift((z - M_mask) mod q)
     * Lift 将 [0, q-1] 映射到中心化区间 (-q/2, q/2] */
    poly_vec_t z_minus_mask;
    pqzk_vec_sub(resp_z, M_mask, &z_minus_mask);

    poly_vec_t z_unmasked;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = (int32_t)(uint16_t)z_minus_mask.coeffs[i];
        /* Lift：将 [0,q-1] 中心化到 (-q/2, q/2] */
        if (v > PQ_ZK_Q_VAL / 2) v -= PQ_ZK_Q_VAL;
        z_unmasked.coeffs[i] = (int16_t)v;
    }

    /* 步骤3（提前）：范数检查
     * 提前执行可避免大矩阵乘法的无谓开销 */
    int32_t inf_norm = 0;
    int64_t l2_sq    = 0;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v  = z_unmasked.coeffs[i];
        int32_t av = (v < 0) ? -v : v;
        if (av > inf_norm) inf_norm = av;
        l2_sq += (int64_t)v * v;
    }
    if (inf_norm > (int32_t)beta_params->beta_final)
        return PQ_ZK_ERR_NORM_BOUND;
    if (l2_sq < (int64_t)beta_params->beta_min * beta_params->beta_min)
        return PQ_ZK_ERR_NORM_BOUND;

    /* 步骤4：W' = A·z_unmasked - T·c_agg mod q */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(mat_A_seed, A_rows, PQ_ZK_K);

    poly_vec_t T_key;
    decode_polyvec_12bit(pk_t + 32, &T_key);

    poly_vec_t Az, Tc, W_prime;
    pqzk_mat_vec_mul(A_rows, &z_unmasked, &Az);
    pqzk_vec_scalar_mul(&T_key, &c_agg, &Tc);
    pqzk_vec_sub(&Az, &Tc, &W_prime);

    /* 步骤5：断言 W' == W（恒定时间比较） */
    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES];
    uint8_t Wp_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W,   W_bytes);
    PQC_EncodePolyVec(&W_prime, Wp_bytes);

    volatile int diff = 0;
    for (int i = 0; i < PQ_ZK_POLYVEC_BYTES; i++)
        diff |= (W_bytes[i] ^ Wp_bytes[i]);

    if (diff) return PQ_ZK_ERR_MAC_FAIL;

    return PQ_ZK_SUCCESS;
}