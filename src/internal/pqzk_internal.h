#ifndef PQZK_INTERNAL_H
#define PQZK_INTERNAL_H

/*
 * pqzk_internal.h
 * 内部工具函数，不对外暴露
 */

#include "pq_zk_esim.h"
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* q 值：官方头文件仅定义宏名，这里补充数值供内部运算使用 */
#ifndef PQ_ZK_Q_VAL
#define PQ_ZK_Q_VAL 3329
#endif

/* ---- 小端序读写工具 ---- */

static inline void write_le32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline void write_le64(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

static inline uint64_t read_le64(const uint8_t *b) {
    return (uint64_t)b[0]
         | ((uint64_t)b[1] << 8)
         | ((uint64_t)b[2] << 16)
         | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32)
         | ((uint64_t)b[5] << 40)
         | ((uint64_t)b[6] << 48)
         | ((uint64_t)b[7] << 56);
}

/* ---- 模 q 运算 ---- */

/* 规约到 [0, q-1] */
static inline int32_t mod_q(int32_t x) {
    int32_t r = x % (int32_t)PQ_ZK_Q_VAL;
    return (r < 0) ? r + (int32_t)PQ_ZK_Q_VAL : r;
}

/* 中心化提升：[0, q-1] → [-q/2, q/2) */
static inline int32_t lift_centered(int32_t x) {
    x = mod_q(x);
    return (x > (int32_t)PQ_ZK_Q_VAL / 2) ? x - (int32_t)PQ_ZK_Q_VAL : x;
}

/* 安全清零 */
static inline void secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

/* ---- 内部密码学原语 ---- */

/* SHA-256 */
int pqzk_sha256(const uint8_t *in, size_t len, uint8_t out[32]);

/* SHA-256 多段输入：iov 数组，最后一个元素 buf==NULL 结束 */
typedef struct { const uint8_t *buf; size_t len; } pqzk_iov_t;
int pqzk_sha256_iov(const pqzk_iov_t *iov, uint8_t out[32]);

/* HMAC-SHA256 多段输入，固定32字节key */
int pqzk_hmac_sha256_iov(const uint8_t key[32], const pqzk_iov_t *iov,
                          uint8_t out[32]);

/* HMAC-SHA256 多段输入，任意长度key */
int pqzk_hmac_sha256_iov_anykey(const uint8_t *key, size_t key_len,
                                  const pqzk_iov_t *iov, uint8_t out[32]);

/* SHAKE-256 XOF */
int pqzk_shake256(const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_len);

/* AES-256-CTR：key(32字节), iv(16字节) → out_len 字节伪随机流 */
int pqzk_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                    uint8_t *out, size_t out_len);

/* 协议 PRF (v4.0)：PRF(K_sym, c_seed || Serialize(ctr) || R_dynamic) → out_len 字节
 * 注意：第三个参数在 4.0 中语义为 R_dynamic（动态验证根），接口名保持不变 */
int pqzk_prf(const uint8_t K_sym[32], const uint8_t c_seed[32],
             uint64_t ctr, const uint8_t R_dynamic[32],
             uint8_t *out, size_t out_len);

/* KDF：HMAC-SHA256(K_sym, d_seed || EID) → new_key[32] */
int pqzk_kdf(const uint8_t K_sym[32], const uint8_t d_seed[32],
             const uint8_t *eid, size_t eid_len, uint8_t new_key[32]);

/* 安全随机数 */
int pqzk_rand_bytes(uint8_t *out, size_t len);

/* ---- 代数采样 ---- */

/*
 * SampleGauss_σ：从 SHAKE-256 扩展流中采样离散高斯多项式向量
 * 使用 CDT 方法，确定性输入→确定性输出
 * sigma = PQ_ZK_SIGMA_PUB
 */
void pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len,
                            poly_vec_t *out);

/*
 * SampleInBall_κ：从哈希输出确定性生成稀疏挑战多项式
 * 输出：‖c‖₁ = κ，系数 ∈ {-1, 0, 1}
 * 已移除拒绝采样，确保恒定时间
 */
void pqzk_sample_in_ball(const uint8_t hash[32], poly_t *c);

/*
 * Parse_{R_q}：PRF 字节流 → 均匀分布多项式向量（系数 ∈ [0, q-1]）
 * 用于生成 M_mask
 */
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len,
                          poly_vec_t *out);

/* ---- 矩阵-向量乘法 ---- */

/*
 * 从种子确定性生成公共矩阵 A（k×k 维，SHAKE-256 扩展）
 * A[i][j] 为 N 维多项式，系数 ∈ [0, q-1]
 * 存储格式：A_flat[i*K+j] 为第 (i,j) 个多项式
 */
void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows,
                        int k_rows);

/*
 * 矩阵-向量乘法：result = A · v mod q
 * A_rows: k 个 poly_vec_t，A_rows[i] 是第 i 行
 * v: 输入向量（poly_vec_t，K 个多项式）
 * result: 输出向量（poly_vec_t）
 */
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v,
                       poly_vec_t *result);

/*
 * 向量数乘（标量多项式 × 向量）：result = S · c mod q
 * S: poly_vec_t（K 个多项式）
 * c: poly_t（标量多项式，系数 ∈ {-1,0,1}）
 * 利用三进制特性转化为加减法，无乘法器
 */
void pqzk_vec_scalar_mul(const poly_vec_t *S, const poly_t *c,
                          poly_vec_t *result);

/* 向量加法：result = a + b mod q */
void pqzk_vec_add(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result);

/* 向量减法：result = a - b mod q */
void pqzk_vec_sub(const poly_vec_t *a, const poly_vec_t *b,
                   poly_vec_t *result);

/* ---- nvram 文件操作 ---- */

/* eUICC 内部状态文件格式 */
#define NVRAM_EID_LEN       16
#define NVRAM_SKEY_LEN      PQ_ZK_POLYVEC_BYTES
#define NVRAM_SYM_LEN       32
#define NVRAM_TEE_LEN       32
#define NVRAM_DSEED_LEN     32
#define NVRAM_YSEC_LEN      PQ_ZK_POLYVEC_BYTES

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];                  /* "PQZK" */
    uint8_t  eid[NVRAM_EID_LEN];
    uint8_t  sk_s[NVRAM_SKEY_LEN];     /* 长期私钥 S */
    uint8_t  k_sym[NVRAM_SYM_LEN];     /* 对称密钥 K_sym */
    uint8_t  k_tee[NVRAM_TEE_LEN];     /* TEE-eUICC 总线密钥 */
    uint8_t  d_seed[NVRAM_DSEED_LEN];  /* KDF 派生种子 */
    uint64_t ctr_local;                /* 物理计数器 */
    uint8_t  y_sec[NVRAM_YSEC_LEN];    /* 会话盲化因子（严禁外泄） */
    uint8_t  y_sec_valid;              /* y_sec 有效标志 */
    uint8_t salt[32];                  /* 生物特征盐，由 TEE 传入 */
    uint8_t cred_kyc[64];              /* KYC 凭证，注册时注入 */
    uint8_t  _pad[7];
} nvram_state_t;

/* 从 nvram_dir 读取状态，返回 0 成功，-1 失败 */
int nvram_read(const char *nvram_dir, nvram_state_t *state);

/* 原子写入（tmpfile + fsync + rename）*/
int nvram_write_atomic(const char *nvram_dir, const nvram_state_t *state);

/* 只更新计数器和 K_sym（两者必须原子绑定） */
int nvram_update_ctr_and_key(const char *nvram_dir, uint64_t new_ctr,
                              const uint8_t new_k_sym[32]);

/* 全局公共矩阵种子（跨端固定） */
extern const uint8_t PQZK_MATRIX_A_SEED[32];

/* q 值（官方头文件未定义数值常量，此处补充供内部运算使用） */
#ifndef PQ_ZK_Q_VAL
#define PQ_ZK_Q_VAL 3329
#endif

#ifdef __cplusplus
}
#endif

#endif /* PQZK_INTERNAL_H */