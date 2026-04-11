/**
 * @file pq_zk_esim.h
 * @brief PQ-ZK-eSIM 全栈工程核心接口与代数标准 (4.0)
 * @note 本文件为跨端一致性最高准则，严禁私自修改参数定义或内存对齐方式。
 * * 编译环境约束：
 * - 依赖：liboqs (Kyber-768 最新版 clone)
 * - CMake >= 3.22
 * - Android NDK r26d (LTS), Min API 28
 */

#ifndef PQ_ZK_ESIM_H
#define PQ_ZK_ESIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* pqzk_merkle.h 包含 merkle_tree_t / merkle_path_t，
 * 供 TEE_GenerateAuthToken 参数使用（内部接口） */
#include "pqzk_merkle.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* 宏定义与密码学原语参数 (基于 Kyber-768 与规范要求)                        */
/* ========================================================================= */
#define PQ_ZK_N 256                     // 多项式环阶数
#define PQ_ZK_K 3                       // Kyber-768 对应的模块维度
#define PQ_ZK_SEED_BYTES 32             // 强制 256-bit 种子长度 (SHA-256 / AES-256)
#define PQ_ZK_TEE_KEY_BYTES 32          // TEE 密钥的长度约束,规范 JNI 层的传参长度
#define PQ_ZK_MAC_BYTES 32              // HMAC-SHA256 输出长度
#define PQ_ZK_CHALLENGE_WEIGHT 26       // 稀疏挑战多项式非零系数个数 (kappa)

// [新增] 大噪声淹没实验参数 (算法师需据此编写测试桩)
#define PQ_ZK_ETA_S 2              // Kyber-768 私钥无穷范数边界
#define PQ_ZK_RENYI_GAMMA 2        // Rényi 散度安全系数
// sigma_pub >= gamma * eta_s * kappa = 2 * 2 * 26 = 104
#define PQ_ZK_SIGMA_PUB 104.0      // 外部盲化因子高斯标准差

// beta_final 必须小于 q/2 (1664)，设定截断参数 tau = 12
// beta_pub = 12 * 104 = 1248。最大理论边界 = 1248 + 1(y_sec) + 52(S*c) = 1301 < 1664
#define PQ_ZK_BETA_FINAL 1301      // 服务器防溢出无穷范数上界阈值
// 完整公钥序列化长度 (32字节种子 + 3*256*12bit系数)
#define PQ_ZK_PUBLICKEY_BYTES 1184
// [新增] 内存安全红线：跨端 FFI/JNI 调用时强制约束的 Buffer 长度
// 假设采用最直接的 16-bit 小端序扁平化: 3(k) * 256(N) * 2(bytes) = 1536 字节
#define PQ_ZK_POLYVEC_BYTES 1536
#define PQ_ZK_POLY_BYTES 512 // 256(N) * 2(bytes)
/* ========================================================================= */
/* 错误码枚举                                                                */
/* ========================================================================= */
typedef enum {
    PQ_ZK_SUCCESS = 0,
    PQ_ZK_ERR_MAC_FAIL = -1,            // MAC 完整性校验失败
    PQ_ZK_ERR_CHALLENGE_WEIGHT = -2,    // 扩展挑战 c_agg 汉明权重或系数校验失败
    PQ_ZK_ERR_NORM_BOUND = -3,          // 代数响应范数边界检查失败 (溢出或裸露)
    PQ_ZK_ERR_INVALID_PARAM = -4,       // 输入参数无效
    PQ_ZK_ERR_NOT_INITIALIZED = -5,     //nvram 未初始化或 magic 校验失败
    PQ_ZK_ERR_YSEC_CONSUMED = -6        // y_sec 已使用或未生成，禁止重复调用
} PQ_ZK_ErrorCode;

/* ========================================================================= */
/* 核心代数数据结构                                                          */
/* ========================================================================= */

/**
 * @brief [新增] 单个多项式结构 (映射至环 R_q)
 * @note 专用于标量多项式，如扩展挑战 c_agg。强制采用小端序存储。
 */
typedef struct {
    int16_t coeffs[PQ_ZK_N];
} poly_t;

typedef struct {
    uint16_t beta_final;   // 无穷范数上界
    uint16_t beta_min;     // 欧几里得范数下界
} beta_params_t;

/**
 * @brief 多项式向量抽象结构 (映射至环 R_q^m)
 * @note 用于私钥 S、响应 z、盲化因子 y 等。JNI 传递时必须展平为一维 byte[]。
 */
typedef struct {
    int16_t coeffs[PQ_ZK_K * PQ_ZK_N];
} poly_vec_t;

/* ========================================================================= */
/* 默认范数边界参数
 *
 * 推导：
 *   beta_final = tau(12) * sigma_pub(104) + eta_s(2) + eta_s(2)*kappa(26)
 *              = 1248 + 2 + 52 = 1302，取保守值 1301
 *   beta_min   基于 y_pub 期望 L2 范数下界，确保 y_pub=0 时验证被拒绝
 *
 * 供 C 测试文件、Python ctypes、Android JNI 统一使用。
 * ========================================================================= */
#define PQZK_DEFAULT_BETA_PARAMS \
    ((beta_params_t){ .beta_final = PQ_ZK_BETA_FINAL, .beta_min = 2735 })

/* ========================================================================= */
/* 统一 API 黑盒声明 (阶段调用基准)                                          */
/* ========================================================================= */

/**
 * @brief [阶段零] 生成长期公私钥对
 * @param pk_t [out] 服务器存储的序列化公钥 T (包含矩阵 A 的种子与多项式向量 T)
 * @param sk_s [out] eUICC 内部存储的长期私钥 S
 */
void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s);

// [补充] 单多项式序列化（供 TEE 计算 AuthToken 使用）
void PQC_EncodePoly(const poly_t *in_poly, uint8_t *out_bytes);

// [补充] 单多项式反序列化（供 JNI 层重构 c_agg 使用）
void PQC_DecodePoly(const uint8_t *in_bytes, poly_t *out_poly);

/**
 * @brief [阶段零] eUICC 状态初始化
 * @note 将设备标识、私钥、对称密钥等安全写入指定的工作目录。
 * @param nvram_dir [in] [新增] eUICC 安全存储的挂载目录路径 (绝对路径)
 */
void PQC_eUICC_Init(const char* nvram_dir, const uint8_t* eid, size_t eid_len,
                    const poly_vec_t* sk_s,
                    const uint8_t* k_sym, size_t k_sym_len,
                    uint64_t initial_ctr,
                    const uint8_t* k_tee, size_t k_tee_len,
                    const uint8_t* salt,
                    const uint8_t* cred_kyc, size_t cred_kyc_len  );
/**
 * @brief [通用标准] 多项式序列化
 * @note 强制采用小端序 (Little-Endian) 和固定位宽对齐，供后端 FFI 调用以验证完整性。
 * @param in_poly [in] 输入的代数多项式向量
 * @param out_bytes [out] 输出的扁平化字节流
 */
void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes);

/**
 * @brief [新增] [通用标准] 多项式向量反序列化 (Decode)
 * @note 跨端联调的生命线。用于将后端 Python 或 JNI 传入的字节流重构为代数对象。
 * @param in_bytes [in] 长度必须为 PQ_ZK_POLYVEC_BYTES
 */
void PQC_DecodePolyVec(const uint8_t *in_bytes, poly_vec_t *out_poly);


/**
 * @brief [阶段一] LPA 外部盲化因子预计算
 * @param W_pub [out] LPA 外部承诺 W_pub = A * y_pub (mod q)
 * @param seed_y [out] LPA 生成的伪随机种子 s_pub
 */
void PQC_PreCompute(poly_vec_t *W_pub, uint8_t seed_y[PQ_ZK_SEED_BYTES]);

/**
 * @brief [阶段五] LPA 恢复外部大方差盲化因子
 * @param seed_y [in] 预计算阶段生成的伪随机种子 s_pub
 * @param y_pub [out] 重新生成的离散高斯分布外部盲化因子 y_pub
 */
void PQC_RegenerateYpub(const uint8_t seed_y[PQ_ZK_SEED_BYTES], poly_vec_t *y_pub);

/**
 * @brief [阶段一] eUICC 内部承诺生成 (安全修正版)
 * @note y_sec 必须安全存储在内部，绝不输出。K_sym 与 ctr 由底层内部读取。
 * @param W_sec [out] 内部承诺 W_sec = A * y_sec (mod q)
 * @param MAC_W [out] 内部防篡改认证码 MAC(K_sym, Encode(W_sec) || Serialize(ctr_local))
 */
void PQC_eUICC_Commit(const char* nvram_dir, poly_vec_t *W_sec, uint8_t MAC_W[PQ_ZK_MAC_BYTES]);

/**
 * @brief [阶段二] 挑战生成 (LPA 多维挑战展开)
 * @param comm_W [in] 聚合后的总承诺 W
 * @param nonce [in] 服务器下发的轻量级挑战种子 c_seed
 * @param c_agg [out] 扩展的高维稀疏挑战标量多项式
 */
void PQC_GenChallenge(const poly_vec_t *comm_W, const uint8_t nonce[PQ_ZK_SEED_BYTES],
                      poly_t *c_agg);

/**
 * @brief [阶段三] TEE 生物鉴权与授权令牌签发（v4.0）
 *
 * 模拟环境：调用即视为活体验证通过。
 * ctr_local 严禁上层传入，内部从 nvram 读取。
 *
 * @param nvram_dir      eUICC 非易失存储路径（只读）
 * @param c_agg          扩展挑战多项式
 * @param R_bio          TEE 存储的静态生物特征根（32字节）
 * @param tree           TEE 本地完整 Merkle 树
 * @param M1             服务器下发的叶子索引
 * @param k_tee          K_TEE-eUICC（32字节）
 * @param R_dynamic_out  [out] 动态验证根
 * @param M2_out         [out] Merkle 验证路径
 * @param AuthToken_out  [out] 授权令牌（32字节）
 */
PQ_ZK_ErrorCode TEE_GenerateAuthToken(
        const char          *nvram_dir,
        const poly_t        *c_agg,
        const uint8_t        R_bio[PQ_ZK_MAC_BYTES],
        const merkle_tree_t *tree,
        uint32_t             M1,
        const uint8_t        k_tee[PQ_ZK_TEE_KEY_BYTES],
        uint8_t              R_dynamic_out[PQ_ZK_SEED_BYTES],
        merkle_path_t       *M2_out,
        uint8_t              AuthToken_out[PQ_ZK_MAC_BYTES]
);

PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(
        const char*    nvram_dir,
        const poly_t  *c_agg,
        const uint8_t  c_seed[PQ_ZK_SEED_BYTES],
        const uint8_t  R_dynamic[PQ_ZK_SEED_BYTES],
        const uint8_t  hash_M2[PQ_ZK_MAC_BYTES],
        const uint8_t  AuthToken[PQ_ZK_MAC_BYTES],
        poly_vec_t    *z_sec_masked);

void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked,
                       const poly_vec_t *y_pub,
                       poly_vec_t *resp_z);

void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES],
                      const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                      uint64_t ctr_session,
                      const uint8_t R_dynamic[PQ_ZK_SEED_BYTES],
                      poly_vec_t *M_mask);

PQ_ZK_ErrorCode PQC_VerifyEngine(
        const uint8_t    mat_A_seed[32],
        const uint8_t    pk_t[PQ_ZK_PUBLICKEY_BYTES],
        const poly_vec_t *comm_W,
        const poly_vec_t *resp_z,
        const uint8_t    nonce_s[32],
        const uint8_t    R_dynamic[32],
        const poly_vec_t *M_mask,
        const beta_params_t *beta_params);

#ifdef __cplusplus
}
#endif

/**
 * @brief [阶段四] 掩码协同计算 (eUICC 极速盲化 - 核心安全禁区)
 */
PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(const char* nvram_dir, const poly_t *c_agg, const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                                      const uint8_t R_dynamic[PQ_ZK_SEED_BYTES], const uint8_t hash_M2[PQ_ZK_MAC_BYTES],
                                      const uint8_t AuthToken[PQ_ZK_MAC_BYTES], poly_vec_t *z_sec_masked);
/**
 * @brief [阶段五] LPA 大噪声聚合
 * @param z_sec_masked [in] eUICC 输出的掩码响应
 * @param y_pub [in] 重新生成的大方差外部盲化因子
 * @param resp_z [out] 最终聚合响应 z = z_sec_masked + y_pub (mod q)
 */
void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked, const poly_vec_t *y_pub,
                       poly_vec_t *resp_z);

/**
 * @brief [阶段六通用] 独立端到端掩码生成引擎
 */
void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES], const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                      uint64_t ctr_session, const uint8_t R_dynamic[PQ_ZK_SEED_BYTES], poly_vec_t *M_mask);

/**
 * @brief [阶段六] 服务器验证引擎
 */
PQ_ZK_ErrorCode PQC_VerifyEngine(const uint8_t mat_A_seed[32],
                                 const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
                                 const poly_vec_t *comm_W, const poly_vec_t *resp_z,
                                 const uint8_t nonce_s[32],
                                 const uint8_t R_dynamic[32],
                                 const poly_vec_t *M_mask,
                                 const beta_params_t *beta_params);

#ifdef __cplusplus
}
#endif

#endif // PQ_ZK_ESIM_H