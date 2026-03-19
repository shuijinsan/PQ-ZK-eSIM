/**
 * @file pq_zk_esim.h
 * @brief PQ-ZK-eSIM 全栈工程核心接口与代数标准 (3.0)
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

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* 宏定义与密码学原语参数 (基于 Kyber-768 与规范要求)                        */
/* ========================================================================= */
#define PQ_ZK_N 256                     // 多项式环阶数
#define PQ_ZK_K 3                       // Kyber-768 对应的模块维度
#define PQ_ZK_SEED_BYTES 32             // 强制 256-bit 种子长度 (SHA-256 / AES-256)
#define PQ_ZK_MAC_BYTES 32              // HMAC-SHA256 输出长度
#define PQ_ZK_CHALLENGE_WEIGHT 39       // 稀疏挑战多项式非零系数个数 (kappa)

// [修正] 完整公钥序列化长度 (32字节种子 + 3*256*12bit系数)
#define PQ_ZK_PUBLICKEY_BYTES 1184

/* ========================================================================= */
/* 错误码枚举                                                                */
/* ========================================================================= */
typedef enum {
    PQ_ZK_SUCCESS = 0,
    PQ_ZK_ERR_MAC_FAIL = -1,            // MAC 完整性校验失败
    PQ_ZK_ERR_CHALLENGE_WEIGHT = -2,    // 扩展挑战 c_agg 汉明权重或系数校验失败
    PQ_ZK_ERR_NORM_BOUND = -3,          // 代数响应范数边界检查失败 (溢出或裸露)
    PQ_ZK_ERR_INVALID_PARAM = -4        // 输入参数无效
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

/**
 * @brief 多项式向量抽象结构 (映射至环 R_q^m)
 * @note 用于私钥 S、响应 z、盲化因子 y 等。JNI 传递时必须展平为一维 byte[]。
 */
typedef struct {
    int16_t coeffs[PQ_ZK_K * PQ_ZK_N];  
} poly_vec_t;

/**
 * @brief 物理上下文结构体
 * @note 【安全红线】__attribute__((packed)) 仅用于内存紧凑。
 * 严禁直接对本结构体指针执行 Hash！生成 H_ctx 前，必须强行调用 
 * PQC_SerializeContext 进行小端序按位序列化，否则跨端必死。
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp;                 // 采集时间戳
    int32_t latitude;                   // 纬度 (实际经纬度 * 10^6 存储，规避浮点数端序差异)
    int32_t longitude;                  // 经度 (实际经纬度 * 10^6 存储)
    char desc[64];                      // 会话描述字符串
} ContextData;

/* ========================================================================= */
/* 统一 API 黑盒声明 (阶段调用基准)                                          */
/* ========================================================================= */

/**
 * @brief [阶段零] 生成长期公私钥对
 * @param pk_t [out] 服务器存储的序列化公钥 T (包含矩阵 A 的种子与多项式向量 T)
 * @param sk_s [out] eUICC 内部存储的长期私钥 S
 */
void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s);

/**
 * @brief [阶段零] eUICC 状态初始化
 * @note 将设备标识、私钥、对称密钥等安全写入指定的工作目录。
 * @param nvram_dir [in] [新增] eUICC 安全存储的挂载目录路径 (绝对路径)
 */
void PQC_eUICC_Init(const char* nvram_dir, const uint8_t* eid, size_t eid_len,
                    const poly_vec_t* sk_s,
                    const uint8_t* k_sym, size_t k_sym_len,
                    uint64_t initial_ctr,
                    const uint8_t* k_tee, size_t k_tee_len);
/**
 * @brief [通用标准] 多项式序列化
 * @note 强制采用小端序 (Little-Endian) 和固定位宽对齐，供后端 FFI 调用以验证完整性。
 * @param in_poly [in] 输入的代数多项式向量
 * @param out_bytes [out] 输出的扁平化字节流
 */
void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes);
/**
 * @brief [通用标准] 上下文确定性序列化
 * @note 必须通过硬编码位移映射为小端序字节流，严禁直接哈希结构体指针。
 * @param ctx [in] 物理上下文结构体
 * @param ctx_bytes [out] 输出的确定性字节流 (供后续 Hash 生成 H_ctx)
 */
void PQC_SerializeContext(const ContextData *ctx, uint8_t *ctx_bytes);
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
 * @param MAC_W [out] 内部防篡改认证码 MAC(K_sym, W_sec || ctr_current)
 */
void PQC_eUICC_Commit(poly_vec_t *W_sec, uint8_t MAC_W[PQ_ZK_MAC_BYTES]);

/**
 * @brief [阶段二] 挑战生成 (LPA 多维挑战展开)
 * @param comm_W [in] 聚合后的总承诺 W
 * @param nonce [in] 服务器下发的轻量级挑战种子 c_seed
 * @param H_ctx [in] 物理上下文哈希
 * @param c_agg [out] [修正类型] 扩展的高维稀疏挑战标量多项式
 */
void PQC_GenChallenge(const poly_vec_t *comm_W, const uint8_t nonce[PQ_ZK_SEED_BYTES], 
                      const uint8_t H_ctx[PQ_ZK_SEED_BYTES], poly_t *c_agg);

/**
 * @brief [阶段四] 掩码协同计算 (eUICC 极速盲化 - 核心安全禁区)
 * @note JNI 层必须传入挂载目录，底层据此执行文件级的原子性 rename 更新。
 * @param nvram_dir [in] [新增] eUICC 安全存储的挂载目录路径 (用于读取 y_sec 并原子步进状态)
 * @param c_agg [in] [修正类型] 扩展挑战标量多项式
 */
void PQC_ComputeZ_and_Mask(const char* nvram_dir, const poly_t *c_agg, const uint8_t c_seed[PQ_ZK_SEED_BYTES], 
                           const uint8_t H_ctx[PQ_ZK_SEED_BYTES], const uint8_t hash_M2[PQ_ZK_MAC_BYTES], 
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
 * @note 供 Python 服务器远端解盲时调用，确保两端掩码生成逻辑与输出多项式一致。
 * @param K_sym [in] 预共享长期对称密钥
 * @param c_seed [in] 下发的挑战种子
 * @param ctr_session [in] Redis 匹配出的滑动窗口计数器
 * @param H_ctx [in] 上下文哈希
 * @param M_mask [out] 生成的伪随机掩码多项式
 */
void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES], const uint8_t c_seed[PQ_ZK_SEED_BYTES], 
                      uint64_t ctr_session, const uint8_t H_ctx[PQ_ZK_SEED_BYTES], poly_vec_t *M_mask);

/**
 * @brief [阶段六] 服务器验证引擎
 * @param mat_A_seed [in] 公共矩阵 A 的生成种子
 * @param pk_t [in] 从数据库提取的用户完整序列化公钥 T
 * @param comm_W [in] 接收到的 LPA 聚合总承诺 W
 * @param resp_z [in] 接收到的最终聚合响应 z
 * @param nonce_s [in] 从 Redis 提取的挑战种子 c_seed
 * @param H_ctx [in] 接收到的上下文哈希
 * @param M_mask [in] 调用 PQC_GenerateMask 拿到的掩码
 * @param beta_params [in] 动态传入的边界检查参数配置结构 (防溢出及裸露阈值)
 * @return PQ_ZK_ErrorCode 验证结果
 */
PQ_ZK_ErrorCode PQC_VerifyEngine(const uint8_t mat_A_seed[PQ_ZK_SEED_BYTES], 
                                 const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], 
                                 const poly_vec_t *comm_W, const poly_vec_t *resp_z, 
                                 const uint8_t nonce_s[PQ_ZK_SEED_BYTES], 
                                 const uint8_t H_ctx[PQ_ZK_SEED_BYTES], 
                                 const poly_vec_t *M_mask, const void *beta_params);

#ifdef __cplusplus
}
#endif

#endif // PQ_ZK_ESIM_H
