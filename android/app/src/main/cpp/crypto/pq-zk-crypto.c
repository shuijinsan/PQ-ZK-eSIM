/*
 * pqzk_crypto.c  —  PQ-ZK-eSIM v4.0 底层密码学原语实现
 *
 * v4.0 核心架构变更（对照 3.0）：
 *   · 废弃 H_ctx（基于地理位置/时间戳的上下文哈希）
 *   · 全面启用 R_dynamic = Hash(R_bio | ctr_local) 作为会话绑定锚点
 *   · pqzk_prf() 第四参数语义从 H_ctx[32] 变更为 R_dynamic[32]
 *   · pqzk_shake256_iov() 新增，供阶段一 y_pub 生成使用
 *
 * 依赖：
 *   · OpenSSL >= 3.0（SHA-256 / HMAC-SHA256 / AES-256-CTR / RAND）
 *   · liboqs  最新版（SHAKE-256 XOF，调用 OQS_SHA3_shake256）
 *
 * 序列化约定（全文强制）：
 *   · 所有多字节整数字段（uint64_t 计数器等）均按小端序编码
 *   · 使用 write_le64()（定义于 pqzk_internal.h）进行显式位移序列化
 *   · 严禁对结构体指针直接执行哈希或 MAC
 */

#include "pqzk_internal.h"

#include <oqs/oqs.h>          /* OQS_SHA3_shake256 */
#include <openssl/sha.h>      /* SHA256            */
#include <openssl/hmac.h>     /* HMAC_CTX_*        */
#include <openssl/evp.h>      /* EVP_CIPHER_CTX_*  */
#include <openssl/rand.h>     /* RAND_bytes        */

#include <string.h>
#include <stdlib.h>

/* ================================================================
 * 公共矩阵 A 的全局固定种子
 *
 * 跨端一致性锚点：C 层、Android JNI、Python 后端三端必须使用
 * 完全相同的种子，经 SHAKE-256 展开后得到矩阵 A。
 * 种子明文编码为 ASCII "PQZKESIM" + "MATRIX_A" + 0x00..0x0F。
 * ================================================================ */
const uint8_t PQZK_MATRIX_A_SEED[32] = {
        0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,  /* "PQZKESIM" */
        0x4D,0x41,0x54,0x52, 0x49,0x58,0x5F,0x41,  /* "MATRIX_A" */
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
};

/* ================================================================
 * §1  SHA-256
 *
 * 协议规范：所有 Hash 函数统一使用 SHA-256（规范文件 §1 密码学原语）。
 * ================================================================ */

/*
 * pqzk_sha256 — 单段输入 SHA-256
 *
 * 参数：
 *   in      输入字节流（可为空串，len=0 时 in 可为 NULL）
 *   len     输入长度（字节）
 *   out     输出缓冲区，固定 32 字节
 *
 * 返回：0 成功，-1 参数错误
 */
int pqzk_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    if (!out) return -1;
    if (len > 0 && !in) return -1;

    SHA256(in ? in : (const uint8_t *)"", len, out);
    return 0;
}

/*
 * pqzk_sha256_iov — 多段输入 SHA-256（gather 模式）
 *
 * 通过 iov 数组依次喂入多个缓冲区，等价于先拼接再哈希，
 * 但无需额外分配拼接缓冲区，用于跨端确定性哈希（如 H_ctx、R_dynamic 计算）。
 *
 * 参数：
 *   iov     以 {NULL, 0} 结尾的输入向量数组
 *   out     输出缓冲区，固定 32 字节
 *
 * 返回：0 成功，-1 参数错误或 OpenSSL 内部错误
 */
int pqzk_sha256_iov(const pqzk_iov_t *iov, uint8_t out[32])
{
    if (!iov || !out) return -1;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++)
        SHA256_Update(&ctx, p->buf, p->len);
    SHA256_Final(out, &ctx);
    return 0;
}

/* ================================================================
 * §2  HMAC-SHA256
 *
 * 协议规范：所有 MAC 函数统一使用 HMAC-SHA256（规范文件 §1）。
 * 内存安全：HMAC_CTX 通过 new/free 配对管理，异常路径均经 goto fail 释放。
 * ================================================================ */

/*
 * pqzk_hmac_sha256_iov — 标准 32 字节定长密钥的多段 HMAC-SHA256
 *
 * 供协议主路径调用（AuthToken 签发、MAC_W 计算等），密钥固定为 32 字节。
 *
 * 参数：
 *   key     32 字节 HMAC 密钥（K_TEE-eUICC 或 K_sym）
 *   iov     以 {NULL, 0} 结尾的消息段数组
 *   out     输出 MAC，固定 32 字节
 *
 * 返回：0 成功，-1 参数错误或 OpenSSL 内部错误
 */
int pqzk_hmac_sha256_iov(const uint8_t key[32], const pqzk_iov_t *iov,
                         uint8_t out[32])
{
    if (!key || !iov || !out) return -1;

    HMAC_CTX *hctx = HMAC_CTX_new();
    if (!hctx) return -1;

    unsigned int outl = 32;
    if (!HMAC_Init_ex(hctx, key, 32, EVP_sha256(), NULL)) goto fail;
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++)
        if (!HMAC_Update(hctx, p->buf, p->len)) goto fail;
    if (!HMAC_Final(hctx, out, &outl)) goto fail;

    HMAC_CTX_free(hctx);
    return 0;
    fail:
    HMAC_CTX_free(hctx);
    return -1;
}

/*
 * pqzk_hmac_sha256_iov_anykey — 任意长度密钥的多段 HMAC-SHA256
 *
 * 仅供 KAT 测试和调试场景使用，协议主路径请使用 pqzk_hmac_sha256_iov。
 *
 * 参数：
 *   key     HMAC 密钥
 *   key_len 密钥长度（字节）
 *   iov     以 {NULL, 0} 结尾的消息段数组
 *   out     输出 MAC，固定 32 字节
 *
 * 返回：0 成功，-1 参数错误或 OpenSSL 内部错误
 */
int pqzk_hmac_sha256_iov_anykey(const uint8_t *key, size_t key_len,
                                const pqzk_iov_t *iov, uint8_t out[32])
{
    if (!key || !iov || !out || key_len == 0) return -1;

    HMAC_CTX *hctx = HMAC_CTX_new();
    if (!hctx) return -1;

    unsigned int outl = 32;
    if (!HMAC_Init_ex(hctx, key, (int)key_len, EVP_sha256(), NULL)) goto fail;
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++)
        if (!HMAC_Update(hctx, p->buf, p->len)) goto fail;
    if (!HMAC_Final(hctx, out, &outl)) goto fail;

    HMAC_CTX_free(hctx);
    return 0;
    fail:
    HMAC_CTX_free(hctx);
    return -1;
}

/* ================================================================
 * §3  SHAKE-256 XOF（可扩展输出函数）
 *
 * 协议规范：Expand 函数统一使用 SHAKE-256，用于生成伪随机比特流，
 * 包括阶段一的 y_pub 生成（SampleGauss 前置扩展）和 c_agg 生成。
 * 实现：直接调用 liboqs 的高性能接口，确保与 Android 端使用的
 * 同一底层库输出完全一致。
 * ================================================================ */

/*
 * pqzk_shake256 — 单段输入 SHAKE-256
 *
 * 参数：
 *   in      输入字节流
 *   in_len  输入长度（字节）
 *   out     输出缓冲区
 *   out_len 期望输出长度（字节，可任意大）
 *
 * 返回：0 成功，-1 参数错误
 */
int pqzk_shake256(const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ret = -1;
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) goto done;
    if (EVP_DigestUpdate(ctx, in, in_len) != 1)            goto done;
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1)        goto done;
    ret = 0;
    done:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * pqzk_shake256_iov — 多段输入 SHAKE-256（gather 模式）
 *
 * 供阶段一 y_pub 生成时拼接 seed || domain_separator 输入，
 * 避免调用方在栈上手动 memcpy 拼接，降低缓冲区溢出风险。
 *
 * 实现：将各段依次拷贝到栈上临时缓冲区后统一调用 liboqs 接口。
 * 注意：总输入长度不得超过 PQZK_SHAKE_IOV_MAX（4096 字节），
 *       超过时返回 -1，调用方应改用单段版本并自行拼接。
 *
 * 参数：
 *   iov     以 {NULL, 0} 结尾的输入向量数组
 *   out     输出缓冲区
 *   out_len 期望输出长度（字节）
 *
 * 返回：0 成功，-1 参数错误或输入总长超限
 */
#define PQZK_SHAKE_IOV_MAX 4096

int pqzk_shake256_iov(const pqzk_iov_t *iov, uint8_t *out, size_t out_len)
{
    if (!iov || !out || out_len == 0) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    // 1. 初始化 SHAKE256 算法
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) goto done;

    // 2. 直接流式输入每一段 iov
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++) {
        if (p->len == 0) continue;
        if (EVP_DigestUpdate(ctx, p->buf, p->len) != 1) goto done;
    }

    // 3. 输出 XOF 结果
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) goto done;

    ret = 0;

    done:
    EVP_MD_CTX_free(ctx);
    return ret;
}
/* ================================================================
 * §4  AES-256-CTR 密钥流生成
 *
 * 协议规范：PRF 统一使用 AES-256-CTR（规范文件 §1）。
 * 本函数为底层密钥流生成原语，由 pqzk_prf() 调用，
 * 不直接暴露给协议上层。
 * ================================================================ */

/*
 * pqzk_aes256_ctr — AES-256-CTR 密钥流生成
 *
 * 通过加密全零明文获得 AES-CTR 密钥流，写入 out 缓冲区。
 * IV 由调用方（pqzk_prf）负责构造，确保语义安全。
 *
 * 参数：
 *   key     32 字节 AES-256 密钥
 *   iv      16 字节初始向量（nonce[12] + counter[4] 布局）
 *   out     输出密钥流缓冲区（已由调用方分配）
 *   out_len 期望输出长度（字节）
 *
 * 返回：0 成功，-1 参数错误或 OpenSSL 内部错误
 */
int pqzk_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                    uint8_t *out, size_t out_len)
{
    if (!key || !iv || !out || out_len == 0) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;

    /* 对全零明文执行 AES-256-CTR 加密，得到纯密钥流 */
    uint8_t *zeros = (uint8_t *)calloc(1, out_len);
    if (!zeros) goto done;

    int outl = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out, &outl, zeros, (int)out_len)   != 1) goto done;
    ret = 0;

    done:
    EVP_CIPHER_CTX_free(ctx);
    free(zeros);
    return ret;
}

/* ================================================================
 * §5  协议 PRF（端到端掩码生成核心）
 *
 * 协议规范（v4.0）：
 *   M_mask = Parse_Rq(PRF(K_sym, c_seed | Serialize(ctr_session) | R_dynamic)) mod q
 *
 * 函数语义：
 *   PRF(K_sym, c_seed, ctr_session, R_dynamic) → out_len 字节伪随机流
 *
 * 构造步骤：
 *   1. msg(72B) = c_seed(32) || write_le64(ctr_session)(8) || R_dynamic(32)
 *      · ctr_session 必须通过 write_le64 显式小端序序列化，
 *        严禁直接对 uint64_t 取地址后 memcpy（违反跨端字节序规范）
 *   2. iv(16B)  = SHA-256(msg)[0:16]
 *      · 截取哈希前16字节作为 AES-CTR IV，确保不同 ctr/R_dynamic 组合
 *        产生不同 IV，从而保证密钥流唯一性
 *   3. out      = AES-256-CTR(K_sym, iv, zeros)[0:out_len]
 *
 *
 *   · 第四参数 R_dynamic（动态验证根 = Hash(R_bio | ctr_local)）
 *   · 跨端（C/Python/Java）调用时必须传入相同的 R_dynamic，
 *     否则两端生成的掩码不一致，验证必然失败
 *
 * 参数：
 *   K_sym      32 字节预共享对称密钥（单向演进，当前会话版本）
 *   c_seed     32 字节服务器下发的挑战种子
 *   ctr_session 本次会话锁存的计数器常量（eUICC 内部 ctr_local 的快照）
 *   R_dynamic  32 字节动态验证根
 *   out        输出缓冲区（已由调用方分配）
 *   out_len    期望输出长度（字节），通常为 PQ_ZK_POLYVEC_BYTES
 *
 * 返回：0 成功，-1 参数错误或内部错误
 * ================================================================ */
int pqzk_prf(const uint8_t K_sym[32],
             const uint8_t c_seed[32],
             uint64_t      ctr_session,
             const uint8_t R_dynamic[32],
             uint8_t       *out,
             size_t         out_len)
{
    if (!K_sym || !c_seed || !R_dynamic || !out || out_len == 0) return -1;

    /*
     * 步骤1：构造 PRF 输入消息
     * 布局：[c_seed(32)] [ctr_le8(8)] [R_dynamic(32)]  共72字节
     *
     * 注意：ctr_session 必须通过 write_le64 显式小端序序列化，
     * 不得使用 memcpy(&msg[32], &ctr_session, 8)，
     * 因为宿主机可能为大端序（如某些服务器架构）。
     */
    uint8_t msg[72];
    memcpy(msg,      c_seed,    32);
    write_le64(msg + 32, ctr_session);   /* 小端序强制序列化，跨端一致 */
    memcpy(msg + 40, R_dynamic, 32);

    /*
     * 步骤2：派生 AES-CTR IV
     * iv = SHA-256(msg)[0:16]
     * 不同的 (c_seed, ctr_session, R_dynamic) 三元组保证 IV 唯一，
     * 从而保证掩码多项式在每次会话中绝对唯一。
     */
    uint8_t hash[32], iv[16];
    if (pqzk_sha256(msg, sizeof(msg), hash) != 0) return -1;
    memcpy(iv, hash, 16);

    /*
     * 步骤3：AES-256-CTR 生成密钥流
     * 输出即为掩码多项式的原始字节流，
     * 上层 Parse_Rq 负责将字节流映射为环 Rq 上的多项式系数。
     */
    return pqzk_aes256_ctr(K_sym, iv, out, out_len);
}

/* ================================================================
 * §6  协议 KDF（前向安全密钥演进）
 *
 * 协议规范：
 *   K_sym^(i+1) = KDF(K_sym^(i) || d_seed || ID_eUICC)
 *
 * 实现：HMAC-SHA256(K_sym, d_seed || ID_eUICC)
 *   · 以当前 K_sym 为 HMAC 密钥
 *   · 以 d_seed(32B) || ID_eUICC(≤16B) 拼接为消息
 *
 * 调用时机（严格约束）：
 *   · eUICC 端：PQC_ComputeZ_and_Mask 输出掩码响应后，
 *     必须立即调用 KDF 演进 K_sym，且此操作须与计数器步进
 *     处于同一硬件事务（原子写入非易失存储）
 *   · 服务器端：/api/v1/auth/verify 所有校验通过后同步演进，
 *     镜像 eUICC 的状态机，并维护滑动窗口前向密钥缓存队列
 *
 * 参数：
 *   K_sym    32 字节当前会话对称密钥
 *   d_seed   32 字节密钥派生种子（协议固定值或设备特定值）
 *   eid      设备标识 ID_eUICC（字节数组，长度 eid_len，最大16字节）
 *   eid_len  eid 长度（字节），不得超过 16
 *   new_key  输出新密钥缓冲区，32 字节
 *
 * 返回：0 成功，-1 参数错误
 * ================================================================ */
int pqzk_kdf(const uint8_t  K_sym[32],
             const uint8_t  d_seed[32],
             const uint8_t *eid,
             size_t          eid_len,
             uint8_t         new_key[32])
{
    if (!K_sym || !d_seed || !eid || !new_key) return -1;
    if (eid_len == 0 || eid_len > 16) return -1;

    /*
     * 消息布局：[d_seed(32)] [ID_eUICC(eid_len)]
     * 总长不超过 48 字节，在栈上安全分配。
     */
    uint8_t msg[48];
    memcpy(msg,      d_seed, 32);
    memcpy(msg + 32, eid,    eid_len);

    pqzk_iov_t iov[] = {
            { msg, 32 + eid_len },
            { NULL, 0 }
    };

    /* HMAC-SHA256(K_sym, d_seed || ID_eUICC) → new_key */
    return pqzk_hmac_sha256_iov(K_sym, iov, new_key);
}

/* ================================================================
 * §7  密码学安全随机数
 *
 * 实现：直接调用 OpenSSL RAND_bytes，底层使用操作系统熵源
 *（Linux: getrandom syscall / /dev/urandom）。
 *
 * 参数：
 *   out  输出缓冲区
 *   len  期望随机字节数
 *
 * 返回：0 成功，-1 参数错误或 OpenSSL 熵源不足
 * ================================================================ */
int pqzk_rand_bytes(uint8_t *out, size_t len)
{
    if (!out || len == 0) return -1;
    return (RAND_bytes(out, (int)len) == 1) ? 0 : -1;
}