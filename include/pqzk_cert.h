/*
 * pqzk_cert.h — 模拟证书体系头文件
 *
 * 解决 GSMA 证书验证链断裂问题：
 *   所有证书签发/验证/CredKYC/ML-DSA 模拟函数均在此声明，
 *   实现在 pqzk_cert_sim.c 中，使用统一的模拟根 CA 密钥。
 */

#ifndef PQZK_CERT_H
#define PQZK_CERT_H

#include "pq_zk_esim.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量定义（与 pqzk_cert_sim.c 严格对应）
 * ================================================================ */

/* 模拟环境：根 CA 公钥长度（对称体系中等于 SK 长度） */
#define PQZK_GSMA_CA_PK_BYTES   32

/* ML-DSA 签名长度（模拟：只用前32字节，其余补零） */
#define PQZK_MLDSA_SIG_BYTES    64

/* ML-KEM 公钥长度（模拟：与 PQ_ZK_PUBLICKEY_BYTES 一致） */
#define PQZK_CERT_MLKEM_PK_BYTES     PQ_ZK_PUBLICKEY_BYTES

/* 运营商标识长度 */
#define PQZK_MNO_ID_BYTES       16

/* 证书序列化字节数：mno_id(16) + mno_sk(32) + mno_pk(32) + ca_sig(32) = 112 */
#define PQZK_CERT_BYTES         (PQZK_MNO_ID_BYTES + 32 + 32 + 32)

/* ================================================================
 * 证书结构体
 * ================================================================ */
typedef struct {
    uint8_t mno_id[PQZK_MNO_ID_BYTES]; /* 运营商标识 */
    uint8_t mno_sk[32];                  /* 运营商私钥（模拟环境存储） */
    uint8_t mno_pk[32];                  /* 运营商公钥（mno_sk 哈希派生） */
    uint8_t ca_sig[32];                  /* GSMA CA 对 (mno_id||mno_pk) 的签名 */
} pqzk_cert_t;

/* ================================================================
 * GSMA 根 CA 接口
 * ================================================================ */

/* 获取模拟根 CA 公钥（所有调用方必须使用此函数，禁止硬编码） */
void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES]);

/* ================================================================
 * 证书接口
 * ================================================================ */

/* 为 MNO 签发证书（由 GSMA CA 签名） */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out);

/* 为目标 MNO 签发证书（私钥由 domain_id 确定性派生） */
int PQZK_Cert_IssueForMNO(const uint8_t  domain_id[PQZK_MNO_ID_BYTES],
                            pqzk_cert_t   *cert_out);

/* 验证证书（使用内置根 CA 公钥） */
int PQZK_Cert_Verify(const pqzk_cert_t *cert);

/* 验证证书（使用指定根 CA 公钥，FIX-D 核心） */
int PQZK_Cert_VerifyWithRootPK(const pqzk_cert_t *cert,
                                 const uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES]);

/* 证书序列化/反序列化 */
void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t cert_bytes[PQZK_CERT_BYTES]);

int PQZK_Cert_Deserialize(const uint8_t cert_bytes[PQZK_CERT_BYTES],
                            pqzk_cert_t  *cert_out);

/* ================================================================
 * CredKYC 接口
 * ================================================================ */

/* 签发 KYC 凭证：HMAC-SHA256(mno_sk, eid || R_bio) */
int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[32]);

/* 验证 KYC 凭证（从 cert_a 中提取 mno_sk） */
int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[32]);

/* ================================================================
 * 模拟 ML-DSA 接口（HMAC-SHA256 替代，接口与真实 ML-DSA 兼容）
 * ================================================================ */

/* 签名：HMAC-SHA256(GSMA_CA_SK, data) */
int PQZK_MLDSA_Sign(const uint8_t sk[32],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES]);

/* 验证：重新计算并比对 */
int PQZK_MLDSA_Verify(const uint8_t pk[32],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_CERT_H */