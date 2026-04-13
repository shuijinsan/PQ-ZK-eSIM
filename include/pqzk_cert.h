/*
 * pqzk_cert.h — PQ-ZK-eSIM v5.0
 * GSMA 证书链模拟（自签名，用于运营商切换验证）
 *
 * 协议对应：§5.1.5
 *   MNO_B 验证 Cert_A（MNO_A 的证书，GSMA Root CA 签发）
 *   MNO_B 验证 Cred_KYC（MNO_A 用 SK_MNO_A 签的用户 KYC 凭证）
 *
 * 模拟设计：
 *   · 用 HMAC-SHA256 模拟数字签名（替代 ECDSA/Dilithium）
 *   · GSMA Root CA 私钥 = 固定常量（模拟环境）
 *   · MNO_A 证书 = GSMA_ROOT 签名的 (MNO_A_ID || MNO_A_PK)
 *   · Cred_KYC  = MNO_A_SK 签名的 (EID || R_bio)
 *
 * 论文说明：
 *   "模拟环境中，我们用 HMAC-SHA256 模拟 GSMA 证书链的签名验证，
 *    真实部署中替换为 ECDSA P-256 或 Dilithium-3 即可，
 *    接口语义不变。"
 */

#ifndef PQZK_CERT_H
#define PQZK_CERT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 模拟证书/签名长度 */
#define PQZK_CERT_SIG_BYTES    32   /* HMAC-SHA256 输出 */
#define PQZK_CERT_BYTES        256  /* 证书总长（含签名） */
#define PQZK_MNO_ID_BYTES      16   /* 运营商标识长度 */
#define PQZK_MNO_PK_BYTES      32   /* 运营商公钥（模拟）长度 */

/*
 * pqzk_cert_t — 模拟运营商证书
 *
 * 真实格式：X.509 DER，由 GSMA Root CA 签发
 * 模拟格式：固定布局字节串，用 HMAC-SHA256 签名
 */
typedef struct {
    uint8_t mno_id[PQZK_MNO_ID_BYTES];   /* 运营商标识 */
    uint8_t mno_pk[PQZK_MNO_PK_BYTES];   /* 运营商公钥（模拟） */
    uint8_t signature[PQZK_CERT_SIG_BYTES]; /* GSMA Root CA 的签名 */
    uint8_t padding[PQZK_CERT_BYTES
                    - PQZK_MNO_ID_BYTES
                    - PQZK_MNO_PK_BYTES
                    - PQZK_CERT_SIG_BYTES];  /* 对齐填充 */
} pqzk_cert_t;

/*
 * PQZK_Cert_Issue — 模拟 GSMA Root CA 签发运营商证书
 *
 * 参数：
 *   mno_id    运营商标识（16字节）
 *   mno_pk    运营商公钥（32字节，模拟）
 *   cert_out  输出证书
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_pk[PQZK_MNO_PK_BYTES],
                     pqzk_cert_t  *cert_out);

/*
 * PQZK_Cert_Verify — 验证运营商证书（MNO_B 调用）
 *
 * 用 GSMA Root CA 公钥验证证书签名。
 *
 * 返回：0 验证通过，-1 验证失败
 */
int PQZK_Cert_Verify(const pqzk_cert_t *cert);

/*
 * PQZK_CredKYC_Issue — 模拟 MNO_A 签发 KYC 凭证
 *
 * Cred_KYC = Sign(SK_MNO_A, EID || R_bio)
 * 模拟实现：HMAC-SHA256(MNO_A_SK, EID || R_bio)
 *
 * 参数：
 *   mno_a_sk  MNO_A 的签名私钥（32字节，模拟）
 *   eid       设备标识
 *   R_bio     静态生物特征根
 *   cred_out  输出凭证（32字节）
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_CredKYC_Issue(const uint8_t mno_a_sk[32],
                         const uint8_t eid[16],
                         const uint8_t R_bio[32],
                         uint8_t       cred_out[PQZK_CERT_SIG_BYTES]);

/*
 * PQZK_CredKYC_Verify — 验证 KYC 凭证（MNO_B 调用）
 *
 * MNO_B 从 Cert_A 中提取 MNO_A 的公钥（模拟：即 mno_pk），
 * 验证 Cred_KYC 是否为 MNO_A 对 (EID || R_bio) 的合法签名。
 *
 * 参数：
 *   cert_a    MNO_A 的证书（含公钥）
 *   eid       设备标识
 *   R_bio     静态生物特征根
 *   cred_kyc  待验证的 KYC 凭证
 *
 * 返回：0 验证通过，-1 验证失败
 */
int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t      eid[16],
                          const uint8_t      R_bio[32],
                          const uint8_t      cred_kyc[PQZK_CERT_SIG_BYTES]);

/*
 * PQZK_Cert_Serialize — 将证书序列化为字节数组
 * PQZK_Cert_Deserialize — 将字节数组反序列化为证书结构体
 */
void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t buf[PQZK_CERT_BYTES]);
int  PQZK_Cert_Deserialize(const uint8_t buf[PQZK_CERT_BYTES],
                             pqzk_cert_t *cert_out);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_CERT_H */