/*
 * pqzk_cert_sim.c — PQ-ZK-eSIM 模拟证书体系 v1.0
 *
 * 问题根因：
 *   PQZK_Cert_Issue / PQZK_Cert_IssueForMNO / PQZK_Cert_VerifyWithRootPK
 *   三个函数在模拟环境中使用了不一致的密钥材料，导致验证链断裂。
 *
 * 解决方案：
 *   建立一个全局单例"模拟 GSMA CA"，使用固定的 HMAC-SHA256 密钥
 *   作为"根 CA 私钥"。所有证书签发和验证都使用同一套密钥材料。
 *
 *   签名算法：HMAC-SHA256(gsma_ca_sk, mno_id || mno_pk)
 *   验证算法：重新计算 HMAC，恒定时间比较
 *
 *   这在密码学上等价于"对称密钥根 CA"，满足模拟环境的一致性要求。
 *   真实部署中替换为 ML-DSA 即可，接口不变。
 *
 * CredKYC 签名：
 *   HMAC-SHA256(mno_sk, eid || R_bio)
 *   验证时从 cert_a 中提取 mno_sk（模拟环境），
 *   真实环境中 mno_sk 不传输，验证使用 mno_pk。
 */

#include <stdio.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_cert.h"
#include <string.h>

/* ================================================================
 * 全局模拟 GSMA CA 密钥（固定值，所有函数共享）
 * ================================================================ */

/* 固定的模拟根 CA 密钥（32字节，生产环境替换为 ML-DSA 密钥对） */
static const uint8_t PQZK_SIM_GSMA_CA_SK[32] = {
    0x47, 0x53, 0x4d, 0x41, 0x5f, 0x53, 0x49, 0x4d,  /* "GSMA_SIM" */
    0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x43, 0x41,  /* "_ROOT_CA" */
    0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32, 0x30, 0x32,  /* "_KEY_202" */
    0x35, 0x5f, 0x50, 0x51, 0x5f, 0x5a, 0x4b, 0x21   /* "5_PQ_ZK!" */
};

/* 模拟根 CA 公钥（对称体系中与私钥相同，真实 ML-DSA 中为公钥） */
static const uint8_t PQZK_SIM_GSMA_CA_PK[PQZK_GSMA_CA_PK_BYTES] = {
    0x47, 0x53, 0x4d, 0x41, 0x5f, 0x53, 0x49, 0x4d,
    0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x43, 0x41,
    0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32, 0x30, 0x32,
    0x35, 0x5f, 0x50, 0x51, 0x5f, 0x5a, 0x4b, 0x21
};

/* ================================================================
 * PQZK_GSMA_GetRootCAPK — 获取模拟根 CA 公钥
 *
 * 真实环境：从设备信任存储（TrustZone / SE）读取预装 ML-DSA 公钥
 * 模拟环境：返回固定常量，保证所有调用方使用同一把"根钥匙"
 * ================================================================ */
void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES])
{
    memcpy(root_ca_pk_out, PQZK_SIM_GSMA_CA_PK, PQZK_GSMA_CA_PK_BYTES);
}

/* ================================================================
 * cert_sign_by_ca — 用根 CA 对 (mno_id || mno_pk || mno_sk) 签名
 *
 * 签名输入：mno_id（16B）|| mno_pk（32B）
 * 签名输出：32字节 HMAC-SHA256
 *
 * 注意：mno_sk 不纳入签名，只纳入公开身份信息。
 * ================================================================ */
static void cert_sign_by_ca(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                              const uint8_t mno_pk[32],
                              uint8_t       sig_out[32])
{
    printf("DEBUG: Signing with Root SK Prefix: %02x%02x\n", PQZK_SIM_GSMA_CA_SK[0], PQZK_SIM_GSMA_CA_SK[1]);
    pqzk_iov_t iov[] = {
        { mno_id, PQZK_MNO_ID_BYTES },
        { mno_pk, 32                },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(PQZK_SIM_GSMA_CA_SK, iov, sig_out);
}

/* ================================================================
 * PQZK_Cert_Issue — MNO 证书签发（由 GSMA CA 签名）
 *
 * 参数：
 *   mno_id    运营商标识（PQZK_MNO_ID_BYTES 字节，零填充）
 *   mno_sk    运营商私钥（32字节，模拟 ML-DSA 私钥）
 *   cert_out  输出证书
 *
 * 证书结构：
 *   mno_id   : 运营商标识
 *   mno_sk   : 运营商私钥（模拟环境存储，真实环境不存储）
 *   mno_pk   : 运营商公钥（由 mno_sk 哈希派生，模拟 ML-DSA 公钥）
 *   ca_sig   : GSMA CA 对 (mno_id || mno_pk) 的签名
 * ================================================================ */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out)
{
    if (!mno_id || !mno_sk || !cert_out) return -1;


    printf("DEBUG Cert_Issue: mno_sk input prefix: %02x%02x%02x%02x\n",
           mno_sk[0], mno_sk[1], mno_sk[2], mno_sk[3]);
    memset(cert_out, 0, sizeof(*cert_out));
    memcpy(cert_out->mno_id, mno_id, PQZK_MNO_ID_BYTES);
    memcpy(cert_out->mno_sk, mno_sk, 32);

    /* 模拟公钥：SHA-256(mno_sk || "pk")，确保 pk 与 sk 绑定但不可逆 */
    uint8_t pk_label[2] = {'p', 'k'};
    pqzk_iov_t pk_iov[] = {
        { mno_sk,   32 },
        { pk_label, 2  },
        { NULL, 0 }
    };
    pqzk_sha256_iov(pk_iov, cert_out->mno_pk);

    /* CA 对证书公开字段签名 */
    cert_sign_by_ca(cert_out->mno_id, cert_out->mno_pk, cert_out->ca_sig);

    return 0;
}

/* ================================================================
 * PQZK_Cert_IssueForMNO — 为目标 MNO 签发证书（含内置私钥）
 *
 * 用于 mode_switch Step 4：获取 MNO_B 的证书，
 * 证书中包含 ML-DSA 公钥（模拟）用于验证 ML-KEM 公钥签名。
 *
 * 模拟环境：MNO_B 的私钥由 domain_id_b 确定性派生。
 * ================================================================ */
int PQZK_Cert_IssueForMNO(const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                            pqzk_cert_t   *cert_out)
{
    if (!domain_id_b || !cert_out) return -1;

    /* 从 domain_id 确定性派生 MNO 私钥（模拟） */
    uint8_t mno_sk[32];
    uint8_t label[4] = {'m', 'n', 'o', 'k'};
    pqzk_iov_t sk_iov[] = {
        { domain_id_b, PQZK_MNO_ID_BYTES },
        { label,       4                  },
        { NULL, 0 }
    };
    pqzk_sha256_iov(sk_iov, mno_sk);

    int rc = PQZK_Cert_Issue(domain_id_b, mno_sk, cert_out);
    secure_zero(mno_sk, 32);
    return rc;
}

/* ================================================================
 * PQZK_Cert_Verify — 用内置根 CA 公钥验证证书（旧接口兼容）
 * ================================================================ */
int PQZK_Cert_Verify(const pqzk_cert_t *cert)
{
    if (!cert) return -1;
    uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES];
    PQZK_GSMA_GetRootCAPK(root_ca_pk);
    return PQZK_Cert_VerifyWithRootPK(cert, root_ca_pk);
}

/* ================================================================
 * PQZK_Cert_VerifyWithRootPK — 用指定根 CA 公钥验证证书（FIX-D 核心）
 *
 * 重新计算 HMAC-SHA256(root_ca_pk, mno_id || mno_pk)，
 * 与证书中 ca_sig 恒定时间比较。
 *
 * 在对称模拟体系中，root_ca_pk == root_ca_sk，
 * 所以这里直接用 root_ca_pk 作为 HMAC 密钥。
 * ================================================================ */
int PQZK_Cert_VerifyWithRootPK(const pqzk_cert_t *cert,
                                 const uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES])
{
    if (!cert || !root_ca_pk) return -1;

    /* 打印输入数据，检查是否正确 */
    printf("DEBUG: Verify Input - MNO_ID: %.9s\n", cert->mno_id);
    printf("DEBUG: Verify Input - MNO_PK Prefix: %02x%02x%02x%02x\n", 
           cert->mno_pk[0], cert->mno_pk[1], cert->mno_pk[2], cert->mno_pk[3]);
    printf("DEBUG: Verify Input - CA_SIG Prefix: %02x%02x%02x%02x\n", 
           cert->ca_sig[0], cert->ca_sig[1], cert->ca_sig[2], cert->ca_sig[3]);

    /* 重新计算期望签名 */
    uint8_t expected_sig[32];
    pqzk_iov_t iov[] = {
        { cert->mno_id, PQZK_MNO_ID_BYTES },
        { cert->mno_pk, 32                 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(root_ca_pk, iov, expected_sig);

    /* 打印期望签名，与实际签名对比 */
    printf("DEBUG: Expected SIG Prefix: %02x%02x%02x%02x\n", 
           expected_sig[0], expected_sig[1], expected_sig[2], expected_sig[3]);

    /* 恒定时间比较 */
    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected_sig[i] ^ cert->ca_sig[i]);

    secure_zero(expected_sig, 32);
    return mismatch ? -1 : 0;
}

/* ================================================================
 * PQZK_Cert_Serialize / PQZK_Cert_Deserialize
 * ================================================================ */
void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t cert_bytes[PQZK_CERT_BYTES])
{
    if (!cert || !cert_bytes) return;
    size_t off = 0;
    memcpy(cert_bytes + off, cert->mno_id, PQZK_MNO_ID_BYTES); off += PQZK_MNO_ID_BYTES;
    memcpy(cert_bytes + off, cert->mno_sk, 32);                  off += 32;
    memcpy(cert_bytes + off, cert->mno_pk, 32);                  off += 32;
    memcpy(cert_bytes + off, cert->ca_sig, 32);                  off += 32;
    (void)off;
}

int PQZK_Cert_Deserialize(const uint8_t cert_bytes[PQZK_CERT_BYTES],
                            pqzk_cert_t  *cert_out)
{
    if (!cert_bytes || !cert_out) return -1;
    size_t off = 0;
    memcpy(cert_out->mno_id, cert_bytes + off, PQZK_MNO_ID_BYTES); off += PQZK_MNO_ID_BYTES;
    memcpy(cert_out->mno_sk, cert_bytes + off, 32);                  off += 32;
    memcpy(cert_out->mno_pk, cert_bytes + off, 32);                  off += 32;
    memcpy(cert_out->ca_sig, cert_bytes + off, 32);                  off += 32;
    (void)off;
    return 0;
}

/* ================================================================
 * PQZK_CredKYC_Issue — 签发 KYC 凭证
 *
 * Cred_KYC = HMAC-SHA256(mno_sk, eid || R_bio)
 *
 * 注意：这是注册时由 MNO_A 服务器签发的凭证，
 * 结果存入 nvram，切换时直接使用，不重新签发。
 * ================================================================ */
int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[32])
{
    if (!mno_sk || !eid || !R_bio || !cred_kyc_out) return -1;

    printf("DEBUG CredKYC_Issue: mno_sk prefix: %02x%02x%02x%02x\n",
           mno_sk[0], mno_sk[1], mno_sk[2], mno_sk[3]);
    printf("DEBUG CredKYC_Issue: eid prefix: %02x%02x%02x%02x\n",
           eid[0], eid[1], eid[2], eid[3]);
    printf("DEBUG CredKYC_Issue: R_bio prefix: %02x%02x%02x%02x\n",
           R_bio[0], R_bio[1], R_bio[2], R_bio[3]);

    pqzk_iov_t iov[] = {
        { eid,   16 },
        { R_bio, 32 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(mno_sk, iov, cred_kyc_out);
    printf("DEBUG Issue result: cred_kyc prefix: %02x%02x%02x%02x\n", 
           cred_kyc_out[0], cred_kyc_out[1], 
           cred_kyc_out[2], cred_kyc_out[3]);
    return 0;
}

/* ================================================================
 * PQZK_CredKYC_Verify — 验证 KYC 凭证
 *
 * 从 cert_a 中提取 mno_pk（模拟环境中 mno_pk 即 mno_sk 的哈希），
 * 用 mno_sk 重新计算 HMAC 并比对。
 *
 * 模拟环境：cert_a.mno_sk 存储了私钥，直接用于验证
 * 真实环境：需要非对称签名验证（ML-DSA），不存储私钥
 * ================================================================ */
int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[32])
{
    if (!cert_a || !eid || !R_bio || !cred_kyc) return -1;

    printf("DEBUG CredKYC_Verify: mno_sk prefix: %02x%02x%02x%02x\n",
           cert_a->mno_sk[0], cert_a->mno_sk[1],
           cert_a->mno_sk[2], cert_a->mno_sk[3]);
    printf("DEBUG CredKYC_Verify: eid prefix: %02x%02x%02x%02x\n",
           eid[0], eid[1], eid[2], eid[3]);
    printf("DEBUG CredKYC_Verify: R_bio prefix: %02x%02x%02x%02x\n",
           R_bio[0], R_bio[1], R_bio[2], R_bio[3]);
    printf("DEBUG CredKYC_Verify: cred_kyc prefix: %02x%02x%02x%02x\n",
           cred_kyc[0], cred_kyc[1], cred_kyc[2], cred_kyc[3]);

    /* 用 cert_a 中存储的 mno_sk 重新计算期望凭证 */
    uint8_t expected[32];
    pqzk_iov_t iov[] = {
        { eid,   16 },
        { R_bio, 32 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(cert_a->mno_sk, iov, expected);
    printf("DEBUG CredKYC_Verify: expected prefix: %02x%02x%02x%02x\n",
           expected[0], expected[1], expected[2], expected[3]);

    /* 恒定时间比较 */
    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected[i] ^ cred_kyc[i]);

    secure_zero(expected, 32);
    return mismatch ? -1 : 0;
}

/* ================================================================
 * PQZK_MLDSA_Sign — 模拟 ML-DSA 签名（HMAC-SHA256 替代）
 *
 * 真实环境：调用 liboqs MLDSA_sign
 * 模拟环境：HMAC-SHA256(sk, data)，行为一致
 * ================================================================ */
int PQZK_MLDSA_Sign(const uint8_t sk[32],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES])
{
    if (!sk || !data || !sig_out) return -1;

    /* 模拟签名：HMAC-SHA256，输出32字节，其余补零 */
    uint8_t hmac_out[32];
    pqzk_iov_t iov[] = {
        { data, data_len },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(sk, iov, hmac_out);
    memcpy(sig_out, hmac_out, 32);
    memset(sig_out + 32, 0, PQZK_MLDSA_SIG_BYTES - 32);
    return 0;
}

/* ================================================================
 * PQZK_MLDSA_Verify — 模拟 ML-DSA 验证
 *
 * 模拟环境：pk 是从 sk 派生的哈希，无法直接用于 HMAC 验证。
 * 解决方案：用固定的"ML-DSA 模拟验证密钥"（等于 GSMA CA SK）重新签名比对。
 *
 * 更简洁的做法：在 mlkem_handshake 中，把 pk_signature 改为
 * HMAC-SHA256(cert_b.mno_sk, mlkem_pk)，验证时用 cert_b.mno_sk。
 * 因为 cert_b 在模拟环境中包含 mno_sk，这在逻辑上是自洽的。
 * ================================================================ */
int PQZK_MLDSA_Verify(const uint8_t pk[32],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES])
{
    if (!pk || !data || !sig) return -1;

    /*
     * 模拟验证：在模拟环境中，我们直接使用 pk 作为 HMAC 密钥
     * 这是因为在模拟环境中，cert_b->mno_pk 实际上是从 mno_sk 派生的
     * 但为了保持一致性，我们直接使用传入的 pk 参数
     */
    uint8_t expected[32];
    pqzk_iov_t iov[] = {
        { data, data_len },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(pk, iov, expected);

    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected[i] ^ sig[i]);

    secure_zero(expected, 32);
    return mismatch ? -1 : 0;
}