/*
 * pqzk_cert.c — PQ-ZK-eSIM v5.0
 * GSMA 证书链模拟实现
 *
 * 模拟方案：用 HMAC-SHA256 替代真实数字签名
 *   · GSMA Root CA "私钥" = 固定32字节常量（仅模拟环境使用）
 *   · MNO_A "私钥" = mno_pk（公私钥合一，模拟环境简化）
 *   · 真实部署替换为 Dilithium-3 或 ECDSA P-256 即可
 */

#include "pqzk_cert.h"
#include "pqzk_internal.h"
#include <string.h>

/* ================================================================
 * 模拟 GSMA Root CA 密钥（固定常量，仅模拟环境）
 *
 * 真实场景：GSMA Root CA 私钥由 GSMA 官方持有，硬件安全模块保护。
 * 模拟场景：用固定常量模拟，论文中注明替换接口即可。
 * ================================================================ */
static const uint8_t GSMA_ROOT_CA_SK[32] = {
    0x47,0x53,0x4D,0x41, 0x52,0x6F,0x6F,0x74,  /* "GSMARoot" */
    0x43,0x41,0x4B,0x65, 0x79,0x53,0x69,0x6D,  /* "CAKeySim" */
    0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,  /* "PQZKESIM" */
    0x76,0x35,0x2E,0x30, 0x00,0x01,0x02,0x03   /* "v5.0\0..." */
};

/* ================================================================
 * PQZK_Cert_Issue
 * 模拟 GSMA Root CA 签发运营商证书
 *
 * 签名输入：mno_id || mno_pk || "GSMA-CERT-v1"
 * 签名算法：HMAC-SHA256(GSMA_ROOT_CA_SK, input)
 * ================================================================ */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_pk[PQZK_MNO_PK_BYTES],
                     pqzk_cert_t  *cert_out)
{
    if (!mno_id || !mno_pk || !cert_out) return -1;

    memset(cert_out, 0, sizeof(*cert_out));
    memcpy(cert_out->mno_id, mno_id, PQZK_MNO_ID_BYTES);
    memcpy(cert_out->mno_pk, mno_pk, PQZK_MNO_PK_BYTES);

    static const uint8_t CERT_LABEL[] = "GSMA-CERT-v1";

    pqzk_iov_t iov[] = {
        { mno_id,    PQZK_MNO_ID_BYTES         },
        { mno_pk,    PQZK_MNO_PK_BYTES         },
        { CERT_LABEL, sizeof(CERT_LABEL) - 1   },
        { NULL, 0 }
    };
    return pqzk_hmac_sha256_iov(GSMA_ROOT_CA_SK, iov, cert_out->signature);
}

/* ================================================================
 * PQZK_Cert_Verify
 * 验证运营商证书（MNO_B 用 GSMA Root CA 公钥验签）
 *
 * 模拟场景：双方都知道 GSMA_ROOT_CA_SK，直接重算比对。
 * 真实场景：GSMA Root CA 公钥出厂预置在所有合法服务器和 eUICC 里。
 * ================================================================ */
int PQZK_Cert_Verify(const pqzk_cert_t *cert)
{
    if (!cert) return -1;

    static const uint8_t CERT_LABEL[] = "GSMA-CERT-v1";

    pqzk_iov_t iov[] = {
        { cert->mno_id,  PQZK_MNO_ID_BYTES       },
        { cert->mno_pk,  PQZK_MNO_PK_BYTES       },
        { CERT_LABEL,    sizeof(CERT_LABEL) - 1   },
        { NULL, 0 }
    };

    uint8_t expected_sig[32];
    if (pqzk_hmac_sha256_iov(GSMA_ROOT_CA_SK, iov, expected_sig) != 0)
        return -1;

    /* 恒定时间比较，防时序侧信道 */
    volatile int diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (expected_sig[i] ^ cert->signature[i]);

    return (diff == 0) ? 0 : -1;
}

/* ================================================================
 * PQZK_CredKYC_Issue
 * 模拟 MNO_A 签发 KYC 凭证
 *
 * Cred_KYC = HMAC-SHA256(MNO_A_SK, EID || R_bio || "KYC-v1")
 * ================================================================ */
int PQZK_CredKYC_Issue(const uint8_t mno_a_sk[32],
                         const uint8_t eid[16],
                         const uint8_t R_bio[32],
                         uint8_t       cred_out[PQZK_CERT_SIG_BYTES])
{
    if (!mno_a_sk || !eid || !R_bio || !cred_out) return -1;

    static const uint8_t KYC_LABEL[] = "KYC-v1";

    pqzk_iov_t iov[] = {
        { eid,       16                       },
        { R_bio,     32                       },
        { KYC_LABEL, sizeof(KYC_LABEL) - 1   },
        { NULL, 0 }
    };
    return pqzk_hmac_sha256_iov(mno_a_sk, iov, cred_out);
}

/* ================================================================
 * PQZK_CredKYC_Verify
 * 验证 KYC 凭证
 *
 * MNO_B 从 Cert_A 中提取 mno_pk（即 MNO_A 的"公钥"，
 * 模拟环境中公私钥相同），重算签名后比对。
 * ================================================================ */
int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t      eid[16],
                          const uint8_t      R_bio[32],
                          const uint8_t      cred_kyc[PQZK_CERT_SIG_BYTES])
{
    if (!cert_a || !eid || !R_bio || !cred_kyc) return -1;

    /*
     * 模拟环境：MNO_A 的"公钥"即为签名时使用的密钥
     * 真实场景：从 Cert_A 提取公钥，用对应验签算法验证
     */
    uint8_t expected[32];
    if (PQZK_CredKYC_Issue(cert_a->mno_pk, eid, R_bio, expected) != 0)
        return -1;

    volatile int diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= (expected[i] ^ cred_kyc[i]);

    return (diff == 0) ? 0 : -1;
}

/* ================================================================
 * PQZK_Cert_Serialize / Deserialize
 * ================================================================ */
void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t buf[PQZK_CERT_BYTES])
{
    if (!cert || !buf) return;
    memcpy(buf, cert, sizeof(pqzk_cert_t));
}

int PQZK_Cert_Deserialize(const uint8_t buf[PQZK_CERT_BYTES],
                            pqzk_cert_t *cert_out)
{
    if (!buf || !cert_out) return -1;
    memcpy(cert_out, buf, sizeof(pqzk_cert_t));
    return 0;
}