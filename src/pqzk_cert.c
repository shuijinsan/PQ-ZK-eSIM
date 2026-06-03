/*
 * pqzk_cert.c — PQ-ZK-eSIM v5.2 simulated certificate authority
 *
 * Uses HMAC-SHA256 as a stand-in for ML-DSA (real deployment: liboqs MLDSA).
 * All functions share a fixed simulated GSMA root CA key.
 */

#include <stdio.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_cert.h"
#include <string.h>

/* Simulated GSMA root CA key (production: replace with ML-DSA key pair) */
static const uint8_t PQZK_SIM_GSMA_CA_SK[32] = {
    0x47, 0x53, 0x4d, 0x41, 0x5f, 0x53, 0x49, 0x4d,  /* "GSMA_SIM" */
    0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x43, 0x41,  /* "_ROOT_CA" */
    0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32, 0x30, 0x32,  /* "_KEY_202" */
    0x35, 0x5f, 0x50, 0x51, 0x5f, 0x5a, 0x4b, 0x21   /* "5_PQ_ZK!" */
};

static const uint8_t PQZK_SIM_GSMA_CA_PK[PQZK_GSMA_CA_PK_BYTES] = {
    0x47, 0x53, 0x4d, 0x41, 0x5f, 0x53, 0x49, 0x4d,
    0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x43, 0x41,
    0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32, 0x30, 0x32,
    0x35, 0x5f, 0x50, 0x51, 0x5f, 0x5a, 0x4b, 0x21
};

void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES])
{
    memcpy(root_ca_pk_out, PQZK_SIM_GSMA_CA_PK, PQZK_GSMA_CA_PK_BYTES);
}

/* Sign (mno_id || mno_pk) with root CA key */
static void cert_sign_by_ca(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                              const uint8_t mno_pk[32],
                              uint8_t       sig_out[32])
{
    pqzk_iov_t iov[] = {
        { mno_id, PQZK_MNO_ID_BYTES },
        { mno_pk, 32                },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(PQZK_SIM_GSMA_CA_SK, iov, sig_out);
}

int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out)
{
    if (!mno_id || !mno_sk || !cert_out) return -1;

    memset(cert_out, 0, sizeof(*cert_out));
    memcpy(cert_out->mno_id, mno_id, PQZK_MNO_ID_BYTES);
    memcpy(cert_out->mno_sk, mno_sk, 32);

    /* Simulated public key: SHA3-256(mno_sk || "pk") */
    uint8_t pk_label[2] = {'p', 'k'};
    pqzk_iov_t pk_iov[] = {
        { mno_sk,   32 },
        { pk_label, 2  },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(pk_iov, cert_out->mno_pk);

    cert_sign_by_ca(cert_out->mno_id, cert_out->mno_pk, cert_out->ca_sig);
    return 0;
}

int PQZK_Cert_IssueForMNO(const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                            pqzk_cert_t   *cert_out)
{
    if (!domain_id_b || !cert_out) return -1;

    uint8_t mno_sk[32];
    uint8_t label[4] = {'m', 'n', 'o', 'k'};
    pqzk_iov_t sk_iov[] = {
        { domain_id_b, PQZK_MNO_ID_BYTES },
        { label,       4                  },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(sk_iov, mno_sk);

    int rc = PQZK_Cert_Issue(domain_id_b, mno_sk, cert_out);
    secure_zero(mno_sk, 32);
    return rc;
}

int PQZK_Cert_Verify(const pqzk_cert_t *cert)
{
    if (!cert) return -1;
    uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES];
    PQZK_GSMA_GetRootCAPK(root_ca_pk);
    return PQZK_Cert_VerifyWithRootPK(cert, root_ca_pk);
}

int PQZK_Cert_VerifyWithRootPK(const pqzk_cert_t *cert,
                                 const uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES])
{
    if (!cert || !root_ca_pk) return -1;

    uint8_t expected_sig[32];
    pqzk_iov_t iov[] = {
        { cert->mno_id, PQZK_MNO_ID_BYTES },
        { cert->mno_pk, 32                 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(root_ca_pk, iov, expected_sig);

    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected_sig[i] ^ cert->ca_sig[i]);
    secure_zero(expected_sig, 32);
    return mismatch ? -1 : 0;
}

void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t cert_bytes[PQZK_CERT_BYTES])
{
    if (!cert || !cert_bytes) return;
    size_t off = 0;
    memcpy(cert_bytes + off, cert->mno_id, PQZK_MNO_ID_BYTES); off += PQZK_MNO_ID_BYTES;
    memcpy(cert_bytes + off, cert->mno_sk, 32);                  off += 32;
    memcpy(cert_bytes + off, cert->mno_pk, 32);                  off += 32;
    memcpy(cert_bytes + off, cert->ca_sig, 32);                  off += 32;
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
    return 0;
}

int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[32])
{
    if (!mno_sk || !eid || !R_bio || !cred_kyc_out) return -1;
    pqzk_iov_t iov[] = {
        { eid,   16 },
        { R_bio, 32 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(mno_sk, iov, cred_kyc_out);
    return 0;
}

int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[32])
{
    if (!cert_a || !eid || !R_bio || !cred_kyc) return -1;

    uint8_t expected[32];
    pqzk_iov_t iov[] = {
        { eid,   16 },
        { R_bio, 32 },
        { NULL, 0 }
    };
    pqzk_hmac_sha256_iov(cert_a->mno_sk, iov, expected);

    volatile int mismatch = 0;
    for (int i = 0; i < 32; i++)
        mismatch |= (expected[i] ^ cred_kyc[i]);
    secure_zero(expected, 32);
    return mismatch ? -1 : 0;
}

int PQZK_MLDSA_Sign(const uint8_t sk[32],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES])
{
    if (!sk || !data || !sig_out) return -1;
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

int PQZK_MLDSA_Verify(const uint8_t pk[32],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES])
{
    if (!pk || !data || !sig) return -1;
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
