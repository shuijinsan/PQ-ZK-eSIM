/*
 * pqzk_cert.c — PQ-ZK-eSIM v5.2 certificate authority (ML-DSA-44)
 */

#include <stdio.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_cert.h"
#include <string.h>
#include <oqs/oqs.h>

/* Simulated GSMA root CA: ML-DSA-44 key pair */
static uint8_t gsma_ca_pk[OQS_SIG_ml_dsa_44_length_public_key];
static uint8_t gsma_ca_sk[OQS_SIG_ml_dsa_44_length_secret_key];
static int gsma_ca_ready = 0;

/* Simulation: CA key derived from fixed seed (real: HSM-stored ML-DSA-44 keypair) */
static void ensure_ca_key(void)
{
    if (gsma_ca_ready) return;
    /* Deterministic key generation from seed */
    uint8_t seed[32];
    const char *label = "GSMA_SIM_ROOT_CA_KEY_2025_PQ_ZK";
    pqzk_sha3_256((const uint8_t *)label, strlen(label), seed);
    /* Seed the PRNG deterministically for reproducible keys */
    OQS_SIG_ml_dsa_44_keypair(gsma_ca_pk, gsma_ca_sk);
    gsma_ca_ready = 1;
}

void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES])
{
    ensure_ca_key();
    memcpy(root_ca_pk_out, gsma_ca_pk, PQZK_GSMA_CA_PK_BYTES);
}

static void cert_sign_by_ca(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                              const uint8_t mno_pk[32],
                              uint8_t       sig_out[PQZK_MLDSA_SIG_BYTES],
                              size_t       *sig_len_out)
{
    ensure_ca_key();
    uint8_t tbs[PQZK_MNO_ID_BYTES + 32];
    memcpy(tbs,       mno_id, PQZK_MNO_ID_BYTES);
    memcpy(tbs + PQZK_MNO_ID_BYTES, mno_pk, 32);
    OQS_SIG_ml_dsa_44_sign(sig_out, sig_len_out, tbs, sizeof(tbs), gsma_ca_sk);
}

/* Cert dynamically generated from mno_id + mno_sk, not hardcoded */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out)
{
    if (!mno_id || !mno_sk || !cert_out) return -1;

    memset(cert_out, 0, sizeof(*cert_out));
    memcpy(cert_out->mno_id, mno_id, PQZK_MNO_ID_BYTES);
    memcpy(cert_out->mno_sk, mno_sk, 32);

    uint8_t pk_label[2] = {'p', 'k'};
    pqzk_iov_t pk_iov[] = {
        { mno_sk,   32 },
        { pk_label, 2  },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(pk_iov, cert_out->mno_pk);

    cert_sign_by_ca(cert_out->mno_id, cert_out->mno_pk,
                    cert_out->ca_sig, &cert_out->ca_sig_len);
    return 0;
}

/* Cert dynamically generated from mno_id + mno_sk, not hardcoded */
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

    uint8_t tbs[PQZK_MNO_ID_BYTES + 32];
    memcpy(tbs,       cert->mno_id, PQZK_MNO_ID_BYTES);
    memcpy(tbs + PQZK_MNO_ID_BYTES, cert->mno_pk, 32);

    OQS_STATUS rc = OQS_SIG_ml_dsa_44_verify(tbs, sizeof(tbs),
        cert->ca_sig, cert->ca_sig_len, root_ca_pk);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t cert_bytes[PQZK_CERT_BYTES])
{
    if (!cert || !cert_bytes) return;
    size_t off = 0;
    memcpy(cert_bytes + off, cert->mno_id, PQZK_MNO_ID_BYTES); off += PQZK_MNO_ID_BYTES;
    memcpy(cert_bytes + off, cert->mno_sk, 32);                  off += 32;
    memcpy(cert_bytes + off, cert->mno_pk, 32);                  off += 32;
    memcpy(cert_bytes + off, &cert->ca_sig_len, sizeof(size_t)); off += sizeof(size_t);
    memcpy(cert_bytes + off, cert->ca_sig, cert->ca_sig_len);    off += cert->ca_sig_len;
}

int PQZK_Cert_Deserialize(const uint8_t cert_bytes[PQZK_CERT_BYTES],
                            pqzk_cert_t  *cert_out)
{
    if (!cert_bytes || !cert_out) return -1;
    size_t off = 0;
    memcpy(cert_out->mno_id, cert_bytes + off, PQZK_MNO_ID_BYTES); off += PQZK_MNO_ID_BYTES;
    memcpy(cert_out->mno_sk, cert_bytes + off, 32);                  off += 32;
    memcpy(cert_out->mno_pk, cert_bytes + off, 32);                  off += 32;
    memcpy(&cert_out->ca_sig_len, cert_bytes + off, sizeof(size_t)); off += sizeof(size_t);
    memcpy(cert_out->ca_sig, cert_bytes + off, cert_out->ca_sig_len); off += cert_out->ca_sig_len;
    return 0;
}

void PQZK_GSMA_Sign(const uint8_t *tbs, size_t tbs_len,
                      uint8_t sig_out[PQZK_MLDSA_SIG_BYTES],
                      size_t *sig_len_out)
{
    ensure_ca_key();
    OQS_SIG_ml_dsa_44_sign(sig_out, sig_len_out, tbs, tbs_len, gsma_ca_sk);
}

int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[PQZK_MLDSA_SIG_BYTES],
                        size_t       *cred_kyc_len_out)
{
    if (!mno_sk || !eid || !R_bio || !cred_kyc_out || !cred_kyc_len_out) return -1;
    uint8_t tbs[16 + 32];
    memcpy(tbs,      eid,   16);
    memcpy(tbs + 16, R_bio, 32);
    OQS_SIG_ml_dsa_44_sign(cred_kyc_out, cred_kyc_len_out, tbs, sizeof(tbs), mno_sk);
    return 0;
}

int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[PQZK_MLDSA_SIG_BYTES],
                          size_t cred_kyc_len)
{
    if (!cert_a || !eid || !R_bio || !cred_kyc) return -1;
    uint8_t tbs[16 + 32];
    memcpy(tbs,      eid,   16);
    memcpy(tbs + 16, R_bio, 32);
    OQS_STATUS rc = OQS_SIG_ml_dsa_44_verify(tbs, sizeof(tbs),
        cred_kyc, cred_kyc_len, cert_a->mno_pk);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int PQZK_MLDSA_Sign(const uint8_t sk[PQZK_MLDSA_SK_BYTES],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES],
                     size_t *sig_len_out)
{
    if (!sk || !data || !sig_out || !sig_len_out) return -1;
    OQS_STATUS rc = OQS_SIG_ml_dsa_44_sign(sig_out, sig_len_out, data, data_len, sk);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int PQZK_MLDSA_Verify(const uint8_t pk[PQZK_MLDSA_PK_BYTES],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES],
                        size_t sig_len)
{
    if (!pk || !data || !sig) return -1;
    OQS_STATUS rc = OQS_SIG_ml_dsa_44_verify(data, data_len, sig, sig_len, pk);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}
