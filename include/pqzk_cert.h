/*
 * pqzk_cert.h — GSMA certificate authority (ML-DSA-44)
 */

#ifndef PQZK_CERT_H
#define PQZK_CERT_H

#include "pq_zk_esim.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PQZK_GSMA_CA_PK_BYTES         1312  /* ML-DSA-44 public key */
#define PQZK_MLDSA_SIG_BYTES          2520  /* ML-DSA-44 max signature */
#define PQZK_MLDSA_PK_BYTES           1312
#define PQZK_MLDSA_SK_BYTES           2560
#define PQZK_CERT_CA_SIG_BYTES        PQZK_MLDSA_SIG_BYTES
#define PQZK_CERT_MLKEM_PK_BYTES      PQ_ZK_PUBLICKEY_BYTES
#define PQZK_MNO_ID_BYTES             16
#define PQZK_CERT_BYTES               (PQZK_MNO_ID_BYTES + 32 + 32 + sizeof(size_t) + PQZK_CERT_CA_SIG_BYTES)

typedef struct {
    uint8_t mno_id[PQZK_MNO_ID_BYTES];
    uint8_t mno_sk[32];
    uint8_t mno_pk[32];
    uint8_t ca_sig[PQZK_CERT_CA_SIG_BYTES];
    size_t  ca_sig_len;
} pqzk_cert_t;

/* Root CA */
void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES]);
void PQZK_GSMA_Sign(const uint8_t *tbs, size_t tbs_len, uint8_t sig_out[PQZK_MLDSA_SIG_BYTES], size_t *sig_len_out);

/* Certificate operations */
int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out);

int PQZK_Cert_IssueForMNO(const uint8_t  domain_id[PQZK_MNO_ID_BYTES],
                            pqzk_cert_t   *cert_out);

int PQZK_Cert_Verify(const pqzk_cert_t *cert);

int PQZK_Cert_VerifyWithRootPK(const pqzk_cert_t *cert,
                                 const uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES]);

void PQZK_Cert_Serialize(const pqzk_cert_t *cert,
                           uint8_t cert_bytes[PQZK_CERT_BYTES]);

int PQZK_Cert_Deserialize(const uint8_t cert_bytes[PQZK_CERT_BYTES],
                            pqzk_cert_t  *cert_out);

/* CredKYC */
int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[PQZK_MLDSA_SIG_BYTES],
                        size_t       *cred_kyc_len_out);

int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[PQZK_MLDSA_SIG_BYTES],
                          size_t cred_kyc_len);

/* ML-DSA-44 signing */
int PQZK_MLDSA_Sign(const uint8_t sk[PQZK_MLDSA_SK_BYTES],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES],
                     size_t *sig_len_out);

int PQZK_MLDSA_Verify(const uint8_t pk[PQZK_MLDSA_PK_BYTES],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES],
                        size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_CERT_H */
