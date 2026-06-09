/*
 * pqzk_cert.c — PQ-ZK-eSIM v5.2 certificate authority (ECDSA P-256)
 */

#include <stdio.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_cert.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

/* Simulated GSMA root CA: ECDSA P-256 key pair */
static EVP_PKEY *gsma_ca_key = NULL;

static EVP_PKEY *load_or_gen_ca_key(void)
{
    if (gsma_ca_key) return gsma_ca_key;

    /* Generate a fixed-deterministic ECDSA P-256 key from a seed */
    const char *seed = "GSMA_SIM_ROOT_CA_KEY_2025_PQ_ZK";
    uint8_t hash[32];
    pqzk_sha3_256((const uint8_t *)seed, strlen(seed), hash);

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *priv = BN_bin2bn(hash, 32, NULL);
    EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(ec));

    EC_POINT_mul(EC_KEY_get0_group(ec), pub, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, priv);
    EC_KEY_set_public_key(ec, pub);

    gsma_ca_key = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(gsma_ca_key, ec);

    BN_free(priv);
    EC_POINT_free(pub);
    return gsma_ca_key;
}

void PQZK_GSMA_GetRootCAPK(uint8_t root_ca_pk_out[PQZK_GSMA_CA_PK_BYTES])
{
    EVP_PKEY *pkey = load_or_gen_ca_key();
    size_t len = PQZK_GSMA_CA_PK_BYTES;
    EVP_PKEY_get_raw_public_key(pkey, root_ca_pk_out, &len);
}

static void cert_sign_by_ca(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                              const uint8_t mno_pk[32],
                              uint8_t       sig_out[PQZK_CERT_CA_SIG_BYTES],
                              size_t       *sig_len_out)
{
    EVP_PKEY *pkey = load_or_gen_ca_key();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);

    uint8_t tbs[PQZK_MNO_ID_BYTES + 32];
    memcpy(tbs,       mno_id, PQZK_MNO_ID_BYTES);
    memcpy(tbs + PQZK_MNO_ID_BYTES, mno_pk, 32);

    EVP_DigestSignUpdate(ctx, tbs, sizeof(tbs));
    EVP_DigestSignFinal(ctx, sig_out, sig_len_out);
    EVP_MD_CTX_free(ctx);
}

int PQZK_Cert_Issue(const uint8_t mno_id[PQZK_MNO_ID_BYTES],
                     const uint8_t mno_sk[32],
                     pqzk_cert_t  *cert_out)
{
    if (!mno_id || !mno_sk || !cert_out) return -1;

    memset(cert_out, 0, sizeof(*cert_out));
    memcpy(cert_out->mno_id, mno_id, PQZK_MNO_ID_BYTES);
    memcpy(cert_out->mno_sk, mno_sk, 32);

    /* Public key: SHA3-256(mno_sk || "pk") */
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

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    EC_POINT *pub = EC_POINT_new(grp);
    EC_POINT_oct2point(grp, pub, root_ca_pk, PQZK_GSMA_CA_PK_BYTES, NULL);
    EC_KEY_set_public_key(ec, pub);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);

    uint8_t tbs[PQZK_MNO_ID_BYTES + 32];
    memcpy(tbs,       cert->mno_id, PQZK_MNO_ID_BYTES);
    memcpy(tbs + PQZK_MNO_ID_BYTES, cert->mno_pk, 32);

    EVP_DigestVerifyUpdate(ctx, tbs, sizeof(tbs));
    int rc = EVP_DigestVerifyFinal(ctx, cert->ca_sig, cert->ca_sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_POINT_free(pub);
    return (rc == 1) ? 0 : -1;
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

int PQZK_CredKYC_Issue(const uint8_t mno_sk[32],
                        const uint8_t eid[16],
                        const uint8_t R_bio[32],
                        uint8_t       cred_kyc_out[PQZK_CERT_CA_SIG_BYTES],
                        size_t       *cred_kyc_len_out)
{
    if (!mno_sk || !eid || !R_bio || !cred_kyc_out || !cred_kyc_len_out) return -1;
    uint8_t tbs[16 + 32];
    memcpy(tbs,      eid,   16);
    memcpy(tbs + 16, R_bio, 32);
    return PQZK_MLDSA_Sign(mno_sk, tbs, sizeof(tbs), cred_kyc_out, cred_kyc_len_out);
}

int PQZK_CredKYC_Verify(const pqzk_cert_t *cert_a,
                          const uint8_t eid[16],
                          const uint8_t R_bio[32],
                          const uint8_t cred_kyc[PQZK_CERT_CA_SIG_BYTES],
                          size_t cred_kyc_len)
{
    if (!cert_a || !eid || !R_bio || !cred_kyc) return -1;
    uint8_t tbs[16 + 32];
    memcpy(tbs,      eid,   16);
    memcpy(tbs + 16, R_bio, 32);
    return PQZK_MLDSA_Verify(cert_a->mno_pk, tbs, sizeof(tbs), cred_kyc, cred_kyc_len);
}

int PQZK_MLDSA_Sign(const uint8_t sk[32],
                     const uint8_t *data, size_t data_len,
                     uint8_t sig_out[PQZK_MLDSA_SIG_BYTES],
                     size_t *sig_len_out)
{
    if (!sk || !data || !sig_out || !sig_len_out) return -1;

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *priv = BN_bin2bn(sk, 32, NULL);
    EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(ec));
    EC_POINT_mul(EC_KEY_get0_group(ec), pub, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, priv);
    EC_KEY_set_public_key(ec, pub);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(ctx, data, data_len);
    EVP_DigestSignFinal(ctx, sig_out, sig_len_out);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(priv);
    EC_POINT_free(pub);
    return 0;
}

int PQZK_MLDSA_Verify(const uint8_t pk[32],
                        const uint8_t *data, size_t data_len,
                        const uint8_t sig[PQZK_MLDSA_SIG_BYTES],
                        size_t sig_len)
{
    if (!pk || !data || !sig) return -1;

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *priv = BN_bin2bn(pk, 32, NULL);
    EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(ec));
    EC_POINT_mul(EC_KEY_get0_group(ec), pub, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(ec, pub);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestVerifyUpdate(ctx, data, data_len);
    int rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(priv);
    EC_POINT_free(pub);
    return (rc == 1) ? 0 : -1;
}
