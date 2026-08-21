/*
 * pqzk_crypto.c — PQ-ZK-eSIM cryptographic primitives
 *
 * Dependencies: OpenSSL >= 3.0, liboqs
 */

#include "pqzk_internal.h"

#include <oqs/oqs.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdlib.h>

/* Global seed for public matrix A (shared across all platforms) */
const uint8_t PQZK_MATRIX_A_SEED[32] = {
    0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,  /* "PQZKESIM" */
    0x4D,0x41,0x54,0x52, 0x49,0x58,0x5F,0x41,  /* "MATRIX_A" */
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
};

/* ================================================================
 * SHA3-256
 * ================================================================ */
int pqzk_sha3_256(const uint8_t *in, size_t len, uint8_t out[32])
{
    if (!out) return -1;
    if (len > 0 && !in) return -1;
    SHA256(in ? in : (const uint8_t *)"", len, out);
    return 0;
}

/* Gather-write SHA3-256 over iov array, avoiding allocation */
int pqzk_sha3_256_iov(const pqzk_iov_t *iov, uint8_t out[32])
{
    if (!iov || !out) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++)
        EVP_DigestUpdate(ctx, p->buf, p->len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* ================================================================
 * HMAC-SHA256 (used by HKDF; MAC is AES-256-CMAC below)
 * ================================================================ */

/* Fixed 32-byte key HMAC-SHA256 */
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

/* Variable-length key HMAC-SHA256 (tests only) */
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
 * SHAKE-256 XOF
 * ================================================================ */

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

/* Gather-write SHAKE-256 over iov array */
int pqzk_shake256_iov(const pqzk_iov_t *iov, uint8_t *out, size_t out_len)
{
    if (!iov || !out || out_len == 0) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ret = -1;
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) goto done;
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++) {
        if (p->len == 0) continue;
        if (EVP_DigestUpdate(ctx, p->buf, p->len) != 1) goto done;
    }
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) goto done;
    ret = 0;
done:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* ================================================================
 * AES-256-CTR keystream
 * ================================================================ */

int pqzk_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                    uint8_t *out, size_t out_len)
{
    if (!key || !iv || !out || out_len == 0) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1;
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
 * PRF: M_mask = Parse_Rq(AES-256-CTR(key, iv=Hash(msg)))
 *   msg = c_seed || le64(ctr_session) || R_dynamic
 * ================================================================ */
int pqzk_prf(const uint8_t K_sym[32],
             const uint8_t c_seed[32],
             uint64_t      ctr_session,
             const uint8_t R_dynamic[32],
             uint8_t       *out,
             size_t         out_len)
{
    if (!K_sym || !c_seed || !R_dynamic || !out || out_len == 0) return -1;

    uint8_t msg[72];
    memcpy(msg,      c_seed,    32);
    write_le64(msg + 32, ctr_session);
    memcpy(msg + 40, R_dynamic, 32);

    uint8_t hash[32], iv[16];
    if (pqzk_sha3_256(msg, sizeof(msg), hash) != 0) return -1;
    memcpy(iv, hash, 16);

    return pqzk_aes256_ctr(K_sym, iv, out, out_len);
}

/* ================================================================
 * AES-256-CMAC (NIST SP 800-38B)
 * 16-byte CMAC tag (128-bit, NIST SP 800-38B).
 * ================================================================ */
int pqzk_aes256_cmac(const uint8_t key[32], const pqzk_iov_t *iov, uint8_t out[16])
{
    if (!key || !iov || !out) return -1;
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return -1;
    CMAC_Init(ctx, key, 32, EVP_aes_256_cbc(), NULL);
    for (const pqzk_iov_t *p = iov; p->buf; p++)
        CMAC_Update(ctx, p->buf, p->len);
    size_t outlen;
    CMAC_Final(ctx, out, &outlen);
    CMAC_CTX_free(ctx);
    if (outlen != 16) return -1;
    return 0;
}

/* ================================================================
 * HKDF-Expand (RFC 5869): T(1) = HMAC-SHA256(prk, info || 0x01)
 * ================================================================ */
int pqzk_hkdf_expand(const uint8_t prk[32], const char *info, size_t info_len,
                      uint8_t okm[32])
{
    pqzk_iov_t iov[] = {
        { (const uint8_t *)info, info_len },
        { (const uint8_t *)"\x01", 1 },
        { NULL, 0 }
    };
    return pqzk_hmac_sha256_iov(prk, iov, okm);
}

/* ================================================================
 * KDF (Paper Table 2): AES-256-CTR encrypt d_seed || EID
 *   K_sym^(i+1) = AES-256-CTR(K_sym^i, iv=d_seed[0:16], d_seed||EID)[0:32]
 * ================================================================ */
int pqzk_kdf(const uint8_t  K_sym[32],
             const uint8_t  d_seed[32],
             const uint8_t *eid,
             size_t          eid_len,
             uint8_t         new_key[32])
{
    if (!K_sym || !d_seed || !eid || !new_key) return -1;
    if (eid_len == 0 || eid_len > 16) return -1;

    uint8_t plain[48], iv[16];
    memset(plain, 0, 48);
    memcpy(plain, d_seed, 32);
    memcpy(plain + 32, eid, eid_len);
    memcpy(iv, d_seed, 16);
    if (pqzk_aes256_ctr(K_sym, iv, plain, 48) != 0) return -1;
    memcpy(new_key, plain, 32);
    secure_zero(plain, sizeof(plain));
    return 0;
}

/* ================================================================
 * Cryptographic RNG (OpenSSL RAND_bytes)
 * ================================================================ */
int pqzk_rand_bytes(uint8_t *out, size_t len)
{
    if (!out || len == 0) return -1;
    return (RAND_bytes(out, (int)len) == 1) ? 0 : -1;
}
