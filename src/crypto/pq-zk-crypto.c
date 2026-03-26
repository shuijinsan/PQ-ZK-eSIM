/*
 * pqzk_crypto.c
 * 密码学原语封装（SHA-256, HMAC-SHA256, AES-256-CTR, SHAKE-256, KDF）
 * 依赖：OpenSSL 3.x（liboqs 环境自带）
 */

#include "pqzk_internal.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

/* 公共矩阵 A 的全局固定种子，跨端一致 */
const uint8_t PQZK_MATRIX_A_SEED[32] = {
    0x50,0x51,0x5A,0x4B, 0x45,0x53,0x49,0x4D,  /* PQZKESIM */
    0x4D,0x41,0x54,0x52, 0x49,0x58,0x5F,0x41,  /* MATRIX_A */
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
};

/* ================================================================
 * SHA-256
 * ================================================================ */

int pqzk_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    if (!in || !out) return -1;
    SHA256(in, len, out);
    return 0;
}

int pqzk_sha256_iov(const pqzk_iov_t *iov, uint8_t out[32])
{
    SHA256_CTX ctx;
    if (!iov || !out) return -1;
    SHA256_Init(&ctx);
    for (const pqzk_iov_t *p = iov; p->buf != NULL; p++)
        SHA256_Update(&ctx, p->buf, p->len);
    SHA256_Final(out, &ctx);
    return 0;
}

/* ================================================================
 * HMAC-SHA256（多段输入）
 * ================================================================ */

int pqzk_hmac_sha256_iov(const uint8_t key[32], const pqzk_iov_t *iov,
                          uint8_t out[32])
{
    HMAC_CTX *hctx;
    unsigned int outl = 32;
    if (!key || !iov || !out) return -1;

    hctx = HMAC_CTX_new();
    if (!hctx) return -1;

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

/* 任意 key 长度版本，供测试代码使用 */
int pqzk_hmac_sha256_iov_anykey(const uint8_t *key, size_t key_len,
                                  const pqzk_iov_t *iov, uint8_t out[32])
{
    HMAC_CTX *hctx;
    unsigned int outl = 32;
    if (!key || !iov || !out) return -1;

    hctx = HMAC_CTX_new();
    if (!hctx) return -1;

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

/* ================================================================
 * AES-256-CTR
 * ================================================================ */

int pqzk_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                    uint8_t *out, size_t out_len)
{
    if (!key || !iv || !out || !out_len) return -1;

    /* 加密全零流 → 得到 AES-CTR 密钥流 */
    uint8_t *zeros = (uint8_t *)calloc(1, out_len);
    if (!zeros) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, ret = -1;
    if (!ctx) { free(zeros); return -1; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out, &outl, zeros, (int)out_len) != 1)    goto done;
    ret = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    free(zeros);
    return ret;
}

/* ================================================================
 * 协议 PRF
 * PRF(K_sym, c_seed || ctr_le8 || H_ctx) → out_len 字节
 *
 * 步骤：
 *   1. msg = c_seed(32) || ctr_le8(8) || H_ctx(32)   共72字节
 *   2. iv[16] = SHA256(msg)[0:16]
 *   3. out = AES-256-CTR(K_sym, iv, zeros)
 * ================================================================ */

int pqzk_prf(const uint8_t K_sym[32], const uint8_t c_seed[32],
             uint64_t ctr, const uint8_t H_ctx[32],
             uint8_t *out, size_t out_len)
{
    if (!K_sym || !c_seed || !H_ctx || !out) return -1;

    uint8_t msg[72];
    memcpy(msg,      c_seed, 32);
    write_le64(msg + 32, ctr);
    memcpy(msg + 40, H_ctx,  32);

    uint8_t hash[32], iv[16];
    if (pqzk_sha256(msg, sizeof(msg), hash) != 0) return -1;
    memcpy(iv, hash, 16);

    return pqzk_aes256_ctr(K_sym, iv, out, out_len);
}

/* ================================================================
 * KDF
 * KDF(K_sym, d_seed || EID) → new_key[32]
 * 实现：HMAC-SHA256(K_sym, d_seed || EID)
 * ================================================================ */

int pqzk_kdf(const uint8_t K_sym[32], const uint8_t d_seed[32],
             const uint8_t *eid, size_t eid_len, uint8_t new_key[32])
{
    if (!K_sym || !d_seed || !eid || !new_key || eid_len > 16) return -1;

    uint8_t ctr_dummy[8] = {0};  /* 占位，保证字节序一致 */
    (void)ctr_dummy;

    uint8_t msg[48];  /* d_seed(32) + EID(最多16) */
    memcpy(msg, d_seed, 32);
    memcpy(msg + 32, eid, eid_len);

    pqzk_iov_t iov[] = {
        { msg, 32 + eid_len },
        { NULL, 0 }
    };
    return pqzk_hmac_sha256_iov(K_sym, iov, new_key);
}

/* ================================================================
 * 安全随机数
 * ================================================================ */

int pqzk_rand_bytes(uint8_t *out, size_t len)
{
    if (!out || !len) return -1;
    return (RAND_bytes(out, (int)len) == 1) ? 0 : -1;
}