/*
 * pqzk_mlkem.c — PQ-ZK-eSIM v5.0
 * ML-KEM（CRYSTALS-Kyber-768）后量子安全 APDU 隧道实现
 *
 * 依赖：
 *   liboqs（OQS_KEM_kyber_768）
 *   pqzk_crypto.c（pqzk_sha256、pqzk_aes256_ctr、pqzk_rand_bytes）
 */

#include "pqzk_mlkem.h"
#include "pqzk_internal.h"

#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * 内部工具：从 KEM 共享密钥派生 APDU 会话密钥
 *
 * session_key = SHA-256(shared_secret || "PQZK-APDU-v1" || tunnel_id)
 *
 * 加入域分离标签和 tunnel_id，确保不同会话的会话密钥互不相关。
 * ================================================================ */
static int derive_session_key(const uint8_t ss[PQZK_MLKEM_SS_BYTES],
                               const uint8_t tunnel_id[16],
                               uint8_t session_key[PQZK_MLKEM_SESSION_KEY_BYTES])
{
    static const uint8_t LABEL[] = "PQZK-APDU-v1";

    pqzk_iov_t iov[] = {
        { ss,        PQZK_MLKEM_SS_BYTES },
        { LABEL,     sizeof(LABEL) - 1   },
        { tunnel_id, 16                  },
        { NULL, 0 }
    };
    return pqzk_sha256_iov(iov, session_key);
}

/* ================================================================
 * PQZK_MLKEM_Keygen
 * MNO_B 生成 ML-KEM-768 密钥对
 * ================================================================ */
int PQZK_MLKEM_Keygen(mlkem_keypair_t *kp_out)
{
    if (!kp_out) return -1;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return -1;

    int ret = -1;
    if (OQS_KEM_keypair(kem, kp_out->pk, kp_out->sk) == OQS_SUCCESS)
        ret = 0;

    OQS_KEM_free(kem);
    return ret;
}

/* ================================================================
 * PQZK_MLKEM_Encapsulate
 * eUICC 端：封装，生成密文和共享密钥，派生会话密钥
 * ================================================================ */
int PQZK_MLKEM_Encapsulate(const uint8_t  server_pk[PQZK_MLKEM_PK_BYTES],
                             uint8_t        ct_out[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out)
{
    if (!server_pk || !ct_out || !tunnel_out) return -1;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return -1;

    uint8_t ss[PQZK_MLKEM_SS_BYTES];
    int ret = -1;

    if (OQS_KEM_encaps(kem, ct_out, ss, server_pk) != OQS_SUCCESS)
        goto done;

    /* 生成随机 tunnel_id */
    if (pqzk_rand_bytes(tunnel_out->tunnel_id, 16) != 0)
        goto done;

    /* 派生会话密钥 */
    if (derive_session_key(ss, tunnel_out->tunnel_id,
                           tunnel_out->session_key) != 0)
        goto done;

    tunnel_out->established = 1;
    ret = 0;

done:
    secure_zero(ss, sizeof(ss));
    OQS_KEM_free(kem);
    return ret;
}

/* ================================================================
 * PQZK_MLKEM_Decapsulate
 * MNO_B 端：解封装，从密文恢复共享密钥，派生相同会话密钥
 * ================================================================ */
int PQZK_MLKEM_Decapsulate(const mlkem_keypair_t *kp,
                             const uint8_t ct[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out)
{
    if (!kp || !ct || !tunnel_out) return -1;
    if (!tunnel_out->established) return -1; /* tunnel_id 须由 eUICC 传入 */

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return -1;

    uint8_t ss[PQZK_MLKEM_SS_BYTES];
    int ret = -1;

    if (OQS_KEM_decaps(kem, ss, ct, kp->sk) != OQS_SUCCESS)
        goto done;

    /* 用 eUICC 传来的 tunnel_id 派生相同的会话密钥 */
    if (derive_session_key(ss, tunnel_out->tunnel_id,
                           tunnel_out->session_key) != 0)
        goto done;

    ret = 0;

done:
    secure_zero(ss, sizeof(ss));
    OQS_KEM_free(kem);
    return ret;
}

/* ================================================================
 * PQZK_APDU_Encrypt / Decrypt
 * 用会话密钥对载荷进行 AES-256-CTR 加密/解密
 *
 * IV = SHA-256(session_key || "ENC" || seq)[0:16]
 * seq 固定为 0（每条隧道消息只发一次，不需要计数器）
 * ================================================================ */
int PQZK_APDU_Encrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext)
{
    if (!tunnel || !tunnel->established) return -1;
    if (!plaintext || !ciphertext || pt_len == 0) return -1;

    static const uint8_t ENC_LABEL[] = "ENC";
    uint8_t seq[8] = {0};

    pqzk_iov_t iov[] = {
        { tunnel->session_key, PQZK_MLKEM_SESSION_KEY_BYTES },
        { ENC_LABEL,           3                            },
        { seq,                 8                            },
        { NULL, 0 }
    };
    uint8_t hash[32], iv[16];
    if (pqzk_sha256_iov(iov, hash) != 0) return -1;
    memcpy(iv, hash, 16);

    return pqzk_aes256_ctr(tunnel->session_key, iv, ciphertext, pt_len);
}

int PQZK_APDU_Decrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext)
{
    /*
     * AES-CTR 加解密完全对称，直接复用 Encrypt。
     * 调用方保证 plaintext 缓冲区 >= ct_len。
     */
    return PQZK_APDU_Encrypt(tunnel, ciphertext, ct_len, plaintext);
}

/* ================================================================
 * PQZK_APDU_SerializePayload / DeserializePayload
 *
 * 序列化格式（全小端序，固定字段布局）：
 *   R_bio_B   [32]
 *   R_bio     [32]
 *   salt      [32]
 *   cred_kyc  [64]
 *   cert_a    [256]
 *   eid       [16]
 *   T_new     [PQ_ZK_PUBLICKEY_BYTES=1184]
 *   总计：32+32+32+64+256+16+1184 = 1616 字节
 * ================================================================ */
#define APDU_PAYLOAD_SERIAL_BYTES \
    (32 + 32 + 32 + 64 + 256 + 16 + PQ_ZK_PUBLICKEY_BYTES)

int PQZK_APDU_SerializePayload(const apdu_payload_t *payload,
                                uint8_t *buf, size_t buf_len)
{
    if (!payload || !buf) return -1;
    if (buf_len < APDU_PAYLOAD_SERIAL_BYTES) return -1;

    size_t off = 0;
    memcpy(buf + off, payload->R_bio_B,  32);   off += 32;
    memcpy(buf + off, payload->R_bio,    32);   off += 32;
    memcpy(buf + off, payload->salt,     32);   off += 32;
    memcpy(buf + off, payload->cred_kyc, 64);   off += 64;
    memcpy(buf + off, payload->cert_a,   256);  off += 256;
    memcpy(buf + off, payload->eid,      16);   off += 16;
    memcpy(buf + off, payload->T_new,    PQ_ZK_PUBLICKEY_BYTES);
    off += PQ_ZK_PUBLICKEY_BYTES;

    return (int)off;
}

int PQZK_APDU_DeserializePayload(const uint8_t *buf, size_t buf_len,
                                   apdu_payload_t *payload_out)
{
    if (!buf || !payload_out) return -1;
    if (buf_len < APDU_PAYLOAD_SERIAL_BYTES) return -1;

    size_t off = 0;
    memcpy(payload_out->R_bio_B,  buf + off, 32);   off += 32;
    memcpy(payload_out->R_bio,    buf + off, 32);   off += 32;
    memcpy(payload_out->salt,     buf + off, 32);   off += 32;
    memcpy(payload_out->cred_kyc, buf + off, 64);   off += 64;
    memcpy(payload_out->cert_a,   buf + off, 256);  off += 256;
    memcpy(payload_out->eid,      buf + off, 16);   off += 16;
    memcpy(payload_out->T_new,    buf + off, PQ_ZK_PUBLICKEY_BYTES);

    return 0;
}