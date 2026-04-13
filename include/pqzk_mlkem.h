/*
 * pqzk_mlkem.h — PQ-ZK-eSIM v5.0
 * ML-KEM（CRYSTALS-Kyber）后量子安全 APDU 隧道
 *
 * 协议对应：§5.1.5 运营商切换
 *   eUICC 与 MNO_B 利用 ML-KEM 算法建立后量子安全的 APDU 隧道，
 *   在隧道内传输身份证据包和新的密钥材料。
 *
 * 实现说明：
 *   · 底层调用 liboqs 的 OQS_KEM_kyber_768
 *   · 隧道建立采用标准 KEM 封装/解封装模式
 *   · 会话密钥派生：SHA-256(shared_secret || "PQZK-APDU-v1")
 *   · 载荷加密：AES-256-CTR（复用 pqzk_crypto.c 的 pqzk_aes256_ctr）
 *
 * 模拟环境说明：
 *   真实场景中隧道建立通过 NFC/USB OOB 信道，
 *   模拟环境中双方共享内存，直接传递字节数组。
 */

#ifndef PQZK_MLKEM_H
#define PQZK_MLKEM_H

#include <stdint.h>
#include <stddef.h>
#include "pqzk_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量定义（基于 ML-KEM-768 / Kyber-768）
 * ================================================================ */

/* Kyber-768 公钥长度 */
#define PQZK_MLKEM_PK_BYTES    1184

/* Kyber-768 私钥长度 */
#define PQZK_MLKEM_SK_BYTES    2400

/* Kyber-768 密文长度 */
#define PQZK_MLKEM_CT_BYTES    1088

/* 共享密钥长度 */
#define PQZK_MLKEM_SS_BYTES    32

/* 会话密钥长度（派生后） */
#define PQZK_MLKEM_SESSION_KEY_BYTES  32

/* APDU 载荷最大长度（模拟环境） */
#define PQZK_APDU_MAX_PAYLOAD  4096

/* ================================================================
 * 数据结构
 * ================================================================ */

/*
 * mlkem_keypair_t — ML-KEM 密钥对（MNO_B 端持有）
 *
 * MNO_B 服务器生成密钥对，将公钥发给 eUICC，
 * 用私钥解封装 eUICC 发来的密文，得到共享密钥。
 */
typedef struct {
    uint8_t pk[PQZK_MLKEM_PK_BYTES];
    uint8_t sk[PQZK_MLKEM_SK_BYTES];
} mlkem_keypair_t;

/*
 * mlkem_tunnel_t — ML-KEM APDU 隧道上下文
 *
 * 双方完成 KEM 握手后，用 session_key 对载荷进行 AES-256-CTR 加密。
 * tunnel_id 用于区分不同的切换会话。
 */
typedef struct {
    uint8_t  session_key[PQZK_MLKEM_SESSION_KEY_BYTES];
    uint8_t  tunnel_id[16];   /* 随机会话标识 */
    uint8_t  established;     /* 1=已建立，0=未建立 */
} mlkem_tunnel_t;

/*
 * apdu_payload_t — 切换时传输的身份证据包
 *
 * 对应协议 §5.1.5：
 *   eUICC 将 (R_bio_B, R_bio, salt, Cred_KYC, Cert_A) 封装进隧道载荷
 */
typedef struct {
    uint8_t  R_bio_B[32];         /* 运营商专属生物根 */
    uint8_t  R_bio[32];           /* 原始静态生物根 */
    uint8_t  salt[32];            /* 设备专属盐 */
    uint8_t  cred_kyc[64];        /* KYC 凭证：Sign(SK_MNO_A, EID||R_bio) */
    uint8_t  cert_a[256];         /* MNO_A 证书（模拟：自签名，256字节占位） */
    uint8_t  eid[16];             /* 设备标识 */
    uint8_t  T_new[PQ_ZK_PUBLICKEY_BYTES]; /* 为 MNO_B 生成的新公钥 */
} apdu_payload_t;

/* ================================================================
 * ML-KEM 接口
 * ================================================================ */

/*
 * PQZK_MLKEM_Keygen — MNO_B 生成 ML-KEM 密钥对
 *
 * MNO_B 在切换握手开始时调用，生成一次性密钥对。
 * 公钥发给 eUICC，私钥留存用于解封装。
 *
 * 参数：
 *   kp_out  输出密钥对
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_MLKEM_Keygen(mlkem_keypair_t *kp_out);

/*
 * PQZK_MLKEM_Encapsulate — eUICC 端封装，建立共享密钥
 *
 * eUICC 收到 MNO_B 的公钥后调用，生成：
 *   · ciphertext：发给 MNO_B 用于解封装
 *   · tunnel：包含派生的会话密钥，用于后续载荷加密
 *
 * 参数：
 *   server_pk    MNO_B 的 ML-KEM 公钥
 *   ct_out       输出密文（发给 MNO_B）
 *   tunnel_out   输出隧道上下文（eUICC 本地持有）
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_MLKEM_Encapsulate(const uint8_t  server_pk[PQZK_MLKEM_PK_BYTES],
                             uint8_t        ct_out[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out);

/*
 * PQZK_MLKEM_Decapsulate — MNO_B 端解封装，得到共享密钥
 *
 * MNO_B 收到 eUICC 发来的密文后调用，派生相同的会话密钥。
 *
 * 参数：
 *   kp           MNO_B 的密钥对（含私钥）
 *   ciphertext   eUICC 发来的密文
 *   tunnel_out   输出隧道上下文（MNO_B 本地持有）
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_MLKEM_Decapsulate(const mlkem_keypair_t *kp,
                             const uint8_t ct[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out);

/*
 * PQZK_APDU_Encrypt — 用隧道会话密钥加密载荷
 *
 * 参数：
 *   tunnel       已建立的隧道上下文
 *   plaintext    明文载荷
 *   pt_len       明文长度
 *   ciphertext   输出密文缓冲区（长度 >= pt_len）
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_APDU_Encrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext);

/*
 * PQZK_APDU_Decrypt — 用隧道会话密钥解密载荷
 *
 * 参数：
 *   tunnel       已建立的隧道上下文
 *   ciphertext   密文
 *   ct_len       密文长度
 *   plaintext    输出明文缓冲区（长度 >= ct_len）
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_APDU_Decrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext);

/*
 * PQZK_APDU_SerializePayload — 序列化身份证据包为字节流
 *
 * 参数：
 *   payload   输入结构体
 *   buf       输出缓冲区
 *   buf_len   缓冲区大小
 *
 * 返回：序列化后字节数，-1 失败
 */
int PQZK_APDU_SerializePayload(const apdu_payload_t *payload,
                                uint8_t *buf, size_t buf_len);

/*
 * PQZK_APDU_DeserializePayload — 反序列化字节流为身份证据包
 *
 * 返回：0 成功，-1 失败
 */
int PQZK_APDU_DeserializePayload(const uint8_t *buf, size_t buf_len,
                                   apdu_payload_t *payload_out);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_MLKEM_H */