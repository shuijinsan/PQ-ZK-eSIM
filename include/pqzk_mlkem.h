/*
 * pqzk_mlkem.h — ML-KEM (CRYSTALS-Kyber-768) APDU tunnel for operator switching
 */

#ifndef PQZK_MLKEM_H
#define PQZK_MLKEM_H

#include <stdint.h>
#include <stddef.h>
#include "pqzk_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PQZK_MLKEM_PK_BYTES          1184
#define PQZK_MLKEM_SK_BYTES          2400
#define PQZK_MLKEM_CT_BYTES          1088
#define PQZK_MLKEM_SS_BYTES          32
#define PQZK_MLKEM_SESSION_KEY_BYTES 32
#define PQZK_APDU_MAX_PAYLOAD        4096

typedef struct {
    uint8_t pk[PQZK_MLKEM_PK_BYTES];
    uint8_t sk[PQZK_MLKEM_SK_BYTES];
} mlkem_keypair_t;

typedef struct {
    uint8_t  session_key[PQZK_MLKEM_SESSION_KEY_BYTES];
    uint8_t  tunnel_id[16];
    uint8_t  established;
} mlkem_tunnel_t;

typedef struct {
    uint8_t  R_bio_B[32];
    uint8_t  R_bio[32];
    uint8_t  salt[32];
    uint8_t  cred_kyc[64];
    uint8_t  cert_a[PQZK_CERT_BYTES];
    uint8_t  eid[16];
    uint8_t  T_new[PQ_ZK_PUBLICKEY_BYTES];
} apdu_payload_t;

int PQZK_MLKEM_Keygen(mlkem_keypair_t *kp_out);

int PQZK_MLKEM_Encapsulate(const uint8_t  server_pk[PQZK_MLKEM_PK_BYTES],
                             uint8_t        ct_out[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out);

int PQZK_MLKEM_Decapsulate(const mlkem_keypair_t *kp,
                             const uint8_t ct[PQZK_MLKEM_CT_BYTES],
                             mlkem_tunnel_t *tunnel_out);

int PQZK_APDU_Encrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext);

int PQZK_APDU_Decrypt(const mlkem_tunnel_t *tunnel,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext);

int PQZK_APDU_SerializePayload(const apdu_payload_t *payload,
                                uint8_t *buf, size_t buf_len);

int PQZK_APDU_DeserializePayload(const uint8_t *buf, size_t buf_len,
                                   apdu_payload_t *payload_out);

#ifdef __cplusplus
}
#endif

#endif /* PQZK_MLKEM_H */
