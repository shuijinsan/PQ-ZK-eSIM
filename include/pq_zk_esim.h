#ifndef PQ_ZK_ESIM_H
#define PQ_ZK_ESIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pqzk_merkle.h"
#include "pqzk_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_ZK_N 256
#define PQ_ZK_K 5
#define PQ_ZK_M 8
#define PQ_ZK_SEED_BYTES 32
#define PQ_ZK_TEE_KEY_BYTES 32
#define PQ_ZK_MAC_BYTES 32
#define PQ_ZK_CHALLENGE_WEIGHT 35
#define PQ_ZK_ETA_S 1
#define PQ_ZK_SIGMA_PUB 5000.0
#define PQ_ZK_BETA_INF 35700
#define PQ_ZK_BETA_FINAL 260000
#define PQ_ZK_PUBLICKEY_BYTES (32 + PQ_ZK_K * PQ_ZK_N * 3)
#define PQ_ZK_POLYVEC_BYTES (PQ_ZK_M * PQ_ZK_N * 4)
#define PQ_ZK_POLY_BYTES (PQ_ZK_N * 4)

typedef enum {
    PQ_ZK_SUCCESS = 0,
    PQ_ZK_ERR_MAC_FAIL = -1,
    PQ_ZK_ERR_CHALLENGE_WEIGHT = -2,
    PQ_ZK_ERR_NORM_BOUND = -3,
    PQ_ZK_ERR_INVALID_PARAM = -4,
    PQ_ZK_ERR_NOT_INITIALIZED = -5,
    PQ_ZK_ERR_YSEC_CONSUMED = -6,
    PQ_ZK_ERR_RESYNC_NEEDED = -7,
    PQ_ZK_ERR_SYNC_WINDOW = -8
} PQ_ZK_ErrorCode;

typedef struct {
    uint64_t ctr_server;
    uint8_t  k_sym[32];
    uint8_t  d_seed[32];
    uint8_t  eid[16];
} server_state_t;

#define PQZK_WINDOW_MAX 32

typedef struct { int32_t coeffs[PQ_ZK_N]; } poly_t;

typedef struct {
    uint32_t beta_final;
    uint32_t beta_min;
    uint32_t beta_l1;
} beta_params_t;

typedef struct { int32_t coeffs[PQ_ZK_M * PQ_ZK_N]; } poly_vec_t;

#define PQZK_DEFAULT_BETA_PARAMS ((beta_params_t){ .beta_final = PQ_ZK_BETA_FINAL, .beta_min = 200000, .beta_l1 = 7400000 })

void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s);
void PQC_EncodePoly(const poly_t *in_poly, uint8_t *out_bytes);
void PQC_DecodePoly(const uint8_t *in_bytes, poly_t *out_poly);
void PQC_eUICC_Init(const char* nvram_dir, const uint8_t* eid, size_t eid_len,
    const poly_vec_t* sk_s, const uint8_t* k_sym, size_t k_sym_len,
    uint64_t initial_ctr, const uint8_t* k_tee, size_t k_tee_len,
    const uint8_t* salt, const uint8_t* R_bio,
    const uint8_t* cred_kyc, size_t cred_kyc_len);
void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes, int vec_dim);
void PQC_DecodePolyVec(const uint8_t *in_bytes, poly_vec_t *out_poly, int vec_dim);
void PQC_PreCompute(poly_vec_t *W_pub, uint8_t seed_y[PQ_ZK_SEED_BYTES]);
void PQC_RegenerateYpub(const uint8_t seed_y[PQ_ZK_SEED_BYTES], poly_vec_t *y_pub);
void PQC_eUICC_Commit(const char* nvram_dir, poly_vec_t *W_sec, uint8_t MAC_W[PQ_ZK_MAC_BYTES]);
void PQC_GenChallenge(const poly_vec_t *comm_W, const uint8_t nonce[PQ_ZK_SEED_BYTES], poly_t *c_agg);

PQ_ZK_ErrorCode TEE_GenerateAuthToken(const char *nvram_dir, const poly_t *c_agg,
    const uint8_t R_bio[PQ_ZK_MAC_BYTES], const merkle_tree_t *tree,
    uint32_t M1, const uint8_t k_tee[PQ_ZK_TEE_KEY_BYTES],
    uint8_t R_dynamic_out[PQ_ZK_SEED_BYTES], merkle_path_t *M2_out,
    uint8_t AuthToken_out[PQ_ZK_MAC_BYTES]);

PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(const char* nvram_dir, const poly_t *c_agg,
    const uint8_t c_seed[PQ_ZK_SEED_BYTES], const uint8_t R_dynamic[PQ_ZK_SEED_BYTES],
    const uint8_t AuthToken[PQ_ZK_MAC_BYTES], poly_vec_t *z_sec_masked);

void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked, const poly_vec_t *y_pub, poly_vec_t *resp_z);
void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES], const uint8_t c_seed[PQ_ZK_SEED_BYTES],
    uint64_t ctr_session, const uint8_t R_dynamic[PQ_ZK_SEED_BYTES], poly_vec_t *M_mask);

PQ_ZK_ErrorCode PQC_VerifyEngine(const uint8_t mat_A_seed[32], const uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES],
    const poly_vec_t *comm_W, const poly_vec_t *resp_z, const uint8_t nonce_s[32],
    const uint8_t R_dynamic[32], const poly_vec_t *M_mask, const beta_params_t *beta_params);

PQ_ZK_ErrorCode PQC_Server_SlidingWindowSync(const server_state_t *srv,
    const poly_vec_t *W_sec, const uint8_t MAC_W[PQ_ZK_MAC_BYTES],
    uint32_t window_size, uint64_t *ctr_session_out, uint8_t k_synced_out[32]);

PQ_ZK_ErrorCode PQC_Server_CommitSync(server_state_t *srv_state_out,
    uint64_t ctr_session, const uint8_t k_synced[32]);

PQ_ZK_ErrorCode PQC_Register(const char *nvram_dir,
    const uint8_t feature_blocks[][PQZK_MERKLE_HASH_BYTES], size_t n_blocks,
    const uint8_t k_sym[32], const uint8_t k_tee[32], uint64_t initial_ctr,
    const uint8_t mno_id[PQZK_MNO_ID_BYTES],
    uint8_t pk_t_out[PQ_ZK_PUBLICKEY_BYTES], uint8_t R_bio_out[32], uint8_t salt_out[32]);

PQ_ZK_ErrorCode PQC_LoadTree(const char *nvram_dir, merkle_tree_t *tree_out);

int mode_switch(const char *nvram_dir, const uint8_t domain_id_b[PQZK_MNO_ID_BYTES],
    const uint8_t mno_a_id[PQZK_MNO_ID_BYTES], const uint8_t mno_a_sk[32]);

#endif
