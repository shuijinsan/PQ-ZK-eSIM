#ifndef PQZK_INTERNAL_H
#define PQZK_INTERNAL_H

#include "pq_zk_esim.h"
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_ZK_Q_VAL 8380417

static inline void write_le32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v);b[1]=(uint8_t)(v>>8);b[2]=(uint8_t)(v>>16);b[3]=(uint8_t)(v>>24);
}
static inline void write_le64(uint8_t *b, uint64_t v) {
    b[0]=(uint8_t)(v);b[1]=(uint8_t)(v>>8);b[2]=(uint8_t)(v>>16);b[3]=(uint8_t)(v>>24);
    b[4]=(uint8_t)(v>>32);b[5]=(uint8_t)(v>>40);b[6]=(uint8_t)(v>>48);b[7]=(uint8_t)(v>>56);
}
static inline uint64_t read_le64(const uint8_t *b) {
    return (uint64_t)b[0]|((uint64_t)b[1]<<8)|((uint64_t)b[2]<<16)|((uint64_t)b[3]<<24)
          |((uint64_t)b[4]<<32)|((uint64_t)b[5]<<40)|((uint64_t)b[6]<<48)|((uint64_t)b[7]<<56);
}
static inline int32_t mod_q(int32_t x) {
    int32_t r=x%(int32_t)PQ_ZK_Q_VAL;return (r<0)?r+(int32_t)PQ_ZK_Q_VAL:r;
}
static inline int32_t lift_centered(int32_t x) {
    x=mod_q(x);return (x>(int32_t)PQ_ZK_Q_VAL/2)?x-(int32_t)PQ_ZK_Q_VAL:x;
}
static inline void secure_zero(void *p, size_t n) {
    volatile uint8_t *vp=(volatile uint8_t*)p;while(n--)*vp++=0;
}

int pqzk_sha3_256(const uint8_t *in, size_t len, uint8_t out[32]);
typedef struct { const uint8_t *buf; size_t len; } pqzk_iov_t;
int pqzk_sha3_256_iov(const pqzk_iov_t *iov, uint8_t out[32]);
int pqzk_hmac_sha256_iov(const uint8_t key[32], const pqzk_iov_t *iov, uint8_t out[32]);
int pqzk_hmac_sha256_iov_anykey(const uint8_t *key, size_t key_len, const pqzk_iov_t *iov, uint8_t out[32]);
int pqzk_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
int pqzk_aes256_ctr(const uint8_t key[32], const uint8_t iv[16], uint8_t *out, size_t out_len);
int pqzk_prf(const uint8_t K_sym[32], const uint8_t c_seed[32], uint64_t ctr, const uint8_t R_dynamic[32], uint8_t *out, size_t out_len);
int pqzk_kdf(const uint8_t K_sym[32], const uint8_t d_seed[32], const uint8_t *eid, size_t eid_len, uint8_t new_key[32]);
int pqzk_rand_bytes(uint8_t *out, size_t len);

void pqzk_sample_gauss_vec(const uint8_t *seed, size_t seed_len, poly_vec_t *out);
void pqzk_sample_in_ball(const uint8_t hash[32], poly_t *c);
void pqzk_parse_poly_vec(const uint8_t *stream, size_t stream_len, poly_vec_t *out);

void pqzk_gen_matrix_A(const uint8_t seed[32], poly_vec_t *A_rows, int k_rows, int m_cols);
void pqzk_mat_vec_mul(const poly_vec_t *A_rows, const poly_vec_t *v, poly_vec_t *result, int k_rows, int m_cols);
void pqzk_mat_vec_mul_ntt(const poly_vec_t *A_rows, const poly_vec_t *v, poly_vec_t *result, int k_rows, int m_cols);
void pqzk_vec_scalar_mul(const poly_vec_t *S, const poly_t *c, poly_vec_t *result, int vec_dim);
void pqzk_vec_add(const poly_vec_t *a, const poly_vec_t *b, poly_vec_t *result, int vec_dim);
void pqzk_vec_sub(const poly_vec_t *a, const poly_vec_t *b, poly_vec_t *result, int vec_dim);

#define NVRAM_EID_LEN 16
#define NVRAM_SKEY_LEN PQ_ZK_POLYVEC_BYTES
#define NVRAM_SYM_LEN 32
#define NVRAM_TEE_LEN 32
#define NVRAM_DSEED_LEN 32
#define NVRAM_YSEC_LEN PQ_ZK_POLYVEC_BYTES

/* Backup slot for previous MNO state (Paper Algorithm 3: switch-back support) */
typedef struct __attribute__((packed)) {
    uint8_t  sk_s[NVRAM_SKEY_LEN];
    uint8_t  k_sym[NVRAM_SYM_LEN];
    uint8_t  d_seed[NVRAM_DSEED_LEN];
    uint8_t  cred_kyc[PQZK_MLDSA_SIG_BYTES];
    uint8_t  mno_id[PQZK_MNO_ID_BYTES];
    uint8_t  active_R_bio[32];
    uint64_t ctr_local;
} mno_backup_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];
    uint8_t  eid[NVRAM_EID_LEN];
    uint8_t  sk_s[NVRAM_SKEY_LEN];
    uint8_t  k_sym[NVRAM_SYM_LEN];
    uint8_t  k_tee[NVRAM_TEE_LEN];
    uint8_t  d_seed[NVRAM_DSEED_LEN];
    uint64_t ctr_local;
    uint8_t  y_sec[NVRAM_YSEC_LEN];
    uint8_t  y_sec_valid;
    uint8_t  salt[32];
    uint8_t  cred_kyc[PQZK_MLDSA_SIG_BYTES];
    uint8_t  auth_retry_count;
    uint8_t  _pad[5];
    uint8_t  R_bio[32];
    uint8_t  tree_nodes[PQZK_MERKLE_MAX_DEPTH+1][PQZK_MERKLE_MAX_LEAVES][PQZK_MERKLE_HASH_BYTES];
    uint32_t tree_n_leaves;
    uint32_t tree_depth;
    uint8_t  tree_valid;
    uint8_t  active_mno_id[PQZK_MNO_ID_BYTES];
    uint8_t  active_R_bio[32];
    uint32_t switch_count;
    mno_backup_t prev_mno;  /* preserved MNO_A state for switch-back */
} nvram_state_t;

int nvram_read(const char *nvram_dir, nvram_state_t *state);
int nvram_write_atomic(const char *nvram_dir, const nvram_state_t *state);
int nvram_update_ctr_and_key(const char *nvram_dir, uint64_t new_ctr, const uint8_t new_k_sym[32]);
void nvram_reset_write_count(void);
uint64_t nvram_get_byte_count(void);
uint64_t nvram_get_write_count(void);

extern const uint8_t PQZK_MATRIX_A_SEED[32];

#ifdef __cplusplus
}
#endif
#endif
