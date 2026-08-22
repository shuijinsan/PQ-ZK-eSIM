/* pq_zk_esim.c — v5.1
 * PQ-ZK-eSIM protocol implementation
 * K=5, M=8, q=8380417, kappa=35, sigma=5000
 * int32_t coefficients, int64_t intermediates (anti-overflow)
 */

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#define PQZK_WINDOW_MAX 32
#define NVRAM_MAGIC "PQZK"

/* ================================================================
 * Internal utilities
 * ================================================================ */

/* sample_binomial_B1 -- centered binomial B_1 (Paper Table 1): Pr[+1]=1/4, Pr[0]=1/2, Pr[-1]=1/4 */static void sample_binomial_B1(const uint8_t seed[32], poly_vec_t *v){    int total = PQ_ZK_M * PQ_ZK_N;    uint8_t buf[PQ_ZK_M * PQ_ZK_N * 2];    uint8_t expanded[40];    memcpy(expanded, seed, 32);    for (int block = 0; block * 32 < total * 2; block++) {        write_le64(expanded + 32, (uint64_t)block);        pqzk_sha3_256(expanded, 40, buf + block * 32);    }    for (int i = 0; i < total; i++) {        int a = (buf[2*i] >> 0) & 1;        int b = (buf[2*i] >> 1) & 1;        v->coeffs[i] = a - b;    }    secure_zero(buf, sizeof(buf));}
static void sample_ternary(const uint8_t seed[32], poly_vec_t *y_sec)
{
    uint8_t buf[PQ_ZK_M * PQ_ZK_N];
    pqzk_shake256(seed, 32, buf, sizeof(buf));
    for (int i = 0; i < PQ_ZK_M * PQ_ZK_N; i++) {
        uint8_t b = buf[i] & 0x03;
        if      (b == 2) y_sec->coeffs[i] =  1;
        else if (b == 3) y_sec->coeffs[i] = -1;
        else             y_sec->coeffs[i] =  0;
    }
    secure_zero(buf, sizeof(buf));
}

/* ================================================================
 * Serialization — int32_t, 4 bytes per coefficient LE
 * ================================================================ */

void PQC_EncodePolyVec(const poly_vec_t *in_poly, uint8_t *out_bytes, int vec_dim)
{
    if (!in_poly || !out_bytes) return;
    for (int i = 0; i < vec_dim * PQ_ZK_N; i++) {
        uint32_t v = (uint32_t)in_poly->coeffs[i];
        out_bytes[i * 4]     = (uint8_t)(v & 0xFF);
        out_bytes[i * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        out_bytes[i * 4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        out_bytes[i * 4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }
}

void PQC_DecodePolyVec(const uint8_t *in_bytes, poly_vec_t *out_poly, int vec_dim)
{
    if (!in_bytes || !out_poly) return;
    for (int i = 0; i < vec_dim * PQ_ZK_N; i++) {
        uint32_t v = (uint32_t)in_bytes[i * 4]
                   | ((uint32_t)in_bytes[i * 4 + 1] << 8)
                   | ((uint32_t)in_bytes[i * 4 + 2] << 16)
                   | ((uint32_t)in_bytes[i * 4 + 3] << 24);
        out_poly->coeffs[i] = (int32_t)v;
    }
}

void PQC_EncodePoly(const poly_t *in_poly, uint8_t *out_bytes)
{
    if (!in_poly || !out_bytes) return;
    for (int i = 0; i < PQ_ZK_N; i++) {
        uint32_t v = (uint32_t)in_poly->coeffs[i];
        out_bytes[i * 4]     = (uint8_t)(v & 0xFF);
        out_bytes[i * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        out_bytes[i * 4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        out_bytes[i * 4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }
}

void PQC_DecodePoly(const uint8_t *in_bytes, poly_t *out_poly)
{
    if (!in_bytes || !out_poly) return;
    for (int i = 0; i < PQ_ZK_N; i++) {
        uint32_t v = (uint32_t)in_bytes[i * 4]
                   | ((uint32_t)in_bytes[i * 4 + 1] << 8)
                   | ((uint32_t)in_bytes[i * 4 + 2] << 16)
                   | ((uint32_t)in_bytes[i * 4 + 3] << 24);
        out_poly->coeffs[i] = (int32_t)v;
    }
}

/* encode/decode_polyvec_24bit — pubkey T compression (3 bytes/coeff) */
static void encode_polyvec_24bit(const poly_vec_t *in, uint8_t *out, int vec_dim)
{
    int total = vec_dim * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        uint32_t v = (uint32_t)((int64_t)in->coeffs[i] % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
        int j = i * 3;
        out[j]   = (uint8_t)(v & 0xFF);
        out[j+1] = (uint8_t)((v >> 8) & 0xFF);
        out[j+2] = (uint8_t)((v >> 16) & 0xFF);
    }
}

static void decode_polyvec_24bit(const uint8_t *in, poly_vec_t *out, int vec_dim)
{
    int total = vec_dim * PQ_ZK_N;
    for (int i = 0; i < total; i++) {
        int j = i * 3;
        uint32_t v = (uint32_t)in[j]
                   | ((uint32_t)in[j+1] << 8)
                   | ((uint32_t)in[j+2] << 16);
        out->coeffs[i] = (int32_t)(v % PQ_ZK_Q_VAL);
    }
}

/* Merkle path serialization (unchanged) */
#define PQZK_MERKLE_PATH_SERIAL_MAX \
    (8 + PQZK_MERKLE_MAX_DEPTH * (PQZK_MERKLE_HASH_BYTES + 1))

static int serialize_merkle_path(const merkle_path_t *path,
                                  uint8_t *buf, size_t buf_len)
{
    if (!path || !buf) return -1;
    size_t needed = 8 + (size_t)path->depth * (PQZK_MERKLE_HASH_BYTES + 1);
    if (buf_len < needed) return -1;
    size_t off = 0;
    write_le32(buf + off, path->depth);       off += 4;
    write_le32(buf + off, path->leaf_index);  off += 4;
    for (uint32_t i = 0; i < path->depth; i++) {
        memcpy(buf + off, path->sibling[i], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        buf[off] = path->is_right_sibling[i];
        off += 1;
    }
    return (int)off;
}

/* ================================================================
 * Key Generation — K=5, M=8 rectangular MSIS
 * ================================================================ */

void PQC_GenKeyPair(uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES], poly_vec_t *sk_s)
{
    if (!pk_t || !sk_s) return;
    uint8_t sk_seed[32];
    pqzk_rand_bytes(sk_seed, 32);
    sample_binomial_B1(sk_seed, sk_s);
    memcpy(pk_t, PQZK_MATRIX_A_SEED, 32);

    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K, PQ_ZK_M);
    poly_vec_t T;
    pqzk_mat_vec_mul(A_rows, sk_s, &T, PQ_ZK_K, PQ_ZK_M);
    encode_polyvec_24bit(&T, pk_t + 32, PQ_ZK_K);

    secure_zero(sk_seed, sizeof(sk_seed));
    secure_zero(A_rows, sizeof(A_rows));
    secure_zero(&T, sizeof(T));
}

void PQC_eUICC_Init(const char* nvram_dir,
                    const uint8_t* eid,   size_t eid_len,
                    const poly_vec_t* sk_s,
                    const uint8_t* k_sym, size_t k_sym_len,
                    uint64_t initial_ctr,
                    const uint8_t* k_tee, size_t k_tee_len,
                    const uint8_t* salt,
                    const uint8_t* R_bio,
                    const uint8_t* cred_kyc, size_t cred_kyc_len)
{
    if (!nvram_dir || !eid || !sk_s || !k_sym || !k_tee) return;
    if (eid_len > NVRAM_EID_LEN || k_sym_len > 32 || k_tee_len > 32) return;

    nvram_state_t state;
    memset(&state, 0, sizeof(state));
    memset(state.active_mno_id, 0, PQZK_MNO_ID_BYTES);
    memset(state.active_R_bio,  0, 32);
    memcpy(state.magic, NVRAM_MAGIC, 4);
    memcpy(state.eid,   eid,   eid_len);
    PQC_EncodePolyVec(sk_s, state.sk_s, PQ_ZK_M);
    memcpy(state.k_sym, k_sym, k_sym_len);
    memcpy(state.k_tee, k_tee, k_tee_len);
    if (salt)      memcpy(state.salt,     salt,     32);
    if (R_bio) { memcpy(state.R_bio, R_bio, 32); memcpy(state.active_R_bio, R_bio, 32); }
    else       { memset(state.R_bio, 0, 32); memset(state.active_R_bio, 0, 32); }
    if (cred_kyc)  memcpy(state.cred_kyc, cred_kyc, cred_kyc_len > 64 ? 64 : cred_kyc_len);
    state.ctr_local = initial_ctr;
    state.switch_count = 0;
    state.auth_retry_count = 0;
    state.y_sec_valid = 0;
    state.tree_valid = 0;
    pqzk_sha3_256(k_sym, k_sym_len, state.d_seed);
    nvram_write_atomic(nvram_dir, &state);
    secure_zero(&state, sizeof(state));
}

PQ_ZK_ErrorCode PQC_Register(
    const char    *nvram_dir,
    const uint8_t  feature_blocks[][PQZK_MERKLE_HASH_BYTES],
    size_t         n_blocks,
    const uint8_t  k_sym[32],
    const uint8_t  k_tee[32],
    uint64_t       initial_ctr,
    const uint8_t  mno_id[PQZK_MNO_ID_BYTES],
    uint8_t        pk_t_out[PQ_ZK_PUBLICKEY_BYTES],
    uint8_t        R_bio_out[32],
    uint8_t        salt_out[32])
{
    if (!nvram_dir || !feature_blocks || !k_sym ||
        !k_tee || !mno_id || !pk_t_out || !R_bio_out || !salt_out)
        return PQ_ZK_ERR_INVALID_PARAM;

    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t_out, &sk_s);
    pqzk_rand_bytes(salt_out, 32);

    merkle_tree_t tree;
    if (PQC_MerkleTree_Build(feature_blocks, n_blocks, salt_out, mno_id, &tree) != 0) {
        secure_zero(&sk_s, sizeof(sk_s));
        return PQ_ZK_ERR_INVALID_PARAM;
    }
    memcpy(R_bio_out, tree.root, 32);

    nvram_state_t state;
    memset(&state, 0, sizeof(state));
    memcpy(state.magic, "PQZK", 4);
    memcpy(state.k_sym, k_sym, 32);
    memcpy(state.k_tee, k_tee, 32);
    memcpy(state.salt, salt_out, 32);
    memcpy(state.R_bio, R_bio_out, 32);
    memcpy(state.active_R_bio, R_bio_out, 32);
    memcpy(state.active_mno_id, mno_id, PQZK_MNO_ID_BYTES);
    PQC_EncodePolyVec(&sk_s, state.sk_s, PQ_ZK_M);
    pqzk_sha3_256(k_sym, 32, state.d_seed);
    state.ctr_local = initial_ctr;
    state.y_sec_valid = 0;
    state.switch_count = 0;
    state.auth_retry_count = 0;
    state.tree_valid = 1;
    state.tree_n_leaves = tree.n_leaves;
    state.tree_depth = tree.depth;
    memcpy(state.tree_nodes, tree.nodes, sizeof(tree.nodes));
    nvram_write_atomic(nvram_dir, &state);

    secure_zero(&sk_s, sizeof(sk_s));
    secure_zero(&state, sizeof(state));
    return PQ_ZK_SUCCESS;
}

PQ_ZK_ErrorCode PQC_LoadTree(const char *nvram_dir, merkle_tree_t *tree_out)
{
    if (!nvram_dir || !tree_out) return PQ_ZK_ERR_INVALID_PARAM;
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) return PQ_ZK_ERR_NOT_INITIALIZED;
    if (!state.tree_valid) { secure_zero(&state, sizeof(state)); return PQ_ZK_ERR_NOT_INITIALIZED; }
    memset(tree_out, 0, sizeof(*tree_out));
    tree_out->n_leaves = state.tree_n_leaves;
    tree_out->depth = state.tree_depth;
    memcpy(tree_out->root, state.active_R_bio, 32);
    memcpy(tree_out->salt, state.salt, 32);
    memcpy(tree_out->nodes, state.tree_nodes, sizeof(tree_out->nodes));
    secure_zero(&state, sizeof(state));
    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * Phase 1: Commitment Generation
 * ================================================================ */

void PQC_PreCompute(poly_vec_t *W_pub, uint8_t seed_y[PQ_ZK_SEED_BYTES])
{
    if (!W_pub || !seed_y) return;
    pqzk_rand_bytes(seed_y, PQ_ZK_SEED_BYTES);
    poly_vec_t y_pub;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, &y_pub);
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K, PQ_ZK_M);
    pqzk_mat_vec_mul_ntt(A_rows, &y_pub, W_pub, PQ_ZK_K, PQ_ZK_M);
    secure_zero(&y_pub, sizeof(y_pub));
    secure_zero(A_rows, sizeof(A_rows));
}

void PQC_RegenerateYpub(const uint8_t seed_y[PQ_ZK_SEED_BYTES], poly_vec_t *y_pub)
{
    if (!seed_y || !y_pub) return;
    pqzk_sample_gauss_vec(seed_y, PQ_ZK_SEED_BYTES, y_pub);
}

void PQC_eUICC_Commit(const char* nvram_dir, poly_vec_t *W_sec,
                       uint8_t MAC_W[PQ_ZK_MAC_BYTES])
{
    if (!nvram_dir || !W_sec || !MAC_W) return;
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) return;

    uint8_t ysec_seed[32];
    pqzk_rand_bytes(ysec_seed, 32);
    poly_vec_t y_sec;
    sample_ternary(ysec_seed, &y_sec);
    secure_zero(ysec_seed, 32);

    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K, PQ_ZK_M);
    pqzk_mat_vec_mul(A_rows, &y_sec, W_sec, PQ_ZK_K, PQ_ZK_M);
    secure_zero(A_rows, sizeof(A_rows));

    uint8_t wsec_bytes[PQ_ZK_POLYVEC_BYTES];
    uint8_t ctr_bytes[8];
    PQC_EncodePolyVec(W_sec, wsec_bytes, PQ_ZK_K);
    write_le64(ctr_bytes, state.ctr_local);
    pqzk_iov_t mac_iov[] = {
        { state.eid, NVRAM_EID_LEN },
        { wsec_bytes, (size_t)PQ_ZK_K * PQ_ZK_N * 4 },
        { ctr_bytes,  8 },
        { NULL, 0 }
    };
    /* HKDF: derive K_MAC from K_sym (Paper Table 2, Algorithm 4) */
    uint8_t k_mac[32];
    pqzk_hkdf_expand(state.k_sym, "MAC", 3, k_mac);
    pqzk_aes256_cmac(k_mac, mac_iov, MAC_W);
    secure_zero(k_mac, sizeof(k_mac));

    PQC_EncodePolyVec(&y_sec, state.y_sec, PQ_ZK_M);
    state.y_sec_valid = 1;
    nvram_write_atomic(nvram_dir, &state);

    secure_zero(&y_sec, sizeof(y_sec));
    secure_zero(wsec_bytes, sizeof(wsec_bytes));
    secure_zero(&state, sizeof(state));
}

/* ================================================================
 * Phase 2: Challenge Generation
 * ================================================================ */

void PQC_GenChallenge(const poly_vec_t *comm_W,
                      const uint8_t nonce[PQ_ZK_SEED_BYTES], poly_t *c_agg)
{
    if (!comm_W || !nonce || !c_agg) return;
    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W, W_bytes, PQ_ZK_K);
    pqzk_iov_t iov[] = {
        { nonce,   PQ_ZK_SEED_BYTES },
        { W_bytes, (size_t)PQ_ZK_K * PQ_ZK_N * 4 },
        { NULL, 0 }
    };
    uint8_t hash[32];
    pqzk_sha3_256_iov(iov, hash);
    pqzk_sample_in_ball(hash, c_agg);
}

/* ================================================================
 * Phase 3: TEE AuthToken
 * ================================================================ */

PQ_ZK_ErrorCode TEE_GenerateAuthToken(
    const char          *nvram_dir,
    const poly_t        *c_agg,
    const uint8_t        R_bio[PQZK_MERKLE_HASH_BYTES],
    const merkle_tree_t *tree,
    uint32_t             M1,
    const uint8_t        k_tee[PQ_ZK_TEE_KEY_BYTES],
    uint8_t              R_dynamic_out[PQ_ZK_SEED_BYTES],
    merkle_path_t       *M2_out,
    uint8_t              AuthToken_out[PQ_ZK_MAC_BYTES])
{
    if (!nvram_dir || !c_agg || !R_bio || !tree ||
        !k_tee || !R_dynamic_out || !M2_out || !AuthToken_out)
        return PQ_ZK_ERR_INVALID_PARAM;
    if (M1 >= tree->n_leaves) return PQ_ZK_ERR_INVALID_PARAM;

    nvram_state_t nvram_st;
    if (nvram_read(nvram_dir, &nvram_st) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    uint8_t ctr_le8[8];
    write_le64(ctr_le8, nvram_st.ctr_local);

    pqzk_iov_t rdyn_iov[] = {
        { R_bio,   PQZK_MERKLE_HASH_BYTES },
        { ctr_le8, 8 },
        { NULL, 0 }
    };
    if (pqzk_sha3_256_iov(rdyn_iov, R_dynamic_out) != 0)
        return PQ_ZK_ERR_MAC_FAIL;

    if (PQC_MerkleTree_GetPath(tree, M1, M2_out) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(c_agg, cagg_bytes);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes,    PQ_ZK_POLY_BYTES },
        { ctr_le8,       8 },
        { R_dynamic_out, PQ_ZK_SEED_BYTES },
        { NULL, 0 }
    };
    if (pqzk_aes256_cmac(k_tee, auth_iov, AuthToken_out) != 0)
        return PQ_ZK_ERR_MAC_FAIL;

    secure_zero(&nvram_st, sizeof(nvram_st));
    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * Phase 4: Masked Computation (eUICC Core, M=8 dim)
 * ================================================================ */

PQ_ZK_ErrorCode PQC_ComputeZ_and_Mask(
    const char*    nvram_dir,
    const poly_t  *c_agg,
    const uint8_t  c_seed[PQ_ZK_SEED_BYTES],
    const uint8_t  R_dynamic[PQ_ZK_SEED_BYTES],
    const uint8_t  AuthToken[PQ_ZK_MAC_BYTES],
    poly_vec_t    *z_sec_masked)
{
    if (!nvram_dir || !c_agg || !c_seed || !R_dynamic ||
        !AuthToken || !z_sec_masked)
        return PQ_ZK_ERR_INVALID_PARAM;

    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0)
        return PQ_ZK_ERR_INVALID_PARAM;

    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    uint8_t ctr_bytes[8];
    PQC_EncodePoly(c_agg, cagg_bytes);
    write_le64(ctr_bytes, state.ctr_local);

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8 },
        { R_dynamic,  PQ_ZK_SEED_BYTES },
        { NULL, 0 }
    };
    uint8_t expected_token[PQ_ZK_MAC_BYTES];
    pqzk_aes256_cmac(state.k_tee, auth_iov, expected_token);

    volatile int mismatch = 0;
    for (int i = 0; i < PQ_ZK_MAC_BYTES; i++)
        mismatch |= (expected_token[i] ^ AuthToken[i]);

    if (mismatch) {
        state.auth_retry_count++;
        if (state.auth_retry_count >= 3) {
            state.auth_retry_count = 0;
            secure_zero(&state, sizeof(state));
            secure_zero(expected_token, PQ_ZK_MAC_BYTES);
            return PQ_ZK_ERR_RESYNC_NEEDED;
        }
        nvram_write_atomic(nvram_dir, &state);
        secure_zero(&state, sizeof(state));
        secure_zero(expected_token, PQ_ZK_MAC_BYTES);
        return PQ_ZK_ERR_MAC_FAIL;
    }
    state.auth_retry_count = 0;

    uint64_t ctr_session = state.ctr_local;

    /* Challenge check: exactly kappa=35 nonzero entries in {-1,1} */
    int ham_weight = 0;
    for (int i = 0; i < PQ_ZK_N; i++) {
        int32_t v = c_agg->coeffs[i];
        if (v != -1 && v != 0 && v != 1) {
            secure_zero(&state, sizeof(state));
            return PQ_ZK_ERR_CHALLENGE_WEIGHT;
        }
        if (v != 0) ham_weight++;
    }
    if (ham_weight != PQ_ZK_CHALLENGE_WEIGHT) {
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_CHALLENGE_WEIGHT;
    }

    if (!state.y_sec_valid) {
        secure_zero(&state, sizeof(state));
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    /* z_sec = y_sec + S*c_agg (M=8 dim) */
    poly_vec_t y_sec, sk_s, S_c_agg, z_sec;
    PQC_DecodePolyVec(state.y_sec, &y_sec, PQ_ZK_M);
    PQC_DecodePolyVec(state.sk_s,  &sk_s,  PQ_ZK_M);
    pqzk_vec_scalar_mul(&sk_s, c_agg, &S_c_agg, PQ_ZK_M);
    pqzk_vec_add(&y_sec, &S_c_agg, &z_sec, PQ_ZK_M);

    /* M_mask = Parse(PRF(K_sym, c_seed||ctr_session||R_dynamic)), M=8 dim */
    size_t mask_stream_len = (size_t)PQ_ZK_M * PQ_ZK_N * 3;
    uint8_t *mask_stream = (uint8_t *)malloc(mask_stream_len);
    if (!mask_stream) {
        secure_zero(&state, sizeof(state));
        secure_zero(&y_sec, sizeof(y_sec));
        secure_zero(&z_sec, sizeof(z_sec));
        secure_zero(&sk_s, sizeof(sk_s));
        return PQ_ZK_ERR_INVALID_PARAM;
    }
    /* HKDF: derive K_PRF from K_sym */
    uint8_t k_prf[32];
    pqzk_hkdf_expand(state.k_sym, "PRF", 3, k_prf);
    pqzk_prf(k_prf, c_seed, ctr_session, R_dynamic,
              mask_stream, mask_stream_len);

    poly_vec_t M_mask;
    pqzk_parse_poly_vec(mask_stream, mask_stream_len, &M_mask);
    free(mask_stream);
    pqzk_vec_add(&z_sec, &M_mask, z_sec_masked, PQ_ZK_M);

    /* Forward-secret key evolution */
    uint8_t new_k_sym[32];
    pqzk_kdf(state.k_sym, state.d_seed, state.eid, NVRAM_EID_LEN, new_k_sym);

    state.ctr_local   = ctr_session + 1;
    state.y_sec_valid = 0;
    memset(state.y_sec, 0, sizeof(state.y_sec));
    memcpy(state.k_sym, new_k_sym, 32);
    nvram_write_atomic(nvram_dir, &state);

    secure_zero(&y_sec,   sizeof(y_sec));
    secure_zero(&sk_s,    sizeof(sk_s));
    secure_zero(&z_sec,   sizeof(z_sec));
    secure_zero(&S_c_agg, sizeof(S_c_agg));
    secure_zero(new_k_sym, 32);
    secure_zero(cagg_bytes, sizeof(cagg_bytes));
    secure_zero(expected_token, PQ_ZK_MAC_BYTES);
    secure_zero(&state, sizeof(state));

    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * Phase 5: LPA Aggregation
 * ================================================================ */

void PQC_LPA_Aggregate(const poly_vec_t *z_sec_masked,
                        const poly_vec_t *y_pub, poly_vec_t *resp_z)
{
    if (!z_sec_masked || !y_pub || !resp_z) return;
    pqzk_vec_add(z_sec_masked, y_pub, resp_z, PQ_ZK_M);
}

/* ================================================================
 * Phase 6: Verification Engine
 * ================================================================ */

void PQC_GenerateMask(const uint8_t K_sym[PQ_ZK_SEED_BYTES],
                       const uint8_t c_seed[PQ_ZK_SEED_BYTES],
                       uint64_t ctr_session,
                       const uint8_t R_dynamic[PQ_ZK_SEED_BYTES],
                       poly_vec_t *M_mask)
{
    if (!K_sym || !c_seed || !R_dynamic || !M_mask) return;
    size_t stream_len = (size_t)PQ_ZK_M * PQ_ZK_N * 3;
    uint8_t *stream = (uint8_t *)malloc(stream_len);
    if (!stream) return;
    uint8_t k_prf[32];
    pqzk_hkdf_expand(K_sym, "PRF", 3, k_prf);
    pqzk_prf(k_prf, c_seed, ctr_session, R_dynamic, stream, stream_len);
    secure_zero(k_prf, sizeof(k_prf));
    pqzk_parse_poly_vec(stream, stream_len, M_mask);
    free(stream);
}

PQ_ZK_ErrorCode PQC_VerifyEngine(
    const uint8_t    mat_A_seed[32],
    const uint8_t    pk_t[PQ_ZK_PUBLICKEY_BYTES],
    const poly_vec_t *comm_W,
    const poly_vec_t *resp_z,
    const uint8_t    nonce_s[32],
    const uint8_t    R_dynamic[32],
    const poly_vec_t *M_mask,
    const beta_params_t *beta_params)
{
    if (!mat_A_seed || !pk_t || !comm_W || !resp_z ||
        !nonce_s || !R_dynamic || !M_mask || !beta_params)
        return PQ_ZK_ERR_INVALID_PARAM;

    /* Step 1: Reconstruct challenge */
    poly_t c_agg;
    PQC_GenChallenge(comm_W, nonce_s, &c_agg);

    /* Step 2: z_unmasked = Lift((z - M_mask) mod q), M=8 dim */
    poly_vec_t z_minus_mask;
    pqzk_vec_sub(resp_z, M_mask, &z_minus_mask, PQ_ZK_M);

    poly_vec_t z_unmasked;
    for (int i = 0; i < PQ_ZK_M * PQ_ZK_N; i++) {
        int32_t v = z_minus_mask.coeffs[i];
        if (v > PQ_ZK_Q_VAL / 2) v -= PQ_ZK_Q_VAL;
        z_unmasked.coeffs[i] = v;
    }

    /* Step 3: Triple norm check (Linf / L2 / L1) on M*N=2048 coefficients */
    int32_t inf_norm = 0;
    int64_t l2_sq    = 0;
    int64_t l1_norm  = 0;
    for (int i = 0; i < PQ_ZK_M * PQ_ZK_N; i++) {
        int32_t v  = z_unmasked.coeffs[i];
        int32_t av = (v < 0) ? -v : v;
        if (av > inf_norm) inf_norm = av;
        l2_sq += (int64_t)v * v;
        l1_norm += (int64_t)av;
    }
    if (l2_sq < (int64_t)beta_params->beta_min * beta_params->beta_min)
        return PQ_ZK_ERR_NORM_BOUND;
    if (l2_sq > (int64_t)beta_params->beta_final * beta_params->beta_final)
        return PQ_ZK_ERR_NORM_BOUND;
    if (inf_norm > (int32_t)PQ_ZK_BETA_INF)
        return PQ_ZK_ERR_NORM_BOUND;
    if (beta_params->beta_l1 > 0 &&
        l1_norm < (int64_t)beta_params->beta_l1)
        return PQ_ZK_ERR_NORM_BOUND;

    /* Step 4: W' = A*z_unmasked - T*c_agg mod q
     * A: KxM, z: M-dim -> Az: K-dim. T: K-dim, c: scalar -> Tc: K-dim */
    poly_vec_t A_rows[PQ_ZK_K];
    pqzk_gen_matrix_A(mat_A_seed, A_rows, PQ_ZK_K, PQ_ZK_M);

    poly_vec_t T_key;
    decode_polyvec_24bit(pk_t + 32, &T_key, PQ_ZK_K);

    poly_vec_t Az, Tc, W_prime;
    pqzk_mat_vec_mul_ntt(A_rows, &z_unmasked, &Az, PQ_ZK_K, PQ_ZK_M);
    pqzk_vec_scalar_mul(&T_key, &c_agg, &Tc, PQ_ZK_K);
    pqzk_vec_sub(&Az, &Tc, &W_prime, PQ_ZK_K);

    /* Step 5: Constant-time W' == W comparison (K-dim, K*N*4 bytes) */
    uint8_t W_bytes[PQ_ZK_POLYVEC_BYTES];
    uint8_t Wp_bytes[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(comm_W,   W_bytes,  PQ_ZK_K);
    PQC_EncodePolyVec(&W_prime, Wp_bytes, PQ_ZK_K);

    volatile int diff = 0;
    int cmp_bytes = PQ_ZK_K * PQ_ZK_N * 4;
    for (int i = 0; i < cmp_bytes; i++)
        diff |= (W_bytes[i] ^ Wp_bytes[i]);

    if (diff) return PQ_ZK_ERR_MAC_FAIL;
    return PQ_ZK_SUCCESS;
}

/* ================================================================
 * Sliding Window Forward Secrecy
 * ================================================================ */

static void evolve_key_n_steps(const uint8_t k_in[32], const uint8_t d_seed[32],
    const uint8_t *eid, size_t eid_len, uint32_t n, uint8_t k_out[32])
{
    uint8_t tmp[32];
    memcpy(tmp, k_in, 32);
    for (uint32_t i = 0; i < n; i++) {
        uint8_t next[32];
        pqzk_kdf(tmp, d_seed, eid, eid_len, next);
        memcpy(tmp, next, 32);
        secure_zero(next, 32);
    }
    memcpy(k_out, tmp, 32);
    secure_zero(tmp, 32);
}

static void compute_mac_w(const uint8_t k_try[32], const poly_vec_t *W_sec,
    uint64_t ctr_window, const uint8_t *eid, uint8_t mac_out[PQ_ZK_MAC_BYTES])
{
    uint8_t wsec_bytes[PQ_ZK_POLYVEC_BYTES];
    uint8_t ctr_bytes[8];
    PQC_EncodePolyVec(W_sec, wsec_bytes, PQ_ZK_K);
    write_le64(ctr_bytes, ctr_window);
    pqzk_iov_t iov[] = {
        { eid, NVRAM_EID_LEN },
        { wsec_bytes, (size_t)PQ_ZK_K * PQ_ZK_N * 4 },
        { ctr_bytes,  8 },
        { NULL, 0 }
    };
    /* HKDF: derive K_MAC from k_try */
    uint8_t k_mac[32];
    pqzk_hkdf_expand(k_try, "MAC", 3, k_mac);
    pqzk_aes256_cmac(k_mac, iov, mac_out);
    secure_zero(k_mac, sizeof(k_mac));
    secure_zero(wsec_bytes, sizeof(wsec_bytes));
    secure_zero(ctr_bytes, sizeof(ctr_bytes));
}

PQ_ZK_ErrorCode PQC_Server_SlidingWindowSync(
    const server_state_t *srv, const poly_vec_t *W_sec,
    const uint8_t MAC_W[PQ_ZK_MAC_BYTES], uint32_t window_size,
    uint64_t *ctr_session_out, uint8_t k_synced_out[32])
{
    if (!srv || !W_sec || !MAC_W || !ctr_session_out || !k_synced_out)
        return PQ_ZK_ERR_INVALID_PARAM;
    if (window_size == 0 || window_size > PQZK_WINDOW_MAX)
        return PQ_ZK_ERR_INVALID_PARAM;

    PQ_ZK_ErrorCode result = PQ_ZK_ERR_SYNC_WINDOW;
    uint8_t k_try[32];
    memcpy(k_try, srv->k_sym, 32);

    for (uint32_t delta = 0; delta <= window_size; delta++) {
        uint64_t ctr_window = srv->ctr_server + (uint64_t)delta;
        uint8_t mac_candidate[PQ_ZK_MAC_BYTES];
        compute_mac_w(k_try, W_sec, ctr_window, srv->eid, mac_candidate);

        volatile int mismatch = 0;
        for (int b = 0; b < PQ_ZK_MAC_BYTES; b++)
            mismatch |= (mac_candidate[b] ^ MAC_W[b]);
        secure_zero(mac_candidate, sizeof(mac_candidate));

        if (!mismatch) {
            memcpy(k_synced_out, k_try, 32);
            *ctr_session_out = ctr_window;
            result = PQ_ZK_SUCCESS;
            break;
        }
        if (delta < window_size) {
            uint8_t k_next[32];
            pqzk_kdf(k_try, srv->d_seed, srv->eid, NVRAM_EID_LEN, k_next);
            memcpy(k_try, k_next, 32);
            secure_zero(k_next, 32);
        }
    }
    secure_zero(k_try, 32);
    return result;
}

PQ_ZK_ErrorCode PQC_Server_CommitSync(
    server_state_t *srv_state_out, uint64_t ctr_session, const uint8_t k_synced[32])
{
    if (!srv_state_out || !k_synced) return PQ_ZK_ERR_INVALID_PARAM;
    memcpy(srv_state_out->k_sym, k_synced, 32);
    srv_state_out->ctr_server = ctr_session + 1;
    return PQ_ZK_SUCCESS;
}
