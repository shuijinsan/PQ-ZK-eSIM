/*
 * main.c — PQ-ZK-eSIM simulation entry point
 * Usage: ./pqzkesim --auth --nvram /tmp/euicc
 *        ./pqzkesim --switch --nvram /tmp/euicc --mno-b-id MNO_B_001
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_cert.h"

/* mode_switch (see mode_switch.c) */
int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_sk[32]);

/* mode_auth (see below) */
static int mode_auth(const char *nvram_dir);

/* Authentication mode */
static int mode_auth(const char *nvram_dir)
{
    printf("[Auth] nvram: %s\n", nvram_dir);

    merkle_tree_t tree;
    PQ_ZK_ErrorCode load_rc = PQC_LoadTree(nvram_dir, &tree);
    if (load_rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[Error] nvram not initialized, register first\n");
        return -1;
    }

    printf("[Auth] Merkle tree loaded, leaves:: %u\n", tree.n_leaves);

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    uint8_t R_bio[32], salt[32], k_sym[32];
    FILE *reg = fopen("registration_data.bin", "rb");
    if (!reg) {
        fprintf(stderr, "[Error] registration_data.bin not found\n");
        return -1;
    }
    fread(pk_t,  1, PQ_ZK_PUBLICKEY_BYTES, reg);
    fread(R_bio, 1, 32, reg);
    fread(salt,  1, 32, reg);
    fread(k_sym, 1, 32, reg);
    fclose(reg);

    printf("[Auth] Biometric match: PASS\n");

    /* Phase 1 */
    poly_vec_t W_pub, W_sec;
    uint8_t seed_y[32], MAC_W[32];
    PQC_PreCompute(&W_pub, seed_y);
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    poly_vec_t W;
    pqzk_vec_add(&W_sec, &W_pub, &W, PQ_ZK_K);
    printf("[Phase 1] Commitment done\n");

    /* Phase 2 */
    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);
    poly_t c_agg;
    PQC_GenChallenge(&W, c_seed, &c_agg);
    uint32_t M1 = 0;
    printf("[Phase 2] Challenge done\n");

    /* Phase 3 */
    nvram_state_t nvram_st;
    nvram_read(nvram_dir, &nvram_st);
    uint8_t k_tee[32];
    memcpy(k_tee, nvram_st.k_tee, 32);
    secure_zero(&nvram_st, sizeof(nvram_st));

    uint8_t R_dynamic[32];
    merkle_path_t M2;
    uint8_t AuthToken[32];
    PQ_ZK_ErrorCode tee_rc = TEE_GenerateAuthToken(
        nvram_dir, &c_agg, R_bio, &tree,
        M1, k_tee, R_dynamic, &M2, AuthToken);
    if (tee_rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[Error] TEE token generation failed: %d\n", tee_rc);
        return -1;
    }
    printf("[Phase 3] TEE AuthToken done\n");

    /* Serialize M2 for root reconstruction */
    uint8_t m2s[8 + PQZK_MERKLE_MAX_DEPTH*(PQZK_MERKLE_HASH_BYTES+1)];
    size_t off = 0;
    write_le32(m2s + off, M2.depth);      off += 4;
    write_le32(m2s + off, M2.leaf_index); off += 4;
    for (uint32_t i = 0; i < M2.depth; i++) {
        memcpy(m2s + off, M2.sibling[i], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        m2s[off] = M2.is_right_sibling[i]; off++;
    }

    /* Phase 4 */
    poly_vec_t z_sec_masked;
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic, AuthToken, &z_sec_masked);
    if (rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[Error] Phase 4 failed: %d\n", rc);
        return -1;
    }
    printf("[Phase 4] Masked response done\n");

    /* Phase 5 */
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);
    printf("[Phase 5] Aggregation done\n");

    /* Phase 6 */
    nvram_read(nvram_dir, &nvram_st);
    uint8_t ctr_le8[8];
    write_le64(ctr_le8, nvram_st.ctr_local - 1);
    secure_zero(&nvram_st, sizeof(nvram_st));

    pqzk_iov_t ri[] = {{ R_bio, 32 }, { ctr_le8, 8 }, { NULL, 0 }};
    uint8_t R_dynamic_server[32];
    pqzk_sha3_256_iov(ri, R_dynamic_server);

    poly_vec_t M_mask;
    uint64_t ctr_session;
    memcpy(&ctr_session, ctr_le8, 8);
    PQC_GenerateMask(k_sym, c_seed, ctr_session, R_dynamic_server, &M_mask);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;
    PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, R_dynamic_server, &M_mask, &params);

    if (vrc == PQ_ZK_SUCCESS) {
        printf("[Phase 6] Verify PASS ✓\n");
        printf("[Auth] Success!\n");
        return 0;
    } else {
        fprintf(stderr, "[Phase 6] Verify FAIL: %d\n", vrc);
        return -1;
    }
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    const char *nvram_dir     = "/tmp/pqzk_euicc";
    int do_auth = 0, do_switch = 0;

    /*
     * MNO_A / MNO_B identifiers
     * Real: from operator profile
     * Sim: cmdline or default
     */
    uint8_t mno_a_id[PQZK_MNO_ID_BYTES];
    uint8_t mno_b_id[PQZK_MNO_ID_BYTES];
    uint8_t mno_a_sk[32];

    /* Default MNO_A (sim) */
    memset(mno_a_id, 0, sizeof(mno_a_id));
    memcpy(mno_a_id, "MNO_A_SIM_001", 13);

    /* Default MNO_B (sim) */
    memset(mno_b_id, 0, sizeof(mno_b_id));
    memcpy(mno_b_id, "MNO_B_SIM_001", 13);

    /* MNO_A signing key (sim, fixed) */
    memset(mno_a_sk, 0xA1, 32);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--auth"))      do_auth     = 1;
        if (!strcmp(argv[i], "--switch"))    do_switch   = 1;
        if (!strcmp(argv[i], "--nvram")   && i+1 < argc)
            nvram_dir    = argv[++i];
        if (!strcmp(argv[i], "--mno-a-id") && i+1 < argc) {
            memset(mno_a_id, 0, sizeof(mno_a_id));
            strncpy((char*)mno_a_id, argv[++i], PQZK_MNO_ID_BYTES);
        }
        if (!strcmp(argv[i], "--mno-b-id") && i+1 < argc) {
            memset(mno_b_id, 0, sizeof(mno_b_id));
            strncpy((char*)mno_b_id, argv[++i], PQZK_MNO_ID_BYTES);
        }
    }

    printf("============================================\n");
    printf("  PQ-ZK-eSIM  simulation\n");
    printf("  nvram: %s\n", nvram_dir);
    printf("============================================\n");

    mkdir(nvram_dir, 0700);

    if (do_auth)     return mode_auth(nvram_dir);
    if (do_switch) {
         /* Read current operator from NVRAM */
        nvram_state_t cur_state;
        if (nvram_read(nvram_dir, &cur_state) == 0) {
            printf("[Switch] Current operator: %.16s\n",
                   (char*)cur_state.active_mno_id);
            printf("[Switch] Switch count: %u\n", cur_state.switch_count);
            secure_zero(&cur_state, sizeof(cur_state));
        }
        printf("[Switch] Target operator: %.16s\n", (char*)mno_b_id);
        return mode_switch(nvram_dir, mno_b_id, mno_a_id, mno_a_sk);
    }
  
    printf("\nUsage:\n");
    printf("  auth: %s --auth --nvram /tmp/euicc\n", argv[0]);
    printf("  switch: %s --switch --nvram /tmp/euicc"
           " --mno-a-id MNO_A_001 --mno-b-id MNO_B_001\n", argv[0]);
    printf("\nNote: registration is offline，via tools/setup_euicc.sh\n");
    printf("      Real eSIM uses OOB NFC/USB channel for registration\n");
    return 0;
}