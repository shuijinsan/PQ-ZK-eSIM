/*
 * mode_switch.c — PQ-ZK-eSIM v5.2 operator switching (Algorithm 3)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "pq_zk_esim.h"
#include <oqs/oqs.h>
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_cert.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-28s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/* Step 1: TEE biometric match (simulated) */
static int tee_biometric_verify(void)
{
    printf("  [TEE] Biometric match (sim): user present\n");
    return 0;
}

/* Step 2: TEE computes domain-bound bio root R_bio_dom_B */
static int tee_derive_domain_root(const uint8_t  R_bio[32],
                                   const uint8_t  did_b[PQZK_MNO_ID_BYTES],
                                   const uint8_t  salt[32],
                                   const uint8_t  feature_blocks[][PQZK_MERKLE_HASH_BYTES],
                                   size_t         n_blocks,
                                   uint8_t        R_bio_B_out[32])
{
    merkle_tree_t tree_b;
    int rc = PQC_MerkleTree_Build(feature_blocks, n_blocks, salt, did_b, &tree_b);
    if (rc != 0) return rc;
    memcpy(R_bio_B_out, tree_b.root, 32);
    return 0;
}

/*
 * Steps 4-6: SM-DP+ interaction (simulated).
 * Real: eUICC → LPA → ES9+ mTLS → SM-DP+
 * Sim: direct function calls.
 */
static int smdp_switch(const uint8_t  eid[16],
                        const uint8_t  did_a[PQZK_MNO_ID_BYTES],
                        const uint8_t  did_b[PQZK_MNO_ID_BYTES],
                        const uint8_t  R_bio_A[32],
                        const uint8_t  cred_kyc_a[PQZK_MLDSA_SIG_BYTES],
                        const uint8_t  R_bio_B[32],
                        uint8_t        cred_kyc_b_out[PQZK_MLDSA_SIG_BYTES],
                        size_t        *cred_kyc_b_len)
{
    /* Verify Cred_KYC_A over (EID, DID_A, R_bio_A) with SM-DP+ public key */
    if (PQZK_CredKYC_Verify(eid, did_a, R_bio_A, cred_kyc_a, PQZK_MLDSA_SIG_BYTES) != 0) {
        fprintf(stderr, "  [SM-DP+] Cred_KYC_A verify failed\n");
        return -1;
    }
    printf("  [SM-DP+] Cred_KYC_A verified\n");

    /* Issue Cred_KYC_B = Sign_SM-DP+(EID, DID_B, R_bio_B) */
    if (PQZK_CredKYC_Issue(eid, did_b, R_bio_B, cred_kyc_b_out, cred_kyc_b_len) != 0) {
        fprintf(stderr, "  [SM-DP+] Cred_KYC_B issue failed\n");
        return -1;
    }
    printf("  [SM-DP+] Cred_KYC_B issued\n");
    return 0;
}

int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES])
{
    printf("\n============================================\n");
    printf("  Operator Switch (MNO_A -> MNO_B)\n");
    printf("============================================\n");

    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "[Error] nvram not initialized\n");
        return -1;
    }

    /* Already registered? Just activate stored assets */
    /* In simulation, check if tree exists for this DID */
    if (memcmp(state.active_mno_id, domain_id_b, PQZK_MNO_ID_BYTES) == 0) {
        printf("[Switch] DID_B already active\n");
        secure_zero(&state, sizeof(state));
        return 0;
    }

    printf("[Switch] EID: ");
    for (int i = 0; i < 16; i++) printf("%02x", state.eid[i]);
    printf("\n");

    /* Step 1: TEE biometric match */
    printf("\n[Step 1] TEE biometric match\n");
    if (tee_biometric_verify() != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 2: TEE computes domain-bound bio root for MNO_B */
    printf("\n[Step 2] Compute domain-bound bio root\n");
    uint8_t R_bio_B[32];
    /* In simulation, reload feature blocks from the stored Merkle tree.
     * Real TEE stores all hashes from enrollment. Here we read the tree. */
    merkle_tree_t tree;
    if (nvram_read(nvram_dir, &state) != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }
    /* Use the stored Merkle tree salt and root to derive R_bio_B.
     * Simplified: R_bio_B = SHA3-256(R_bio || DID_B) */
    pqzk_iov_t iov[] = {
        { state.R_bio, 32 },
        { domain_id_b, PQZK_MNO_ID_BYTES },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(iov, R_bio_B);
    print_hex("R_bio (original, unchanged)", state.R_bio, 32);
    print_hex("Target DID_B", domain_id_b, PQZK_MNO_ID_BYTES);
    print_hex("R_bio_B (domain-specific)", R_bio_B, 32);

    /* Step 3: eUICC generates new keypair for MNO_B */
    printf("\n[Step 3] eUICC generates MNO_B keypair\n");
    poly_vec_t sk_b;
    uint8_t    pk_b[PQ_ZK_PUBLICKEY_BYTES];
    PQC_GenKeyPair(pk_b, &sk_b);
    print_hex("T_B (new public key)", pk_b, 8);
    printf("  [eUICC] S_B generated\n");

    /* Steps 4-5: SM-DP+ interaction */
    printf("\n[Step 4-5] SM-DP+ credential exchange\n");
    printf("  [eUICC → LPA → ES9+ → SM-DP+] Send Cred_KYC_A, R_bio_B\n");

    uint8_t cred_kyc_b[PQZK_MLDSA_SIG_BYTES];
    size_t cred_kyc_b_len = 0;
    if (smdp_switch(state.eid, mno_a_id, domain_id_b,
                    state.R_bio, state.cred_kyc,
                    R_bio_B, cred_kyc_b, &cred_kyc_b_len) != 0) {
        fprintf(stderr, "[Step 4-5] SM-DP+ handshake failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 6: MNO_B provisions keys and verifies */
    printf("\n[Step 6] MNO_B provisions keys\n");
    printf("  [SM-DP+ → eUICC] Deliver Cred_KYC_B, K_sym_B, d_seed_B\n");

    /* MNO_B pre-provisions new symmetric keys */
    uint8_t k_sym_b[32], d_seed_b[32];
    pqzk_rand_bytes(k_sym_b,  32);
    pqzk_rand_bytes(d_seed_b, 32);
    print_hex("K_sym_B[0:16]", k_sym_b, 16);

    /* eUICC verifies Cred_KYC_B over (EID, DID_B, R_bio_B) with SM-DP+ public key */
    if (PQZK_CredKYC_Verify(state.eid, domain_id_b, R_bio_B, cred_kyc_b, cred_kyc_b_len) != 0) {
        fprintf(stderr, "  [eUICC] Cred_KYC_B verify failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    printf("  [eUICC] Cred_KYC_B verified\n");

    /* Upload T_B to MNO_B (via SM-DP+ in real deployment) */
    printf("  [eUICC → SM-DP+ → MNO_B] Upload T_B\n");

    /* Step 7: Activate MNO_B assets */
    printf("\n[Step 7] Activate MNO_B assets\n");

    /* Update symmetric keys */
    memcpy(state.k_sym,  k_sym_b,  32);
    memcpy(state.d_seed, d_seed_b, 32);

    /* Update lattice secret key */
    PQC_EncodePolyVec(&sk_b, state.sk_s, PQ_ZK_M);

    /* Update active biometric root */
    memcpy(state.active_R_bio, R_bio_B, 32);
    /* R_bio (static root) unchanged */

    /* Random counter init */
    uint64_t new_ctr;
    pqzk_rand_bytes((uint8_t*)&new_ctr, 8);
    state.ctr_local   = new_ctr;
    state.y_sec_valid = 0;
    memset(state.y_sec, 0, sizeof(state.y_sec));

    /* Update active MNO ID */
    memcpy(state.active_mno_id, domain_id_b, PQZK_MNO_ID_BYTES);
    state.switch_count += 1;

    /* Update Cred_KYC to new one */
    memset(state.cred_kyc, 0, PQZK_MLDSA_SIG_BYTES);
    memcpy(state.cred_kyc, cred_kyc_b, cred_kyc_b_len);

    /* Atomic NVRAM write */
    if (nvram_write_atomic(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram write failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    printf("  [eUICC] NVRAM updated\n");
    printf("  [eUICC] R_bio (static root) unchanged\n");
    printf("  [eUICC] active_R_bio = R_bio_B\n");
    printf("  [eUICC] counter reset to random\n");

    secure_zero(&state,  sizeof(state));
    secure_zero(&sk_b,   sizeof(sk_b));
    secure_zero(k_sym_b,  32);
    secure_zero(d_seed_b, 32);

    printf("\n============================================\n");
    printf("  Operator switch complete\n");
    printf("============================================\n");
    return 0;
}
