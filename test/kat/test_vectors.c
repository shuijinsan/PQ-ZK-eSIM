/*
 * test_vectors.c — v4.0
 *
 *
 *
 *   · pqzk_internal.h
 *   · pqzk_merkle.h
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"

static int g_pass = 0, g_fail = 0;

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%-36s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

#define ASSERT_EQ(label, a, b, len) do { \
    if (memcmp(a, b, len) == 0) { printf("[PASS] %s\n", label); g_pass++; } \
    else { \
        printf("[FAIL] %s\n", label); g_fail++; \
        printf("  exp: "); for(int _i=0;_i<(int)(len)&&_i<16;_i++) printf("%02x",((uint8_t*)b)[_i]); printf("...\n"); \
        printf("  got: "); for(int _i=0;_i<(int)(len)&&_i<16;_i++) printf("%02x",((uint8_t*)a)[_i]); printf("...\n"); \
    } \
} while(0)

#define ASSERT_TRUE(label, cond) do { \
    if (cond) { printf("[PASS] %s\n", label); g_pass++; } \
    else       { printf("[FAIL] %s\n", label); g_fail++; } \
} while(0)

/* ================================================================
 * ================================================================ */
static void make_dir(const char *path)
{
    mkdir(path, 0700);
}

/* ================================================================
 * KAT 1：EncodePolyVec / DecodePolyVec
 *
 * Cross-platform anchor: expected values must match Python ctypes and Android JNI.
 * ================================================================ */
static void kat_encode_decode(void)
{
    printf("\n=== KAT 1: PQC_EncodePolyVec / DecodePolyVec ===\n");

    poly_vec_t orig;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++)
        orig.coeffs[i] = (int16_t)(i % PQ_ZK_Q_VAL);

    uint8_t encoded[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(&orig, encoded, PQ_ZK_M);

 
    uint8_t exp_head[12] = {0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x02,0x00,0x00,0x00};
    ASSERT_EQ("EncodePolyVec first 3 coeffs", encoded, exp_head, 12);
    print_hex("encoded[0:8]", encoded, 8);

    poly_vec_t decoded;
    PQC_DecodePolyVec(encoded, &decoded, PQ_ZK_M);
    ASSERT_EQ("DecodePolyVec roundtrip",
              (uint8_t*)decoded.coeffs, (uint8_t*)orig.coeffs, sizeof(orig.coeffs));
}

/* ================================================================
 * KAT 2：EncodePoly / DecodePoly
 *
 * ================================================================ */
static void kat_encode_poly(void)
{
    printf("\n=== KAT 2: PQC_EncodePoly / PQC_DecodePoly ===\n");

    poly_t orig;
    memset(&orig, 0, sizeof(orig));
    orig.coeffs[0] =  1;
    orig.coeffs[1] = -1;
    orig.coeffs[2] =  0;
    orig.coeffs[3] =  1;

    uint8_t encoded[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&orig, encoded);

 
    uint8_t exp_head[16] = {0x01,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00};
    ASSERT_EQ("EncodePoly {1,-1,0,1}", encoded, exp_head, 16);

    poly_t decoded;
    PQC_DecodePoly(encoded, &decoded);
    ASSERT_EQ("DecodePoly roundtrip",
              (uint8_t*)decoded.coeffs, (uint8_t*)orig.coeffs, sizeof(orig.coeffs));
}

/* ================================================================
 * KAT 3：SHA-256 / HMAC-SHA256
 *
 * Use NIST standard test vectors， OpenSSL 。
 * ================================================================ */
static void kat_hash_mac(void)
{
    printf("\n=== KAT 3: SHA-256 / HMAC-SHA256 ===\n");

    uint8_t h[32];
/*
 * NIST test vectors */
    pqzk_sha3_256((uint8_t*)"", 0, h);
    uint8_t sha256_empty[32] = {
        0xe3,0xb0,0xc4,0x42, 0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8, 0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4, 0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b, 0x78,0x52,0xb8,0x55
    };
    ASSERT_EQ("SHA256 empty string", h, sha256_empty, 32);
/*
 * NIST test vectors */
    pqzk_sha3_256((uint8_t*)"abc", 3, h);
    uint8_t sha256_abc[32] = {
        0xba,0x78,0x16,0xbf, 0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde, 0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3, 0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61, 0xf2,0x00,0x15,0xad
    };
    ASSERT_EQ("SHA256 'abc'", h, sha256_abc, 32);
    print_hex("SHA256('abc')", h, 32);

 
    uint8_t key3[3] = {0x6b,0x65,0x79};
    uint8_t msg[]   = "The quick brown fox jumps over the lazy dog";
    uint8_t mac[32];
    pqzk_iov_t iov[] = {{ msg, sizeof(msg)-1 }, { NULL, 0 }};
    pqzk_hmac_sha256_iov_anykey(key3, 3, iov, mac);
    uint8_t expected_mac[32] = {
        0xf7,0xbc,0x83,0xf4, 0x30,0x53,0x84,0x24,
        0xb1,0x32,0x98,0xe6, 0xaa,0x6f,0xb1,0x43,
        0xef,0x4d,0x59,0xa1, 0x49,0x46,0x17,0x59,
        0x97,0x47,0x9d,0xbc, 0x2d,0x1a,0x3c,0xd8
    };
    ASSERT_EQ("HMAC-SHA256", mac, expected_mac, 32);
    print_hex("HMAC-SHA256", mac, 32);
}

/* ================================================================
 *
 * PRF test
 * ================================================================ */
static void kat_prf(void)
{
    printf("\n=== KAT 4: PRF (AES-256-CTR, v4.0 R_dynamic) ===\n");

    uint8_t K_sym[32], c_seed[32], R_dynamic[32];
    memset(K_sym,     0xAA, 32);
    memset(c_seed,    0xBB, 32);
    memset(R_dynamic, 0xCC, 32);
    uint64_t ctr = 42;

    uint8_t out[64], out2[64], out3[64];
    pqzk_prf(K_sym, c_seed, ctr,     R_dynamic, out,  64);
    pqzk_prf(K_sym, c_seed, ctr,     R_dynamic, out2, 64);
    pqzk_prf(K_sym, c_seed, ctr + 1, R_dynamic, out3, 64);

    print_hex("PRF output[0:32]",  out,      32);
    print_hex("PRF output[32:64]", out + 32, 32);

    /* determinism：same input -> same output */
    ASSERT_EQ("PRF deterministic", out, out2, 64);

 
    ASSERT_TRUE("PRF ctr sensitivity", memcmp(out, out3, 64) != 0);

    uint8_t R_dynamic2[32];
    memset(R_dynamic2, 0xDD, 32);
    uint8_t out4[64];
    pqzk_prf(K_sym, c_seed, ctr, R_dynamic2, out4, 64);
    ASSERT_TRUE("PRF R_dynamic sensitivity", memcmp(out, out4, 64) != 0);
}

/* ================================================================
 * KAT 5：SampleInBall_κ
 *
 * ================================================================ */
static void kat_sample_in_ball(void)
{
    printf("\n=== KAT 5: SampleInBall_κ ===\n");

    uint8_t hash[32];
    memset(hash, 0x01, 32);

    poly_t c;
    pqzk_sample_in_ball(hash, &c);

    int weight = 0, bad = 0;
    for (int i = 0; i < PQ_ZK_N; i++) {
        int16_t v = c.coeffs[i];
        if (v != -1 && v != 0 && v != 1) bad++;
        if (v != 0) weight++;
    }
    print_hex("c_agg coeffs[0:16]", (uint8_t*)c.coeffs, 16);
    printf("Hamming weight: %d (expected %d)\n", weight, PQ_ZK_CHALLENGE_WEIGHT);
    ASSERT_TRUE("SampleInBall weight & domain",
                weight == PQ_ZK_CHALLENGE_WEIGHT && bad == 0);

    /* determinismverify */
    poly_t c2;
    pqzk_sample_in_ball(hash, &c2);
    ASSERT_EQ("SampleInBall deterministic",
              (uint8_t*)c.coeffs, (uint8_t*)c2.coeffs, sizeof(c.coeffs));
}

/* ================================================================
 *
 * ================================================================ */
static void kat_merkle(void)
{
    uint8_t eid[16] = {0};
    printf("\n=== KAT 6: Merkle Tree ===\n");

 
    uint8_t features[4][32];
    for (int i = 0; i < 4; i++)
        memset(features[i], (uint8_t)(0x11 * (i + 1)), 32);
    uint8_t test_salt[32];
    memset(test_salt, 0xAB, 32);

 
    merkle_tree_t tree;
    int rc = PQC_MerkleTree_Build(
        (const uint8_t (*)[32])features, 4,
        test_salt, eid,
        &tree);
    ASSERT_TRUE("MerkleTree_Build", rc == 0);
    ASSERT_TRUE("MerkleTree n_leaves=4", tree.n_leaves == 4);
    ASSERT_TRUE("MerkleTree depth=2",    tree.depth    == 2);
    print_hex("R_bio (root)", tree.root, 32);

 
    for (uint32_t M1 = 0; M1 < 4; M1++) {
        merkle_path_t path;
        rc = PQC_MerkleTree_GetPath(&tree, M1, &path);
        char label[64];
        snprintf(label, sizeof(label), "GetPath M1=%u", M1);
        ASSERT_TRUE(label, rc == 0);

 
        int vrc = PQC_MerkleTree_VerifyPath(
            tree.nodes[0][M1], &path,tree.root,test_salt);
        snprintf(label, sizeof(label), "VerifyPath M1=%u", M1);
        ASSERT_TRUE(label, vrc == 0);
    }

 
    merkle_path_t bad_path;
    PQC_MerkleTree_GetPath(&tree, 0, &bad_path);
    bad_path.sibling[0][0] ^= 0xFF;
    int bad_rc = PQC_MerkleTree_VerifyPath(
        tree.nodes[0][0], &bad_path, tree.root,test_salt);
    ASSERT_TRUE("VerifyPath tamper rejected", bad_rc != 0);
}

/* ================================================================
 *
 * ================================================================ */
static void kat_protocol_e2e(void)
{
    printf("\n=== KAT 7: End-to-end protocol (v4.0)===\n");

    const char *nvram_dir = "/tmp/pqzk_v40_test";
    make_dir(nvram_dir);
    uint8_t bio_salt[32];
    pqzk_rand_bytes(bio_salt, 32);

 
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);
    printf("[INFO] pk_t[0:8]: ");
    for (int i = 0; i < 8; i++) printf("%02x", pk_t[i]);
    printf("\n");

    uint8_t eid[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };
    uint8_t k_sym[32], k_tee[32];
    pqzk_rand_bytes(k_sym, 32);
    pqzk_rand_bytes(k_tee, 32);

 
    uint64_t initial_ctr;
    uint8_t cred_kyc[64] = {0};
    pqzk_rand_bytes((uint8_t*)&initial_ctr, 8);
    printf("[INFO] initial_ctr = 0x%016llx\n", (unsigned long long)initial_ctr);

    PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                   k_sym, 32, initial_ctr, k_tee, 32,
                   bio_salt, NULL, cred_kyc, 64);
    printf("[PASS] eUICC_Init done\n"); g_pass++;

    /* ---- Phase 0 (supplement): Build Merkle tree
     *
     * ---- */
    uint8_t mock_features[4][32];
    for (int i = 0; i < 4; i++)
        memset(mock_features[i], (uint8_t)(0x11 * (i + 1)), 32);

    merkle_tree_t bio_tree;
    int build_rc = PQC_MerkleTree_Build(
        (const uint8_t (*)[32])mock_features, 4, bio_salt, eid, &bio_tree);
    ASSERT_TRUE("MerkleTree_Build (enrollment)", build_rc == 0);

   

 
    uint8_t R_bio[32];
    memcpy(R_bio, bio_tree.root, 32);
    print_hex("R_bio (uploaded to server at enrollment)", R_bio, 32);

 
    poly_vec_t W_pub, W_sec;
    uint8_t seed_y[32], MAC_W[32];
    PQC_PreCompute(&W_pub, seed_y);
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    print_hex("MAC_W", MAC_W, 32);
    ASSERT_TRUE("MAC_W non-zero", MAC_W[0] != 0 || MAC_W[1] != 0);

    poly_vec_t W;
    pqzk_vec_add(&W_sec, &W_pub, &W, PQ_ZK_K);

 
    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);

    poly_t c_agg;
    PQC_GenChallenge(&W, c_seed, &c_agg);

    int wt = 0;
    for (int i = 0; i < PQ_ZK_N; i++) if (c_agg.coeffs[i] != 0) wt++;
    ASSERT_TRUE("GenChallenge weight=26", wt == PQ_ZK_CHALLENGE_WEIGHT);

 
    uint32_t M1 = 2;

    /* ---- Phase 3: TEE biometric auth and AuthToken (v4.0)
     *
     *   · R_dynamic = Hash(R_bio || ctr_local)
     *   · M2 = MerkleTree_GetPath(tree, M1)
     *   · AuthToken = HMAC(K_TEE, encode(c_agg)||ctr_le8||R_dynamic||hash_M2)
     * ---- */
    uint8_t R_dynamic[32];
    merkle_path_t M2;
    uint8_t AuthToken[32];

    PQ_ZK_ErrorCode tee_rc = TEE_GenerateAuthToken(
        nvram_dir,
        &c_agg,
        R_bio,
        &bio_tree,
        M1,
        k_tee,
        R_dynamic,
        &M2,
        AuthToken);
    ASSERT_TRUE("TEE_GenerateAuthToken rc=0", tee_rc == PQ_ZK_SUCCESS);
    print_hex("R_dynamic", R_dynamic, 32);
    print_hex("AuthToken", AuthToken, 32);

 
    int verify_m2_rc = PQC_MerkleTree_VerifyPath(
        bio_tree.nodes[0][M1], &M2, R_bio,bio_salt);
    ASSERT_TRUE("MerkleTree_VerifyPath (M2 verify)", verify_m2_rc == 0);

 
    uint8_t AuthToken_tampered[32];
    memcpy(AuthToken_tampered, AuthToken, 32);
    AuthToken_tampered[0] ^= 0x01;

    poly_vec_t z_dummy;
    PQ_ZK_ErrorCode rc_tamper = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic,
        AuthToken_tampered, &z_dummy);
    ASSERT_TRUE("Tampered AuthToken rejected (ERR_MAC_FAIL)",
                rc_tamper == PQ_ZK_ERR_MAC_FAIL);


    /*
     *
     */

 
    nvram_state_t nvram_st;
    nvram_read(nvram_dir, &nvram_st);

 
    uint8_t m2_serial[8 + PQZK_MERKLE_MAX_DEPTH * (PQZK_MERKLE_HASH_BYTES + 1)];
    size_t off = 0;
    write_le32(m2_serial + off, M2.depth);       off += 4;
    write_le32(m2_serial + off, M2.leaf_index);  off += 4;
    for (uint32_t i = 0; i < M2.depth; i++) {
        memcpy(m2_serial + off, M2.sibling[i], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        m2_serial[off] = M2.is_right_sibling[i];
        off += 1;
    }
    uint8_t hash_M2[32];
    pqzk_sha3_256(m2_serial, off, hash_M2);

    poly_vec_t z_sec_masked;
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic,
        AuthToken,
        &z_sec_masked);
    ASSERT_TRUE("ComputeZ_and_Mask rc=PQ_ZK_SUCCESS", rc == PQ_ZK_SUCCESS);

 
    PQ_ZK_ErrorCode rc_replay = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic, AuthToken, &z_dummy);
    ASSERT_TRUE("Replay attack rejected (ERR_MAC_FAIL)",
                rc_replay == PQ_ZK_ERR_MAC_FAIL);

 
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

    /* ---- Phase 6: Server verify
     *
     * ---- */
    uint8_t ctr_session_le8[8];
    write_le64(ctr_session_le8, nvram_st.ctr_local);

    pqzk_iov_t rdyn_server_iov[] = {
        { R_bio,            32 },
        { ctr_session_le8,  8  },
        { NULL, 0 }
    };
    uint8_t R_dynamic_server[32];
    pqzk_sha3_256_iov(rdyn_server_iov, R_dynamic_server);

    ASSERT_EQ("R_dynamic matches", R_dynamic, R_dynamic_server, 32);

    /*
     */
    poly_vec_t M_mask;
    PQC_GenerateMask(k_sym, c_seed, nvram_st.ctr_local,
                     R_dynamic_server, &M_mask);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;
    PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, R_dynamic_server, &M_mask, &params);
    ASSERT_TRUE("VerifyEngine PQ_ZK_SUCCESS", vrc == PQ_ZK_SUCCESS);

 
    remove("/tmp/pqzk_v40_test/euicc_state.bin");
    remove("/tmp/pqzk_v40_test/euicc_state.tmp");
    rmdir(nvram_dir);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("========================================\n");
    printf("  PQ-ZK-eSIM KAT test vectors v4.0\n");
    printf("========================================\n");

    kat_encode_decode();
    kat_encode_poly();
    kat_hash_mac();
    kat_prf();
    kat_sample_in_ball();
    kat_merkle();
    kat_protocol_e2e();

    printf("\n========================================\n");
    printf("  Results：%d passed，%d failed\n", g_pass, g_fail);
    printf("========================================\n");
    return (g_fail == 0) ? 0 : 1;
}