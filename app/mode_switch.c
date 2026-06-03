/*
 * mode_switch.c — PQ-ZK-eSIM v5.2 operator switching
 *
 * FIX-A: ML-KEM pk signed with ML-DSA (MitM prevention)
 * FIX-B: read cred_kyc directly from nvram (no reissue)  
 * FIX-C: remove gsma_root_cert field (MNO_B preinstalled)
 * FIX-D: MNO_B verifies Cert_A with own root CA
 * FIX-E: keep original R_bio static root, update active_R_bio
 * FIX-F: random counter reset
 * FIX-G: CredKYC verify uses R_bio (static root)
 * FIX-H: reissue cred_kyc with R_bio (cross-switch consistency)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_mlkem.h"
#include "pqzk_cert.h"

/* ================================================================
 * Internal helpers
 * ================================================================ */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-28s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/* ================================================================
 * Step 1：TEE Biometric match (sim)
 * ================================================================ */
static int tee_biometric_verify(void)
{
    printf("  [TEE] Biometric match (sim): user present ✓\n");
    return 0;
}

/* ================================================================
 * Step 2: compute domain-specific bio root
 * R_bio_B = SHA-256(R_bio || Domain_ID_B)
 * ================================================================ */
static int tee_derive_domain_bio_root(const uint8_t R_bio[32],
                                       const uint8_t domain_id_b[PQZK_MNO_ID_BYTES],
                                       uint8_t       R_bio_B_out[32])
{
    pqzk_iov_t iov[] = {
        { R_bio,       32                 },
        { domain_id_b, PQZK_MNO_ID_BYTES },
        { NULL, 0 }
    };
    return pqzk_sha3_256_iov(iov, R_bio_B_out);
}

/* ================================================================
 * Step 3：eUICC generate new keypair for MNO_B
 * ================================================================ */
static int euicc_gen_new_keypair(poly_vec_t *sk_b_out,
                                  uint8_t     pk_b_out[PQ_ZK_PUBLICKEY_BYTES])
{
    PQC_GenKeyPair(pk_b_out, sk_b_out);
    return 0;
}

/* ================================================================
 * Step 4：ML-KEM handshake (FIX-A)
 * ================================================================ */
static int mlkem_handshake(
    const pqzk_cert_t *cert_b,
    const uint8_t     *domain_id_b,
    mlkem_tunnel_t    *euicc_tunnel_out,
    mlkem_tunnel_t    *server_tunnel_out)
{
    static mlkem_keypair_t server_kp;
    if (PQZK_MLKEM_Keygen(&server_kp) != 0) {
        fprintf(stderr, "  [Error] ML-KEM keygen failed\n");
        return -1;
    }
    printf("  [ML-KEM] MNO_B temp keypair generated\n");
    print_hex("server pk[0:16]", server_kp.pk, 16);

    static uint8_t pk_signature[PQZK_MLDSA_SIG_BYTES];
    if (PQZK_MLDSA_Sign(cert_b->mno_sk, server_kp.pk,
                         PQZK_MLKEM_PK_BYTES, pk_signature) != 0) {
        fprintf(stderr, "  [Error] ML-KEM pk sign failed\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] MNO_B ML-DSA signature on pk done\n");

    if (domain_id_b &&
        memcmp(cert_b->mno_id, domain_id_b, PQZK_MNO_ID_BYTES) != 0) {
        fprintf(stderr, "  [Warning] cert_b MNO_ID != domain_id_b\n");
    }

    if (PQZK_MLDSA_Verify(cert_b->mno_sk, server_kp.pk,
                            PQZK_MLKEM_PK_BYTES, pk_signature) != 0) {
        fprintf(stderr, "  [eUICC] ML-KEM pk verify FAIL (MitM?)\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [eUICC] ML-KEM pk verified ✓\n");

    static uint8_t ciphertext[PQZK_MLKEM_CT_BYTES];
    if (PQZK_MLKEM_Encapsulate(server_kp.pk, ciphertext,
                                euicc_tunnel_out) != 0) {
        fprintf(stderr, "  [Error] ML-KEM encapsulation failed\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] eUICC encapsulation done, ct len:: %d bytes\n",
           PQZK_MLKEM_CT_BYTES);

    memcpy(server_tunnel_out->tunnel_id, euicc_tunnel_out->tunnel_id, 16);
    server_tunnel_out->established = 1;

    if (PQZK_MLKEM_Decapsulate(&server_kp, ciphertext,
                                server_tunnel_out) != 0) {
        fprintf(stderr, "  [Error] ML-KEM decapsulation failed\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] MNO_B decapsulation done\n");

    if (memcmp(euicc_tunnel_out->session_key,
               server_tunnel_out->session_key, 32) != 0) {
        fprintf(stderr, "  [Error] session_key mismatch\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    print_hex("session_key[0:16]", euicc_tunnel_out->session_key, 16);
    printf("  [ML-KEM] tunnel established ✓\n");

    secure_zero(&server_kp, sizeof(server_kp));
    return 0;
}

/* ================================================================
 * Step 5：eUICC send identity payload (FIX-B/C)
 *
 * Payload (paper §5.1.5 ：
 *   R_bio_B(32) | R_bio(32) | salt(32) | cred_kyc(64) |
 *   cert_a(PQZK_CERT_BYTES) | eid(16) | T_new(PQ_ZK_PUBLICKEY_BYTES)
 * ================================================================ */
static int euicc_send_identity_payload(
    const mlkem_tunnel_t *euicc_tunnel,
    const uint8_t R_bio_B[32],
    const uint8_t R_bio[32],
    const uint8_t salt[32],
    const uint8_t cred_kyc[64],
    const uint8_t cert_a_bytes[PQZK_CERT_BYTES],
    const uint8_t eid[16],
    const uint8_t T_new[PQ_ZK_PUBLICKEY_BYTES],
    uint8_t *encrypted_payload_out,
    size_t  *encrypted_len_out)
{
    apdu_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    memcpy(payload.R_bio_B,  R_bio_B,      32);
    memcpy(payload.R_bio,    R_bio,        32);
    memcpy(payload.salt,     salt,         32);
    memcpy(payload.cred_kyc, cred_kyc,     64);
    memcpy(payload.cert_a,   cert_a_bytes, PQZK_CERT_BYTES);
    memcpy(payload.eid,      eid,          16);
    memcpy(payload.T_new,    T_new,        PQ_ZK_PUBLICKEY_BYTES);

    static uint8_t serial_buf[4096];
    int serial_len = PQZK_APDU_SerializePayload(
        &payload, serial_buf, sizeof(serial_buf));
    if (serial_len < 0) return -1;

    if (PQZK_APDU_Encrypt(euicc_tunnel, serial_buf, serial_len,
                           encrypted_payload_out) != 0)
        return -1;

    *encrypted_len_out = (size_t)serial_len;
    printf("  [eUICC] identity payload encrypted, len:: %d bytes\n", serial_len);
    return 0;
}

/* ================================================================
 * Step 6：MNO_B verify identity (FIX-D/G)
 *
 * FIX-G: CredKYC verify uses payload_out->R_bio（static root），
 *         not payload_out->R_bio_B（domain-specific root）。
 *
 *         Cred_KYC = HMAC(mno_sk, eid || R_bio_static root)
 *         R_bio_B only for domain derivation (Step 6.4)
 * ================================================================ */
static int mnob_verify_identity(
    const mlkem_tunnel_t *server_tunnel,
    const uint8_t *encrypted_payload,
    size_t         payload_len,
    const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
    const uint8_t  physical_eid[16],
    const uint8_t  gsma_root_ca_pk[PQZK_GSMA_CA_PK_BYTES],
    apdu_payload_t *payload_out)
{
    /* 6.0 decrypt payload */
    static uint8_t decrypted[4096];
    if (PQZK_APDU_Decrypt(server_tunnel, encrypted_payload,
                           payload_len, decrypted) != 0) {
        fprintf(stderr, "  [MNO_B] decrypt failed\n");
        return -1;
    }
    if (PQZK_APDU_DeserializePayload(decrypted, payload_len,
                                      payload_out) != 0) {
        fprintf(stderr, "  [MNO_B] payload deserialize failed\n");
        return -1;
    }
    printf("  [MNO_B] payload decrypted\n");

    /* 6.1 verify Cert_A (FIX-D: preinstalled root CA) */
    static pqzk_cert_t cert_a;
    if (PQZK_Cert_Deserialize(payload_out->cert_a, &cert_a) != 0) {
        fprintf(stderr, "  [MNO_B] Cert_A deserialize failed\n");
        return -1;
    }
    if (PQZK_Cert_VerifyWithRootPK(&cert_a, gsma_root_ca_pk) != 0) {
        fprintf(stderr, "  [MNO_B] Cert_A verify failed (GSMA chain)\n");
        return -1;
    }
    printf("  [MNO_B] Cert_A verified ✓\n");
    print_hex("MNO_A ID", cert_a.mno_id, PQZK_MNO_ID_BYTES);

    /* 6.2 verify Cred_KYC (FIX-G: use R_bio static root)
     *
     * Cred_KYC = HMAC(mno_a_sk, eid || R_bio)
     * R_bio is the global static anchor, invariant across switches.
     * payload_out->R_bio is the original R_bio from enrollment, sent in Step 5.
     */
    if (PQZK_CredKYC_Verify(&cert_a,
                              payload_out->eid,
                              payload_out->R_bio,      /* FIX-G: static root */
                              payload_out->cred_kyc) != 0) {
        fprintf(stderr, "  [MNO_B] Cred_KYC verify failed\n");
        return -1;
    }
    printf("  [MNO_B] Cred_KYC verified ✓\n");

    /* 6.3 physical EID == logical EID */
    if (memcmp(physical_eid, payload_out->eid, 16) != 0) {
        fprintf(stderr, "  [MNO_B] EID mismatch\n");
        return -1;
    }
    printf("  [MNO_B] EID match ✓\n");

    /* 6.4 reconstruct R_bio_B' = SHA-256(R_bio || Domain_ID_B) */
    uint8_t R_bio_B_recomputed[32];
    pqzk_iov_t iov[] = {
        { payload_out->R_bio, 32                 },
        { domain_id_b,        PQZK_MNO_ID_BYTES },
        { NULL, 0 }
    };
    pqzk_sha3_256_iov(iov, R_bio_B_recomputed);
    if (memcmp(R_bio_B_recomputed, payload_out->R_bio_B, 32) != 0) {
        fprintf(stderr, "  [MNO_B] R_bio_B verify failed\n");
        return -1;
    }
    printf("  [MNO_B] R_bio_B verified ✓\n");
    print_hex("R_bio_B", payload_out->R_bio_B, 32);

    return 0;
}

/* ================================================================
 * Step 7：inject keys, update nvram (FIX-E/F/H)
 *
 * FIX-H：reissue cred_kyc with R_bio (static root), consistent with FIX-G.
 *         CredKYC issuance and verification always uses:
 *           HMAC(current_sk, eid || R_bio)
 * ================================================================ */
static int mnob_inject_new_keys(
    const char           *nvram_dir,
    const mlkem_tunnel_t *euicc_tunnel,
    const mlkem_tunnel_t *server_tunnel,
    const poly_vec_t     *sk_b,
    const apdu_payload_t *payload,
    const uint8_t         domain_id_b[PQZK_MNO_ID_BYTES],
    const uint8_t         mno_b_sk[32])
{
    /* MNO_B generates new symmetric keys */
    uint8_t k_sym_b[32], d_seed_b[32];
    pqzk_rand_bytes(k_sym_b,  32);
    pqzk_rand_bytes(d_seed_b, 32);
    printf("  [MNO_B] new keys K_symB, d_seedB generated\n");
    print_hex("K_symB[0:16]", k_sym_b, 16);

    /* encrypt (K_symB || d_seedB) via tunnel */
    uint8_t key_material[64];
    memcpy(key_material,      k_sym_b,  32);
    memcpy(key_material + 32, d_seed_b, 32);

    uint8_t encrypted_keys[64];
    if (PQZK_APDU_Encrypt(server_tunnel, key_material, 64,
                           encrypted_keys) != 0) {
        fprintf(stderr, "  [MNO_B] key encrypt failed\n");
        return -1;
    }

    uint8_t decrypted_keys[64];
    if (PQZK_APDU_Decrypt(euicc_tunnel, encrypted_keys, 64,
                           decrypted_keys) != 0) {
        fprintf(stderr, "  [eUICC] key decrypt failed\n");
        return -1;
    }

    /* read nvram */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram read failed\n");
        return -1;
    }

    /* update symmetric key and d_seed */
    memcpy(state.k_sym,  decrypted_keys,      32);
    memcpy(state.d_seed, decrypted_keys + 32, 32);

    /* update lattice secret key */
    PQC_EncodePolyVec(sk_b, state.sk_s, PQ_ZK_M);

    /* FIX-E：keep R_bio static root, update active_R_bio */
    memcpy(state.active_R_bio, payload->R_bio_B, 32);

    /* FIX-F：random counter init */
    uint64_t new_ctr;
    pqzk_rand_bytes((uint8_t*)&new_ctr, 8);
    state.ctr_local   = new_ctr;
    state.y_sec_valid = 0;
    memset(state.y_sec, 0, sizeof(state.y_sec));

    /* update operator ID */
    memcpy(state.active_mno_id, domain_id_b, PQZK_MNO_ID_BYTES);
    state.switch_count += 1;

    /* FIX-H：reissue cred_kyc with new key + R_bio
     *
     * consistent with FIX-G：
     *   Cred_KYC = HMAC(mno_b_sk, eid || R_bio)
     *
     * R_bio is the global static anchor, unchanged (FIX-E),
     * so reissue is verifiable on next switch.
     */
    uint8_t new_cred_kyc[32];
    memset(new_cred_kyc, 0, 32);
    if (PQZK_CredKYC_Issue(mno_b_sk,
                            state.eid,
                            state.R_bio,      /* FIX-H: static root, not R_bio_B */
                            new_cred_kyc) != 0) {
        fprintf(stderr, "  [MNO_B] Cred_KYC reissue failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    memset(state.cred_kyc, 0, 64);
    memcpy(state.cred_kyc, new_cred_kyc, 32);
    secure_zero(new_cred_kyc, 32);
    printf("  [MNO_B] Cred_KYC reissued (new key + R_bio static)✓\n");

    /* atomic nvram write */
    if (nvram_write_atomic(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram write failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    secure_zero(&state, sizeof(state));

    printf("  [eUICC] nvram updated ✓\n");
    printf("  [eUICC] R_bio static root unchanged (FIX-E)✓\n");
    printf("  [eUICC] active_R_bio updated to R_bio_B\n");
    printf("  [eUICC] counter reset to random (FIX-F)✓\n");

    secure_zero(k_sym_b,      32);
    secure_zero(d_seed_b,     32);
    secure_zero(key_material, 64);
    secure_zero(decrypted_keys, 64);
    return 0;
}

/* ================================================================
 * mode_switch — operator switching entry
 *
 * Parameters:
 *   nvram_dir    eUICC nvram directory
 *   domain_id_b  target MNO_B ID (zero-padded)
 *   mno_a_id     current MNO_A ID (zero-padded)
 *   mno_a_sk     MNO_A signing key (32 bytes)
 * ================================================================ */
int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_sk[32])
{
    printf("\n============================================\n");
    printf("  Operator Switch (MNO_A -> MNO_B)\n");
    printf("============================================\n");

    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "[Error] nvram not initialized\n");
        return -1;
    }
    printf("[Switch] EID: ");
    for (int i = 0; i < 16; i++) printf("%02x", state.eid[i]);
    printf("\n");

    /* Step 1：biometric match */
    printf("\n[Step 1] TEE biometric match\n");
    if (tee_biometric_verify() != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 2：compute domain-specific bio root */
    printf("\n[Step 2] compute domain-specific bio root\n");
    uint8_t R_bio_B[32];
    if (tee_derive_domain_bio_root(state.R_bio, domain_id_b, R_bio_B) != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("R_bio(original, unchanged)", state.R_bio, 32);
    print_hex("Domain_ID_B",             domain_id_b,  PQZK_MNO_ID_BYTES);
    print_hex("R_bio_B(domain-specific)",          R_bio_B,      32);

    /* Step 3：generate new keypair */
    printf("\n[Step 3] eUICC generate MNO_B keypair\n");
    poly_vec_t sk_b;
    uint8_t    pk_b[PQ_ZK_PUBLICKEY_BYTES];
    if (euicc_gen_new_keypair(&sk_b, pk_b) != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("T_B(new pk)", pk_b, 8);
    printf("  [eUICC] new S_B generated\n");

    /* Step 4：ML-KEM handshake */
    printf("\n[Step 4] ML-KEM handshake(with ML-DSA pk auth)\n");
    sync();
    usleep(5000);

    pqzk_cert_t cert_b;
    if (PQZK_Cert_IssueForMNO(domain_id_b, &cert_b) != 0) {
        fprintf(stderr, "[Step 4] MNO_B cert obtain failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    mlkem_tunnel_t euicc_tunnel, server_tunnel;
    memset(&euicc_tunnel,  0, sizeof(euicc_tunnel));
    memset(&server_tunnel, 0, sizeof(server_tunnel));

    if (mlkem_handshake(&cert_b, domain_id_b,
                         &euicc_tunnel, &server_tunnel) != 0) {
        fprintf(stderr, "[Step 4] ML-KEM handshake failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 5：send identity payload */
    printf("\n[Step 5] eUICC send identity payload\n");

    pqzk_cert_t cert_a;
    if (PQZK_Cert_Issue(mno_a_id, mno_a_sk, &cert_a) != 0) {
        fprintf(stderr, "[Step 5] Cert_A issue failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    uint8_t cert_a_bytes[PQZK_CERT_BYTES];
    PQZK_Cert_Serialize(&cert_a, cert_a_bytes);

    static uint8_t encrypted_payload[4096];
    size_t encrypted_len = 0;
    if (euicc_send_identity_payload(
            &euicc_tunnel,
            R_bio_B,
            state.R_bio,       /* static root */
            state.salt,
            state.cred_kyc,    /* from nvram, FIX-B */
            cert_a_bytes,
            state.eid,
            pk_b,
            encrypted_payload, &encrypted_len) != 0) {
        fprintf(stderr, "[Step 5] identity payload send failed\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 6：verify identity payload */
    printf("\n[Step 6] MNO_B verify identity payload\n");

    uint8_t gsma_root_ca_pk[PQZK_GSMA_CA_PK_BYTES];
    PQZK_GSMA_GetRootCAPK(gsma_root_ca_pk);

    apdu_payload_t received_payload;
    if (mnob_verify_identity(
            &server_tunnel,
            encrypted_payload, encrypted_len,
            domain_id_b,
            state.eid,
            gsma_root_ca_pk,
            &received_payload) != 0) {
        fprintf(stderr, "[Step 6] identity verify failed, abort\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    printf("[Step 6] identity verified ✓\n");

    /* Step 7：inject new keys */
    printf("\n[Step 7] MNO_B inject new keys\n");
    if (mnob_inject_new_keys(
            nvram_dir,
            &euicc_tunnel, &server_tunnel,
            &sk_b, &received_payload,
            domain_id_b,
            cert_b.mno_sk) != 0) {
        fprintf(stderr, "[Step 7] key injection failed\n");
        secure_zero(&state, sizeof(state));
        secure_zero(&sk_b,  sizeof(sk_b));
        return -1;
    }

    secure_zero(&state,         sizeof(state));
    secure_zero(&sk_b,          sizeof(sk_b));
    secure_zero(&euicc_tunnel,  sizeof(euicc_tunnel));
    secure_zero(&server_tunnel, sizeof(server_tunnel));

    printf("\n============================================\n");
    printf("  Operator switch complete ✓\n");
    printf("============================================\n");
    return 0;
}