/*
 * mode_switch.c — PQ-ZK-eSIM v5.2
 *
 * 修复清单（相对 v5.1）：
 *   FIX-A  Step 4：ML-KEM 公钥用 ML-DSA 签名认证，防 MitM
 *   FIX-B  Step 5：直接读取 nvram 中已有的 cred_kyc，禁止现场重新签发
 *   FIX-C  Step 5：移除 gsma_root_cert 字段（MNO_B 预装，不由 eUICC 传输）
 *   FIX-D  Step 6：MNO_B 用自身预装根 CA 验证 Cert_A，消除循环信任
 *   FIX-E  Step 7：保留原始 R_bio 静态根，只更新 active_R_bio
 *   FIX-F  Step 7：计数器重置使用随机初始值，而非固定 0
 *   FIX-G  Step 6：CredKYC 验证统一使用 R_bio（静态根），而非 R_bio_B
 *   FIX-H  Step 7：重签 cred_kyc 统一使用 R_bio（静态根），保证跨切换一致
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
 * 内部工具
 * ================================================================ */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-28s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/* ================================================================
 * Step 1：TEE 活体验证（模拟）
 * ================================================================ */
static int tee_biometric_verify(void)
{
    printf("  [TEE] 活体验证（模拟）：用户在场确认 ✓\n");
    return 0;
}

/* ================================================================
 * Step 2：TEE 计算运营商专属生物根
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
    return pqzk_sha256_iov(iov, R_bio_B_out);
}

/* ================================================================
 * Step 3：eUICC 为 MNO_B 生成新格密钥对
 * ================================================================ */
static int euicc_gen_new_keypair(poly_vec_t *sk_b_out,
                                  uint8_t     pk_b_out[PQ_ZK_PUBLICKEY_BYTES])
{
    PQC_GenKeyPair(pk_b_out, sk_b_out);
    return 0;
}

/* ================================================================
 * Step 4：ML-KEM 握手（FIX-A）
 * ================================================================ */
static int mlkem_handshake(
    const pqzk_cert_t *cert_b,
    const uint8_t     *domain_id_b,
    mlkem_tunnel_t    *euicc_tunnel_out,
    mlkem_tunnel_t    *server_tunnel_out)
{
    static mlkem_keypair_t server_kp;
    if (PQZK_MLKEM_Keygen(&server_kp) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 密钥生成失败\n");
        return -1;
    }
    printf("  [ML-KEM] MNO_B 临时密钥对生成完成\n");
    print_hex("server pk[0:16]", server_kp.pk, 16);

    static uint8_t pk_signature[PQZK_MLDSA_SIG_BYTES];
    if (PQZK_MLDSA_Sign(cert_b->mno_sk, server_kp.pk,
                         PQZK_MLKEM_PK_BYTES, pk_signature) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 公钥签名失败\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] MNO_B 对公钥完成 ML-DSA 签名\n");

    if (domain_id_b &&
        memcmp(cert_b->mno_id, domain_id_b, PQZK_MNO_ID_BYTES) != 0) {
        fprintf(stderr, "  [警告] cert_b MNO_ID 与 domain_id_b 不符\n");
    }

    if (PQZK_MLDSA_Verify(cert_b->mno_sk, server_kp.pk,
                            PQZK_MLKEM_PK_BYTES, pk_signature) != 0) {
        fprintf(stderr, "  [eUICC] ML-KEM 公钥签名验证失败，疑似 MitM\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [eUICC] ML-KEM 公钥签名验证通过 ✓\n");

    static uint8_t ciphertext[PQZK_MLKEM_CT_BYTES];
    if (PQZK_MLKEM_Encapsulate(server_kp.pk, ciphertext,
                                euicc_tunnel_out) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 封装失败\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] eUICC 封装完成，密文长度: %d 字节\n",
           PQZK_MLKEM_CT_BYTES);

    memcpy(server_tunnel_out->tunnel_id, euicc_tunnel_out->tunnel_id, 16);
    server_tunnel_out->established = 1;

    if (PQZK_MLKEM_Decapsulate(&server_kp, ciphertext,
                                server_tunnel_out) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 解封装失败\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    printf("  [ML-KEM] MNO_B 解封装完成\n");

    if (memcmp(euicc_tunnel_out->session_key,
               server_tunnel_out->session_key, 32) != 0) {
        fprintf(stderr, "  [错误] 双方 session_key 不一致\n");
        secure_zero(&server_kp, sizeof(server_kp));
        return -1;
    }
    print_hex("session_key[0:16]", euicc_tunnel_out->session_key, 16);
    printf("  [ML-KEM] 隧道建立成功 ✓\n");

    secure_zero(&server_kp, sizeof(server_kp));
    return 0;
}

/* ================================================================
 * Step 5：eUICC 发送身份证据包（FIX-B / FIX-C）
 *
 * 载荷字段（与论文 §5.1.5 一致）：
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
    printf("  [eUICC] 身份证据包加密完成，载荷长度: %d 字节\n", serial_len);
    return 0;
}

/* ================================================================
 * Step 6：MNO_B 验证身份证据包（FIX-D / FIX-G）
 *
 * FIX-G：CredKYC 验证统一使用 payload_out->R_bio（静态根），
 *         而非 payload_out->R_bio_B（域专属根）。
 *
 *         约定：Cred_KYC = HMAC(mno_sk, eid || R_bio_静态根)
 *         R_bio_B 仅用于域派生验证（Step 6.4），不参与 CredKYC 计算。
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
    /* 6.0 解密 */
    static uint8_t decrypted[4096];
    if (PQZK_APDU_Decrypt(server_tunnel, encrypted_payload,
                           payload_len, decrypted) != 0) {
        fprintf(stderr, "  [MNO_B] 解密失败\n");
        return -1;
    }
    if (PQZK_APDU_DeserializePayload(decrypted, payload_len,
                                      payload_out) != 0) {
        fprintf(stderr, "  [MNO_B] 载荷反序列化失败\n");
        return -1;
    }
    printf("  [MNO_B] 载荷解密成功\n");

    /* 6.1 验证 Cert_A（FIX-D：用预装根 CA 公钥） */
    static pqzk_cert_t cert_a;
    if (PQZK_Cert_Deserialize(payload_out->cert_a, &cert_a) != 0) {
        fprintf(stderr, "  [MNO_B] Cert_A 反序列化失败\n");
        return -1;
    }
    if (PQZK_Cert_VerifyWithRootPK(&cert_a, gsma_root_ca_pk) != 0) {
        fprintf(stderr, "  [MNO_B] Cert_A 验证失败（GSMA 证书链无效）\n");
        return -1;
    }
    printf("  [MNO_B] Cert_A 验证通过 ✓\n");
    print_hex("MNO_A ID", cert_a.mno_id, PQZK_MNO_ID_BYTES);

    /* 6.2 验证 Cred_KYC（FIX-G：使用 R_bio 静态根，不用 R_bio_B）
     *
     * Cred_KYC = HMAC(mno_a_sk, eid || R_bio)
     * R_bio 是注册时的全局静态锚点，与域无关，跨切换保持不变。
     * payload_out->R_bio 即注册时的原始 R_bio，由 eUICC 在 Step 5 传来。
     */
    if (PQZK_CredKYC_Verify(&cert_a,
                              payload_out->eid,
                              payload_out->R_bio,      /* FIX-G: 静态根 */
                              payload_out->cred_kyc) != 0) {
        fprintf(stderr, "  [MNO_B] Cred_KYC 验证失败\n");
        return -1;
    }
    printf("  [MNO_B] Cred_KYC 验证通过 ✓\n");

    /* 6.3 物理 EID == 逻辑 EID */
    if (memcmp(physical_eid, payload_out->eid, 16) != 0) {
        fprintf(stderr, "  [MNO_B] EID 不匹配\n");
        return -1;
    }
    printf("  [MNO_B] EID 比对通过 ✓\n");

    /* 6.4 重构 R_bio_B' = SHA-256(R_bio || Domain_ID_B) */
    uint8_t R_bio_B_recomputed[32];
    pqzk_iov_t iov[] = {
        { payload_out->R_bio, 32                 },
        { domain_id_b,        PQZK_MNO_ID_BYTES },
        { NULL, 0 }
    };
    pqzk_sha256_iov(iov, R_bio_B_recomputed);
    if (memcmp(R_bio_B_recomputed, payload_out->R_bio_B, 32) != 0) {
        fprintf(stderr, "  [MNO_B] R_bio_B 验证失败\n");
        return -1;
    }
    printf("  [MNO_B] R_bio_B 验证通过 ✓\n");
    print_hex("R_bio_B", payload_out->R_bio_B, 32);

    return 0;
}

/* ================================================================
 * Step 7：注入新密钥，更新 nvram（FIX-E / FIX-F / FIX-H）
 *
 * FIX-H：重签 cred_kyc 使用 R_bio（静态根），与 FIX-G 约定一致。
 *         这样无论切换多少次，CredKYC 的签发和验证始终使用：
 *           HMAC(当前运营商私钥, eid || R_bio_静态根)
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
    /* MNO_B 生成新对称密钥材料 */
    uint8_t k_sym_b[32], d_seed_b[32];
    pqzk_rand_bytes(k_sym_b,  32);
    pqzk_rand_bytes(d_seed_b, 32);
    printf("  [MNO_B] 生成新密钥材料 K_symB, d_seedB\n");
    print_hex("K_symB[0:16]", k_sym_b, 16);

    /* 通过隧道加密传输 (K_symB || d_seedB) */
    uint8_t key_material[64];
    memcpy(key_material,      k_sym_b,  32);
    memcpy(key_material + 32, d_seed_b, 32);

    uint8_t encrypted_keys[64];
    if (PQZK_APDU_Encrypt(server_tunnel, key_material, 64,
                           encrypted_keys) != 0) {
        fprintf(stderr, "  [MNO_B] 密钥加密失败\n");
        return -1;
    }

    uint8_t decrypted_keys[64];
    if (PQZK_APDU_Decrypt(euicc_tunnel, encrypted_keys, 64,
                           decrypted_keys) != 0) {
        fprintf(stderr, "  [eUICC] 密钥解密失败\n");
        return -1;
    }

    /* 读取 nvram */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram 读取失败\n");
        return -1;
    }

    /* 更新对称密钥和派生种子 */
    memcpy(state.k_sym,  decrypted_keys,      32);
    memcpy(state.d_seed, decrypted_keys + 32, 32);

    /* 更新格私钥 */
    PQC_EncodePolyVec(sk_b, state.sk_s, PQ_ZK_M);

    /* FIX-E：state.R_bio 静态根保持不变，只更新 active_R_bio */
    memcpy(state.active_R_bio, payload->R_bio_B, 32);

    /* FIX-F：计数器随机初始化 */
    uint64_t new_ctr;
    pqzk_rand_bytes((uint8_t*)&new_ctr, 8);
    state.ctr_local   = new_ctr;
    state.y_sec_valid = 0;
    memset(state.y_sec, 0, sizeof(state.y_sec));

    /* 更新运营商标识 */
    memcpy(state.active_mno_id, domain_id_b, PQZK_MNO_ID_BYTES);
    state.switch_count += 1;

    /* FIX-H：用新运营商私钥 + R_bio 静态根重签 cred_kyc
     *
     * 约定与 FIX-G 保持一致：
     *   Cred_KYC = HMAC(mno_b_sk, eid || R_bio_静态根)
     *
     * state.R_bio 是注册时写入的全局静态锚点，此处不会被修改（FIX-E），
     * 因此重签结果在下次切换时可被正确验证。
     */
    uint8_t new_cred_kyc[32];
    memset(new_cred_kyc, 0, 32);
    if (PQZK_CredKYC_Issue(mno_b_sk,
                            state.eid,
                            state.R_bio,      /* FIX-H: 静态根，不用 R_bio_B */
                            new_cred_kyc) != 0) {
        fprintf(stderr, "  [MNO_B] Cred_KYC 重签失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    memset(state.cred_kyc, 0, 64);
    memcpy(state.cred_kyc, new_cred_kyc, 32);
    secure_zero(new_cred_kyc, 32);
    printf("  [MNO_B] Cred_KYC 重签完成（新运营商私钥 + R_bio 静态根）✓\n");

    /* 原子写入 nvram */
    if (nvram_write_atomic(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram 写入失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    secure_zero(&state, sizeof(state));

    printf("  [eUICC] nvram 更新完成 ✓\n");
    printf("  [eUICC] R_bio 静态根保持不变（FIX-E）✓\n");
    printf("  [eUICC] active_R_bio 已更新为 R_bio_B\n");
    printf("  [eUICC] 计数器重置为随机值（FIX-F）✓\n");

    secure_zero(k_sym_b,      32);
    secure_zero(d_seed_b,     32);
    secure_zero(key_material, 64);
    secure_zero(decrypted_keys, 64);
    return 0;
}

/* ================================================================
 * mode_switch — 运营商切换主入口
 *
 * 参数：
 *   nvram_dir    eUICC nvram 目录
 *   domain_id_b  目标运营商 MNO_B 标识（PQZK_MNO_ID_BYTES，零填充）
 *   mno_a_id     当前运营商 MNO_A 标识（PQZK_MNO_ID_BYTES，零填充）
 *   mno_a_sk     MNO_A 的私钥（32字节），用于构造 Cert_A
 * ================================================================ */
int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_sk[32])
{
    printf("\n============================================\n");
    printf("  运营商切换流程（MNO_A → MNO_B）\n");
    printf("============================================\n");

    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "[错误] nvram 未初始化\n");
        return -1;
    }
    printf("[切换] EID: ");
    for (int i = 0; i < 16; i++) printf("%02x", state.eid[i]);
    printf("\n");

    /* Step 1：活体验证 */
    printf("\n[Step 1] TEE 活体验证\n");
    if (tee_biometric_verify() != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 2：计算域专属生物根 */
    printf("\n[Step 2] 计算运营商专属生物根\n");
    uint8_t R_bio_B[32];
    if (tee_derive_domain_bio_root(state.R_bio, domain_id_b, R_bio_B) != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("R_bio（原始，保持不变）", state.R_bio, 32);
    print_hex("Domain_ID_B",             domain_id_b,  PQZK_MNO_ID_BYTES);
    print_hex("R_bio_B（专属）",          R_bio_B,      32);

    /* Step 3：生成新格密钥对 */
    printf("\n[Step 3] eUICC 生成 MNO_B 专属格密钥对\n");
    poly_vec_t sk_b;
    uint8_t    pk_b[PQ_ZK_PUBLICKEY_BYTES];
    if (euicc_gen_new_keypair(&sk_b, pk_b) != 0) {
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("T_B（新公钥）", pk_b, 8);
    printf("  [eUICC] 新私钥 S_B 已生成\n");

    /* Step 4：ML-KEM 握手 */
    printf("\n[Step 4] ML-KEM 握手（含 ML-DSA 公钥认证）\n");
    sync();
    usleep(5000);

    pqzk_cert_t cert_b;
    if (PQZK_Cert_IssueForMNO(domain_id_b, &cert_b) != 0) {
        fprintf(stderr, "[Step 4] MNO_B 证书获取失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    mlkem_tunnel_t euicc_tunnel, server_tunnel;
    memset(&euicc_tunnel,  0, sizeof(euicc_tunnel));
    memset(&server_tunnel, 0, sizeof(server_tunnel));

    if (mlkem_handshake(&cert_b, domain_id_b,
                         &euicc_tunnel, &server_tunnel) != 0) {
        fprintf(stderr, "[Step 4] ML-KEM 握手失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 5：发送身份证据包 */
    printf("\n[Step 5] eUICC 发送身份证据包\n");

    pqzk_cert_t cert_a;
    if (PQZK_Cert_Issue(mno_a_id, mno_a_sk, &cert_a) != 0) {
        fprintf(stderr, "[Step 5] Cert_A 签发失败\n");
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
            state.R_bio,       /* 静态根 */
            state.salt,
            state.cred_kyc,    /* 来自 nvram，FIX-B */
            cert_a_bytes,
            state.eid,
            pk_b,
            encrypted_payload, &encrypted_len) != 0) {
        fprintf(stderr, "[Step 5] 身份证据包发送失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* Step 6：验证身份证据包 */
    printf("\n[Step 6] MNO_B 验证身份证据包\n");

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
        fprintf(stderr, "[Step 6] 身份验证失败，切换中止\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    printf("[Step 6] 身份验证全部通过 ✓\n");

    /* Step 7：注入新密钥 */
    printf("\n[Step 7] MNO_B 注入新密钥材料\n");
    if (mnob_inject_new_keys(
            nvram_dir,
            &euicc_tunnel, &server_tunnel,
            &sk_b, &received_payload,
            domain_id_b,
            cert_b.mno_sk) != 0) {
        fprintf(stderr, "[Step 7] 密钥注入失败\n");
        secure_zero(&state, sizeof(state));
        secure_zero(&sk_b,  sizeof(sk_b));
        return -1;
    }

    secure_zero(&state,         sizeof(state));
    secure_zero(&sk_b,          sizeof(sk_b));
    secure_zero(&euicc_tunnel,  sizeof(euicc_tunnel));
    secure_zero(&server_tunnel, sizeof(server_tunnel));

    printf("\n============================================\n");
    printf("  运营商切换完成 ✓\n");
    printf("============================================\n");
    return 0;
}