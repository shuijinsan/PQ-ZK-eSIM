/*
 * mode_switch.c — PQ-ZK-eSIM v5.0
 * 运营商切换（MNO_A → MNO_B）完整流程
 *
 * 协议对应：§5.1.5 多域预置与运营商切换
 *
 * 切换流程（七步）：
 *
 *   Step 1  TEE 活体验证
 *           TEE 唤起生物识别，验证用户在场。
 *
 *   Step 2  TEE 计算运营商专属生物根
 *           R_bio_B = Hash(R_bio || Domain_ID_B)
 *
 *   Step 3  eUICC 为 MNO_B 生成新格密钥对
 *           T_B, S_B ← KeyGen(λ)
 *           仅上传 T_B，S_B 永不离开 eUICC
 *
 *   Step 4  ML-KEM 握手建立后量子安全 APDU 隧道
 *           MNO_B → eUICC：ML-KEM 公钥
 *           eUICC → MNO_B：ML-KEM 密文 + tunnel_id
 *           双方独立派生：session_key = KDF(shared_secret, tunnel_id)
 *
 *   Step 5  eUICC 在隧道内发送身份证据包
 *           加密载荷：(R_bio_B, R_bio, salt, Cred_KYC, Cert_A, T_B)
 *
 *   Step 6  MNO_B 验证身份证据包
 *           6.1 验证 Cert_A（GSMA 证书链）
 *           6.2 验证 Cred_KYC（MNO_A 对 EID||R_bio 的签名）
 *           6.3 比对物理 ID_eUICC 和逻辑 ID_eUICC
 *           6.4 重构 R_bio_B' = Hash(R_bio || Domain_ID_B)，断言一致
 *
 *   Step 7  MNO_B 注入新密钥材料
 *           通过隧道加密传输：(K_symB, d_seedB)
 *           eUICC 更新 nvram，完成切换
 *
 * 模拟说明：
 *   · "MNO_B 服务器"和"eUICC"运行在同一进程，通过内存传递消息
 *   · ML-KEM 隧道实际建立（liboqs），只是省去了网络传输
 *   · 证书链用 HMAC-SHA256 模拟数字签名
 *   · 活体验证调用即视为通过
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_mlkem.h"
#include "pqzk_cert.h"

/* ================================================================
 * 内部工具：打印十六进制（带标签）
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
    /*
     * 真实场景：Android TEE 调用 BiometricPrompt，
     *            弹出人脸/指纹验证界面，用户完成验证后返回。
     * 模拟场景：直接返回成功，代表"用户已在场确认"。
     */
    printf("  [TEE] 活体验证（模拟）：用户在场确认 ✓\n");
    return 0;
}

/* ================================================================
 * Step 2：TEE 计算运营商专属生物根
 *
 * R_bio_B = SHA-256(R_bio || Domain_ID_B)
 *
 * Domain_ID_B 是目标运营商的标识，由 MNO_B 提供。
 * 不同运营商的 Domain_ID_B 不同，同一用户在不同运营商处
 * 有不同的 R_bio_B，保护跨运营商的生物特征隐私。
 * ================================================================ */
static int tee_derive_domain_bio_root(const uint8_t R_bio[32],
                                       const uint8_t domain_id_b[PQZK_MNO_ID_BYTES],
                                       uint8_t       R_bio_B_out[32])
{
    pqzk_iov_t iov[] = {
        { R_bio,       32                   },
        { domain_id_b, PQZK_MNO_ID_BYTES   },
        { NULL, 0 }
    };
    return pqzk_sha256_iov(iov, R_bio_B_out);
}

/* ================================================================
 * Step 3：eUICC 为 MNO_B 生成新格密钥对
 *
 * 使用全局公共矩阵 A（跨运营商共享），生成独立的 T_B, S_B。
 * S_B 写入 nvram，T_B 通过隧道发给 MNO_B。
 * ================================================================ */
static int euicc_gen_new_keypair(poly_vec_t *sk_b_out,
                                  uint8_t     pk_b_out[PQ_ZK_PUBLICKEY_BYTES])
{
    PQC_GenKeyPair(pk_b_out, sk_b_out);
    return 0;
}

/* ================================================================
 * Step 4：ML-KEM 握手（模拟）
 *
 * 真实场景：MNO_B 公钥通过 OOB 信道或初始握手包发给 eUICC。
 * 模拟场景：双方在同一进程内直接传递结构体。
 * ================================================================ */
static int mlkem_handshake(mlkem_tunnel_t *euicc_tunnel_out,
                            mlkem_tunnel_t *server_tunnel_out)
{
    /* MNO_B 生成密钥对 */
    mlkem_keypair_t server_kp;
    if (PQZK_MLKEM_Keygen(&server_kp) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 密钥生成失败\n");
        return -1;
    }
    printf("  [ML-KEM] MNO_B 密钥对生成完成\n");
    print_hex("server pk[0:16]", server_kp.pk, 16);

    /* eUICC 封装：生成密文和 session_key */
    uint8_t ciphertext[PQZK_MLKEM_CT_BYTES];
    if (PQZK_MLKEM_Encapsulate(server_kp.pk, ciphertext,
                                euicc_tunnel_out) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 封装失败\n");
        return -1;
    }
    printf("  [ML-KEM] eUICC 封装完成，密文长度: %d 字节\n",
           PQZK_MLKEM_CT_BYTES);

    /*
     * eUICC → MNO_B：发送密文和 tunnel_id
     * 模拟：直接复制 tunnel_id 到 server_tunnel
     */
    memcpy(server_tunnel_out->tunnel_id,
           euicc_tunnel_out->tunnel_id, 16);
    server_tunnel_out->established = 1;

    /* MNO_B 解封装：从密文恢复 session_key */
    if (PQZK_MLKEM_Decapsulate(&server_kp, ciphertext,
                                server_tunnel_out) != 0) {
        fprintf(stderr, "  [错误] ML-KEM 解封装失败\n");
        return -1;
    }
    printf("  [ML-KEM] MNO_B 解封装完成\n");

    /* 验证双方 session_key 一致 */
    if (memcmp(euicc_tunnel_out->session_key,
               server_tunnel_out->session_key, 32) != 0) {
        fprintf(stderr, "  [错误] 双方 session_key 不一致\n");
        return -1;
    }
    print_hex("session_key[0:16]", euicc_tunnel_out->session_key, 16);
    printf("  [ML-KEM] 隧道建立成功，session_key 两端一致 ✓\n");

    /* 安全清零服务器私钥 */
    secure_zero(&server_kp, sizeof(server_kp));
    return 0;
}

/* ================================================================
 * Step 5：eUICC 在隧道内发送身份证据包
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
    /* 构造身份证据包 */
    apdu_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    memcpy(payload.R_bio_B,  R_bio_B,      32);
    memcpy(payload.R_bio,    R_bio,        32);
    memcpy(payload.salt,     salt,         32);
    memcpy(payload.cred_kyc, cred_kyc,     64);
    memcpy(payload.cert_a,   cert_a_bytes, PQZK_CERT_BYTES);
    memcpy(payload.eid,      eid,          16);
    memcpy(payload.T_new,    T_new,        PQ_ZK_PUBLICKEY_BYTES);

    /* 序列化 */
    static uint8_t serial_buf[4096];
    int serial_len = PQZK_APDU_SerializePayload(
        &payload, serial_buf, sizeof(serial_buf));
    if (serial_len < 0) return -1;

    /* 隧道加密 */
    if (PQZK_APDU_Encrypt(euicc_tunnel, serial_buf, serial_len,
                           encrypted_payload_out) != 0)
        return -1;

    *encrypted_len_out = (size_t)serial_len;
    printf("  [eUICC] 身份证据包加密完成，载荷长度: %d 字节\n", serial_len);
    return 0;
}

/* ================================================================
 * Step 6：MNO_B 验证身份证据包
 * ================================================================ */
static int mnob_verify_identity(
    const mlkem_tunnel_t *server_tunnel,
    const uint8_t *encrypted_payload,
    size_t         payload_len,
    const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
    const uint8_t  physical_eid[16],
    apdu_payload_t *payload_out)
{
    /* 6.0 解密载荷 */
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

    /* 6.1 验证 Cert_A（GSMA 证书链）*/
    pqzk_cert_t cert_a;
    if (PQZK_Cert_Deserialize(payload_out->cert_a, &cert_a) != 0) {
        fprintf(stderr, "  [MNO_B] 证书反序列化失败\n");
        return -1;
    }
    if (PQZK_Cert_Verify(&cert_a) != 0) {
        fprintf(stderr, "  [MNO_B] Cert_A 验证失败（GSMA 证书链无效）\n");
        return -1;
    }
    printf("  [MNO_B] Cert_A 验证通过 ✓（GSMA 证书链合法）\n");
    print_hex("MNO_A ID", cert_a.mno_id, PQZK_MNO_ID_BYTES);

    /* 6.2 验证 Cred_KYC */
    if (PQZK_CredKYC_Verify(&cert_a,
                              payload_out->eid,
                              payload_out->R_bio,
                              payload_out->cred_kyc) != 0) {
        fprintf(stderr, "  [MNO_B] Cred_KYC 验证失败（凭证非法）\n");
        return -1;
    }
    printf("  [MNO_B] Cred_KYC 验证通过 ✓（用户身份合法）\n");

    /* 6.3 比对物理 ID_eUICC 和逻辑 ID_eUICC */
    if (memcmp(physical_eid, payload_out->eid, 16) != 0) {
        fprintf(stderr, "  [MNO_B] EID 不匹配（疑似设备冒名顶替）\n");
        return -1;
    }
    printf("  [MNO_B] EID 比对通过 ✓（物理 == 逻辑）\n");

    /* 6.4 重构 R_bio_B' 并与载荷中的 R_bio_B 比对 */
    uint8_t R_bio_B_recomputed[32];
    pqzk_iov_t iov[] = {
        { payload_out->R_bio, 32                   },
        { domain_id_b,        PQZK_MNO_ID_BYTES   },
        { NULL, 0 }
    };
    pqzk_sha256_iov(iov, R_bio_B_recomputed);

    if (memcmp(R_bio_B_recomputed, payload_out->R_bio_B, 32) != 0) {
        fprintf(stderr, "  [MNO_B] R_bio_B 验证失败（生物根不一致）\n");
        return -1;
    }
    printf("  [MNO_B] R_bio_B 验证通过 ✓（生物特征根一致）\n");
    print_hex("R_bio_B", payload_out->R_bio_B, 32);

    return 0;
}

/* ================================================================
 * Step 7：MNO_B 注入新密钥材料，eUICC 更新 nvram
 * ================================================================ */
static int mnob_inject_new_keys(
    const char    *nvram_dir,
    const mlkem_tunnel_t *euicc_tunnel,
    const mlkem_tunnel_t *server_tunnel,
    const poly_vec_t *sk_b,
    const apdu_payload_t *payload,
    const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES])
{
    /* MNO_B 生成新的对称密钥材料 */
    uint8_t k_sym_b[32], d_seed_b[32];
    pqzk_rand_bytes(k_sym_b,  32);
    pqzk_rand_bytes(d_seed_b, 32);

    printf("  [MNO_B] 生成新密钥材料 K_symB, d_seedB\n");
    print_hex("K_symB[0:16]", k_sym_b, 16);

    /*
     * MNO_B 通过隧道加密发送 (K_symB || d_seedB)
     * 模拟：直接传内存
     */
    uint8_t key_material[64];
    memcpy(key_material,      k_sym_b,  32);
    memcpy(key_material + 32, d_seed_b, 32);

    uint8_t encrypted_keys[64];
    if (PQZK_APDU_Encrypt(server_tunnel, key_material, 64,
                           encrypted_keys) != 0) {
        fprintf(stderr, "  [MNO_B] 密钥加密失败\n");
        return -1;
    }

    /* eUICC 解密收到的密钥材料 */
    uint8_t decrypted_keys[64];
    if (PQZK_APDU_Decrypt(euicc_tunnel, encrypted_keys, 64,
                           decrypted_keys) != 0) {
        fprintf(stderr, "  [eUICC] 密钥解密失败\n");
        return -1;
    }

    uint8_t *k_sym_b_recv  = decrypted_keys;
    uint8_t *d_seed_b_recv = decrypted_keys + 32;

    /* eUICC 更新 nvram：写入 MNO_B 的新状态 */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "  [eUICC] nvram 读取失败\n");
        return -1;
    }

    /* 更新密钥材料 */
    memcpy(state.k_sym,   k_sym_b_recv,  32);
    memcpy(state.d_seed,  d_seed_b_recv, 32);

    /* 更新私钥为 MNO_B 对应的新私钥 S_B */
    PQC_EncodePolyVec(sk_b, state.sk_s);

    /* 更新生物特征根为运营商专属根 */
    memcpy(state.R_bio, payload->R_bio_B, 32);

    /* 重置计数器（新运营商从0开始）*/
    state.ctr_local   = 0;
    state.y_sec_valid = 0;
    memset(state.y_sec, 0, sizeof(state.y_sec));

    /* 更新运营商标识和激活生物根 */
    memcpy(state.active_mno_id, domain_id_b, PQZK_MNO_ID_BYTES);
    memcpy(state.active_R_bio,  payload->R_bio_B, 32);
    state.switch_count += 1;

    nvram_write_atomic(nvram_dir, &state);
    secure_zero(&state, sizeof(state));

    printf("  [eUICC] nvram 更新完成（MNO_B 密钥材料已写入）\n");
    printf("  [eUICC] 计数器重置为 0\n");
    printf("  [eUICC] R_bio 更新为运营商专属根 R_bio_B\n");

    /* 清零敏感数据 */
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
 *   nvram_dir      当前 eUICC 的 nvram 目录（MNO_A 的状态）
 *   domain_id_b    目标运营商 MNO_B 的标识（16字节）
 *   mno_a_id       当前运营商 MNO_A 的标识（16字节）
 *   mno_a_sk       MNO_A 的签名私钥（32字节，模拟）
 *
 * 返回：0 成功，-1 失败
 * ================================================================ */
int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_sk[32])
{
    printf("\n============================================\n");
    printf("  运营商切换流程（MNO_A → MNO_B）\n");
    printf("============================================\n");

    /* 读取当前 nvram 状态（MNO_A 的注册数据） */
    nvram_state_t state;
    if (nvram_read(nvram_dir, &state) != 0) {
        fprintf(stderr, "[错误] nvram 未初始化，请先完成注册\n");
        return -1;
    }
    printf("[切换] 当前 nvram 读取成功，EID: ");
    for (int i = 0; i < 16; i++) printf("%02x", state.eid[i]);
    printf("\n");

    /* ---- Step 1：TEE 活体验证 ---- */
    printf("\n[Step 1] TEE 活体验证\n");
    if (tee_biometric_verify() != 0) {
        fprintf(stderr, "[Step 1] 活体验证失败，切换中止\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* ---- Step 2：TEE 计算运营商专属生物根 ---- */
    printf("\n[Step 2] 计算运营商专属生物根\n");
    uint8_t R_bio_B[32];
    if (tee_derive_domain_bio_root(state.R_bio, domain_id_b,
                                    R_bio_B) != 0) {
        fprintf(stderr, "[Step 2] R_bio_B 计算失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("R_bio（原始）", state.R_bio, 32);
    print_hex("Domain_ID_B", domain_id_b, PQZK_MNO_ID_BYTES);
    print_hex("R_bio_B（专属）", R_bio_B, 32);

    /* ---- Step 3：eUICC 为 MNO_B 生成新格密钥对 ---- */
    printf("\n[Step 3] eUICC 生成 MNO_B 专属格密钥对\n");
    poly_vec_t sk_b;
    uint8_t pk_b[PQ_ZK_PUBLICKEY_BYTES];
    if (euicc_gen_new_keypair(&sk_b, pk_b) != 0) {
        fprintf(stderr, "[Step 3] 密钥对生成失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    print_hex("T_B（新公钥）", pk_b, 8);
    printf("  [eUICC] 新私钥 S_B 已生成，永不离开 eUICC\n");

    /* ---- Step 4：ML-KEM 握手建立隧道 ---- */
    printf("\n[Step 4] ML-KEM 握手建立后量子安全 APDU 隧道\n");
    mlkem_tunnel_t euicc_tunnel, server_tunnel;
    memset(&euicc_tunnel,  0, sizeof(euicc_tunnel));
    memset(&server_tunnel, 0, sizeof(server_tunnel));

    if (mlkem_handshake(&euicc_tunnel, &server_tunnel) != 0) {
        fprintf(stderr, "[Step 4] ML-KEM 握手失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* ---- Step 5：eUICC 发送身份证据包 ---- */
    printf("\n[Step 5] eUICC 发送身份证据包（隧道加密）\n");

    /* 准备 MNO_A 证书（模拟：用 mno_a_id 和 mno_a_sk 签发） */
    pqzk_cert_t cert_a;
    if (PQZK_Cert_Issue(mno_a_id, mno_a_sk, &cert_a) != 0) {
        fprintf(stderr, "[Step 5] Cert_A 签发失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    uint8_t cert_a_bytes[PQZK_CERT_BYTES];
    PQZK_Cert_Serialize(&cert_a, cert_a_bytes);

    /* 准备 KYC 凭证 */
    uint8_t cred_kyc[32];
    if (PQZK_CredKYC_Issue(mno_a_sk, state.eid,
                             state.R_bio, cred_kyc) != 0) {
        fprintf(stderr, "[Step 5] Cred_KYC 签发失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    static uint8_t encrypted_payload[4096];
    size_t encrypted_len = 0;
    if (euicc_send_identity_payload(
            &euicc_tunnel,
            R_bio_B, state.R_bio, state.salt,
            cred_kyc, cert_a_bytes, state.eid, pk_b,
            encrypted_payload, &encrypted_len) != 0) {
        fprintf(stderr, "[Step 5] 身份证据包发送失败\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }

    /* ---- Step 6：MNO_B 验证身份证据包 ---- */
    printf("\n[Step 6] MNO_B 验证身份证据包\n");
    apdu_payload_t received_payload;
    if (mnob_verify_identity(
            &server_tunnel,
            encrypted_payload, encrypted_len,
            domain_id_b,
            state.eid,   /* 物理 EID */
            &received_payload) != 0) {
        fprintf(stderr, "[Step 6] 身份验证失败，切换中止\n");
        secure_zero(&state, sizeof(state));
        return -1;
    }
    printf("[Step 6] 身份验证全部通过 ✓\n");

    /* ---- Step 7：MNO_B 注入新密钥，eUICC 更新 nvram ---- */
    printf("\n[Step 7] MNO_B 注入新密钥材料\n");
    if (mnob_inject_new_keys(
            nvram_dir,
            &euicc_tunnel, &server_tunnel,
            &sk_b, &received_payload,
            domain_id_b) != 0) {
        fprintf(stderr, "[Step 7] 密钥注入失败\n");
        secure_zero(&state, sizeof(state));
        secure_zero(&sk_b, sizeof(sk_b));
        return -1;
    }

    /* 清零所有敏感数据 */
    secure_zero(&state,        sizeof(state));
    secure_zero(&sk_b,         sizeof(sk_b));
    secure_zero(&euicc_tunnel, sizeof(euicc_tunnel));
    secure_zero(&server_tunnel,sizeof(server_tunnel));

    printf("\n============================================\n");
    printf("  运营商切换完成 ✓\n");
    printf("  eUICC 已切换到 MNO_B\n");
    printf("  新 R_bio_B 已写入 nvram\n");
    printf("  新密钥 K_symB 已写入 nvram\n");
    printf("  计数器已重置为 0\n");
    printf("  可使用 --auth 进行新运营商认证\n");
    printf("============================================\n");

    return 0;
}  