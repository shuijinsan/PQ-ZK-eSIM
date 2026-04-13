/*
 * main.c — PQ-ZK-eSIM v5.0 软件入口（完整版，含运营商切换）
 *
 * 用法：
 *   注册：  ./pqzkesim --register --face features.bin --nvram /tmp/euicc
 *   认证：  ./pqzkesim --auth     --nvram /tmp/euicc
 *   切换：  ./pqzkesim --switch   --nvram /tmp/euicc \
 *                      --mno-b-id "operator_b_id_16b" \
 *                      --mno-a-id "operator_a_id_16b"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_cert.h"

/* mode_switch 声明（实现在 mode_switch.c） */
int mode_switch(const char    *nvram_dir,
                const uint8_t  domain_id_b[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_id[PQZK_MNO_ID_BYTES],
                const uint8_t  mno_a_sk[32]);

/* mode_register / mode_auth 声明（实现见下方或独立文件） */
static int mode_register(const char *nvram_dir, const char *feature_file);
static int mode_auth(const char *nvram_dir);

/* ================================================================
 * 注册模式（同前，保持不变）
 * ================================================================ */
static int mode_register(const char *nvram_dir, const char *feature_file)
{
    printf("[注册] nvram: %s\n", nvram_dir);
    printf("[注册] 特征文件: %s\n", feature_file);

    FILE *f = fopen(feature_file, "r");
    if (!f) {
        fprintf(stderr, "[错误] 无法读取特征文件: %s\n", feature_file);
        fprintf(stderr, "[提示] 先运行: python3 tools/gen_face_feature.py"
                        " --img face.jpg --out features.bin\n");
        return -1;
    }

    int n_blocks;
    fscanf(f, "%d", &n_blocks);
    if (n_blocks <= 0 || n_blocks > PQZK_MERKLE_MAX_LEAVES) {
        fclose(f); return -1;
    }

    uint8_t (*features)[32] = malloc(n_blocks * 32);
    if (!features) { fclose(f); return -1; }

    for (int i = 0; i < n_blocks; i++) {
        for (int j = 0; j < 32; j++) {
            unsigned int v;
            fscanf(f, "%02x", &v);
            features[i][j] = (uint8_t)v;
        }
    }
    fclose(f);

    uint8_t k_sym[32], k_tee[32];
    pqzk_rand_bytes(k_sym, 32);
    pqzk_rand_bytes(k_tee, 32);

    uint64_t initial_ctr = 0;
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    uint8_t R_bio[32], salt[32];
    uint8_t cred_kyc[64] = {0};
    uint8_t  mno_id[PQZK_MNO_ID_BYTES];

    PQ_ZK_ErrorCode rc = PQC_Register(
        nvram_dir,
        (const uint8_t (*)[32])features, n_blocks,mno_id,
        k_sym, k_tee, initial_ctr,
        pk_t, R_bio, salt);

    free(features);

    if (rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[错误] 注册失败: %d\n", rc);
        return -1;
    }

    printf("[注册] 完成\n");
    printf("[注册] R_bio = ");
    for (int i = 0; i < 32; i++) printf("%02x", R_bio[i]);
    printf("\n");

    /* 保存注册数据供后续使用 */
    FILE *reg = fopen("registration_data.bin", "wb");
    if (reg) {
        fwrite(pk_t,  1, PQ_ZK_PUBLICKEY_BYTES, reg);
        fwrite(R_bio, 1, 32, reg);
        fwrite(salt,  1, 32, reg);
        fwrite(k_sym, 1, 32, reg);
        fclose(reg);
        printf("[注册] 数据已保存到 registration_data.bin\n");
    }

    return 0;
}

/* ================================================================
 * 认证模式（同前，保持不变）
 * ================================================================ */
static int mode_auth(const char *nvram_dir)
{
    printf("[认证] nvram: %s\n", nvram_dir);

    merkle_tree_t tree;
    PQ_ZK_ErrorCode load_rc = PQC_LoadTree(nvram_dir, &tree);
    if (load_rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[错误] nvram 未初始化，请先注册\n");
        return -1;
    }

    printf("[认证] Merkle 树加载成功，叶子数: %u\n", tree.n_leaves);

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    uint8_t R_bio[32], salt[32], k_sym[32];
    FILE *reg = fopen("registration_data.bin", "rb");
    if (!reg) {
        fprintf(stderr, "[错误] 找不到 registration_data.bin\n");
        return -1;
    }
    fread(pk_t,  1, PQ_ZK_PUBLICKEY_BYTES, reg);
    fread(R_bio, 1, 32, reg);
    fread(salt,  1, 32, reg);
    fread(k_sym, 1, 32, reg);
    fclose(reg);

    printf("[认证] 活体验证（模拟）：通过\n");

    /* 阶段一 */
    poly_vec_t W_pub, W_sec;
    uint8_t seed_y[32], MAC_W[32];
    PQC_PreCompute(&W_pub, seed_y);
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    poly_vec_t W;
    pqzk_vec_add(&W_sec, &W_pub, &W);
    printf("[阶段一] 承诺生成完成\n");

    /* 阶段二 */
    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);
    poly_t c_agg;
    PQC_GenChallenge(&W, c_seed, &c_agg);
    uint32_t M1 = 0;
    printf("[阶段二] 挑战生成完成\n");

    /* 阶段三 */
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
        fprintf(stderr, "[错误] TEE 令牌生成失败: %d\n", tee_rc);
        return -1;
    }
    printf("[阶段三] TEE 授权令牌生成完成\n");

    /* 序列化 M2 */
    uint8_t m2s[8 + PQZK_MERKLE_MAX_DEPTH*(PQZK_MERKLE_HASH_BYTES+1)];
    size_t off = 0;
    write_le32(m2s + off, M2.depth);      off += 4;
    write_le32(m2s + off, M2.leaf_index); off += 4;
    for (uint32_t i = 0; i < M2.depth; i++) {
        memcpy(m2s + off, M2.sibling[i], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        m2s[off] = M2.is_right_sibling[i]; off++;
    }
    uint8_t hash_M2[32];
    pqzk_sha256(m2s, off, hash_M2);

    /* 阶段四 */
    poly_vec_t z_sec_masked;
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed,
        R_dynamic, hash_M2, AuthToken, &z_sec_masked);
    if (rc != PQ_ZK_SUCCESS) {
        fprintf(stderr, "[错误] 阶段四失败: %d\n", rc);
        return -1;
    }
    printf("[阶段四] 掩码计算完成\n");

    /* 阶段五 */
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);
    printf("[阶段五] 响应聚合完成\n");

    /* 阶段六 */
    nvram_read(nvram_dir, &nvram_st);
    uint8_t ctr_le8[8];
    write_le64(ctr_le8, nvram_st.ctr_local - 1);
    secure_zero(&nvram_st, sizeof(nvram_st));

    pqzk_iov_t ri[] = {{ R_bio, 32 }, { ctr_le8, 8 }, { NULL, 0 }};
    uint8_t R_dynamic_server[32];
    pqzk_sha256_iov(ri, R_dynamic_server);

    poly_vec_t M_mask;
    uint64_t ctr_session;
    memcpy(&ctr_session, ctr_le8, 8);
    PQC_GenerateMask(k_sym, c_seed, ctr_session, R_dynamic_server, &M_mask);

    beta_params_t params = PQZK_DEFAULT_BETA_PARAMS;
    PQ_ZK_ErrorCode vrc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, R_dynamic_server, &M_mask, &params);

    if (vrc == PQ_ZK_SUCCESS) {
        printf("[阶段六] 验证通过 ✓\n");
        printf("[认证] 认证成功！\n");
        return 0;
    } else {
        fprintf(stderr, "[阶段六] 验证失败: %d\n", vrc);
        return -1;
    }
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    const char *nvram_dir     = "/tmp/pqzk_euicc";
    const char *feature_file  = "features.bin";
    int do_register = 0, do_auth = 0, do_switch = 0;

    /*
     * MNO_A / MNO_B 标识（切换模式使用）
     * 真实场景：从运营商配置文件或 SIM 配置中读取
     * 模拟场景：命令行参数或默认值
     */
    uint8_t mno_a_id[PQZK_MNO_ID_BYTES];
    uint8_t mno_b_id[PQZK_MNO_ID_BYTES];
    uint8_t mno_a_sk[32];

    /* 默认 MNO_A 标识（模拟） */
    memset(mno_a_id, 0, sizeof(mno_a_id));
    memcpy(mno_a_id, "MNO_A_SIM_001", 13);

    /* 默认 MNO_B 标识（模拟） */
    memset(mno_b_id, 0, sizeof(mno_b_id));
    memcpy(mno_b_id, "MNO_B_SIM_001", 13);

    /* MNO_A 签名私钥（模拟：固定值，真实场景由 HSM 保护） */
    memset(mno_a_sk, 0xA1, 32);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--register"))  do_register = 1;
        if (!strcmp(argv[i], "--auth"))      do_auth     = 1;
        if (!strcmp(argv[i], "--switch"))    do_switch   = 1;
        if (!strcmp(argv[i], "--nvram")   && i+1 < argc)
            nvram_dir    = argv[++i];
        if (!strcmp(argv[i], "--face")    && i+1 < argc)
            feature_file = argv[++i];
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
    printf("  PQ-ZK-eSIM  模拟软件\n");
    printf("  nvram: %s\n", nvram_dir);
    printf("============================================\n");

    mkdir(nvram_dir, 0700);

    if (do_register) return mode_register(nvram_dir, feature_file);
    if (do_auth)     return mode_auth(nvram_dir);
    if (do_switch) {
         /* 从 nvram 读取当前运营商信息并显示 */
        nvram_state_t cur_state;
        if (nvram_read(nvram_dir, &cur_state) == 0) {
            printf("[切换] 当前运营商: %.16s\n",
                   (char*)cur_state.active_mno_id);
            printf("[切换] 已切换次数: %u\n", cur_state.switch_count);
            secure_zero(&cur_state, sizeof(cur_state));
        }
        printf("[切换] 目标运营商: %.16s\n", (char*)mno_b_id);
        return mode_switch(nvram_dir, mno_b_id, mno_a_id, mno_a_sk);
    }
  
    printf("\n用法：\n");
    printf("  注册: %s --register --face features.bin"
           " --nvram /tmp/euicc\n", argv[0]);
    printf("  认证: %s --auth --nvram /tmp/euicc\n", argv[0]);
    printf("  切换: %s --switch --nvram /tmp/euicc"
           " --mno-a-id MNO_A_001 --mno-b-id MNO_B_001\n", argv[0]);
    return 0;
}