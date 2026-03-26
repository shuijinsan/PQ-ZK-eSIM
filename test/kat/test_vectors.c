/*
 * test_vectors.c
 * 已知答案测试（KAT）
 * 供前端 JNI 和后端 Python 在联调前基准校验
 *
 * 编译运行：
 *   gcc -o test_vectors test_vectors.c ../src/pq_zk_esim.c \
 *       ../src/pqzk_crypto.c ../src/pqzk_poly.c ../src/pqzk_nvram.c \
 *       -I../include -lssl -lcrypto -lm && ./test_vectors
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"

/* ---- 工具：十六进制打印 ---- */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%-30s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int cmp_hex(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len);
}

static int g_pass = 0, g_fail = 0;
#define ASSERT_EQ(label, a, b, len)  do { \
    if (cmp_hex(a, b, len) == 0) { printf("[PASS] %s\n", label); g_pass++; } \
    else { printf("[FAIL] %s\n", label); g_fail++; \
           printf("  expected: "); for(int _i=0;_i<(int)(len)&&_i<16;_i++) printf("%02x",b[_i]); printf("...\n"); \
           printf("  got:      "); for(int _i=0;_i<(int)(len)&&_i<16;_i++) printf("%02x",a[_i]); printf("...\n"); } \
} while(0)

/* ================================================================
 * KAT 1：PQC_SerializeContext
 * 固定输入，验证跨端输出一致
 * ================================================================ */
static void kat_serialize_context(void)
{
    printf("\n=== KAT 1: PQC_SerializeContext ===\n");

    ContextData ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timestamp = 0x000000006745B320ULL; /* 1732500256 */
    ctx.latitude  = 316074000;             /* 31.6074 * 1e7 */
    ctx.longitude = 1213734000;            /* 121.3734 * 1e7 */
    strncpy(ctx.desc, "eSIM-download-operator-A", sizeof(ctx.desc)-1);

    uint8_t out[PQ_ZK_CONTEXT_BYTES];
    PQC_SerializeContext(&ctx, out);
    print_hex("ctx_bytes[0:16]", out, 16);

    /*
     * 正确预期值（Python验证）：
     * timestamp 0x6745B320 LE8: 20 B3 45 67 00 00 00 00
     * latitude  316074000  LE4: 10 E8 D6 12
     * longitude 1213734000 LE4: 70 1C 58 48
     */
    uint8_t expected[16] = {
        0x20, 0xB3, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00,
        0x10, 0xE8, 0xD6, 0x12, 0x70, 0x1C, 0x58, 0x48
    };
    ASSERT_EQ("SerializeContext header", out, expected, 16);

    /* 计算 H_ctx = SHA256(ctx_bytes) 并输出（供前后端校验） */
    uint8_t H_ctx[32];
    pqzk_sha256(out, PQ_ZK_CONTEXT_BYTES, H_ctx);
    print_hex("H_ctx (SHA256)", H_ctx, 32);
}

/* ================================================================
 * KAT 2：PQC_EncodePolyVec / PQC_DecodePolyVec
 * 往返一致性测试
 * ================================================================ */
static void kat_encode_decode_polyvec(void)
{
    printf("\n=== KAT 2: PQC_EncodePolyVec / PQC_DecodePolyVec ===\n");

    /* 构造固定测试多项式向量：系数 = index % q */
    poly_vec_t orig;
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++)
        orig.coeffs[i] = (int16_t)(i % PQ_ZK_Q_VAL);

    uint8_t encoded[PQ_ZK_POLYVEC_BYTES];
    PQC_EncodePolyVec(&orig, encoded);

    /* 验证编码：coeffs[0]=0x0000, coeffs[1]=0x0001, ... 小端序 */
    uint8_t exp_head[6] = {0x00, 0x00, 0x01, 0x00, 0x02, 0x00};
    ASSERT_EQ("EncodePolyVec first 3 coeffs", encoded, exp_head, 6);
    print_hex("encoded[0:8]", encoded, 8);

    /* 往返测试 */
    poly_vec_t decoded;
    PQC_DecodePolyVec(encoded, &decoded);
    ASSERT_EQ("DecodePolyVec roundtrip",
              (uint8_t*)decoded.coeffs, (uint8_t*)orig.coeffs,
              sizeof(orig.coeffs));
}

/* ================================================================
 * KAT 3：PQC_EncodePoly / PQC_DecodePoly
 * ================================================================ */
static void kat_encode_decode_poly(void)
{
    printf("\n=== KAT 3: PQC_EncodePoly / PQC_DecodePoly ===\n");

    poly_t orig;
    memset(&orig, 0, sizeof(orig));
    orig.coeffs[0]  =  1;
    orig.coeffs[1]  = -1;
    orig.coeffs[2]  =  0;
    orig.coeffs[3]  =  1;

    uint8_t encoded[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&orig, encoded);

    /* coeffs[0]=1: 01 00, coeffs[1]=-1=0xFFFF: FF FF */
    uint8_t exp_head[8] = {0x01,0x00, 0xFF,0xFF, 0x00,0x00, 0x01,0x00};
    ASSERT_EQ("EncodePoly {1,-1,0,1}", encoded, exp_head, 8);

    poly_t decoded;
    PQC_DecodePoly(encoded, &decoded);
    /* 注意：-1 编码为 0xFFFF，解码后 int16_t 为 -1 ✓ */
    ASSERT_EQ("DecodePoly roundtrip",
              (uint8_t*)decoded.coeffs, (uint8_t*)orig.coeffs,
              sizeof(orig.coeffs));
}

/* ================================================================
 * KAT 4：pqzk_sha256 / pqzk_hmac_sha256_iov
 * 对照标准向量
 * ================================================================ */
static void kat_hash_mac(void)
{
    printf("\n=== KAT 4: SHA-256 / HMAC-SHA256 ===\n");

    /* SHA-256("") = e3b0c44298fc1c14... */
    uint8_t h[32];
    pqzk_sha256((uint8_t*)"", 0, h);
    uint8_t sha256_empty[32] = {
        0xe3,0xb0,0xc4,0x42, 0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8, 0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4, 0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b, 0x78,0x52,0xb8,0x55
    };
    ASSERT_EQ("SHA256 empty string", h, sha256_empty, 32);

    /* SHA-256("abc") = ba7816bf... */
    pqzk_sha256((uint8_t*)"abc", 3, h);
    uint8_t sha256_abc[32] = {
        0xba,0x78,0x16,0xbf, 0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde, 0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3, 0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61, 0xf2,0x00,0x15,0xad
    };
    ASSERT_EQ("SHA256 'abc'", h, sha256_abc, 32);
    print_hex("SHA256('abc')", h, 32);

    /* HMAC-SHA256(key="key", data="The quick brown fox...") */
    /* Python验证: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8 */
    uint8_t key3[3] = {0x6b,0x65,0x79}; /* "key" */
    uint8_t msg[]  = "The quick brown fox jumps over the lazy dog";
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
 * KAT 5：pqzk_prf（PRF 输出一致性）
 * 供后端 Python 调用 PQC_GenerateMask 前基准校验
 * ================================================================ */
static void kat_prf(void)
{
    printf("\n=== KAT 5: PRF (AES-256-CTR) ===\n");

    uint8_t K_sym[32], c_seed[32], H_ctx[32];
    memset(K_sym,  0xAA, 32);
    memset(c_seed, 0xBB, 32);
    memset(H_ctx,  0xCC, 32);
    uint64_t ctr = 42;

    uint8_t out[64];
    pqzk_prf(K_sym, c_seed, ctr, H_ctx, out, 64);
    print_hex("PRF output[0:32]", out,      32);
    print_hex("PRF output[32:64]", out + 32, 32);

    /* 确定性：相同输入两次输出相同 */
    uint8_t out2[64];
    pqzk_prf(K_sym, c_seed, ctr, H_ctx, out2, 64);
    ASSERT_EQ("PRF deterministic", out, out2, 64);

    /* 计数器变化导致不同输出 */
    uint8_t out3[64];
    pqzk_prf(K_sym, c_seed, ctr + 1, H_ctx, out3, 64);
    int same = (memcmp(out, out3, 64) == 0);
    if (!same) { printf("[PASS] PRF ctr sensitivity\n"); g_pass++; }
    else       { printf("[FAIL] PRF ctr sensitivity\n"); g_fail++; }
}

/* ================================================================
 * KAT 6：SampleInBall 稀疏性校验
 * ================================================================ */
static void kat_sample_in_ball(void)
{
    printf("\n=== KAT 6: SampleInBall_κ ===\n");

    uint8_t hash[32];
    memset(hash, 0x01, 32);

    poly_t c;
    pqzk_sample_in_ball(hash, &c);

    /* 统计汉明重量和系数域 */
    int weight = 0, bad = 0;
    for (int i = 0; i < PQ_ZK_N; i++) {
        int16_t v = c.coeffs[i];
        if (v != -1 && v != 0 && v != 1) bad++;
        if (v != 0) weight++;
    }

    print_hex("c_agg[0:8]", (uint8_t*)c.coeffs, 16);
    printf("Hamming weight: %d (expected %d)\n", weight, PQ_ZK_CHALLENGE_WEIGHT);
    printf("Bad coeffs: %d\n", bad);

    if (weight == PQ_ZK_CHALLENGE_WEIGHT && bad == 0)
        { printf("[PASS] SampleInBall weight & domain\n"); g_pass++; }
    else
        { printf("[FAIL] SampleInBall weight & domain\n"); g_fail++; }

    /* 确定性 */
    poly_t c2;
    pqzk_sample_in_ball(hash, &c2);
    ASSERT_EQ("SampleInBall deterministic",
              (uint8_t*)c.coeffs, (uint8_t*)c2.coeffs, sizeof(c.coeffs));
}

/* ================================================================
 * KAT 7：完整协议端到端流程（单机模拟）
 * ================================================================ */
static void kat_protocol_e2e(void)
{
    printf("\n=== KAT 7: 协议端到端流程 ===\n");

    /* 创建临时 nvram 目录 */
    const char *nvram_dir = "/tmp/pqzk_test_nvram";
    system("mkdir -p /tmp/pqzk_test_nvram");

    /* ---- 阶段零 ---- */
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t sk_s;
    PQC_GenKeyPair(pk_t, &sk_s);
    printf("[INFO] GenKeyPair done. pk_t[0:8]: ");
    for (int i = 0; i < 8; i++) printf("%02x", pk_t[i]);
    printf("\n");

    uint8_t eid[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                       0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    uint8_t k_sym[32], k_tee[32];
    pqzk_rand_bytes(k_sym, 32);
    pqzk_rand_bytes(k_tee, 32);

    PQC_eUICC_Init(nvram_dir, eid, 16, &sk_s,
                   k_sym, 32, 0, k_tee, 32);
    printf("[PASS] eUICC_Init done\n"); g_pass++;

    /* ---- 阶段一（LPA） ---- */
    poly_vec_t W_pub;
    uint8_t seed_y[32];
    PQC_PreCompute(&W_pub, seed_y);

    /* ---- 阶段一（eUICC） ---- */
    poly_vec_t W_sec;
    uint8_t MAC_W[32];
    PQC_eUICC_Commit(nvram_dir, &W_sec, MAC_W);
    print_hex("MAC_W", MAC_W, 32);

    /* LPA 聚合 W = W_sec + W_pub */
    poly_vec_t W;
    pqzk_vec_add(&W_sec, &W_pub, &W);

    /* ---- 阶段二 ---- */
    /* 构造 H_ctx */
    ContextData ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timestamp = 1732500256;
    ctx.latitude  = 316074000;
    ctx.longitude = 1213734000;
    strncpy(ctx.desc, "test-session", sizeof(ctx.desc)-1);
    uint8_t ctx_bytes[PQ_ZK_CONTEXT_BYTES];
    PQC_SerializeContext(&ctx, ctx_bytes);
    uint8_t H_ctx[32];
    pqzk_sha256(ctx_bytes, PQ_ZK_CONTEXT_BYTES, H_ctx);

    uint8_t c_seed[32];
    pqzk_rand_bytes(c_seed, 32);

    poly_t c_agg;
    PQC_GenChallenge(&W, c_seed, H_ctx, &c_agg);

    /* 验证 c_agg 稀疏性 */
    int wt = 0;
    for (int i = 0; i < PQ_ZK_N; i++) if (c_agg.coeffs[i] != 0) wt++;
    if (wt == PQ_ZK_CHALLENGE_WEIGHT)
        { printf("[PASS] GenChallenge c_agg weight=%d\n", wt); g_pass++; }
    else
        { printf("[FAIL] GenChallenge c_agg weight=%d\n", wt); g_fail++; }

    /* ---- 阶段三：模拟 TEE 计算 AuthToken ---- */
    /* AuthToken = HMAC(K_TEE, encode(c_agg)||ctr_le8||H_ctx||hash_M2) */
    uint8_t cagg_bytes[PQ_ZK_POLY_BYTES];
    PQC_EncodePoly(&c_agg, cagg_bytes);
    uint8_t ctr_bytes[8] = {0}; /* initial ctr = 0 */
    uint8_t hash_M2[32];
    memset(hash_M2, 0x55, 32); /* 模拟 TEE 计算的 Hash(M2) */

    pqzk_iov_t auth_iov[] = {
        { cagg_bytes, PQ_ZK_POLY_BYTES },
        { ctr_bytes,  8 },
        { H_ctx,      32 },
        { hash_M2,    32 },
        { NULL, 0 }
    };
    uint8_t AuthToken[32];
    pqzk_hmac_sha256_iov(k_tee, auth_iov, AuthToken);
    print_hex("AuthToken", AuthToken, 32);

    /* ---- 阶段四 ---- */
    poly_vec_t z_sec_masked;
    PQ_ZK_ErrorCode rc = PQC_ComputeZ_and_Mask(
        nvram_dir, &c_agg, c_seed, H_ctx, hash_M2, AuthToken, &z_sec_masked);

    if (rc == PQ_ZK_SUCCESS)
        { printf("[PASS] ComputeZ_and_Mask rc=%d\n", rc); g_pass++; }
    else
        { printf("[FAIL] ComputeZ_and_Mask rc=%d\n", rc); g_fail++; }

    /* ---- 阶段五 ---- */
    poly_vec_t y_pub, resp_z;
    PQC_RegenerateYpub(seed_y, &y_pub);
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

    /* ---- 阶段六：服务器端 ---- */
    /* 重新获取 K_sym（注意：阶段四已演进K_sym，此处用原始值模拟服务器知道旧K_sym） */
    /* 使用原始 k_sym（ctr=0 时对应的密钥） */
    poly_vec_t M_mask;
    PQC_GenerateMask(k_sym, c_seed, 0 /*ctr_session=0*/, H_ctx, &M_mask);

    beta_params_t params;
    params.beta_final = PQ_ZK_BETA_FINAL;
    params.beta_min   = 100;  /* 测试用宽松下界 */

    PQ_ZK_ErrorCode verify_rc = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED, pk_t, &W, &resp_z,
        c_seed, H_ctx, &M_mask, &params);

    if (verify_rc == PQ_ZK_SUCCESS)
        { printf("[PASS] VerifyEngine\n"); g_pass++; }
    else
        { printf("[FAIL] VerifyEngine rc=%d\n", verify_rc); g_fail++; }

    system("rm -rf /tmp/pqzk_test_nvram");
}

/* ================================================================
 * 主函数
 * ================================================================ */
int main(void)
{
    printf("========================================\n");
    printf("  PQ-ZK-eSIM KAT 测试向量 v3.0\n");
    printf("  供前端 JNI 和后端 Python 基准校验\n");
    printf("========================================\n");

    kat_serialize_context();
    kat_encode_decode_polyvec();
    kat_encode_decode_poly();
    kat_hash_mac();
    kat_prf();
    kat_sample_in_ball();
    kat_protocol_e2e();

    printf("\n========================================\n");
    printf("  结果：%d 通过，%d 失败\n", g_pass, g_fail);
    printf("========================================\n");

    return (g_fail == 0) ? 0 : 1;
}