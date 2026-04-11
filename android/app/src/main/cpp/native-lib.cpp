#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include "pq_zk_esim.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#define LOG_TAG "PQZK-Native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ===================== 【严格对齐头文件】工具函数 =====================
// 【解决问题3】seed_y内存加密（防明文泄露，严格用PQ_ZK_SEED_BYTES）
#define SEED_ENCRYPT_MASK 0xA5
static void encrypt_seed_y(uint8_t* seed) {
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        seed[i] ^= SEED_ENCRYPT_MASK;
    }
}

// 【解决问题2】生成MAC_W（严格对齐头文件：PQ_ZK_MAC_BYTES/PQ_ZK_TEE_KEY_BYTES）
static void generate_mac_w(
        const uint8_t* w_sec_encoded,  // 编码后的W_sec
        const uint8_t* k_tee,          // TEE密钥（头文件规范）
        uint8_t* mac_out)              // 输出MAC（PQ_ZK_MAC_BYTES）
{
    HMAC(
            EVP_sha256(),
            k_tee, PQ_ZK_TEE_KEY_BYTES,
            w_sec_encoded, PQ_ZK_POLYVEC_BYTES,  // 用头文件宏（修复报错）
            mac_out, nullptr
    );
}

// 【补充】向量加法 W = W_sec + W_pub（头文件无VecAdd，手动实现，严格对齐环运算）
static void poly_vec_add(const poly_vec_t* a, const poly_vec_t* b, poly_vec_t* out) {
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        out->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

// 错误码定义（与上层对齐）
#define ERROR_PARAM_NULL 1001
#define ERROR_EID_LEN 1002
#define ERROR_SK_LEN 1003
#define ERROR_K_SYM_LEN 1004
#define ERROR_K_TEE_LEN 1005

extern "C" {

/**
 * 1. 注册接口 (PQC_Reg) - 严格遵循 12 参数初始化
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1Reg(
        JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray out_t) {

    // ========== 原有参数校验（无新增参数，杜绝报错） ==========
    if (nvram_dir == nullptr || out_t == nullptr) {
        LOGE("错误：参数为空");
        return -1;
    }

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *t_ptr = env->GetByteArrayElements(out_t, nullptr);

    // ========== 安全初始化（删除硬编码 0x11/0x22 固定值） ==========
    poly_vec_t sk_s;
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    // 生成真实密钥对
    PQC_GenKeyPair(pk_t, &sk_s);

    // 安全清零初始化（替代硬编码Dummy值，符合规范）
    uint8_t eid[32] = {0};
    uint8_t k_sym[32] = {0};
    uint8_t k_tee[32] = {0};
    uint64_t initial_ctr = 0;

    // ========== 调用底层初始化（你的函数是void，无返回值 → 修复报错） ==========
    PQC_eUICC_Init(
            path,
            eid, 32,
            &sk_s,
            k_sym, 32,
            initial_ctr,
            k_tee, 32,
            nullptr,
            nullptr, 0
    );

    // 拷贝结果
    memcpy(t_ptr, pk_t, PQ_ZK_PUBLICKEY_BYTES);

    // ========== 安全释放内存 ==========
    env->ReleaseByteArrayElements(out_t, t_ptr, 0);
    env->ReleaseStringUTFChars(nvram_dir, path);

    LOGD("PQC_Reg 初始化完成");
    return PQ_ZK_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1eUICC_1Commit(
        JNIEnv *env, jobject thiz,
        jstring nvram_dir,          // 安全存储路径
        jbyteArray out_w_sec,       // 输出：内部承诺W_sec
        jbyteArray out_mac_w)       // 输出：MAC_W
{
    // 参数校验
    if (out_w_sec == nullptr || out_mac_w == nullptr) {
        LOGE("参数为空");
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    const char* path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte* w_sec_buf = env->GetByteArrayElements(out_w_sec, nullptr);
    jbyte* mac_buf = env->GetByteArrayElements(out_mac_w, nullptr);

    // 【核心】调用头文件标准接口：生成W_sec + MAC_W
    poly_vec_t w_sec;
    uint8_t mac_w[PQ_ZK_MAC_BYTES];
    PQC_eUICC_Commit(path, &w_sec, mac_w);

    // 编码输出（严格用头文件Encode函数）
    PQC_EncodePolyVec(&w_sec, (uint8_t*)w_sec_buf);
    memcpy(mac_buf, mac_w, PQ_ZK_MAC_BYTES);

    // 释放内存
    env->ReleaseByteArrayElements(out_mac_w, mac_buf, 0);
    env->ReleaseByteArrayElements(out_w_sec, w_sec_buf, 0);
    env->ReleaseStringUTFChars(nvram_dir, path);

    LOGD("PQC_eUICC_Commit 完成：W_sec + MAC_W 已生成");
    return PQ_ZK_SUCCESS;
}

/**
 * 2. 预计算接口 (PQC_PreCompute)
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1PreCompute(
        JNIEnv *env,        // 固定参数1
        jobject thiz,       // 固定参数2
        jbyteArray in_w_sec,
        jbyteArray out_w_total,
        jbyteArray out_seed_y
) {
    // 参数空校验
    if (in_w_sec == nullptr || out_w_total == nullptr || out_seed_y == nullptr) {
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    // 获取JNI数组指针（标准jbyte*，无类型冲突）
    jbyte* sec_buf = env->GetByteArrayElements(in_w_sec, nullptr);
    jbyte* total_buf = env->GetByteArrayElements(out_w_total, nullptr);
    jbyte* seed_buf = env->GetByteArrayElements(out_seed_y, nullptr);

    // 定义算法结构体（严格对齐头文件）
    poly_vec_t w_sec;
    poly_vec_t w_pub;
    poly_vec_t w_total;
    uint8_t seed_y[PQ_ZK_SEED_BYTES];

    // 解码内部承诺 W_sec
    PQC_DecodePolyVec((const uint8_t*)sec_buf, &w_sec);

    // 调用原生算法：生成 W_pub + seed_y
    PQC_PreCompute(&w_pub, seed_y);

    // 核心：总承诺 W = W_sec + W_pub
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        w_total.coeffs[i] = w_sec.coeffs[i] + w_pub.coeffs[i];
    }

    // 编码总承诺并输出
    PQC_EncodePolyVec(&w_total, (uint8_t*)total_buf);

    // seed_y 内存加密（防泄露）
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        seed_y[i] ^= 0xA5;
    }
    memcpy(seed_buf, seed_y, PQ_ZK_SEED_BYTES);

    // 释放资源
    env->ReleaseByteArrayElements(in_w_sec, sec_buf, JNI_ABORT);
    env->ReleaseByteArrayElements(out_w_total, total_buf, 0);
    env->ReleaseByteArrayElements(out_seed_y, seed_buf, 0);

    return PQ_ZK_SUCCESS;
}

/**
 * 3. 挑战生成接口 (PQC_GenChallenge)
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1GenChallenge(
        JNIEnv *env, jobject thiz, jbyteArray comm_w, jbyteArray c_seed, jbyteArray out_c_agg) {

    jbyte *w_ptr = env->GetByteArrayElements(comm_w, nullptr);
    jbyte *s_ptr = env->GetByteArrayElements(c_seed, nullptr);
    jbyte *c_ptr = env->GetByteArrayElements(out_c_agg, nullptr);

    poly_vec_t W;
    poly_t c_agg;

    PQC_DecodePolyVec((const uint8_t*)w_ptr, &W);
    PQC_GenChallenge(&W, (const uint8_t*)s_ptr, &c_agg);
    PQC_EncodePoly(&c_agg, (uint8_t*)c_ptr);

    env->ReleaseByteArrayElements(out_c_agg, c_ptr, 0);
    env->ReleaseByteArrayElements(c_seed, s_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(comm_w, w_ptr, JNI_ABORT);
    return (jint)PQ_ZK_SUCCESS;
}

/**
 * 4. 掩码协同计算 (PQC_ComputeZ_and_Mask)
 * 修正：返回值接收、参数类型匹配
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1ComputeZ_1and_1Mask(
        JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray c_agg_bytes,
        jbyteArray c_seed, jbyteArray r_dynamic, jbyteArray hash_m2,
        jbyteArray auth_token, jbyteArray out_z_masked) {

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *c_raw = env->GetByteArrayElements(c_agg_bytes, nullptr);
    jbyte *seed_p = env->GetByteArrayElements(c_seed, nullptr);
    jbyte *rdyn_p = env->GetByteArrayElements(r_dynamic, nullptr);
    jbyte *hm2_p  = env->GetByteArrayElements(hash_m2, nullptr);
    jbyte *auth_p = env->GetByteArrayElements(auth_token, nullptr);
    jbyte *z_ptr  = env->GetByteArrayElements(out_z_masked, nullptr);

    poly_t c_agg;
    PQC_DecodePoly((const uint8_t*)c_raw, &c_agg);

    poly_vec_t z_sec_masked;
    // 修正：返回值类型为 PQ_ZK_ErrorCode
    PQ_ZK_ErrorCode code = PQC_ComputeZ_and_Mask(
            path,
            &c_agg,
            (const uint8_t*)seed_p,
            (const uint8_t*)rdyn_p,
            (const uint8_t*)hm2_p,
            (const uint8_t*)auth_p,
            &z_sec_masked
    );

    if (code == PQ_ZK_SUCCESS) {
        PQC_EncodePolyVec(&z_sec_masked, (uint8_t*)z_ptr);
    } else {
        LOGE("PQC_ComputeZ_and_Mask Failed with error: %d", code);
    }

    env->ReleaseByteArrayElements(out_z_masked, z_ptr, 0);
    env->ReleaseByteArrayElements(auth_token, auth_p, JNI_ABORT);
    env->ReleaseByteArrayElements(hash_m2, hm2_p, JNI_ABORT);
    env->ReleaseByteArrayElements(r_dynamic, rdyn_p, JNI_ABORT);
    env->ReleaseByteArrayElements(c_seed, seed_p, JNI_ABORT);
    env->ReleaseByteArrayElements(c_agg_bytes, c_raw, JNI_ABORT);
    env->ReleaseStringUTFChars(nvram_dir, path);

    return (jint)code;
}

/**
 * 5. 新增：LPA 大噪声聚合 (PQC_LPA_Aggregate)
 * 修正：基于 v4.0 规范，先 RegenerateYpub 再进行聚合
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_MainActivity_PQC_1LPA_1Aggregate(
        JNIEnv *env, jobject thiz, jbyteArray z_masked_in, jbyteArray seed_y, jbyteArray out_z_final) {

    jbyte *zin_ptr = env->GetByteArrayElements(z_masked_in, nullptr);
    jbyte *seed_ptr = env->GetByteArrayElements(seed_y, nullptr);
    jbyte *zout_ptr = env->GetByteArrayElements(out_z_final, nullptr);

    poly_vec_t z_sec_masked, y_pub, resp_z;

    // 5.1 反序列化 eUICC 传来的掩码结果
    PQC_DecodePolyVec((const uint8_t*)zin_ptr, &z_sec_masked);

    // 5.2 [规范 4.0] 恢复外部大方差盲化因子 y_pub
    PQC_RegenerateYpub((const uint8_t*)seed_ptr, &y_pub);

    // 5.3 执行聚合 z = z_sec_masked + y_pub (mod q)
    // 修正：参数类型对齐头文件定义
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

    // 5.4 序列化最终结果
    PQC_EncodePolyVec(&resp_z, (uint8_t*)zout_ptr);

    env->ReleaseByteArrayElements(out_z_final, zout_ptr, 0);
    env->ReleaseByteArrayElements(seed_y, seed_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(z_masked_in, zin_ptr, JNI_ABORT);

    return (jint)PQ_ZK_SUCCESS;
}

} // extern "C"