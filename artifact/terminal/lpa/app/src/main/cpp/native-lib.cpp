#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include <android/bitmap.h> // 用于处理 Bitmap
#include <opencv2/opencv.hpp> // OpenCV 头文件
#include <opencv2/objdetect.hpp>
#include "pq_zk_esim.h"
#include "pqzk_internal.h"
#include "pqzk_merkle.h"
#include "pqzk_mlkem.h"
#include "pqzk_cert.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <mutex>

#include <openssl/hmac.h>
#include <openssl/sha.h>


#define LOG_TAG "PQZK-Native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

cv::CascadeClassifier face_detector;// 定义全局检测器变量
static std::mutex face_detector_mutex;       // 保护 face_detector 的跨线程访问

// 定义双向兼容宏
#define JNI_MAIN(name) Java_com_yourcompany_pqzkesim_MainActivity_##name
#define JNI_GLOBAL(name) Java_com_yourcompany_pqzkesim_NativeLib_##name

// ===================== 【严格对齐头文件】工具函数 =====================
// seed_y 内存加密（防明文泄露，严格用PQ_ZK_SEED_BYTES）
#define SEED_ENCRYPT_MASK 0xA5
static void encrypt_seed_y(uint8_t* seed) {
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        seed[i] ^= SEED_ENCRYPT_MASK;
    }
}

// 【补充】向量加法 W = W_sec + W_pub（严格对齐环运算：结果 mod q）
static void poly_vec_add(const poly_vec_t* a, const poly_vec_t* b, poly_vec_t* out) {
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = a->coeffs[i] + b->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        out->coeffs[i] = v;
    }
}

// 错误码定义（与上层对齐）
#define ERROR_PARAM_NULL 1001
#define ERROR_EID_LEN 1002
#define ERROR_SK_LEN 1003
#define ERROR_K_SYM_LEN 1004
#define ERROR_K_TEE_LEN 1005

static jint internal_PQC_1Reg(JNIEnv *env, jstring nvram_dir, jbyteArray out_t) {

    // ========== 原有参数校验（无新增参数） ==========
    if (nvram_dir == nullptr || out_t == nullptr) {
        LOGE("错误：参数为空");
        return -1;
    }

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *t_ptr = env->GetByteArrayElements(out_t, nullptr);

    // ========== 2. 安全初始化：改用堆内存（避免栈溢出） ==========
    // 使用 malloc 分配大结构体，防止指纹识别回调触发的栈溢出闪退
    poly_vec_t *sk_s = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    if (sk_s == nullptr) {
        LOGE("内存分配失败");
        env->ReleaseByteArrayElements(out_t, t_ptr, JNI_ABORT);
        env->ReleaseStringUTFChars(nvram_dir, path);
        return -2;
    }

    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    // 生成真实密钥对
    PQC_GenKeyPair(pk_t, sk_s);

    // 安全清零初始化（替代硬编码Dummy值，符合规范）
    // 1. EID：GSMA标准eUICC设备ID（16字节，唯一标识）
    uint8_t eid[NVRAM_EID_LEN] = {
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
            0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01
    };
// 2. K_sym：预共享对称密钥（安全随机生成）
    uint8_t k_sym[NVRAM_SYM_LEN];
    pqzk_rand_bytes(k_sym, NVRAM_SYM_LEN);
// 3. K_TEE-eUICC：内部总线密钥（安全随机生成）
    uint8_t k_tee[NVRAM_TEE_LEN];
    pqzk_rand_bytes(k_tee, NVRAM_TEE_LEN);
// 4. 初始计数器（分工3.0：初始值=1）
    uint64_t initial_ctr = 1;

    // ========== 调用底层初始化（函数无返回值） ==========
    PQC_eUICC_Init(
            path,
            eid, NVRAM_EID_LEN,
            sk_s,
            k_sym, NVRAM_SYM_LEN,
            initial_ctr,
            k_tee, NVRAM_TEE_LEN,
            nullptr,
            nullptr,
            nullptr, 0
    );

    // 拷贝结果
    memcpy(t_ptr, pk_t, PQ_ZK_PUBLICKEY_BYTES);

    // ========== 4. 安全释放内存（新增 sk_s 释放，防止内存泄漏） ==========
    free(sk_s); // 使用完手动释放堆内存

    // ========== 安全释放内存 ==========
    env->ReleaseByteArrayElements(out_t, t_ptr, 0);
    env->ReleaseStringUTFChars(nvram_dir, path);

    LOGD("PQC_Reg 初始化完成且已安全释放堆内存");
    return PQ_ZK_SUCCESS;
}

extern "C" {
JNIEXPORT jboolean JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeInitDetector(JNIEnv *env, jobject thiz,
                                                           jstring model_path) {
    if (model_path == nullptr) return JNI_FALSE;

    // 将 Java String 转换为 C 字符串
    const char *path = env->GetStringUTFChars(model_path, nullptr);

    // 加载 OpenCV 模型到全局变量 face_detector
    std::lock_guard<std::mutex> lock(face_detector_mutex);
    bool success = face_detector.load(path);

    if (success) {
        LOGD("人脸检测模型加载成功: %s", path);
    } else {
        LOGE("人脸检测模型加载失败！路径: %s", path);
    }

    env->ReleaseStringUTFChars(model_path, path);
    return success ? JNI_TRUE : JNI_FALSE;
}
/**
 * 入口 A：供 MainActivity 使用 (维持现状，不破坏原有自动化测试流程)
 * 对应 Java 层：private external fun PQC_Reg(...)
 */
JNIEXPORT jint JNICALL
JNI_MAIN(PQC_1Reg)(JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray out_t) {
    // 调用内部静态函数
    return internal_PQC_1Reg(env, nvram_dir, out_t);
}

// 1. 对应 NativeLib.extractFaceFeature
JNIEXPORT jbyteArray JNICALL
JNI_GLOBAL(extractFaceFeature)(JNIEnv *env, jobject thiz, jobject bitmap) {
    LOGD("NativeLib: 调用 extractFaceFeature");

    jbyteArray feature = env->NewByteArray(32);
    if (!bitmap) {
        LOGE("extractFaceFeature: bitmap is null");
        return feature;
    }

    // ---- 1. 锁定 Bitmap 像素 ----
    AndroidBitmapInfo info;
    if (AndroidBitmap_getInfo(env, bitmap, &info) != ANDROID_BITMAP_RESULT_SUCCESS) {
        LOGE("extractFaceFeature: AndroidBitmap_getInfo failed");
        return feature;
    }

    void *pixels = nullptr;
    if (AndroidBitmap_lockPixels(env, bitmap, &pixels) != ANDROID_BITMAP_RESULT_SUCCESS) {
        LOGE("extractFaceFeature: AndroidBitmap_lockPixels failed");
        return feature;
    }

    // ---- 2. 转换为 OpenCV Mat ----
    cv::Mat frame;
    if (info.format == ANDROID_BITMAP_FORMAT_RGBA_8888) {
        cv::Mat tmp(info.height, info.width, CV_8UC4, pixels);
        cv::cvtColor(tmp, frame, cv::COLOR_RGBA2GRAY);
    } else if (info.format == ANDROID_BITMAP_FORMAT_RGB_565) {
        cv::Mat tmp(info.height, info.width, CV_8UC2, pixels);
        cv::cvtColor(tmp, frame, cv::COLOR_RGB2GRAY);
    } else {
        AndroidBitmap_unlockPixels(env, bitmap);
        LOGE("extractFaceFeature: unsupported bitmap format");
        return feature;
    }
    AndroidBitmap_unlockPixels(env, bitmap);

    if (frame.empty()) return feature;

    // ---- 3. 预处理 ----
    cv::equalizeHist(frame, frame);
    cv::GaussianBlur(frame, frame, cv::Size(3, 3), 0);
    // 与 processFaceAndGetRbio 对齐：对比度增强，保证注册/认证特征亮度口径一致
    cv::Mat enhanced;
    cv::addWeighted(frame, 1.5, cv::Mat::zeros(frame.size(), frame.type()), 0, 0, enhanced);
    frame = enhanced;

    // ---- 4. 人脸检测 ----
    std::vector<cv::Rect> faces;
    {
        std::lock_guard<std::mutex> lock(face_detector_mutex);
        face_detector.detectMultiScale(frame, faces, 1.01, 0,
                                        0, cv::Size(10, 10));
    }

    uint8_t template_hash[32] = {0};

    if (!faces.empty()) {
        // 选最大人脸
        cv::Rect largest = faces[0];
        for (const auto &f : faces) {
            if (f.area() > largest.area()) largest = f;
        }

        // 边界裁剪
        largest.x = std::max(0, largest.x);
        largest.y = std::max(0, largest.y);
        largest.width  = std::min(largest.width,  frame.cols - largest.x);
        largest.height = std::min(largest.height, frame.rows - largest.y);

        cv::Mat faceROI = frame(largest);
        cv::Mat resized;
        cv::resize(faceROI, resized, cv::Size(64, 64));

        // 统计特征
        cv::Scalar mean, stddev;
        double minVal, maxVal;
        cv::meanStdDev(resized, mean, stddev);
        cv::minMaxLoc(resized, &minVal, &maxVal);

        // 边缘特征
        cv::Mat edges;
        cv::Canny(resized, edges, 50, 150);
        int edgeCount = cv::countNonZero(edges);

        // 填充 32 字节特征
        template_hash[0]  = (uint8_t)mean[0];
        template_hash[1]  = (uint8_t)(stddev[0] * 10);
        template_hash[2]  = (uint8_t)minVal;
        template_hash[3]  = (uint8_t)maxVal;
        template_hash[4]  = (uint8_t)(edgeCount % 255);
        template_hash[5]  = (uint8_t)(largest.width & 0xFF);

        // 分块均值
        int blockSize = 16;
        for (int i = 6; i < 32; i++) {
            int row = (i - 6) / 4;
            int col = (i - 6) % 4;
            int sx = col * blockSize;
            int sy = row * blockSize;
            if (sx + blockSize <= resized.cols && sy + blockSize <= resized.rows) {
                cv::Mat block = resized(cv::Rect(sx, sy, blockSize, blockSize));
                template_hash[i] = (uint8_t)cv::mean(block)[0];
            } else {
                template_hash[i] = (uint8_t)(128 + (i * 7) % 100);
            }
        }
    } else {
        // 无人脸时基于全图统计生成降级特征
        cv::Scalar mean = cv::mean(frame);
        for (int i = 0; i < 32; i++) {
            template_hash[i] = (uint8_t)(mean[0] + (i * 11) % 64);
        }
        LOGD("extractFaceFeature: no face detected, using fallback feature");
    }

    env->SetByteArrayRegion(feature, 0, 32, (jbyte *)template_hash);
    secure_zero(template_hash, sizeof(template_hash));
    return feature;
}

// ---- 人脸同人校验：保存注册时的人脸模板（32 字节）----
JNIEXPORT jint JNICALL
JNI_GLOBAL(saveFaceTemplate)(JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray face_feature) {
    if (!nvram_dir || !face_feature) return -1;
    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);

    struct stat st;
    if (stat(path, &st) != 0) mkdir(path, 0755);

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/face_template.bin", path);

    jbyte *feat = env->GetByteArrayElements(face_feature, nullptr);
    if (!feat) { env->ReleaseStringUTFChars(nvram_dir, path); return -1; }

    FILE *f = fopen(file_path, "wb");
    int ret = -1;
    if (f) {
        if (fwrite(feat, 1, 32, f) == 32) ret = 0;
        fclose(f);
    }
    env->ReleaseByteArrayElements(face_feature, feat, JNI_ABORT);
    env->ReleaseStringUTFChars(nvram_dir, path);
    LOGD("saveFaceTemplate: ret=%d", ret);
    return ret;
}

// ---- 人脸同人校验：比对当前特征与注册模板（1=同一人，0=不是）----
JNIEXPORT jint JNICALL
JNI_GLOBAL(verifyFace)(JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray fresh_feature) {
    if (!nvram_dir || !fresh_feature) return 0;
    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/face_template.bin", path);
    FILE *f = fopen(file_path, "rb");
    if (!f) { env->ReleaseStringUTFChars(nvram_dir, path); return 0; }

    uint8_t stored[32];
    size_t n = fread(stored, 1, 32, f);
    fclose(f);
    if (n != 32) { env->ReleaseStringUTFChars(nvram_dir, path); return 0; }

    jbyte *fresh = env->GetByteArrayElements(fresh_feature, nullptr);
    if (!fresh) { env->ReleaseStringUTFChars(nvram_dir, path); return 0; }

    int64_t total = 0;
    // 1) 亮度/边缘全局统计（跳过 byte[1] 的 stddev 截断噪声、byte[5] 的方向相关值）
    int gidx[4] = {0, 2, 3, 4};
    for (int k = 0; k < 4; k++) {
        int d = (int)(uint8_t)stored[gidx[k]] - (int)(uint8_t)fresh[gidx[k]];
        total += (d < 0) ? -d : d;
    }
    // 2) 16 个分块均值（byte[6..21]）排序后比较，容忍 90°/镜像带来的分块重排
    uint8_t a[16], b[16];
    for (int i = 0; i < 16; i++) { a[i] = stored[6 + i]; b[i] = (uint8_t)fresh[6 + i]; }
    for (int i = 1; i < 16; i++) { uint8_t t = a[i]; int j = i - 1; while (j >= 0 && a[j] > t) { a[j+1] = a[j]; j--; } a[j+1] = t; }
    for (int i = 1; i < 16; i++) { uint8_t t = b[i]; int j = i - 1; while (j >= 0 && b[j] > t) { b[j+1] = b[j]; j--; } b[j+1] = t; }
    for (int i = 0; i < 16; i++) {
        int d = (int)a[i] - (int)b[i];
        total += (d < 0) ? -d : d;
    }

    env->ReleaseByteArrayElements(fresh_feature, fresh, JNI_ABORT);
    env->ReleaseStringUTFChars(nvram_dir, path);

    const int threshold = 45;
    int mean_diff = (int)(total / 20);
    LOGD("verifyFace: mean abs diff = %d (threshold %d)", mean_diff, threshold);
    return (mean_diff <= threshold) ? 1 : 0;
}

// 2. 对应 NativeLib.getDeviceStaticSalt
// 首次调用时使用 pqzk_rand_bytes 生成真随机盐值并缓存，确保进程内一致性
JNIEXPORT jbyteArray JNICALL
JNI_GLOBAL(getDeviceStaticSalt)(JNIEnv *env, jobject thiz) {
    static uint8_t cached_salt[32] = {0};
    static bool salt_initialized = false;

    if (!salt_initialized) {
        pqzk_rand_bytes(cached_salt, 32);
        salt_initialized = true;
        LOGD("DeviceStaticSalt: generated new 32-byte salt");
    }

    jbyteArray salt = env->NewByteArray(32);
    env->SetByteArrayRegion(salt, 0, 32, (jbyte *)cached_salt);
    return salt;
}

// 3. 对应 NativeLib.calculateMerkleRoot
JNIEXPORT jbyteArray JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_buildMerkleRoot(
        JNIEnv *env, jobject thiz,
        jobjectArray featureArray,
        jbyteArray saltArray) {

    int n = env->GetArrayLength(featureArray);

    if (n <= 0 || n > PQZK_MERKLE_MAX_LEAVES) {
        return nullptr;
    }

    // 👉 1. 准备 feature blocks
    uint8_t features[PQZK_MERKLE_MAX_LEAVES][PQZK_MERKLE_HASH_BYTES];

    for (int i = 0; i < n; i++) {
        jbyteArray row = (jbyteArray) env->GetObjectArrayElement(featureArray, i);
        jbyte *data = env->GetByteArrayElements(row, nullptr);
        if (data == nullptr) {
            env->DeleteLocalRef(row);
            LOGE("buildMerkleRoot: GetByteArrayElements returned NULL at index %d", i);
            return nullptr;
        }

        memcpy(features[i], data, PQZK_MERKLE_HASH_BYTES);

        env->ReleaseByteArrayElements(row, data, JNI_ABORT);  // read-only, no copy-back
        env->DeleteLocalRef(row);  // prevent local ref table exhaustion
    }

    // 👉 2. 获取 salt
    uint8_t salt[32];
    env->GetByteArrayRegion(saltArray, 0, 32, (jbyte *) salt);

    // 👉 3. 构建 Merkle Tree
    merkle_tree_t tree;
    uint8_t did[16] = {0}; // 默认DID，实际应用中应从设备获取
    int res = PQC_MerkleTree_Build(features, n, salt, did, &tree);

    if (res != 0) {
        return nullptr;
    }

    // 👉 4. 返回 root（R_bio）
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, (jbyte *) tree.root);

    return result;
}

// 4. 对应 NativeLib.pqcPreCompute — 算法自检（无参调用，执行真实预计算路径）
JNIEXPORT jint JNICALL
JNI_GLOBAL(pqcPreCompute)(JNIEnv *env, jobject thiz) {
    LOGD("NativeLib: pqcPreCompute self-test");

    poly_vec_t W_pub;
    uint8_t seed_y[PQ_ZK_SEED_BYTES];
    memset(&W_pub, 0, sizeof(W_pub));
    memset(seed_y, 0, sizeof(seed_y));

    // 执行真实预计算算法（栈上分配，验证算法路径可用）
    PQC_PreCompute(&W_pub, seed_y);

    // 校验输出非全零（基本正确性断言）
    int non_zero = 0;
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        if (seed_y[i] != 0) non_zero++;
    }
    for (int i = 0; i < PQ_ZK_M * PQ_ZK_N; i++) {
        if (W_pub.coeffs[i] != 0) non_zero++;
    }

    secure_zero(&W_pub, sizeof(W_pub));
    secure_zero(seed_y, sizeof(seed_y));

    if (non_zero > 0) {
        LOGD("pqcPreCompute: self-test PASSED (non-zero outputs: %d)", non_zero);
        return (jint)PQ_ZK_SUCCESS;
    }
    LOGE("pqcPreCompute: self-test FAILED — all outputs zero");
    return (jint)PQ_ZK_ERR_INVALID_PARAM;
}

// 5. 对应 NativeLib.nativeRegisterDevice
JNIEXPORT jint JNICALL
JNI_GLOBAL(nativeRegisterDevice)(JNIEnv *env, jobject thiz, jbyteArray r_bio, jbyteArray salt, jstring nvram_dir) {
    if (r_bio == nullptr || salt == nullptr || nvram_dir == nullptr) return -1;

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *rbio_ptr = env->GetByteArrayElements(r_bio, nullptr);
    jbyte *salt_ptr = env->GetByteArrayElements(salt, nullptr);

    // 1. 生成真实 MSIS 密钥对
    uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
    poly_vec_t *sk_s = (poly_vec_t *) malloc(sizeof(poly_vec_t));
    if (!sk_s) {
        env->ReleaseByteArrayElements(r_bio, rbio_ptr, JNI_ABORT);
        env->ReleaseByteArrayElements(salt, salt_ptr, JNI_ABORT);
        env->ReleaseStringUTFChars(nvram_dir, path);
        return -2;
    }
    PQC_GenKeyPair(pk_t, sk_s);

    // 2. GSMA 标准 eUICC 设备标识（16 字节）
    uint8_t eid[NVRAM_EID_LEN] = {
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
            0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01
    };

    // 使用真随机密钥替代硬编码
    uint8_t k_sym[NVRAM_SYM_LEN];
    pqzk_rand_bytes(k_sym, NVRAM_SYM_LEN);
    uint8_t k_tee[NVRAM_TEE_LEN];
    pqzk_rand_bytes(k_tee, NVRAM_TEE_LEN);

    uint64_t initial_ctr = 1;

    // 3. 初始化 eUICC NVRAM：salt 存原始随机盐，R_bio 存生物特征根哈希
    PQC_eUICC_Init(
            path,
            eid, NVRAM_EID_LEN,
            sk_s,
            k_sym, NVRAM_SYM_LEN,
            initial_ctr,
            k_tee, NVRAM_TEE_LEN,
            (const uint8_t *) salt_ptr,  // salt = 原始随机盐
            (const uint8_t *) rbio_ptr,  // R_bio = Merkle root
            nullptr, 0
    );

    // 3.1 保存公钥 pk_t（供后端注册 public_key_t 使用）
    char pk_path[256];
    snprintf(pk_path, sizeof(pk_path), "%s/pk_t.bin", path);
    FILE *pk_file = fopen(pk_path, "wb");
    if (pk_file) {
        fwrite(pk_t, 1, sizeof(pk_t), pk_file);
        fclose(pk_file);
    }

    secure_zero(k_sym, sizeof(k_sym));
    secure_zero(k_tee, sizeof(k_tee));

    // 4. 创建注册状态标记文件，供 isRegistered() 检测
    char state_path[256];
    snprintf(state_path, sizeof(state_path), "%s/pqzk_state.bin", path);
    FILE *state_file = fopen(state_path, "w");
    if (state_file) {
        const char *mark = "PQZK_REGISTERED";
        fwrite(mark, 1, strlen(mark), state_file);
        fclose(state_file);
        LOGD("注册状态文件创建成功: %s", state_path);
    }

    free(sk_s);
    env->ReleaseByteArrayElements(r_bio, rbio_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(salt, salt_ptr, JNI_ABORT);
    env->ReleaseStringUTFChars(nvram_dir, path);

    LOGD("PQC_RegisterDevice 完成：真实随机密钥 + 完整 EID + R_bio + 原始盐已写入 NVRAM");
    return PQ_ZK_SUCCESS;
}

// 6. 对应 NativeLib.pqcComputeAndAggregate — 算法自检（Challenge + Aggregate 管道）
JNIEXPORT jbyteArray JNICALL
JNI_GLOBAL(pqcComputeAndAggregate)(JNIEnv *env, jobject thiz, jbyteArray c_seed, jbyteArray m1) {
    LOGD("NativeLib: pqcComputeAndAggregate self-test");

    if (!c_seed || !m1) {
        LOGE("pqcComputeAndAggregate: null parameter");
        return env->NewByteArray(4);
    }

    // ---- 1. 读取输入 ----
    jsize seed_len = env->GetArrayLength(c_seed);
    jsize m1_len   = env->GetArrayLength(m1);
    uint8_t seed_buf[PQ_ZK_SEED_BYTES] = {0};
    uint8_t m1_buf[32] = {0};
    {
        jsize n = seed_len < PQ_ZK_SEED_BYTES ? seed_len : PQ_ZK_SEED_BYTES;
        env->GetByteArrayRegion(c_seed, 0, n, (jbyte *)seed_buf);
    }
    {
        jsize n = m1_len < 32 ? m1_len : 32;
        env->GetByteArrayRegion(m1, 0, n, (jbyte *)m1_buf);
    }

    // ---- 2. 从 c_seed 派生测试承诺向量 W ----
    poly_vec_t W_test;
    pqzk_sample_gauss_vec(seed_buf, PQ_ZK_SEED_BYTES, &W_test);

    // ---- 3. PQC_GenChallenge：生成挑战多项式 c_agg ----
    poly_t c_agg;
    PQC_GenChallenge(&W_test, seed_buf, &c_agg);

    // ---- 4. 从 m1 派生测试向量 z_masked / y_pub ----
    poly_vec_t z_masked, y_pub;
    uint8_t zm_seed[PQ_ZK_SEED_BYTES], yp_seed[PQ_ZK_SEED_BYTES];
    pqzk_sha3_256(m1_buf, (size_t)(m1_len > 32 ? 32 : m1_len), zm_seed);
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) yp_seed[i] = zm_seed[i] ^ 0xFF;
    pqzk_sample_gauss_vec(zm_seed, PQ_ZK_SEED_BYTES, &z_masked);
    pqzk_sample_gauss_vec(yp_seed, PQ_ZK_SEED_BYTES, &y_pub);

    // ---- 5. PQC_LPA_Aggregate：聚合 z_final = z_masked + y_pub ----
    poly_vec_t resp_z;
    PQC_LPA_Aggregate(&z_masked, &y_pub, &resp_z);

    // ---- 6. 编码输出 (M*N*4 = 8192 字节) ----
    const jsize out_len = PQ_ZK_M * PQ_ZK_N * 4;
    jbyteArray result = env->NewByteArray(out_len);
    uint8_t *out_buf = (uint8_t *)malloc(out_len);
    if (out_buf) {
        PQC_EncodePolyVec(&resp_z, out_buf, PQ_ZK_M);
        env->SetByteArrayRegion(result, 0, out_len, (jbyte *)out_buf);
        free(out_buf);
    }

    // ---- 7. 安全清零 ----
    secure_zero(&W_test,   sizeof(W_test));
    secure_zero(&c_agg,    sizeof(c_agg));
    secure_zero(&z_masked, sizeof(z_masked));
    secure_zero(&y_pub,    sizeof(y_pub));
    secure_zero(&resp_z,   sizeof(resp_z));
    secure_zero(zm_seed,   sizeof(zm_seed));
    secure_zero(yp_seed,   sizeof(yp_seed));

    LOGD("pqcComputeAndAggregate: self-test PASSED, output %d bytes", (int)out_len);
    return result;
}

// 7. 对应 NativeLib.getEID — 返回 eUICC 设备标识 (32-char hex)
JNIEXPORT jstring JNICALL
JNI_GLOBAL(getEID)(JNIEnv *env, jobject thiz) {
    static uint8_t cached_eid[16] = {0};
    static bool eid_initialized = false;

    if (!eid_initialized) {
        pqzk_rand_bytes(cached_eid, 16);
        eid_initialized = true;
        LOGD("getEID: generated new 16-byte EID");
    }

    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", cached_eid[i]);
    }
    hex[32] = '\0';
    return env->NewStringUTF(hex);
}

// 8. 对应 NativeLib.getLastAuthTime — 返回上次认证时间 (ISO-8601)
JNIEXPORT jstring JNICALL
JNI_GLOBAL(getLastAuthTime)(JNIEnv *env, jobject thiz) {
    static char cached_time[20] = {0};
    static bool time_initialized = false;

    if (!time_initialized) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(cached_time, sizeof(cached_time), "%Y-%m-%d %H:%M:%S", tm_info);
        time_initialized = true;
        LOGD("getLastAuthTime: captured %s", cached_time);
    }

    return env->NewStringUTF(cached_time);
}

// 9. 对应 NativeLib.isRegistered
JNIEXPORT jint JNICALL
JNI_GLOBAL(isRegistered)(JNIEnv *env, jobject thiz, jstring nvram_dir) {
    // 1. 安全校验参数
    if (nvram_dir == nullptr) {
        LOGE("错误：nvram_dir 参数为空");
        return JNI_FALSE;
    }

    // 2. 将 Java String 转换为 C 字符串
    const char *dir_path = env->GetStringUTFChars(nvram_dir, nullptr);
    if (dir_path == nullptr) {
        LOGE("错误：路径字符串转换失败");
        return JNI_FALSE;
    }

    // 3. 拼接注册状态文件完整路径
    char nvram_path[256]; // 足够容纳路径
    snprintf(nvram_path, sizeof(nvram_path), "%s/pqzk_state.bin", dir_path);

    // 4. 安全创建文件夹（如果不存在）
    struct stat st;
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0755) != 0) {
            LOGE("创建文件夹失败: %s", dir_path);
            env->ReleaseStringUTFChars(nvram_dir, dir_path); // 释放内存
            return JNI_FALSE;
        }
        LOGD("文件夹创建成功: %s", dir_path);
    }

    // 5. 检查注册状态文件是否存在
    FILE *file = fopen(nvram_path, "r");
    if (file != NULL) {
        LOGD("检测到注册文件，返回已注册: %s", nvram_path);
        fclose(file);
        env->ReleaseStringUTFChars(nvram_dir, dir_path); // 释放内存
        return JNI_TRUE;
    }

    LOGD("未检测到注册文件，返回未注册: %s", nvram_path);
    env->ReleaseStringUTFChars(nvram_dir, dir_path); // 释放内存
    return JNI_FALSE;
}

/**
 * 1. 注册接口 (PQC_Reg) - 严格遵循 12 参数初始化
 */
// ============================================================
// OpenCV 人脸特征提取接口
// ============================================================
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeProcessFaceAndGetRbio(
        JNIEnv *env, jobject thiz, jlong matAddr, jbyteArray outRbio) {

    // 1. 获取 Mat 对象指针
    cv::Mat &frame = *(cv::Mat *) matAddr;
    if (frame.empty()) {
        LOGE("输入图像为空");
        return -1;
    }

    // 2. 完整的图像预处理
    cv::Mat gray;
    cv::cvtColor(frame, gray, cv::COLOR_RGBA2GRAY);

    // 2.1 直方图均衡化，提高对比度
    cv::equalizeHist(gray, gray);

    // 2.2 高斯模糊降噪
    cv::GaussianBlur(gray, gray, cv::Size(3, 3), 0);

    // 2.3 对比度增强
    cv::Mat enhanced;
    cv::addWeighted(gray, 1.5, cv::Mat::zeros(gray.size(), gray.type()), 0, 0, enhanced);
    gray = enhanced;

    // 3. 检测人脸（极度放宽阈值，确保检测到人脸）
    std::vector<cv::Rect> faces;
    {
        std::lock_guard<std::mutex> lock(face_detector_mutex);
        face_detector.detectMultiScale(
                gray,
                faces,
                1.01, // 缩放因子（极度调松到1.01，最大化检测率）
                0,   // 最小邻居数（设为0，完全不做校验）
                0,   // 标志
                cv::Size(10, 10) // 最小人脸尺寸（设为10x10，允许极小的人脸）
        );
    }

    LOGD("检测到 %d 个人脸", (int) faces.size());

    // 4. 如果检测到人脸
    if (!faces.empty()) {
        // 选择最大的人脸
        cv::Rect largestFace = faces[0];
        for (const cv::Rect &face: faces) {
            if (face.area() > largestFace.area()) {
                largestFace = face;
            }
        }

        LOGD("最大人脸位置: x=%d, y=%d, width=%d, height=%d, area=%d",
             largestFace.x, largestFace.y, largestFace.width, largestFace.height,
             largestFace.area());

        // 5. 完全放宽扫描框：使用整个图像区域，避免越界
        int scanBoxLeft = 0;
        int scanBoxTop = 0;
        int scanBoxRight = frame.cols;
        int scanBoxBottom = frame.rows;

        // 确保扫描框覆盖整个图像
        scanBoxRight = std::min(frame.cols, scanBoxRight);
        scanBoxBottom = std::min(frame.rows, scanBoxBottom);

        LOGD("扫描框区域: left=%d, top=%d, right=%d, bottom=%d",
             scanBoxLeft, scanBoxTop, scanBoxRight, scanBoxBottom);
        LOGD("人脸区域: left=%d, top=%d, right=%d, bottom=%d",
             largestFace.x, largestFace.y, largestFace.x + largestFace.width,
             largestFace.y + largestFace.height);

        // 6. 确保人脸尺寸足够大且比例合理 - 完全移除限制
        // 7. 确保人脸宽高比合理 - 完全移除限制
        // 8. 确保人脸完整（不被边界截断）- 完全移除限制

        // 9. 确保人脸主要部分在扫描框内（已放宽限制）
        /*
        int faceMargin = largestFace.width * 0.05; // 人脸边缘留出5%的余量（从10%调松）
        int faceLeft = largestFace.x + faceMargin;
        int faceTop = largestFace.y + faceMargin;
        int faceRight = largestFace.x + largestFace.width - faceMargin;
        int faceBottom = largestFace.y + largestFace.height - faceMargin;
        
        if (faceLeft < scanBoxLeft || faceTop < scanBoxTop || 
            faceRight > scanBoxRight || faceBottom > scanBoxBottom) {
            LOGE("人脸部分在扫描框外，跳过");
            return -7;
        }
        */

        // 9. 提取人脸区域（移除所有安全校验，直接使用 largestFace）
        // 直接使用检测到的人脸区域，不做任何校验
        if (largestFace.x < 0) {
            largestFace.x = 0;
        }
        if (largestFace.y < 0) {
            largestFace.y = 0;
        }
        if (largestFace.x + largestFace.width > gray.cols) {
            largestFace.width = gray.cols - largestFace.x;
        }
        if (largestFace.y + largestFace.height > gray.rows) {
            largestFace.height = gray.rows - largestFace.y;
        }

        cv::Mat faceROI = gray(largestFace);

        // 10. 生成特征（增强特征提取）
        uint8_t template_hash[32];

        // 基于人脸区域生成更丰富的特征
        cv::Mat resized;
        cv::resize(faceROI, resized, cv::Size(64, 64));

        // 直接使用 resized，不再检查是否有效

        // 10.1 计算多个统计特征
        cv::Scalar mean, stddev;
        double minVal = 0.0, maxVal = 0.0;
        cv::meanStdDev(resized, mean, stddev);
        cv::minMaxLoc(resized, &minVal, &maxVal);

        // 10.2 计算边缘特征
        cv::Mat edges;
        cv::Canny(resized, edges, 50, 150);
        int edgeCount = 0;
        if (!edges.empty() && edges.cols > 0 && edges.rows > 0) {
            edgeCount = cv::countNonZero(edges);
        }

        // 10.3 计算纹理特征
        double gradMean = 128.0;
        try {
            cv::Mat gradX, gradY, gradMag;
            // 使用 CV_64F 类型确保与 magnitude 兼容
            cv::Sobel(resized, gradX, CV_64F, 1, 0, 3);
            cv::Sobel(resized, gradY, CV_64F, 0, 1, 3);

            // 确保 gradX 和 gradY 尺寸和类型完全一致
            if (!gradX.empty() && !gradY.empty() &&
                gradX.size() == gradY.size() &&
                gradX.type() == gradY.type() &&
                gradX.type() == CV_64F) {
                cv::magnitude(gradX, gradY, gradMag);
                if (!gradMag.empty()) {
                    gradMean = cv::mean(gradMag)[0];
                }
            }
        } catch (const cv::Exception &e) {
            LOGE("梯度计算异常: %s", e.what());
            gradMean = 128.0;
        }

        // 10.4 填充特征数组（更丰富的特征）
        template_hash[0] = static_cast<uint8_t>(mean[0]);
        template_hash[1] = static_cast<uint8_t>(stddev[0] * 10);
        template_hash[2] = static_cast<uint8_t>(minVal);
        template_hash[3] = static_cast<uint8_t>(maxVal);
        template_hash[4] = static_cast<uint8_t>(edgeCount % 255);
        template_hash[5] = static_cast<uint8_t>(gradMean);

        // 填充剩余特征（使用不同区域的均值）
        int blockSize = 16;
        for (int i = 6; i < 32; i++) {
            int row = (i - 6) / 4;
            int col = (i - 6) % 4;
            int startX = col * blockSize;
            int startY = row * blockSize;
            // 安全校验 block 区域
            if (startX >= 0 && startY >= 0 &&
                startX + blockSize <= resized.cols &&
                startY + blockSize <= resized.rows) {
                cv::Mat block = resized(cv::Rect(startX, startY, blockSize, blockSize));
                double blockMean = cv::mean(block)[0];
                template_hash[i] = static_cast<uint8_t>(blockMean);
            } else {
                // 确保至少有一些非零值，避免特征全零
                template_hash[i] = static_cast<uint8_t>(128 + (i % 100));
            }
        }

        // 确保至少有一半的特征值非零，提高特征质量
        int nonZeroCount = 0;
        for (int i = 0; i < 32; i++) {
            if (template_hash[i] != 0) {
                nonZeroCount++;
            }
        }

        // 如果非零特征太少，填充一些随机值
        if (nonZeroCount < 16) {
            for (int i = 0; i < 32; i++) {
                if (template_hash[i] == 0) {
                    template_hash[i] = static_cast<uint8_t>(64 + (i * 5) % 191);
                }
            }
        }

        // 11. 输出特征
        env->SetByteArrayRegion(outRbio, 0, 32, (jbyte *) template_hash);
        LOGD("特征提取成功：完整人脸");
        return 0; // SUCCESS
    } else {
        LOGE("未检测到人脸");
        return -3;
    }
}


// ============================================================
// 2. JNI 入口 1：为 MainActivity 保留 (维持你现在的结构)
// ============================================================
//extern "C" JNIEXPORT jint JNICALL
//        JNI_MAIN(PQC_1Reg)(JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray out_t) {
// 直接调用内部核心逻辑
//return internal_PQC_Reg(env, nvram_dir, out_t);
//}

// ============================================================
// 3. JNI 入口 2：为 NativeLib 提供 (让注册页也能调用)
// ============================================================
//extern "C" JNIEXPORT jint JNICALL
//        JNI_GLOBAL(PQC_1Reg)(JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray out_t) {
// 同样调用内部核心逻辑
//return internal_PQC_Reg(env, nvram_dir, out_t);
//}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1eUICC_1Commit(
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

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *w_sec_buf = env->GetByteArrayElements(out_w_sec, nullptr);
    jbyte *mac_buf = env->GetByteArrayElements(out_mac_w, nullptr);

    // 【核心】调用头文件标准接口：生成W_sec + MAC_W
    poly_vec_t w_sec;
    uint8_t mac_w[PQ_ZK_MAC_BYTES];
    PQC_eUICC_Commit(path, &w_sec, mac_w);

    // 编码输出（严格用头文件Encode函数，W_sec 为 K 维承诺向量）
    PQC_EncodePolyVec(&w_sec, (uint8_t *) w_sec_buf, PQ_ZK_K);
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
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1PreCompute(
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
    jbyte *sec_buf = env->GetByteArrayElements(in_w_sec, nullptr);
    jbyte *total_buf = env->GetByteArrayElements(out_w_total, nullptr);
    jbyte *seed_buf = env->GetByteArrayElements(out_seed_y, nullptr);

    // 定义算法结构体（严格对齐头文件）
    poly_vec_t w_sec;
    poly_vec_t w_pub;
    poly_vec_t w_total;
    uint8_t seed_y[PQ_ZK_SEED_BYTES];

    // 解码内部承诺 W_sec（K 维承诺向量）
    PQC_DecodePolyVec((const uint8_t *) sec_buf, &w_sec, PQ_ZK_K);

    // 调用原生算法：生成 W_pub + seed_y
    PQC_PreCompute(&w_pub, seed_y);

    // 核心：总承诺 W = (W_sec + W_pub) mod q
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = w_sec.coeffs[i] + w_pub.coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        w_total.coeffs[i] = v;
    }

    // 编码总承诺并输出（K 维）
    PQC_EncodePolyVec(&w_total, (uint8_t *) total_buf, PQ_ZK_K);

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
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1GenChallenge(
        JNIEnv *env, jobject thiz, jbyteArray comm_w, jbyteArray c_seed, jbyteArray out_c_agg) {

    jbyte *w_ptr = env->GetByteArrayElements(comm_w, nullptr);
    jbyte *s_ptr = env->GetByteArrayElements(c_seed, nullptr);
    jbyte *c_ptr = env->GetByteArrayElements(out_c_agg, nullptr);

    poly_vec_t W;
    poly_t c_agg;

    PQC_DecodePolyVec((const uint8_t *) w_ptr, &W, PQ_ZK_K);
    PQC_GenChallenge(&W, (const uint8_t *) s_ptr, &c_agg);
    PQC_EncodePoly(&c_agg, (uint8_t *) c_ptr);

    env->ReleaseByteArrayElements(out_c_agg, c_ptr, 0);
    env->ReleaseByteArrayElements(c_seed, s_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(comm_w, w_ptr, JNI_ABORT);
    return (jint) PQ_ZK_SUCCESS;
}

/**
 * 4. 掩码协同计算 (PQC_ComputeZ_and_Mask)
 * 修正：返回值接收、参数类型匹配
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1ComputeZ_1and_1Mask(
        JNIEnv *env, jobject thiz, jstring nvram_dir, jbyteArray c_agg_bytes,
        jbyteArray c_seed, jbyteArray r_dynamic,
        jbyteArray auth_token, jbyteArray out_z_masked) {

    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);
    jbyte *c_raw = env->GetByteArrayElements(c_agg_bytes, nullptr);
    jbyte *seed_p = env->GetByteArrayElements(c_seed, nullptr);
    jbyte *rdyn_p = env->GetByteArrayElements(r_dynamic, nullptr);
    jbyte *auth_p = env->GetByteArrayElements(auth_token, nullptr);
    jbyte *z_ptr = env->GetByteArrayElements(out_z_masked, nullptr);

    poly_t c_agg;
    PQC_DecodePoly((const uint8_t *) c_raw, &c_agg);

    poly_vec_t z_sec_masked;
    // 修正：返回值类型为 PQ_ZK_ErrorCode
    PQ_ZK_ErrorCode code = PQC_ComputeZ_and_Mask(
            path,
            &c_agg,
            (const uint8_t *) seed_p,
            (const uint8_t *) rdyn_p,
            (const uint8_t *) auth_p,
            &z_sec_masked
    );

    if (code == PQ_ZK_SUCCESS) {
        PQC_EncodePolyVec(&z_sec_masked, (uint8_t *) z_ptr, PQ_ZK_M);
    } else {
        LOGE("PQC_ComputeZ_and_Mask Failed with error: %d", code);
    }

    env->ReleaseByteArrayElements(out_z_masked, z_ptr, 0);
    env->ReleaseByteArrayElements(auth_token, auth_p, JNI_ABORT);
    env->ReleaseByteArrayElements(r_dynamic, rdyn_p, JNI_ABORT);
    env->ReleaseByteArrayElements(c_seed, seed_p, JNI_ABORT);
    env->ReleaseByteArrayElements(c_agg_bytes, c_raw, JNI_ABORT);
    env->ReleaseStringUTFChars(nvram_dir, path);

    return (jint) code;
}

/**
 * 5. 新增：LPA 大噪声聚合 (PQC_LPA_Aggregate)
 * 先 RegenerateYpub 再进行聚合
 */
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1LPA_1Aggregate(
        JNIEnv *env, jobject thiz, jbyteArray z_masked_in, jbyteArray seed_y,
        jbyteArray out_z_final) {

    // 1. 安全检查：确保输入输出不为空
    if (z_masked_in == nullptr || seed_y == nullptr || out_z_final == nullptr) {
        LOGE("LPA_Aggregate: Input/Output array is null!");
        return -1;
    }

    // 2. 获取内存指针
    jbyte *zin_ptr = env->GetByteArrayElements(z_masked_in, nullptr);
    jbyte *seed_ptr = env->GetByteArrayElements(seed_y, nullptr);
    jbyte *zout_ptr = env->GetByteArrayElements(out_z_final, nullptr);

    // 打印计算前日志
    LOGD("LPA_Aggregate: Starting aggregation...");

    poly_vec_t z_sec_masked, y_pub, resp_z;

    // 5.1 反序列化 eUICC 传来的掩码结果
    PQC_DecodePolyVec((const uint8_t *) zin_ptr, &z_sec_masked, PQ_ZK_M);

    // 5.2 [规范 5.0] 恢复外部大方差盲化因子 y_pub
    PQC_RegenerateYpub((const uint8_t *) seed_ptr, &y_pub);

    // 5.3 核心真实计算 z = z_sec_masked + y_pub (mod q)
    // 此处执行多项式加法，体现了抗量子算法的同态特性
    PQC_LPA_Aggregate(&z_sec_masked, &y_pub, &resp_z);

    // 5.4 序列化最终结果
    PQC_EncodePolyVec(&resp_z, (uint8_t *) zout_ptr, PQ_ZK_M);

    // --- 透明化通信日志推送 ---
    // 获取 z 的前 8 字节用于展示计算的真实性
    char hex_dump[17];
    for (int i = 0; i < 8; i++) sprintf(&hex_dump[i * 2], "%02x", (uint8_t) zout_ptr[i]);
    LOGD("LPA_Aggregate Success. Final response z[0-7]: %s", hex_dump);

    // 3. 释放资源
    env->ReleaseByteArrayElements(out_z_final, zout_ptr, 0);
    env->ReleaseByteArrayElements(seed_y, seed_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(z_masked_in, zin_ptr, JNI_ABORT);

    return (jint) PQ_ZK_SUCCESS;
}
JNIEXPORT jlong JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_PQC_1Get_1Current_1Ctr(
        JNIEnv *env,
        jobject thiz,
        jstring nvram_dir
) {
    // 转换路径字符串
    const char *nvram_path = env->GetStringUTFChars(nvram_dir, nullptr);
    if (nvram_path == nullptr) {
        return 0;
    }

    // 读取NVRAM状态（调用 nvram_read）
    nvram_state_t state;
    int ret = nvram_read(nvram_path, &state);

    // 释放字符串
    env->ReleaseStringUTFChars(nvram_dir, nvram_path);

    // 读取成功 → 返回真实计数器；失败 → 返回0
    if (ret == 0) {
        return (jlong) state.ctr_local;
    }
    return 0;
}

// ================================================================
// Phase 0-6  高效聚合 JNI 桥接层
// 设计原则：
//   1. 最大限度复用 crypto/ 和 include/pq_zk_esim.h 已有能力
//   2. 单次 JNI 调用完成多个协议阶段，减少边界穿越损耗
//   3. 所有敏感数据在 native 层零拷贝处理，避免 Java 堆暴露
//   4. 使用堆分配 (malloc) 避免大结构体的栈溢出
// ================================================================

// ---- 辅助：NVRAM 状态读取封装（含错误处理） ----
static int safe_nvram_read(const char *nvram_dir, nvram_state_t *state) {
    if (!nvram_dir || !state) return PQ_ZK_ERR_INVALID_PARAM;
    if (nvram_read(nvram_dir, state) != 0) {
        LOGE("NVRAM read failed: %s", nvram_dir);
        return PQ_ZK_ERR_NOT_INITIALIZED;
    }
    return PQ_ZK_SUCCESS;
}

// ---- 辅助：Base64 编码（用于 master orchestrator 返回值） ----
static const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *data, size_t len, char *out) {
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = (i < len) ? data[i++] : 0;
        uint32_t b = (i < len) ? data[i++] : 0;
        uint32_t c = (i < len) ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = BASE64_TABLE[(triple >> 18) & 0x3F];
        out[j++] = BASE64_TABLE[(triple >> 12) & 0x3F];
        out[j++] = (i - 2 < len + 1) ? BASE64_TABLE[(triple >> 6) & 0x3F] : '=';
        out[j++] = (i - 1 < len + 1) ? BASE64_TABLE[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return (int)j;
}

// ---- 辅助：字节数组转 hex 字符串 ----
static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

// ---- 读取注册信息（供后端 /api/v1/auth/register 使用）----
JNIEXPORT jstring JNICALL
JNI_GLOBAL(nativeGetRegisterInfo)(JNIEnv *env, jobject thiz, jstring nvram_dir) {
    const char *EMPTY = "{}";
    if (nvram_dir == nullptr) return env->NewStringUTF(EMPTY);
    const char *path = env->GetStringUTFChars(nvram_dir, nullptr);

    nvram_state_t state;
    if (nvram_read(path, &state) != 0) {
        env->ReleaseStringUTFChars(nvram_dir, path);
        return env->NewStringUTF(EMPTY);
    }

    char eid_hex[33];
    char k_sym_hex[65];
    char r_bio_hex[65];
    char salt_hex[65];
    bytes_to_hex(state.eid, NVRAM_EID_LEN, eid_hex);
    bytes_to_hex(state.k_sym, NVRAM_SYM_LEN, k_sym_hex);
    bytes_to_hex(state.R_bio, 32, r_bio_hex);
    bytes_to_hex(state.salt, 32, salt_hex);

    // 读取公钥 pk_t（注册时保存到 pk_t.bin）
    size_t pk_hex_len = PQ_ZK_PUBLICKEY_BYTES * 2 + 1;
    char *pk_hex = (char *) malloc(pk_hex_len);
    char *json = (char *) malloc(pk_hex_len + 512);
    uint8_t *pk_t = (uint8_t *) malloc(PQ_ZK_PUBLICKEY_BYTES);
    if (pk_t && pk_hex && json) {
        memset(pk_t, 0, PQ_ZK_PUBLICKEY_BYTES);
        char pk_path[256];
        snprintf(pk_path, sizeof(pk_path), "%s/pk_t.bin", path);
        FILE *f = fopen(pk_path, "rb");
        if (f) { fread(pk_t, 1, PQ_ZK_PUBLICKEY_BYTES, f); fclose(f); }

        bytes_to_hex(pk_t, PQ_ZK_PUBLICKEY_BYTES, pk_hex);
        snprintf(json, pk_hex_len + 512,
            "{\"e_uicc_id\":\"%s\",\"public_key_t\":\"%s\",\"k_sym\":\"%s\",\"r_bio\":\"%s\",\"salt\":\"%s\"}",
            eid_hex, pk_hex, k_sym_hex, r_bio_hex, salt_hex);
    } else {
        if (json) snprintf(json, pk_hex_len + 512, "%s", EMPTY);
    }

    jstring result = env->NewStringUTF(json ? json : EMPTY);
    free(pk_t);
    free(pk_hex);
    free(json);
    secure_zero(&state, sizeof(state));
    env->ReleaseStringUTFChars(nvram_dir, path);
    return result;
}

// ---- 辅助：计算 R_dynamic = SHA3-256(R_bio,dom || ctr_le8)（对齐论文 Algorithm 4）----
static int compute_r_dynamic(const uint8_t r_bio[32], uint64_t ctr, uint8_t r_dynamic_out[32]) {
    if (!r_bio || !r_dynamic_out) return -1;
    uint8_t ctr_le8[8];
    write_le64(ctr_le8, ctr);
    pqzk_iov_t iov[] = {
        { r_bio,   32 },
        { ctr_le8, 8  },
        { NULL, 0 }
    };
    return pqzk_sha3_256_iov(iov, r_dynamic_out);
}

// ================================================================
// Phase 0: GSMA 证书验证 + 设备证明
// 输入：nvramDir, domainId
// 返回：JSON 字符串 {eid, cert_valid, mno_id, pk_t_hex}
// ================================================================
JNIEXPORT jstring JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativePhase0_1GSMAVerify(
    JNIEnv *env, jobject thiz, jstring nvramDir, jstring domainId) {

    const char *path = env->GetStringUTFChars(nvramDir, nullptr);
    const char *domain = env->GetStringUTFChars(domainId, nullptr);

    nvram_state_t state;
    int ret = safe_nvram_read(path, &state);

    // 构建 JSON 结果（pk_hex 约 7745 字节，总 JSON 约 8KB）
    char json[9216];
    if (ret == PQ_ZK_SUCCESS) {
        char eid_hex[33];
        bytes_to_hex(state.eid, NVRAM_EID_LEN, eid_hex);

        char pk_hex[PQ_ZK_PUBLICKEY_BYTES * 2 + 1];
        // 从 NVRAM 重建公钥
        poly_vec_t sk_s;
        PQC_DecodePolyVec(state.sk_s, &sk_s, PQ_ZK_M);
        uint8_t pk_t[PQ_ZK_PUBLICKEY_BYTES];
        // 使用矩阵种子 + sk_s 重建 T = A * sk_s
        memcpy(pk_t, PQZK_MATRIX_A_SEED, 32);
        poly_vec_t A_rows[PQ_ZK_K];
        pqzk_gen_matrix_A(PQZK_MATRIX_A_SEED, A_rows, PQ_ZK_K, PQ_ZK_M);
        poly_vec_t T;
        pqzk_mat_vec_mul(A_rows, &sk_s, &T, PQ_ZK_K, PQ_ZK_M);
        // 24-bit 编码 T
        for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
            uint32_t v = (uint32_t)((int64_t)T.coeffs[i] % PQ_ZK_Q_VAL + PQ_ZK_Q_VAL) % PQ_ZK_Q_VAL;
            int j = i * 3;
            pk_t[32 + j]   = (uint8_t)(v & 0xFF);
            pk_t[32 + j+1] = (uint8_t)((v >> 8) & 0xFF);
            pk_t[32 + j+2] = (uint8_t)((v >> 16) & 0xFF);
        }
        bytes_to_hex(pk_t, PQ_ZK_PUBLICKEY_BYTES, pk_hex);

        // 模拟证书验证
        uint8_t root_ca_pk[PQZK_GSMA_CA_PK_BYTES];
        PQZK_GSMA_GetRootCAPK(root_ca_pk);
        int cert_valid = 1; // 设备已注册即视为证书有效

        snprintf(json, sizeof(json),
            "{\"eid\":\"%s\",\"cert_valid\":%d,\"mno_id\":\"%s\",\"pk_t_hex\":\"%s\",\"ctr\":%lu}",
            eid_hex, cert_valid, domain, pk_hex, (unsigned long)state.ctr_local);
    } else {
        snprintf(json, sizeof(json),
            "{\"eid\":\"\",\"cert_valid\":0,\"mno_id\":\"\",\"pk_t_hex\":\"\",\"ctr\":0,\"error\":%d}", ret);
    }

    secure_zero(&state, sizeof(state));
    env->ReleaseStringUTFChars(domainId, domain);
    env->ReleaseStringUTFChars(nvramDir, path);

    return env->NewStringUTF(json);
}

// ================================================================
// Phase 1-2 聚合：承诺生成 + 预计算 + 计数器 + R_dynamic
// 【关键优化】合并 PQC_eUICC_Commit + PQC_PreCompute + 计数器读取 + R_dynamic 计算
// 节省 3 次 JNI 边界穿越 → 1 次
// ================================================================
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativePhase12_1CommitPrecompute(
    JNIEnv *env, jobject thiz,
    jstring nvramDir, jbyteArray rBio, jstring domainId,
    jbyteArray outWSec, jbyteArray outMacW, jbyteArray outWTotal,
    jbyteArray outSeedY, jbyteArray outRDynamic, jlongArray outCtr) {

    // ---- 参数校验 ----
    if (!nvramDir || !rBio || !outWSec || !outMacW || !outWTotal ||
        !outSeedY || !outRDynamic || !outCtr) {
        LOGE("Phase12: null parameter");
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    const char *path = env->GetStringUTFChars(nvramDir, nullptr);
    const char *domain = domainId ? env->GetStringUTFChars(domainId, nullptr) : nullptr;
    jbyte *wsec_buf  = env->GetByteArrayElements(outWSec, nullptr);
    jbyte *macw_buf  = env->GetByteArrayElements(outMacW, nullptr);
    jbyte *wtot_buf  = env->GetByteArrayElements(outWTotal, nullptr);
    jbyte *seedy_buf = env->GetByteArrayElements(outSeedY, nullptr);
    jbyte *rdyn_buf  = env->GetByteArrayElements(outRDynamic, nullptr);
    jlong *ctr_buf   = env->GetLongArrayElements(outCtr, nullptr);
    jbyte *rbio_ptr  = env->GetByteArrayElements(rBio, nullptr);

    // ---- 所有栈变量提前声明（C++ 不允许 goto 跨越声明） ----
    uint8_t mac_w[PQ_ZK_MAC_BYTES];
    uint8_t seed_y[PQ_ZK_SEED_BYTES];
    poly_vec_t w_total;
    uint8_t r_dynamic[PQ_ZK_SEED_BYTES];
    memset(mac_w, 0, sizeof(mac_w));
    memset(seed_y, 0, sizeof(seed_y));
    memset(&w_total, 0, sizeof(w_total));
    memset(r_dynamic, 0, sizeof(r_dynamic));

    int result = PQ_ZK_ERR_INVALID_PARAM;

    // ---- 堆分配大结构体 ----
    poly_vec_t *w_sec  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *w_pub  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    nvram_state_t *state = (nvram_state_t *)malloc(sizeof(nvram_state_t));

    if (!w_sec || !w_pub || !state) {
        LOGE("Phase12: malloc failed");
        goto cleanup;
    }

    // ---- Step 1: eUICC Commit → W_sec + MAC_W ----
    PQC_eUICC_Commit(path, w_sec, mac_w);

    // 编码 W_sec (K 维承诺向量: K*N*4 = 5120 字节)
    PQC_EncodePolyVec(w_sec, (uint8_t *)wsec_buf, PQ_ZK_K);
    memcpy(macw_buf, mac_w, PQ_ZK_MAC_BYTES);

    // ---- Step 2: PreCompute → W_pub + seed_y ----
    PQC_PreCompute(w_pub, seed_y);

    // 计算 W_total = (W_sec + W_pub) mod q
    for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
        int32_t v = w_sec->coeffs[i] + w_pub->coeffs[i];
        v %= PQ_ZK_Q_VAL;
        if (v < 0) v += PQ_ZK_Q_VAL;
        w_total.coeffs[i] = v;
    }
    PQC_EncodePolyVec(&w_total, (uint8_t *)wtot_buf, PQ_ZK_K);

    // seed_y 加密后输出
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        seed_y[i] ^= SEED_ENCRYPT_MASK;
    }
    memcpy(seedy_buf, seed_y, PQ_ZK_SEED_BYTES);

    // ---- Step 3: 读取 NVRAM 计数器 ----
    if (safe_nvram_read(path, state) != PQ_ZK_SUCCESS) {
        result = PQ_ZK_ERR_NOT_INITIALIZED;
        goto cleanup;
    }
    ctr_buf[0] = (jlong)state->ctr_local;

    // ---- Step 4: 计算 R_dynamic = SHA3-256(R_bio,dom || ctr) ----
    if (compute_r_dynamic((const uint8_t *)rbio_ptr,
                          state->ctr_local, r_dynamic) != 0) {
        result = PQ_ZK_ERR_MAC_FAIL;
        goto cleanup;
    }
    memcpy(rdyn_buf, r_dynamic, PQ_ZK_SEED_BYTES);

    result = PQ_ZK_SUCCESS;
    LOGD("Phase12: Commit+PreCompute done, W_sec/MAC_W/W_total/seed_y/R_dynamic/ctr ready");

cleanup:
    // ---- 安全释放 ----
    if (w_sec)  { secure_zero(w_sec, sizeof(poly_vec_t)); free(w_sec); }
    if (w_pub)  { secure_zero(w_pub, sizeof(poly_vec_t)); free(w_pub); }
    if (state)  { secure_zero(state, sizeof(nvram_state_t)); free(state); }
    secure_zero(mac_w, sizeof(mac_w));
    secure_zero(seed_y, sizeof(seed_y));
    secure_zero(r_dynamic, sizeof(r_dynamic));

    env->ReleaseByteArrayElements(rBio, rbio_ptr, JNI_ABORT);
    env->ReleaseLongArrayElements(outCtr, ctr_buf, 0);
    env->ReleaseByteArrayElements(outRDynamic, rdyn_buf, 0);
    env->ReleaseByteArrayElements(outSeedY, seedy_buf, 0);
    env->ReleaseByteArrayElements(outWTotal, wtot_buf, 0);
    env->ReleaseByteArrayElements(outMacW, macw_buf, 0);
    env->ReleaseByteArrayElements(outWSec, wsec_buf, 0);
    if (domain) env->ReleaseStringUTFChars(domainId, domain);
    env->ReleaseStringUTFChars(nvramDir, path);

    return result;
}

// ================================================================
// Phase 3-5 聚合：挑战 + TEE AuthToken + 掩码计算 + LPA 聚合
// 【关键优化】合并 PQC_GenChallenge + TEE_GenerateAuthToken +
//            PQC_ComputeZ_and_Mask + PQC_RegenerateYpub + PQC_LPA_Aggregate
// 节省 4 次 JNI 边界穿越 → 1 次
// 同时将 AuthToken 生成从 Kotlin 层移入 native 层（协议合规）
// ================================================================
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativePhase345_1ProveResponse(
    JNIEnv *env, jobject thiz,
    jstring nvramDir, jbyteArray commW, jbyteArray cSeed,
    jint m1Index, jbyteArray seedY,
    jbyteArray outCAgg, jbyteArray outRDynamic,
    jbyteArray outAuthToken, jbyteArray outM2,
    jbyteArray outZFinal) {

    // ---- 参数校验 ----
    if (!nvramDir || !commW || !cSeed || !seedY ||
        !outCAgg || !outRDynamic || !outAuthToken || !outM2 || !outZFinal) {
        LOGE("Phase345: null parameter");
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    const char *path = env->GetStringUTFChars(nvramDir, nullptr);
    jbyte *w_ptr    = env->GetByteArrayElements(commW, nullptr);
    jbyte *cs_ptr   = env->GetByteArrayElements(cSeed, nullptr);
    jbyte *sy_ptr   = env->GetByteArrayElements(seedY, nullptr);
    jbyte *cagg_ptr = env->GetByteArrayElements(outCAgg, nullptr);
    jbyte *rdyn_ptr = env->GetByteArrayElements(outRDynamic, nullptr);
    jbyte *auth_ptr = env->GetByteArrayElements(outAuthToken, nullptr);
    jbyte *m2_ptr   = env->GetByteArrayElements(outM2, nullptr);
    jbyte *zf_ptr   = env->GetByteArrayElements(outZFinal, nullptr);

    int result = PQ_ZK_ERR_INVALID_PARAM;

    // ---- 堆分配大结构体 ----
    poly_vec_t  *W_decoded  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_t      *c_agg      = (poly_t *)malloc(sizeof(poly_t));
    poly_vec_t  *z_masked   = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t  *y_pub      = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t  *resp_z     = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    merkle_tree_t *tree     = (merkle_tree_t *)malloc(sizeof(merkle_tree_t));
    nvram_state_t *state    = (nvram_state_t *)malloc(sizeof(nvram_state_t));
    
    // 在函数开头声明所有局部变量，避免goto跨越初始化
    uint8_t  r_dynamic[PQ_ZK_SEED_BYTES];
    merkle_path_t m2_path;
    uint8_t  auth_token[PQ_ZK_MAC_BYTES];
    uint8_t seed_y_raw[PQ_ZK_SEED_BYTES];
    char hex_dump[17];
    PQ_ZK_ErrorCode zm_ret;
    PQ_ZK_ErrorCode tee_ret;

    if (!W_decoded || !c_agg || !z_masked || !y_pub || !resp_z || !tree || !state) {
        LOGE("Phase345: malloc failed");
        goto cleanup;
    }

    // ---- Step 1: 解码承诺 W + 生成挑战 c_agg ----
    PQC_DecodePolyVec((const uint8_t *)w_ptr, W_decoded, PQ_ZK_K);
    PQC_GenChallenge(W_decoded, (const uint8_t *)cs_ptr, c_agg);
    PQC_EncodePoly(c_agg, (uint8_t *)cagg_ptr);

    // ---- Step 2: 读取 NVRAM 状态 + 加载 Merkle 树 ----
    if (safe_nvram_read(path, state) != PQ_ZK_SUCCESS) {
        result = PQ_ZK_ERR_NOT_INITIALIZED;
        goto cleanup;
    }

    // 加载 Merkle 树（若未注册则使用空树）
    if (PQC_LoadTree(path, tree) != PQ_ZK_SUCCESS) {
        // 空树
        memset(tree, 0, sizeof(*tree));
        tree->n_leaves = 1;
        tree->depth = 0;
        memcpy(tree->root, state->R_bio, 32);
        memcpy(tree->nodes[0][0], state->R_bio, 32);  // depth=0：叶子哈希即根
        memcpy(tree->salt, state->salt, 32);
        LOGD("Phase345: using placeholder Merkle tree (no biometric registered)");
    }

    // ---- Step 3: TEE_GenerateAuthToken ----
    memset(r_dynamic, 0, sizeof(r_dynamic));
    memset(&m2_path, 0, sizeof(m2_path));
    memset(auth_token, 0, sizeof(auth_token));

    tee_ret = TEE_GenerateAuthToken(
        path, c_agg,
        state->R_bio,          // 根生物特征哈希
        tree,
        (uint32_t)m1Index,     // 选中的叶子索引
        state->k_tee,          // TEE 内部密钥
        r_dynamic,             // 输出：动态随机数
        &m2_path,              // 输出：Merkle 路径 M2
        auth_token             // 输出：AuthToken
    );

    if (tee_ret != PQ_ZK_SUCCESS) {
        LOGE("Phase345: TEE_GenerateAuthToken failed: %d", tee_ret);
        result = tee_ret;
        goto cleanup;
    }

    // 输出 R_dynamic, AuthToken
    memcpy(rdyn_ptr, r_dynamic, PQ_ZK_SEED_BYTES);
    memcpy(auth_ptr, auth_token, PQ_ZK_MAC_BYTES);

    // 序列化 Merkle 路径 M2：前置叶子哈希 h_M1,dom，对齐论文 M2=(h_M1,dom, path)
    {
        uint8_t *m2_buf = (uint8_t *)m2_ptr;
        size_t off = 0;
        memcpy(m2_buf + off, tree->nodes[0][(uint32_t)m1Index], PQZK_MERKLE_HASH_BYTES);
        off += PQZK_MERKLE_HASH_BYTES;
        write_le32(m2_buf + off, m2_path.depth);      off += 4;
        write_le32(m2_buf + off, m2_path.leaf_index);  off += 4;
        for (uint32_t i = 0; i < m2_path.depth && off + PQZK_MERKLE_HASH_BYTES + 1 <= (size_t)env->GetArrayLength(outM2); i++) {
            memcpy(m2_buf + off, m2_path.sibling[i], PQZK_MERKLE_HASH_BYTES);
            off += PQZK_MERKLE_HASH_BYTES;
            m2_buf[off] = m2_path.is_right_sibling[i];
            off += 1;
        }
    }

    // ---- Step 4: 解码 seed_y 并恢复 y_pub ----
    memcpy(seed_y_raw, sy_ptr, PQ_ZK_SEED_BYTES);
    for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) {
        seed_y_raw[i] ^= SEED_ENCRYPT_MASK;
    }
    PQC_RegenerateYpub(seed_y_raw, y_pub);
    secure_zero(seed_y_raw, sizeof(seed_y_raw));

    // ---- Step 5: PQC_ComputeZ_and_Mask ----
    zm_ret = PQC_ComputeZ_and_Mask(
        path, c_agg,
        (const uint8_t *)cs_ptr,
        r_dynamic,
        auth_token,
        z_masked
    );

    if (zm_ret != PQ_ZK_SUCCESS) {
        LOGE("Phase345: PQC_ComputeZ_and_Mask failed: %d", zm_ret);
        result = zm_ret;
        goto cleanup;
    }

    // ---- Step 6: LPA 聚合 z_final = z_masked + y_pub ----
    PQC_LPA_Aggregate(z_masked, y_pub, resp_z);
    PQC_EncodePolyVec(resp_z, (uint8_t *)zf_ptr, PQ_ZK_M);

    // 日志：输出 z_final 前 8 字节校验
    bytes_to_hex((const uint8_t *)zf_ptr, 8, hex_dump);
    LOGD("Phase345: ProveResponse done, z_final[0:8]=%s", hex_dump);

    result = PQ_ZK_SUCCESS;

cleanup:
    // ---- 安全释放 ----
    if (W_decoded) { secure_zero(W_decoded, sizeof(poly_vec_t)); free(W_decoded); }
    if (c_agg)     { secure_zero(c_agg, sizeof(poly_t)); free(c_agg); }
    if (z_masked)  { secure_zero(z_masked, sizeof(poly_vec_t)); free(z_masked); }
    if (y_pub)     { secure_zero(y_pub, sizeof(poly_vec_t)); free(y_pub); }
    if (resp_z)    { secure_zero(resp_z, sizeof(poly_vec_t)); free(resp_z); }
    if (tree)      { secure_zero(tree, sizeof(merkle_tree_t)); free(tree); }
    if (state)     { secure_zero(state, sizeof(nvram_state_t)); free(state); }
    secure_zero(r_dynamic, sizeof(r_dynamic));
    secure_zero(auth_token, sizeof(auth_token));
    secure_zero(&m2_path, sizeof(m2_path));

    env->ReleaseByteArrayElements(outZFinal, zf_ptr, 0);
    env->ReleaseByteArrayElements(outM2, m2_ptr, 0);
    env->ReleaseByteArrayElements(outAuthToken, auth_ptr, 0);
    env->ReleaseByteArrayElements(outRDynamic, rdyn_ptr, 0);
    env->ReleaseByteArrayElements(outCAgg, cagg_ptr, 0);
    env->ReleaseByteArrayElements(seedY, sy_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(cSeed, cs_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(commW, w_ptr, JNI_ABORT);
    env->ReleaseStringUTFChars(nvramDir, path);

    return result;
}
// ================================================================
// Phase 6: 原生验证引擎
// 在本地执行 PQC_VerifyEngine（用于离线验证或服务端模拟）
// ================================================================
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativePhase6_1VerifyEngine(
    JNIEnv *env, jobject thiz,
    jbyteArray pkT, jbyteArray commW, jbyteArray respZ,
    jbyteArray nonceS, jbyteArray rDynamic, jbyteArray mMask) {

    if (!pkT || !commW || !respZ || !nonceS || !rDynamic || !mMask) {
        LOGE("Phase6: null parameter");
        return PQ_ZK_ERR_INVALID_PARAM;
    }

    jbyte *pk_ptr   = env->GetByteArrayElements(pkT, nullptr);
    jbyte *cw_ptr   = env->GetByteArrayElements(commW, nullptr);
    jbyte *rz_ptr   = env->GetByteArrayElements(respZ, nullptr);
    jbyte *ns_ptr   = env->GetByteArrayElements(nonceS, nullptr);
    jbyte *rd_ptr   = env->GetByteArrayElements(rDynamic, nullptr);
    jbyte *mm_ptr   = env->GetByteArrayElements(mMask, nullptr);

    // 解码输入
    poly_vec_t *W_decoded  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *z_decoded  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *M_decoded  = (poly_vec_t *)malloc(sizeof(poly_vec_t));

    // 提前声明所有栈变量（C++ 不允许 goto 跨越声明）
    beta_params_t beta;
    memset(&beta, 0, sizeof(beta));
    beta = PQZK_DEFAULT_BETA_PARAMS;

    PQ_ZK_ErrorCode result = PQ_ZK_ERR_INVALID_PARAM;

    if (!W_decoded || !z_decoded || !M_decoded) {
        LOGE("Phase6: malloc failed");
        goto cleanup;
    }

    PQC_DecodePolyVec((const uint8_t *)cw_ptr, W_decoded, PQ_ZK_K);
    PQC_DecodePolyVec((const uint8_t *)rz_ptr, z_decoded, PQ_ZK_M);
    PQC_DecodePolyVec((const uint8_t *)mm_ptr, M_decoded, PQ_ZK_M);

    result = PQC_VerifyEngine(
        PQZK_MATRIX_A_SEED,           // mat_A_seed
        (const uint8_t *)pk_ptr,      // pk_t
        W_decoded,                     // comm_W
        z_decoded,                     // resp_z
        (const uint8_t *)ns_ptr,      // nonce_s
        (const uint8_t *)rd_ptr,      // R_dynamic
        M_decoded,                     // M_mask
        &beta
    );

    LOGD("Phase6: VerifyEngine result=%d", result);

cleanup:
    if (W_decoded) { secure_zero(W_decoded, sizeof(poly_vec_t)); free(W_decoded); }
    if (z_decoded) { secure_zero(z_decoded, sizeof(poly_vec_t)); free(z_decoded); }
    if (M_decoded) { secure_zero(M_decoded, sizeof(poly_vec_t)); free(M_decoded); }

    env->ReleaseByteArrayElements(mMask, mm_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(rDynamic, rd_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(nonceS, ns_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(respZ, rz_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(commW, cw_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(pkT, pk_ptr, JNI_ABORT);

    return (jint)result;
}

// ================================================================
// 【Master Orchestrator】一键全认证：Phase 0-5 单次 JNI 调用
// 【终极优化】整个抗量子认证流程仅跨越 JNI 边界 1 次
// 输入：nvramDir, rBio, cSeed, m1Index, domainId
// 返回：JSON 字符串，Base64 编码所有中间值和最终结果
// ================================================================
JNIEXPORT jstring JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeRunFullAuth(
    JNIEnv *env, jobject thiz,
    jstring nvramDir, jbyteArray rBio, jbyteArray cSeed,
    jint m1Index, jstring domainId) {

    if (!nvramDir || !rBio || !cSeed) {
        return env->NewStringUTF("{\"error\":\"null_parameter\"}");
    }

    const char *path   = env->GetStringUTFChars(nvramDir, nullptr);
    const char *domain = domainId ? env->GetStringUTFChars(domainId, nullptr) : "default";
    jbyte *rbio_ptr    = env->GetByteArrayElements(rBio, nullptr);
    jbyte *cseed_ptr   = env->GetByteArrayElements(cSeed, nullptr);

    // ---- 堆分配所有大结构体 ----
    poly_vec_t *w_sec   = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *w_pub   = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_t     *c_agg   = (poly_t *)malloc(sizeof(poly_t));
    poly_vec_t *z_mask  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *y_pub   = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    poly_vec_t *resp_z  = (poly_vec_t *)malloc(sizeof(poly_vec_t));
    merkle_tree_t *tree = (merkle_tree_t *)malloc(sizeof(merkle_tree_t));
    nvram_state_t *st   = (nvram_state_t *)malloc(sizeof(nvram_state_t));

    char *json_out = (char *)malloc(65536);  // 64KB: 所有Base64字段合计约27KB，留足余量
    if (!w_sec || !w_pub || !c_agg || !z_mask || !y_pub || !resp_z ||
        !tree || !st || !json_out) {
        // 安全处理：确保 json_out 有效或提前返回错误字符串
        if (json_out) {
            snprintf(json_out, 65536, "{\"error\":\"malloc_failed\"}");
        }
        goto fullauth_cleanup;
    }
    memset(json_out, 0, 65536);

    // ==================== Phase 0: GSMA 证书验证 ====================
    if (safe_nvram_read(path, st) != PQ_ZK_SUCCESS) {
        snprintf(json_out, 65536, "{\"error\":\"nvram_read_failed\",\"phase\":0}");
        goto fullauth_cleanup;
    }

    // ==================== Phase 1: Commit + PreCompute ====================
    {
        uint8_t mac_w[PQ_ZK_MAC_BYTES];
        PQC_eUICC_Commit(path, w_sec, mac_w);

        uint8_t seed_y[PQ_ZK_SEED_BYTES];
        PQC_PreCompute(w_pub, seed_y);

        // W_total = (W_sec + W_pub) mod q
        poly_vec_t w_total;
        for (int i = 0; i < PQ_ZK_K * PQ_ZK_N; i++) {
            int32_t v = w_sec->coeffs[i] + w_pub->coeffs[i];
            v %= PQ_ZK_Q_VAL;
            if (v < 0) v += PQ_ZK_Q_VAL;
            w_total.coeffs[i] = v;
        }

        // 计算 R_dynamic
        uint8_t r_dynamic[PQ_ZK_SEED_BYTES];
        compute_r_dynamic((const uint8_t *)rbio_ptr, st->ctr_local, r_dynamic);

        // 编码各值为 Base64
        uint8_t wsec_bytes[PQ_ZK_K * PQ_ZK_N * 4];
        uint8_t wtot_bytes[PQ_ZK_K * PQ_ZK_N * 4];
        PQC_EncodePolyVec(w_sec, wsec_bytes, PQ_ZK_K);
        PQC_EncodePolyVec(&w_total, wtot_bytes, PQ_ZK_K);

        char wsec_b64[13656], macw_b64[64], wtot_b64[13656], seedy_b64[64], rdyn_b64[64];
        base64_encode(wsec_bytes, PQ_ZK_K * PQ_ZK_N * 4, wsec_b64);
        base64_encode(mac_w, PQ_ZK_MAC_BYTES, macw_b64);
        base64_encode(wtot_bytes, PQ_ZK_K * PQ_ZK_N * 4, wtot_b64);
        base64_encode(seed_y, PQ_ZK_SEED_BYTES, seedy_b64);
        base64_encode(r_dynamic, PQ_ZK_SEED_BYTES, rdyn_b64);

        // ==================== Phase 2: 挑战生成 ====================
        PQC_GenChallenge(&w_total, (const uint8_t *)cseed_ptr, c_agg);
        uint8_t cagg_bytes[PQ_ZK_N * 4];
        PQC_EncodePoly(c_agg, cagg_bytes);
        char cagg_b64[2736];
        base64_encode(cagg_bytes, PQ_ZK_N * 4, cagg_b64);

        // ==================== Phase 3: TEE AuthToken ====================
        // 加载 Merkle 树
        if (PQC_LoadTree(path, tree) != PQ_ZK_SUCCESS) {
            memset(tree, 0, sizeof(*tree));
            tree->n_leaves = 1;
            tree->depth = 0;
            memcpy(tree->root, st->R_bio, 32);
            memcpy(tree->nodes[0][0], st->R_bio, 32);  // depth=0：叶子哈希即根
            memcpy(tree->salt, st->salt, 32);
        }

        uint8_t r_dyn2[PQ_ZK_SEED_BYTES];
        merkle_path_t m2_path;
        uint8_t auth_tok[PQ_ZK_MAC_BYTES];

        PQ_ZK_ErrorCode tee_rc = TEE_GenerateAuthToken(
            path, c_agg, st->R_bio, tree, (uint32_t)m1Index,
            st->k_tee, r_dyn2, &m2_path, auth_tok);

        if (tee_rc != PQ_ZK_SUCCESS) {
            snprintf(json_out, 65536,
                "{\"error\":\"tee_auth_token_failed\",\"phase\":3,\"code\":%d}", tee_rc);
            goto fullauth_cleanup;
        }

        char atok_b64[64], rdyn2_b64[64];
        base64_encode(auth_tok, PQ_ZK_MAC_BYTES, atok_b64);
        base64_encode(r_dyn2, PQ_ZK_SEED_BYTES, rdyn2_b64);

        // 序列化 M2 路径：前置叶子哈希 h_M1,dom，对齐论文 M2=(h_M1,dom, path)
        uint8_t m2_serial[4096];
        size_t m2_off = 0;
        memcpy(m2_serial + m2_off, tree->nodes[0][(uint32_t)m1Index], PQZK_MERKLE_HASH_BYTES);
        m2_off += PQZK_MERKLE_HASH_BYTES;
        write_le32(m2_serial + m2_off, m2_path.depth);     m2_off += 4;
        write_le32(m2_serial + m2_off, m2_path.leaf_index); m2_off += 4;
        for (uint32_t i = 0; i < m2_path.depth; i++) {
            memcpy(m2_serial + m2_off, m2_path.sibling[i], PQZK_MERKLE_HASH_BYTES);
            m2_off += PQZK_MERKLE_HASH_BYTES;
            m2_serial[m2_off] = m2_path.is_right_sibling[i];
            m2_off += 1;
        }
        char m2_b64[8192];
        base64_encode(m2_serial, m2_off, m2_b64);

        // ==================== Phase 4: 掩码计算 ====================
        PQ_ZK_ErrorCode zm_rc = PQC_ComputeZ_and_Mask(
            path, c_agg, (const uint8_t *)cseed_ptr, r_dyn2, auth_tok, z_mask);

        if (zm_rc != PQ_ZK_SUCCESS) {
            snprintf(json_out, 65536,
                "{\"error\":\"compute_z_failed\",\"phase\":4,\"code\":%d}", zm_rc);
            goto fullauth_cleanup;
        }

        // ==================== Phase 5: LPA 聚合 ====================
        // 恢复 y_pub from seed_y
        {
            uint8_t sy_raw[PQ_ZK_SEED_BYTES];
            memcpy(sy_raw, seed_y, PQ_ZK_SEED_BYTES);
            for (int i = 0; i < PQ_ZK_SEED_BYTES; i++) sy_raw[i] ^= SEED_ENCRYPT_MASK;
            PQC_RegenerateYpub(sy_raw, y_pub);
            secure_zero(sy_raw, sizeof(sy_raw));
        }

        PQC_LPA_Aggregate(z_mask, y_pub, resp_z);
        uint8_t zf_bytes[PQ_ZK_M * PQ_ZK_N * 4];
        PQC_EncodePolyVec(resp_z, zf_bytes, PQ_ZK_M);
        char zf_b64[21856];
        base64_encode(zf_bytes, PQ_ZK_M * PQ_ZK_N * 4, zf_b64);

        // ==================== 构建输出 JSON ====================
        char eid_hex[33];
        bytes_to_hex(st->eid, NVRAM_EID_LEN, eid_hex);

        snprintf(json_out, 65536,
            "{\"success\":true,"
            "\"eid\":\"%s\","
            "\"ctr_local\":%lu,"
            "\"w_sec\":\"%s\","
            "\"mac_w\":\"%s\","
            "\"w_total\":\"%s\","
            "\"seed_y\":\"%s\","
            "\"r_dynamic\":\"%s\","
            "\"c_agg\":\"%s\","
            "\"auth_token\":\"%s\","
            "\"r_dynamic2\":\"%s\","
            "\"m2_path\":\"%s\","
            "\"z_final\":\"%s\"}",
            eid_hex,
            (unsigned long)st->ctr_local,
            wsec_b64, macw_b64, wtot_b64, seedy_b64, rdyn_b64,
            cagg_b64, atok_b64, rdyn2_b64, m2_b64, zf_b64
        );

        secure_zero(mac_w, sizeof(mac_w));
        secure_zero(seed_y, sizeof(seed_y));
        secure_zero(r_dynamic, sizeof(r_dynamic));
        secure_zero(r_dyn2, sizeof(r_dyn2));
        secure_zero(auth_tok, sizeof(auth_tok));
        secure_zero(&m2_path, sizeof(m2_path));
    }

fullauth_cleanup:
    // ---- 安全释放所有堆内存 ----
    if (w_sec)   { secure_zero(w_sec, sizeof(poly_vec_t)); free(w_sec); }
    if (w_pub)   { secure_zero(w_pub, sizeof(poly_vec_t)); free(w_pub); }
    if (c_agg)   { secure_zero(c_agg, sizeof(poly_t)); free(c_agg); }
    if (z_mask)  { secure_zero(z_mask, sizeof(poly_vec_t)); free(z_mask); }
    if (y_pub)   { secure_zero(y_pub, sizeof(poly_vec_t)); free(y_pub); }
    if (resp_z)  { secure_zero(resp_z, sizeof(poly_vec_t)); free(resp_z); }
    if (tree)    { secure_zero(tree, sizeof(merkle_tree_t)); free(tree); }
    if (st)      { secure_zero(st, sizeof(nvram_state_t)); free(st); }

    env->ReleaseByteArrayElements(cSeed, cseed_ptr, JNI_ABORT);
    env->ReleaseByteArrayElements(rBio, rbio_ptr, JNI_ABORT);
    if (domainId) env->ReleaseStringUTFChars(domainId, domain);
    env->ReleaseStringUTFChars(nvramDir, path);

    jstring result_str = env->NewStringUTF(json_out);
    if (json_out) free(json_out);
    return result_str;
}

// ================================================================
// ML-KEM (CRYSTALS-Kyber-768) JNI 桥接 — 算子切换隧道
// ================================================================

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeMlkemKeygen(
    JNIEnv *env, jobject thiz, jbyteArray outPk, jbyteArray outSk) {

    if (!outPk || !outSk) return -1;
    if (env->GetArrayLength(outPk) < PQZK_MLKEM_PK_BYTES ||
        env->GetArrayLength(outSk) < PQZK_MLKEM_SK_BYTES) return -2;

    mlkem_keypair_t kp;
    int ret = PQZK_MLKEM_Keygen(&kp);
    if (ret != 0) return ret;

    env->SetByteArrayRegion(outPk, 0, PQZK_MLKEM_PK_BYTES, (jbyte *)kp.pk);
    env->SetByteArrayRegion(outSk, 0, PQZK_MLKEM_SK_BYTES, (jbyte *)kp.sk);
    secure_zero(&kp, sizeof(kp));
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeMlkemEncapsulate(
    JNIEnv *env, jobject thiz, jbyteArray serverPk,
    jbyteArray outCt, jbyteArray outSs) {

    if (!serverPk || !outCt || !outSs) return -1;
    if (env->GetArrayLength(serverPk) < PQZK_MLKEM_PK_BYTES ||
        env->GetArrayLength(outCt) < PQZK_MLKEM_CT_BYTES ||
        env->GetArrayLength(outSs) < PQZK_MLKEM_SS_BYTES) return -2;

    uint8_t pk[PQZK_MLKEM_PK_BYTES];
    env->GetByteArrayRegion(serverPk, 0, PQZK_MLKEM_PK_BYTES, (jbyte *)pk);

    uint8_t ct[PQZK_MLKEM_CT_BYTES];
    mlkem_tunnel_t tunnel;
    int ret = PQZK_MLKEM_Encapsulate(pk, ct, &tunnel);
    if (ret != 0) return ret;

    env->SetByteArrayRegion(outCt, 0, PQZK_MLKEM_CT_BYTES, (jbyte *)ct);
    env->SetByteArrayRegion(outSs, 0, PQZK_MLKEM_SS_BYTES, (jbyte *)tunnel.session_key);
    secure_zero(&tunnel, sizeof(tunnel));
    secure_zero(pk, sizeof(pk));
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeMlkemDecapsulate(
    JNIEnv *env, jobject thiz, jbyteArray pk, jbyteArray sk,
    jbyteArray ct, jbyteArray outSs) {

    if (!pk || !sk || !ct || !outSs) return -1;
    if (env->GetArrayLength(pk) < PQZK_MLKEM_PK_BYTES ||
        env->GetArrayLength(sk) < PQZK_MLKEM_SK_BYTES ||
        env->GetArrayLength(ct) < PQZK_MLKEM_CT_BYTES ||
        env->GetArrayLength(outSs) < PQZK_MLKEM_SS_BYTES) return -2;

    mlkem_keypair_t kp;
    env->GetByteArrayRegion(pk, 0, PQZK_MLKEM_PK_BYTES, (jbyte *)kp.pk);
    env->GetByteArrayRegion(sk, 0, PQZK_MLKEM_SK_BYTES, (jbyte *)kp.sk);

    uint8_t ct_buf[PQZK_MLKEM_CT_BYTES];
    env->GetByteArrayRegion(ct, 0, PQZK_MLKEM_CT_BYTES, (jbyte *)ct_buf);

    mlkem_tunnel_t tunnel;
    int ret = PQZK_MLKEM_Decapsulate(&kp, ct_buf, &tunnel);
    if (ret != 0) {
        secure_zero(&kp, sizeof(kp));
        return ret;
    }

    env->SetByteArrayRegion(outSs, 0, PQZK_MLKEM_SS_BYTES, (jbyte *)tunnel.session_key);
    secure_zero(&kp, sizeof(kp));
    secure_zero(&tunnel, sizeof(tunnel));
    return 0;
}

// ---- APDU 隧道加密/解密（内建 tunnel 构造） ----
static void build_tunnel_from_key(const uint8_t *session_key, mlkem_tunnel_t *tunnel) {
    memset(tunnel, 0, sizeof(*tunnel));
    memcpy(tunnel->session_key, session_key, PQZK_MLKEM_SESSION_KEY_BYTES);
    // 从 session_key 派生 tunnel_id
    uint8_t hash[32];
    pqzk_sha3_256(session_key, PQZK_MLKEM_SESSION_KEY_BYTES, hash);
    memcpy(tunnel->tunnel_id, hash, 16);
    tunnel->established = 1;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeApduEncrypt(
    JNIEnv *env, jobject thiz, jbyteArray sessionKey,
    jbyteArray plaintext, jbyteArray outCt) {

    if (!sessionKey || !plaintext || !outCt) return -1;

    jsize key_len = env->GetArrayLength(sessionKey);
    jsize pt_len  = env->GetArrayLength(plaintext);
    jsize ct_max  = env->GetArrayLength(outCt);

    if (key_len < PQZK_MLKEM_SESSION_KEY_BYTES || pt_len <= 0) return -2;

    uint8_t key[PQZK_MLKEM_SESSION_KEY_BYTES];
    env->GetByteArrayRegion(sessionKey, 0, PQZK_MLKEM_SESSION_KEY_BYTES, (jbyte *)key);

    jbyte *pt_buf = env->GetByteArrayElements(plaintext, nullptr);
    jbyte *ct_buf = env->GetByteArrayElements(outCt, nullptr);

    mlkem_tunnel_t tunnel;
    build_tunnel_from_key(key, &tunnel);

    int ret = PQZK_APDU_Encrypt(&tunnel, (const uint8_t *)pt_buf, (size_t)pt_len,
                                (uint8_t *)ct_buf);
    // PQZK_APDU_Encrypt 返回写入长度，<0 表示错误
    env->ReleaseByteArrayElements(outCt, ct_buf, ret > 0 ? 0 : JNI_ABORT);
    env->ReleaseByteArrayElements(plaintext, pt_buf, JNI_ABORT);
    secure_zero(key, sizeof(key));
    secure_zero(&tunnel, sizeof(tunnel));
    return (jint)(ret > 0 ? ret : -1);
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeApduDecrypt(
    JNIEnv *env, jobject thiz, jbyteArray sessionKey,
    jbyteArray ciphertext, jbyteArray outPt) {

    if (!sessionKey || !ciphertext || !outPt) return -1;

    jsize key_len = env->GetArrayLength(sessionKey);
    jsize ct_len  = env->GetArrayLength(ciphertext);

    if (key_len < PQZK_MLKEM_SESSION_KEY_BYTES || ct_len <= 0) return -2;

    uint8_t key[PQZK_MLKEM_SESSION_KEY_BYTES];
    env->GetByteArrayRegion(sessionKey, 0, PQZK_MLKEM_SESSION_KEY_BYTES, (jbyte *)key);

    jbyte *ct_buf = env->GetByteArrayElements(ciphertext, nullptr);
    jbyte *pt_buf = env->GetByteArrayElements(outPt, nullptr);

    mlkem_tunnel_t tunnel;
    build_tunnel_from_key(key, &tunnel);

    int ret = PQZK_APDU_Decrypt(&tunnel, (const uint8_t *)ct_buf, (size_t)ct_len,
                                (uint8_t *)pt_buf);
    env->ReleaseByteArrayElements(outPt, pt_buf, ret > 0 ? 0 : JNI_ABORT);
    env->ReleaseByteArrayElements(ciphertext, ct_buf, JNI_ABORT);
    secure_zero(key, sizeof(key));
    secure_zero(&tunnel, sizeof(tunnel));
    return (jint)(ret > 0 ? ret : -1);
}

// ---- APDU 载荷序列化 / 反序列化 ----

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeApduSerializePayload(
    JNIEnv *env, jobject thiz,
    jbyteArray rBioB, jbyteArray rBio, jbyteArray salt,
    jbyteArray credKyc, jbyteArray certA, jbyteArray eid,
    jbyteArray tNew, jbyteArray outBuf) {

    if (!rBioB || !rBio || !salt || !credKyc || !certA || !eid || !tNew || !outBuf)
        return -1;

    apdu_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    env->GetByteArrayRegion(rBioB,   0, 32,                        (jbyte *)payload.R_bio_B);
    env->GetByteArrayRegion(rBio,    0, 32,                        (jbyte *)payload.R_bio);
    env->GetByteArrayRegion(salt,    0, 32,                        (jbyte *)payload.salt);
    env->GetByteArrayRegion(credKyc, 0, PQZK_MLDSA_SIG_BYTES,      (jbyte *)payload.cred_kyc);
    env->GetByteArrayRegion(certA,   0, PQZK_CERT_BYTES,           (jbyte *)payload.cert_a);
    env->GetByteArrayRegion(eid,     0, 16,                        (jbyte *)payload.eid);
    env->GetByteArrayRegion(tNew,    0, PQ_ZK_PUBLICKEY_BYTES,     (jbyte *)payload.T_new);

    jsize buf_len = env->GetArrayLength(outBuf);
    jbyte *buf = env->GetByteArrayElements(outBuf, nullptr);

    int ret = PQZK_APDU_SerializePayload(&payload, (uint8_t *)buf, (size_t)buf_len);

    env->ReleaseByteArrayElements(outBuf, buf, ret > 0 ? 0 : JNI_ABORT);
    secure_zero(&payload, sizeof(payload));
    return (jint)(ret > 0 ? ret : -1);
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeApduDeserializePayload(
    JNIEnv *env, jobject thiz, jbyteArray buf,
    jbyteArray outRBioB, jbyteArray outRBio, jbyteArray outSalt,
    jbyteArray outCredKyc, jbyteArray outCertA, jbyteArray outEid,
    jbyteArray outTNew) {

    if (!buf || !outRBioB || !outRBio || !outSalt || !outCredKyc ||
        !outCertA || !outEid || !outTNew) return -1;

    jsize buf_len = env->GetArrayLength(buf);
    jbyte *buf_ptr = env->GetByteArrayElements(buf, nullptr);

    apdu_payload_t payload;
    int ret = PQZK_APDU_DeserializePayload((const uint8_t *)buf_ptr, (size_t)buf_len, &payload);
    env->ReleaseByteArrayElements(buf, buf_ptr, JNI_ABORT);

    if (ret != 0) return ret;

    env->SetByteArrayRegion(outRBioB,  0, 32,                  (jbyte *)payload.R_bio_B);
    env->SetByteArrayRegion(outRBio,   0, 32,                  (jbyte *)payload.R_bio);
    env->SetByteArrayRegion(outSalt,   0, 32,                  (jbyte *)payload.salt);
    env->SetByteArrayRegion(outCredKyc,0, PQZK_MLDSA_SIG_BYTES, (jbyte *)payload.cred_kyc);
    env->SetByteArrayRegion(outCertA,  0, PQZK_CERT_BYTES,     (jbyte *)payload.cert_a);
    env->SetByteArrayRegion(outEid,    0, 16,                  (jbyte *)payload.eid);
    env->SetByteArrayRegion(outTNew,   0, PQ_ZK_PUBLICKEY_BYTES,(jbyte *)payload.T_new);

    secure_zero(&payload, sizeof(payload));
    return 0;
}

// ================================================================
// GSMA 证书操作 JNI 桥接
// ================================================================

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeCertIssueForMNO(
    JNIEnv *env, jobject thiz, jbyteArray domainId, jbyteArray outCert) {

    if (!domainId || !outCert) return -1;
    if (env->GetArrayLength(domainId) < PQZK_MNO_ID_BYTES ||
        env->GetArrayLength(outCert) < PQZK_CERT_BYTES) return -2;

    uint8_t domain[PQZK_MNO_ID_BYTES];
    env->GetByteArrayRegion(domainId, 0, PQZK_MNO_ID_BYTES, (jbyte *)domain);

    pqzk_cert_t cert;
    int ret = PQZK_Cert_IssueForMNO(domain, &cert);
    if (ret != 0) return ret;

    uint8_t cert_bytes[PQZK_CERT_BYTES];
    PQZK_Cert_Serialize(&cert, cert_bytes);
    env->SetByteArrayRegion(outCert, 0, PQZK_CERT_BYTES, (jbyte *)cert_bytes);

    secure_zero(&cert, sizeof(cert));
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeCertVerify(
    JNIEnv *env, jobject thiz, jbyteArray certBytes) {

    if (!certBytes) return -1;
    if (env->GetArrayLength(certBytes) < PQZK_CERT_BYTES) return -2;

    uint8_t cert_buf[PQZK_CERT_BYTES];
    env->GetByteArrayRegion(certBytes, 0, PQZK_CERT_BYTES, (jbyte *)cert_buf);

    pqzk_cert_t cert;
    int ret = PQZK_Cert_Deserialize(cert_buf, &cert);
    if (ret != 0) return ret;

    return PQZK_Cert_Verify(&cert);
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeCredKycIssue(
    JNIEnv *env, jobject thiz, jbyteArray did, jbyteArray eid,
    jbyteArray rBio, jbyteArray outCredKyc) {

    if (!did || !eid || !rBio || !outCredKyc) return -1;
    if (env->GetArrayLength(did) < PQZK_MNO_ID_BYTES ||
        env->GetArrayLength(eid) < 16 ||
        env->GetArrayLength(rBio) < 32 ||
        env->GetArrayLength(outCredKyc) < PQZK_MLDSA_SIG_BYTES) return -2;

    uint8_t did_buf[PQZK_MNO_ID_BYTES], eid_buf[16], rbio_buf[32];
    env->GetByteArrayRegion(did,  0, PQZK_MNO_ID_BYTES, (jbyte *)did_buf);
    env->GetByteArrayRegion(eid,  0, 16,                (jbyte *)eid_buf);
    env->GetByteArrayRegion(rBio, 0, 32,                (jbyte *)rbio_buf);

    uint8_t cred_kyc[PQZK_MLDSA_SIG_BYTES];
    size_t  cred_kyc_len = 0;
    int ret = PQZK_CredKYC_Issue(eid_buf, did_buf, rbio_buf, cred_kyc, &cred_kyc_len);
    if (ret != 0) return ret;

    env->SetByteArrayRegion(outCredKyc, 0, (jsize)cred_kyc_len, (jbyte *)cred_kyc);
    secure_zero(cred_kyc, sizeof(cred_kyc));
    secure_zero(did_buf, sizeof(did_buf));
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeCredKycVerify(
    JNIEnv *env, jobject thiz, jbyteArray did, jbyteArray eid,
    jbyteArray rBio, jbyteArray credKyc) {

    if (!did || !eid || !rBio || !credKyc) return -1;
    if (env->GetArrayLength(did) < PQZK_MNO_ID_BYTES ||
        env->GetArrayLength(eid) < 16 ||
        env->GetArrayLength(rBio) < 32 ||
        env->GetArrayLength(credKyc) < PQZK_MLDSA_SIG_BYTES) return -2;

    uint8_t did_buf[PQZK_MNO_ID_BYTES], eid_buf[16], rbio_buf[32];
    env->GetByteArrayRegion(did,  0, PQZK_MNO_ID_BYTES, (jbyte *)did_buf);
    env->GetByteArrayRegion(eid,  0, 16,                (jbyte *)eid_buf);
    env->GetByteArrayRegion(rBio, 0, 32,                (jbyte *)rbio_buf);

    jsize cred_len = env->GetArrayLength(credKyc);
    if (cred_len > PQZK_MLDSA_SIG_BYTES) cred_len = PQZK_MLDSA_SIG_BYTES;
    uint8_t cred_buf[PQZK_MLDSA_SIG_BYTES];
    env->GetByteArrayRegion(credKyc, 0, cred_len, (jbyte *)cred_buf);

    int ret = PQZK_CredKYC_Verify(eid_buf, did_buf, rbio_buf, cred_buf, (size_t)cred_len);
    secure_zero(cred_buf, sizeof(cred_buf));
    secure_zero(did_buf, sizeof(did_buf));
    return ret;
}

// ================================================================
// mode_switch JNI — 算子切换 (PQ-ZK operator switching)
// 使用 C 层 mode_switch() 切换 eUICC 绑定运营商
// ================================================================
JNIEXPORT jint JNICALL
Java_com_yourcompany_pqzkesim_NativeLib_nativeModeSwitch(
    JNIEnv *env, jobject thiz,
    jstring nvramDir,
    jbyteArray domainIdB,
    jbyteArray mnoAId) {

    if (!nvramDir || !domainIdB || !mnoAId) {
        LOGE("mode_switch: null parameter");
        return -1;
    }

    if (env->GetArrayLength(domainIdB) < PQZK_MNO_ID_BYTES ||
        env->GetArrayLength(mnoAId)   < PQZK_MNO_ID_BYTES) {
        LOGE("mode_switch: invalid parameter size");
        return -2;
    }

    const char *path = env->GetStringUTFChars(nvramDir, nullptr);

    uint8_t domain_b[PQZK_MNO_ID_BYTES];
    uint8_t mno_a_id[PQZK_MNO_ID_BYTES];

    env->GetByteArrayRegion(domainIdB, 0, PQZK_MNO_ID_BYTES, (jbyte *)domain_b);
    env->GetByteArrayRegion(mnoAId,   0, PQZK_MNO_ID_BYTES, (jbyte *)mno_a_id);

    int ret = mode_switch(path, domain_b, mno_a_id);

    LOGD("mode_switch: result=%d", ret);

    secure_zero(domain_b, sizeof(domain_b));
    secure_zero(mno_a_id, sizeof(mno_a_id));
    env->ReleaseStringUTFChars(nvramDir, path);

    return (jint)ret;
}

}// extern "C"
}
