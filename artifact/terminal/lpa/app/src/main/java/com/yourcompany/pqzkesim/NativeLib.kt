package com.yourcompany.pqzkesim

import android.graphics.Bitmap
import android.util.Log
import org.json.JSONObject

/**
 * PQ-ZK-eSIM 底层算法库调度器 (v5.2 — Phase 0-6 聚合 JNI 桥接)
 *
 * 设计原则：
 *   - 高度聚合接口，单次 JNI 调用完成多个协议阶段
 *   - 所有敏感密码运算在 native 层完成，Kotlin 仅做数据透传
 *   - 字节大小严格对齐 C 头文件定义（ProtocolConstants）
 */
object NativeLib {
    private const val TAG = "PQZK-Native"

    @Volatile var isDetectorInitialized = false
        private set

    init {
        try {
            System.loadLibrary("pqzkesim")
            Log.d(TAG, "✅ 库文件 pqzkesim 加载成功")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ 库文件加载失败: ${e.message}")
        }
    }

    // ================================================================
    // 检测器初始化（OpenCV 人脸检测）
    // ================================================================

    @Synchronized
    fun initDetector(modelPath: String): Boolean {
        if (isDetectorInitialized) {
            Log.d(TAG, "检测器已初始化，跳过重复操作")
            return true
        }
        return try {
            val success = nativeInitDetector(modelPath)
            isDetectorInitialized = success
            Log.d(TAG, "检测器初始化结果: $success")
            success
        } catch (e: Exception) {
            Log.e(TAG, "检测器初始化异常", e)
            false
        }
    }

    fun processFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int {
        if (!isDetectorInitialized) {
            Log.e(TAG, "❌ 检测器未初始化！请先调用 initDetector()")
            return -1
        }
        return try {
            nativeProcessFaceAndGetRbio(matAddr, latestRBio)
        } catch (e: Exception) {
            Log.e(TAG, "特征提取异常", e)
            -2
        }
    }

    // ---- 原生 JNI 函数声明 ----
    private external fun nativeInitDetector(modelPath: String): Boolean
    private external fun nativeProcessFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int

    // ================================================================
    // Phase 0: GSMA 证书验证 (聚合)
    // 单次 JNI → 完成证书验证 + EID 获取 + 公钥导出
    // ================================================================

    /**
     * Phase 0: GSMA 证书验证 + 设备证明
     * @return JSON {eid, cert_valid, mno_id, pk_t_hex, ctr}
     */
    fun phase0_GSMAVerify(nvramDirPath: String, domainId: String): JSONObject {
        val jsonStr = nativePhase0_GSMAVerify(nvramDirPath, domainId)
        return JSONObject(jsonStr)
    }

    /**
     * 读取注册信息（e_uicc_id / public_key_t / k_sym / r_bio / salt），
     * 供后端 /api/v1/auth/register 使用。
     */
    fun getRegisterInfo(nvramDirPath: String): JSONObject {
        return JSONObject(nativeGetRegisterInfo(nvramDirPath))
    }

    // ================================================================
    // Phase 1-2 聚合：承诺生成 + 预计算 + 计数器 + R_dynamic
    // 合并 PQC_eUICC_Commit + PQC_PreCompute + 计数器读取 → 1 次 JNI
    // ================================================================

    /**
     * Phase 1-2 聚合：承诺生成 + 预计算
     * @return Pair<Int, NativeLib.PreNetworkResult> (错误码, 结果数据)
     */
    data class PreNetworkResult(
        val wSec: ByteArray,        // K*N*4 = 5120 字节
        val macW: ByteArray,        // 32 字节
        val wTotal: ByteArray,      // K*N*4 = 5120 字节
        val seedY: ByteArray,       // 32 字节
        val rDynamic: ByteArray,    // 32 字节
        val ctrLocal: Long          // 当前计数器值
    )

    fun phase12_CommitPrecompute(
        nvramDirPath: String,
        rBio: ByteArray,
        domainId: String
    ): Pair<Int, PreNetworkResult?> {
        val wSec     = ByteArray(ProtocolConstants.POLYVEC_K_BYTES)
        val macW     = ByteArray(ProtocolConstants.MAC_BYTES)
        val wTotal   = ByteArray(ProtocolConstants.POLYVEC_K_BYTES)
        val seedY    = ByteArray(ProtocolConstants.SEED_BYTES)
        val rDynamic = ByteArray(ProtocolConstants.SEED_BYTES)
        val ctrArr   = LongArray(1)

        val ret = nativePhase12_CommitPrecompute(
            nvramDirPath, rBio, domainId,
            wSec, macW, wTotal, seedY, rDynamic, ctrArr
        )

        if (ret != 0) {
            Log.e(TAG, "Phase12 失败: $ret")
            return Pair(ret, null)
        }

        Log.d(TAG, "Phase12 完成: ctr=${ctrArr[0]}")
        return Pair(ret, PreNetworkResult(wSec, macW, wTotal, seedY, rDynamic, ctrArr[0]))
    }

    // ================================================================
    // Phase 3-5 聚合：挑战 + AuthToken + 掩码计算 + LPA 聚合
    // 合并 PQC_GenChallenge + TEE_AuthToken + ComputeZ + Aggregate → 1 次 JNI
    // ================================================================

    /**
     * Phase 3-5 聚合：生成证明响应
     * @return Pair<Int, NativeLib.ProveResponseResult>
     */
    data class ProveResponseResult(
        val cAgg: ByteArray,        // N*4 = 1024 字节
        val rDynamic: ByteArray,    // 32 字节
        val authToken: ByteArray,   // 32 字节
        val m2Path: ByteArray,      // Merkle 路径（变长，最大约 256 字节）
        val zFinal: ByteArray       // M*N*4 = 8192 字节
    )

    fun phase345_ProveResponse(
        nvramDirPath: String,
        commW: ByteArray,
        cSeed: ByteArray,
        m1Index: Int,
        seedY: ByteArray
    ): Pair<Int, ProveResponseResult?> {
        val cAgg      = ByteArray(ProtocolConstants.POLY_BYTES)
        val rDynamic  = ByteArray(ProtocolConstants.SEED_BYTES)
        val authToken = ByteArray(ProtocolConstants.MAC_BYTES)
        val m2Path    = ByteArray(512)  // Merkle 路径最大 512 字节（depth≤6: 6*(32+1)+8=206）
        val zFinal    = ByteArray(ProtocolConstants.POLYVEC_M_BYTES)

        val ret = nativePhase345_ProveResponse(
            nvramDirPath, commW, cSeed, m1Index, seedY,
            cAgg, rDynamic, authToken, m2Path, zFinal
        )

        if (ret != 0) {
            Log.e(TAG, "Phase345 失败: $ret")
            return Pair(ret, null)
        }

        Log.d(TAG, "Phase345 完成: z_final 已生成")
        return Pair(ret, ProveResponseResult(cAgg, rDynamic, authToken, m2Path, zFinal))
    }

    // ================================================================
    // Phase 6: 原生验证引擎
    // ================================================================

    /**
     * Phase 6: 服务端验证（可选本地执行）
     * @return 0 = 验证通过
     */
    fun phase6_VerifyEngine(
        pkT: ByteArray,
        commW: ByteArray,
        respZ: ByteArray,
        nonceS: ByteArray,
        rDynamic: ByteArray,
        mMask: ByteArray
    ): Int {
        return nativePhase6_VerifyEngine(pkT, commW, respZ, nonceS, rDynamic, mMask)
    }

    // ================================================================
    // 【Master Orchestrator】一键全认证：Phase 0-5 单次 JNI 调用
    // 返回完整 JSON，包含所有 Base64 编码的中间结果
    // ================================================================

    /**
     * 一键全认证（Master Orchestrator）
     * 所有密码学计算在单次 JNI 调用内完成，仅返回最终结果
     *
     * @param nvramDirPath eUICC NVRAM 路径
     * @param rBio         生物特征（32 字节）
     * @param cSeed        服务端挑战种子（32 字节）
     * @param m1Index      生物特征叶子索引
     * @param domainId     运营商域 ID
     * @return Pair<Int, JSONObject?> (错误码, 结果JSON)
     */
    fun runFullAuth(
        nvramDirPath: String,
        rBio: ByteArray,
        cSeed: ByteArray,
        m1Index: Int,
        domainId: String
    ): Pair<Int, JSONObject?> {
        return try {
            val jsonStr = nativeRunFullAuth(nvramDirPath, rBio, cSeed, m1Index, domainId)
            val json = JSONObject(jsonStr)
            if (json.has("error")) {
                Log.e(TAG, "FullAuth 失败: ${json.optString("error")}")
                Pair(-1, json)
            } else {
                Log.d(TAG, "FullAuth 成功: ctr=${json.optLong("ctr_local")}")
                Pair(0, json)
            }
        } catch (e: Exception) {
            Log.e(TAG, "FullAuth 异常", e)
            Pair(-2, null)
        }
    }

    // ================================================================
    // 【兼容层】保留原有 JNI 声明（向后兼容 RegisterActivity / MainActivity）
    // ================================================================

    external fun extractFaceFeature(bitmap: Bitmap): ByteArray
    external fun saveFaceTemplate(nvramDirPath: String, faceFeature: ByteArray): Int
    external fun verifyFace(nvramDirPath: String, freshFeature: ByteArray): Int
    external fun getDeviceStaticSalt(): ByteArray
    external fun buildMerkleRoot(features: Array<ByteArray>, salt: ByteArray): ByteArray
    external fun nativeRegisterDevice(rBio: ByteArray, salt: ByteArray, nvramDirPath: String): Int
    external fun nativeGetRegisterInfo(nvramDirPath: String): String
    external fun pqcPreCompute(): Int
    external fun pqcComputeAndAggregate(cSeed: ByteArray, m1: ByteArray): ByteArray
    external fun PQC_eUICC_Commit(nvramDir: String, outWSec: ByteArray, outMacW: ByteArray): Int
    external fun PQC_PreCompute(inWSec: ByteArray, outWTotal: ByteArray, outSeedY: ByteArray): Int
    external fun PQC_GenChallenge(commW: ByteArray, cSeed: ByteArray, outCAgg: ByteArray): Int
    external fun PQC_ComputeZ_and_Mask(
        nvramDir: String, cAgg: ByteArray, cSeed: ByteArray,
        rDynamic: ByteArray, authToken: ByteArray, outZMasked: ByteArray
    ): Int
    external fun PQC_LPA_Aggregate(zMaskedIn: ByteArray, seedY: ByteArray, outZFinal: ByteArray): Int
    external fun PQC_Get_Current_Ctr(nvramDir: String): Long
    external fun getEID(): String
    external fun getLastAuthTime(): String
    external fun isRegistered(nvramDirPath: String): Int

    // ================================================================
    // ML-KEM (CRYSTALS-Kyber-768) 算子切换隧道
    // ================================================================

    /** ML-KEM 密钥对生成，返回 Pair(pk, sk) */
    fun mlkemKeygen(): Pair<ByteArray, ByteArray>? {
        val pk = ByteArray(ProtocolConstants.MLKEM_PK_BYTES)
        val sk = ByteArray(ProtocolConstants.MLKEM_SK_BYTES)
        val ret = nativeMlkemKeygen(pk, sk)
        return if (ret == 0) Pair(pk, sk) else null
    }

    /** ML-KEM 封装（客户端），返回 Triple(ret, ct, sessionKey) */
    fun mlkemEncapsulate(serverPk: ByteArray): Triple<Int, ByteArray, ByteArray>? {
        val ct = ByteArray(ProtocolConstants.MLKEM_CT_BYTES)
        val ss  = ByteArray(ProtocolConstants.MLKEM_SS_BYTES)
        val ret = nativeMlkemEncapsulate(serverPk, ct, ss)
        return if (ret == 0) Triple(ret, ct, ss) else null
    }

    /** ML-KEM 解封装（服务端），返回共享密钥 */
    fun mlkemDecapsulate(pk: ByteArray, sk: ByteArray, ct: ByteArray): ByteArray? {
        val ss = ByteArray(ProtocolConstants.MLKEM_SS_BYTES)
        val ret = nativeMlkemDecapsulate(pk, sk, ct, ss)
        return if (ret == 0) ss else null
    }

    /** APDU 隧道加密 */
    fun apduEncrypt(sessionKey: ByteArray, plaintext: ByteArray): ByteArray? {
        val ct = ByteArray(plaintext.size + 32) // 预留 MAC 空间
        val ret = nativeApduEncrypt(sessionKey, plaintext, ct)
        // native returns 0 on success, but JNI bridge maps 0→-1 via (ret>0?ret:-1)
        // AES-CTR keystream is length-preserving; output size = plaintext size
        return if (ret == -1 || ret > 0) ct.copyOf(plaintext.size) else null
    }

    /** APDU 隧道解密 */
    fun apduDecrypt(sessionKey: ByteArray, ciphertext: ByteArray): ByteArray? {
        val pt = ByteArray(ciphertext.size)
        val ret = nativeApduDecrypt(sessionKey, ciphertext, pt)
        // JNI 将 native 成功码 0 映射为 -1
        return if (ret == -1 || ret > 0) pt.copyOf(ciphertext.size) else null
    }

    /** APDU 序列化算子切换载荷 */
    fun apduSerializePayload(
        rBioB: ByteArray, rBio: ByteArray, salt: ByteArray,
        credKyc: ByteArray, certA: ByteArray, eid: ByteArray, tNew: ByteArray
    ): ByteArray? {
        val buf = ByteArray(ProtocolConstants.APDU_MAX_PAYLOAD)
        val actualLen = nativeApduSerializePayload(rBioB, rBio, salt, credKyc, certA, eid, tNew, buf)
        return if (actualLen > 0) buf.copyOf(actualLen) else null
    }

    /** APDU 反序列化算子切换载荷 */
    data class ApduPayload(
        val rBioB: ByteArray, val rBio: ByteArray, val salt: ByteArray,
        val credKyc: ByteArray, val certA: ByteArray, val eid: ByteArray, val tNew: ByteArray
    )

    fun apduDeserializePayload(buf: ByteArray): ApduPayload? {
        val rBioB   = ByteArray(32)
        val rBio    = ByteArray(32)
        val salt    = ByteArray(32)
        val credKyc = ByteArray(ProtocolConstants.MLDSA_SIG_BYTES)
        val certA   = ByteArray(ProtocolConstants.CERT_BYTES)
        val eid     = ByteArray(16)
        val tNew    = ByteArray(ProtocolConstants.PK_BYTES)
        val ret = nativeApduDeserializePayload(buf, rBioB, rBio, salt, credKyc, certA, eid, tNew)
        return if (ret == 0) ApduPayload(rBioB, rBio, salt, credKyc, certA, eid, tNew) else null
    }

    // ================================================================
    // GSMA 证书操作 (pqzk_cert.h)
    // ================================================================

    /** 签发运营商证书，返回序列化后的证书字节数组 */
    fun certIssueForMNO(domainId: ByteArray): ByteArray? {
        val cert = ByteArray(ProtocolConstants.CERT_BYTES)
        val ret = nativeCertIssueForMNO(domainId, cert)
        return if (ret == 0) cert else null
    }

    /** 验证证书 */
    fun certVerify(certBytes: ByteArray): Boolean {
        return nativeCertVerify(certBytes) == 0
    }

    /** 签发 CredKYC */
    fun credKycIssue(did: ByteArray, eid: ByteArray, rBio: ByteArray): ByteArray? {
        val credKyc = ByteArray(ProtocolConstants.MLDSA_SIG_BYTES)
        val ret = nativeCredKycIssue(did, eid, rBio, credKyc)
        return if (ret == 0) credKyc else null
    }

    /** 验证 CredKYC */
    fun credKycVerify(did: ByteArray, eid: ByteArray, rBio: ByteArray, credKyc: ByteArray): Boolean {
        return nativeCredKycVerify(did, eid, rBio, credKyc) == 0
    }

    // ================================================================
    // mode_switch — 算子切换
    // ================================================================

    /**
     * 切换 eUICC NVRAM 绑定运营商 (mode_switch)
     * 通过 ML-KEM APDU 隧道安全传输凭证，从运营商 A 切换到运营商 B
     *
     * @param nvramDirPath  eUICC NVRAM 目录路径
     * @param domainIdB     目标运营商 B 的 domain ID (16 字节)
     * @param mnoAId        当前运营商 A 的 domain ID (16 字节)
     * @param mnoASk        当前运营商 A 的密钥 (32 字节)
     * @return 0 = 成功, 负数 = 错误码
     */
    fun modeSwitch(
        nvramDirPath: String,
        domainIdB: ByteArray,
        mnoAId: ByteArray
    ): Int {
        return nativeModeSwitch(nvramDirPath, domainIdB, mnoAId)
    }

    // ================================================================
    // 聚合 JNI 声明（Phase 0-6 + ML-KEM + Cert）
    // ================================================================
    private external fun nativePhase0_GSMAVerify(nvramDir: String, domainId: String): String
    private external fun nativePhase12_CommitPrecompute(
        nvramDir: String, rBio: ByteArray, domainId: String,
        outWSec: ByteArray, outMacW: ByteArray, outWTotal: ByteArray,
        outSeedY: ByteArray, outRDynamic: ByteArray, outCtr: LongArray
    ): Int
    private external fun nativePhase345_ProveResponse(
        nvramDir: String, commW: ByteArray, cSeed: ByteArray,
        m1Index: Int, seedY: ByteArray,
        outCAgg: ByteArray, outRDynamic: ByteArray,
        outAuthToken: ByteArray, outM2: ByteArray, outZFinal: ByteArray
    ): Int
    private external fun nativePhase6_VerifyEngine(
        pkT: ByteArray, commW: ByteArray, respZ: ByteArray,
        nonceS: ByteArray, rDynamic: ByteArray, mMask: ByteArray
    ): Int
    private external fun nativeRunFullAuth(
        nvramDir: String, rBio: ByteArray, cSeed: ByteArray,
        m1Index: Int, domainId: String
    ): String

    // ML-KEM JNI
    private external fun nativeMlkemKeygen(outPk: ByteArray, outSk: ByteArray): Int
    private external fun nativeMlkemEncapsulate(serverPk: ByteArray, outCt: ByteArray, outSs: ByteArray): Int
    private external fun nativeMlkemDecapsulate(pk: ByteArray, sk: ByteArray, ct: ByteArray, outSs: ByteArray): Int
    private external fun nativeApduEncrypt(sessionKey: ByteArray, plaintext: ByteArray, outCt: ByteArray): Int
    private external fun nativeApduDecrypt(sessionKey: ByteArray, ciphertext: ByteArray, outPt: ByteArray): Int
    private external fun nativeApduSerializePayload(
        rBioB: ByteArray, rBio: ByteArray, salt: ByteArray,
        credKyc: ByteArray, certA: ByteArray, eid: ByteArray, tNew: ByteArray, outBuf: ByteArray
    ): Int
    private external fun nativeApduDeserializePayload(
        buf: ByteArray, outRBioB: ByteArray, outRBio: ByteArray, outSalt: ByteArray,
        outCredKyc: ByteArray, outCertA: ByteArray, outEid: ByteArray, outTNew: ByteArray
    ): Int

    // Certificate JNI
    private external fun nativeCertIssueForMNO(domainId: ByteArray, outCert: ByteArray): Int
    private external fun nativeCertVerify(certBytes: ByteArray): Int
    private external fun nativeCredKycIssue(did: ByteArray, eid: ByteArray, rBio: ByteArray, outCredKyc: ByteArray): Int
    private external fun nativeCredKycVerify(did: ByteArray, eid: ByteArray, rBio: ByteArray, credKyc: ByteArray): Int

    // mode_switch JNI
    private external fun nativeModeSwitch(
        nvramDir: String, domainIdB: ByteArray,
        mnoAId: ByteArray
    ): Int
}
