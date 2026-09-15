package com.yourcompany.pqzkesim

import android.graphics.Bitmap
import android.util.Log
import org.json.JSONObject

/**
 *
 */
object NativeLib {
    private const val TAG = "PQZK-Native"

    @Volatile var isDetectorInitialized = false
        private set

    init {
        try {
            System.loadLibrary("pqzkesim")
            Log.d(TAG, "✅ pqzkesim library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Library loading failed: ${e.message}")
        }
    }

    // ================================================================
    // ================================================================

    @Synchronized
    fun initDetector(modelPath: String): Boolean {
        if (isDetectorInitialized) {
            Log.d(TAG, "Detector already initialized; skipping duplicate setup")
            return true
        }
        return try {
            val success = nativeInitDetector(modelPath)
            isDetectorInitialized = success
            Log.d(TAG, "Detector initialization result: $success")
            success
        } catch (e: Exception) {
            Log.e(TAG, "Detector initialization error", e)
            false
        }
    }

    fun processFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int {
        if (!isDetectorInitialized) {
            Log.e(TAG, "Detector is not initialized. Call initDetector() first.")
            return -1
        }
        return try {
            nativeProcessFaceAndGetRbio(matAddr, latestRBio)
        } catch (e: Exception) {
            Log.e(TAG, "Feature extraction error", e)
            -2
        }
    }

    private external fun nativeInitDetector(modelPath: String): Boolean
    private external fun nativeProcessFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int

    // ================================================================
    // ================================================================

    /**
     * @return JSON {eid, cert_valid, mno_id, pk_t_hex, ctr}
     */
    fun phase0_GSMAVerify(nvramDirPath: String, domainId: String): JSONObject {
        val jsonStr = nativePhase0_GSMAVerify(nvramDirPath, domainId)
        return JSONObject(jsonStr)
    }

    /**
     */
    fun getRegisterInfo(nvramDirPath: String): JSONObject {
        return JSONObject(nativeGetRegisterInfo(nvramDirPath))
    }

    // ================================================================
    // ================================================================

    /**
     */
    data class PreNetworkResult(
        val wSec: ByteArray,
        val macW: ByteArray,
        val wTotal: ByteArray,
        val seedY: ByteArray,
        val rDynamic: ByteArray,
        val ctrLocal: Long
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
            Log.e(TAG, "Phase12 Failed: $ret")
            return Pair(ret, null)
        }

        Log.d(TAG, "Phase12 Done: ctr=${ctrArr[0]}")
        return Pair(ret, PreNetworkResult(wSec, macW, wTotal, seedY, rDynamic, ctrArr[0]))
    }

    // ================================================================
    // ================================================================

    /**
     * @return Pair<Int, NativeLib.ProveResponseResult>
     */
    data class ProveResponseResult(
        val cAgg: ByteArray,
        val rDynamic: ByteArray,
        val authToken: ByteArray,
        val m2Path: ByteArray,
        val zFinal: ByteArray
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
        val m2Path    = ByteArray(512)
        val zFinal    = ByteArray(ProtocolConstants.POLYVEC_M_BYTES)

        val ret = nativePhase345_ProveResponse(
            nvramDirPath, commW, cSeed, m1Index, seedY,
            cAgg, rDynamic, authToken, m2Path, zFinal
        )

        if (ret != 0) {
            Log.e(TAG, "Phase345 Failed: $ret")
            return Pair(ret, null)
        }

        Log.d(TAG, "Phase345 complete: z_final generated")
        return Pair(ret, ProveResponseResult(cAgg, rDynamic, authToken, m2Path, zFinal))
    }

    // ================================================================
    // ================================================================

    /**
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
    // ================================================================

    /**
     *
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
                Log.e(TAG, "FullAuth Failed: ${json.optString("error")}")
                Pair(-1, json)
            } else {
                Log.d(TAG, "FullAuth Success: ctr=${json.optLong("ctr_local")}")
                Pair(0, json)
            }
        } catch (e: Exception) {
            Log.e(TAG, "FullAuth error", e)
            Pair(-2, null)
        }
    }

    // ================================================================
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
    // ================================================================

    fun mlkemKeygen(): Pair<ByteArray, ByteArray>? {
        val pk = ByteArray(ProtocolConstants.MLKEM_PK_BYTES)
        val sk = ByteArray(ProtocolConstants.MLKEM_SK_BYTES)
        val ret = nativeMlkemKeygen(pk, sk)
        return if (ret == 0) Pair(pk, sk) else null
    }

    fun mlkemEncapsulate(serverPk: ByteArray): Triple<Int, ByteArray, ByteArray>? {
        val ct = ByteArray(ProtocolConstants.MLKEM_CT_BYTES)
        val ss  = ByteArray(ProtocolConstants.MLKEM_SS_BYTES)
        val ret = nativeMlkemEncapsulate(serverPk, ct, ss)
        return if (ret == 0) Triple(ret, ct, ss) else null
    }

    fun mlkemDecapsulate(pk: ByteArray, sk: ByteArray, ct: ByteArray): ByteArray? {
        val ss = ByteArray(ProtocolConstants.MLKEM_SS_BYTES)
        val ret = nativeMlkemDecapsulate(pk, sk, ct, ss)
        return if (ret == 0) ss else null
    }

    fun apduEncrypt(sessionKey: ByteArray, plaintext: ByteArray): ByteArray? {
        val ct = ByteArray(plaintext.size + 32)
        val ret = nativeApduEncrypt(sessionKey, plaintext, ct)
        // native returns 0 on success, but JNI bridge maps 0→-1 via (ret>0?ret:-1)
        // AES-CTR keystream is length-preserving; output size = plaintext size
        return if (ret == -1 || ret > 0) ct.copyOf(plaintext.size) else null
    }

    fun apduDecrypt(sessionKey: ByteArray, ciphertext: ByteArray): ByteArray? {
        val pt = ByteArray(ciphertext.size)
        val ret = nativeApduDecrypt(sessionKey, ciphertext, pt)
        return if (ret == -1 || ret > 0) pt.copyOf(ciphertext.size) else null
    }

    fun apduSerializePayload(
        rBioB: ByteArray, rBio: ByteArray, salt: ByteArray,
        credKyc: ByteArray, certA: ByteArray, eid: ByteArray, tNew: ByteArray
    ): ByteArray? {
        val buf = ByteArray(ProtocolConstants.APDU_MAX_PAYLOAD)
        val actualLen = nativeApduSerializePayload(rBioB, rBio, salt, credKyc, certA, eid, tNew, buf)
        return if (actualLen > 0) buf.copyOf(actualLen) else null
    }

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
    // ================================================================

    fun certIssueForMNO(domainId: ByteArray): ByteArray? {
        val cert = ByteArray(ProtocolConstants.CERT_BYTES)
        val ret = nativeCertIssueForMNO(domainId, cert)
        return if (ret == 0) cert else null
    }

    fun certVerify(certBytes: ByteArray): Boolean {
        return nativeCertVerify(certBytes) == 0
    }

    fun credKycIssue(did: ByteArray, eid: ByteArray, rBio: ByteArray): ByteArray? {
        val credKyc = ByteArray(ProtocolConstants.MLDSA_SIG_BYTES)
        val ret = nativeCredKycIssue(did, eid, rBio, credKyc)
        return if (ret == 0) credKyc else null
    }

    fun credKycVerify(did: ByteArray, eid: ByteArray, rBio: ByteArray, credKyc: ByteArray): Boolean {
        return nativeCredKycVerify(did, eid, rBio, credKyc) == 0
    }

    // ================================================================
    // ================================================================

    /**
     *
     */
    fun modeSwitch(
        nvramDirPath: String,
        domainIdB: ByteArray,
        mnoAId: ByteArray
    ): Int {
        return nativeModeSwitch(nvramDirPath, domainIdB, mnoAId)
    }

    // ================================================================
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
