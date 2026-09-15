package com.yourcompany.pqzkesim.repository


import com.yourcompany.pqzkesim.NativeLib
import com.yourcompany.pqzkesim.data.remote.ChallengeResponse
import com.yourcompany.pqzkesim.data.remote.PqcNetworkClient
import com.yourcompany.pqzkesim.data.remote.ProfileResponse
import com.yourcompany.pqzkesim.data.remote.VerifyResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

class ActivationRepository {

    data class PreComputeResult(
        val wSec: ByteArray,
        val macW: ByteArray,
        val wTotal: ByteArray,
        val seedY: ByteArray,
        val rDynamic: ByteArray,
        val ctrLocal: Long
    )

    data class ProveResult(
        val cAgg: ByteArray,
        val rDynamic: ByteArray,
        val authToken: ByteArray,
        val m2Path: ByteArray,
        val zFinal: ByteArray
    )

    suspend fun gsmaVerify(nvramDir: String, domainId: String): JSONObject =
        withContext(Dispatchers.IO) {
            NativeLib.phase0_GSMAVerify(nvramDir, domainId)
        }

    suspend fun commitAndPreCompute(nvramDir: String, rBio: ByteArray, domainId: String)
            : PreComputeResult = withContext(Dispatchers.IO) {
        val (ret, result) = NativeLib.phase12_CommitPrecompute(nvramDir, rBio, domainId)
        if (ret != 0 || result == null) {
            throw ActivationException("Phase12 JNI failed: code=$ret")
        }
        PreComputeResult(
            wSec = result.wSec, macW = result.macW,
            wTotal = result.wTotal, seedY = result.seedY,
            rDynamic = result.rDynamic, ctrLocal = result.ctrLocal
        )
    }

    suspend fun proveResponse(nvramDir: String, commW: ByteArray, cSeed: ByteArray,
                              m1Index: Int, seedY: ByteArray): ProveResult =
        withContext(Dispatchers.IO) {
            val (ret, result) = NativeLib.phase345_ProveResponse(
                nvramDir, commW, cSeed, m1Index, seedY
            )
            if (ret != 0 || result == null) {
                throw ActivationException("Phase345 JNI failed: code=$ret")
            }
            ProveResult(
                cAgg = result.cAgg, rDynamic = result.rDynamic,
                authToken = result.authToken, m2Path = result.m2Path,
                zFinal = result.zFinal
            )
        }

    suspend fun getChallenge(wTotal: ByteArray, wSec: ByteArray, macW: ByteArray,
                             rDynamic: ByteArray, domainId: String = "com.mno.test")
            : ChallengeResponse = withContext(Dispatchers.IO) {
        PqcNetworkClient.getChallenge(wTotal, wSec, macW, rDynamic, domainId)
            ?: throw ActivationException("Server challenge request failed")
    }

    suspend fun submitVerify(zFinal: ByteArray, m2Path: ByteArray, sessionId: String,
                             domainId: String = "com.mno.test"): VerifyResult =
        withContext(Dispatchers.IO) {
            PqcNetworkClient.submitVerify(zFinal, m2Path, sessionId, domainId)
        }

    suspend fun downloadProfile(sessionId: String, domainId: String,
                                encryptedRequest: ByteArray): ProfileResponse =
        withContext(Dispatchers.IO) {
            PqcNetworkClient.downloadProfile(sessionId, domainId, encryptedRequest)
                ?: throw ActivationException("Profile download failed")
        }
}

class ActivationException(message: String) : Exception(message)
