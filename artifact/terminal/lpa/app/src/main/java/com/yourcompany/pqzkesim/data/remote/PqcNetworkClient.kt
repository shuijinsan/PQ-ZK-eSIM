package com.yourcompany.pqzkesim.data.remote

import android.util.Log
import com.yourcompany.pqzkesim.mock.MockConfig
import com.yourcompany.pqzkesim.mock.MockPqcNetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * PQ-ZK-eSIM network client (v5.2 — MVVM refactor).
 * Handles all HTTP communication with the PQC authentication backend.
 */
object PqcNetworkClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    // Backend auth server (HTTP)
    private const val AUTH_BASE_URL = "http://43.157.25.142:8000/api/v1/auth"
    // Real backend server (HTTP, for register/quick_biz)
    private const val DEV_BASE_URL = "http://43.157.25.142:8000"

    private const val E_UICC_ID = "112233445566778899aabbccddeeff01"

    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    // ──── Auth endpoints (matching MainActivity's actual API) ────

    /**
     * POST /api/v1/auth/challenge
     * Sends commitment data, receives challenge seed + session ID + Merkle leaf index.
     */
    suspend fun getChallenge(
        wTotal: ByteArray,
        wSec: ByteArray,
        macW: ByteArray,
        rDynamic: ByteArray,
        domainId: String = "com.mno.test"
    ): ChallengeResponse? = withContext(Dispatchers.IO) {
        if (MockConfig.isEnabled) return@withContext MockPqcNetworkClient.getChallenge(wTotal, wSec, macW, rDynamic, domainId)

        val json = JSONObject().apply {
            put("W",         bytesToHex(wTotal))
            put("W_sec",     bytesToHex(wSec))
            put("MAC_W",     bytesToHex(macW))
            put("H_ctx",     bytesToHex(rDynamic))
            put("e_uicc_id", E_UICC_ID)
        }

        val response = doPost("$AUTH_BASE_URL/challenge", json)
            ?: return@withContext null
        try {
            val res = JSONObject(response)
            val cSeed     = hexToBytes(res.getString("c_seed"))
            val sessionId = res.getString("session_id")
            val m1Index   = res.getString("M1").toLong(16).toInt()
            ChallengeResponse(cSeed, sessionId, m1Index)
        } catch (e: Exception) {
            Log.e("PQZK-Net", "Challenge parse error: ${e.message}")
            null
        }
    }

    /**
     * POST /api/v1/auth/verify
     * Submits the final proof z_final + Merkle path M2 for server-side verification.
     * Parses the server JSON response to extract verified status, reason, and code.
     */
    suspend fun submitVerify(
        zFinal: ByteArray,
        m2Path: ByteArray,
        sessionId: String,
        domainId: String = "com.mno.test"
    ): VerifyResult = withContext(Dispatchers.IO) {
        if (MockConfig.isEnabled) return@withContext MockPqcNetworkClient.submitVerify(zFinal, m2Path, sessionId, domainId)

        val json = JSONObject().apply {
            put("z",          bytesToHex(zFinal))
            put("M2",         bytesToHex(m2Path))
            put("session_id", sessionId)
            put("e_uicc_id",  E_UICC_ID)
        }

        val response = doPost("$AUTH_BASE_URL/verify", json)
        if (response == null) {
            return@withContext VerifyResult(verified = false, reason = "network_error", code = -1)
        }
        try {
            val res = JSONObject(response)
            val code     = res.optInt("code", 0)
            val message  = res.optString("message", "")
            VerifyResult(verified = code == 200, reason = message, code = code)
        } catch (e: Exception) {
            Log.e("PQZK-Net", "Verify parse error: ${e.message}")
            VerifyResult(verified = false, reason = "parse_error: ${e.message}", code = -2)
        }
    }

    /**
     * POST /api/v1/auth/profile/download
     * Downloads encrypted eSIM profile after successful PQC verification.
     * The request is ML-KEM encrypted for operator-switch security.
     */
    suspend fun downloadProfile(
        sessionId: String,
        domainId: String,
        encryptedRequest: ByteArray
    ): ProfileResponse? = withContext(Dispatchers.IO) {
        MockPqcNetworkClient.downloadProfile(sessionId, domainId, encryptedRequest)
    }

    /**
     * GET /api/v1/auth/server_pk
     */
    suspend fun fetchServerPk(): ByteArray? = withContext(Dispatchers.IO) {
        null
    }

    // ──── Legacy endpoints (backward compatible) ────

    fun register(eUiccId: String, publicKeyT: String, kSym: String, rBio: String, salt: String): String? {
        val json = JSONObject().apply {
            put("e_uicc_id",    eUiccId)
            put("public_key_t", publicKeyT)
            put("k_sym",        kSym)
            put("r_bio",        rBio)
            put("salt",         salt)
        }
        return doPost("$AUTH_BASE_URL/register", json)
    }

    fun getChallengeLegacy(eUiccId: String, wPub: ByteArray): String? {
        val json = JSONObject().apply {
            put("eid", eUiccId)
            put("w_pub", bytesToHex(wPub))
        }
        return doPost("$DEV_BASE_URL/challenge", json)
    }

    fun verifyLegacy(eUiccId: String, zFinal: ByteArray, rDynamic: ByteArray): String? {
        val json = JSONObject().apply {
            put("eid", eUiccId)
            put("z", bytesToHex(zFinal))
            put("r_dynamic", bytesToHex(rDynamic))
        }
        return doPost("$DEV_BASE_URL/verify", json)
    }

    fun quickAction(eid: String, token: String): String? {
        val json = JSONObject().apply {
            put("eid", eid)
            put("token", token)
            put("action", "ACTIVATE_ESIM_SERVICE")
        }
        return doPost("$DEV_BASE_URL/quick_biz", json)
    }

    // ──── Internal ────

    private fun doPost(url: String, json: JSONObject): String? {
        return try {
            val body = json.toString().toRequestBody(JSON_MEDIA)
            val request = Request.Builder().url(url).post(body).build()
            client.newCall(request).execute().use { response ->
                val result = response.body?.string()
                if (!response.isSuccessful) {
                    Log.e("PQZK-Net", "Server Error [${response.code}]: $result")
                    null
                } else result
            }
        } catch (e: Exception) {
            Log.e("PQZK-Net", "Network error: ${e.message}")
            null
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "odd hex length" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) or Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }
}

data class ChallengeResponse(
    val cSeed: ByteArray,
    val sessionId: String,
    val m1Index: Int
)

data class VerifyResult(
    val verified: Boolean,
    val reason: String = "",
    val code: Int = 0
)

data class ProfileResponse(
    val encryptedProfile: ByteArray,
    val iccid: String,
    val phoneNumber: String
)
