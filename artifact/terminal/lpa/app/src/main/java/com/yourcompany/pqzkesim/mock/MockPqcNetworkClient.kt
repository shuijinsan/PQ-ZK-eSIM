package com.yourcompany.pqzkesim.mock

import android.util.Log
import com.yourcompany.pqzkesim.ProtocolConstants
import com.yourcompany.pqzkesim.data.remote.ChallengeResponse
import com.yourcompany.pqzkesim.data.remote.ProfileResponse
import com.yourcompany.pqzkesim.data.remote.VerifyResult
import kotlinx.coroutines.delay
import java.security.SecureRandom
import java.util.UUID

/**
 * Centralized mock backend — provides realistic simulated data for the entire
 * PQC eSIM activation flow so the frontend can be exercised without a deployed server.
 *
 * Design:
 *  - fetchServerPk() returns null  → triggers ActivationViewModel's existing
 *    self-encapsulation fallback (client generates its own ML-KEM keypair).
 *  - downloadProfile() echoes back the client-encrypted request as the
 *    "encrypted profile".  Because the client encrypted it with its own session key,
 *    apduDecrypt() succeeds naturally — no crypto keys leave the native layer.
 *  - A stable sessionId ties getChallenge → submitVerify → downloadProfile together.
 */
object MockPqcNetworkClient {

    private const val TAG = "PQZK-Mock"

    @Volatile
    private var currentSessionId: String = freshSessionId()

    // 每个运营商的手机号尾号计数器，每次认证递增，确保每次下发唯一号码
    @Volatile private var cmccCounter = 1
    @Volatile private var cuccCounter = 1
    @Volatile private var ctccCounter = 1
    @Volatile private var iccidCounter = 42L

    private fun freshSessionId(): String = "mock-session-${UUID.randomUUID()}"

    /** Reset the session id for a new activation round. */
    fun resetSession() {
        currentSessionId = freshSessionId()
        Log.d(TAG, "[Mock] 会话已重置: ${currentSessionId.take(12)}...")
    }

    // ──── /api/v1/auth/challenge ────

    suspend fun getChallenge(
        wTotal: ByteArray,
        wSec: ByteArray,
        macW: ByteArray,
        rDynamic: ByteArray,
        domainId: String
    ): ChallengeResponse {
        delay(300L) // simulated network latency
        val cSeed = ByteArray(ProtocolConstants.SEED_BYTES).also {
            SecureRandom().nextBytes(it)
        }
        Log.d(TAG, "[Mock] getChallenge → session=${currentSessionId.take(12)}...  m1Index=0")
        return ChallengeResponse(
            cSeed     = cSeed,
            sessionId = currentSessionId,
            m1Index   = 0   // must be < tree.n_leaves; placeholder tree has 1 leaf
        )
    }

    // ──── /api/v1/auth/verify ────

    suspend fun submitVerify(
        zFinal: ByteArray,
        m2Path: ByteArray,
        sessionId: String,
        domainId: String
    ): VerifyResult {
        delay(300L)
        Log.d(TAG, "[Mock] submitVerify → verified=true  session=${sessionId.take(12)}...")
        return VerifyResult(verified = true, reason = "mock_ok", code = 0)
    }

    // ──── /api/v1/auth/server_pk ────

    suspend fun fetchServerPk(): ByteArray? {
        delay(200L)
        Log.d(TAG, "[Mock] fetchServerPk → null (triggers self-encapsulation fallback)")
        // Returning null triggers the existing self-encapsulation branch in
        // ActivationViewModel, which generates a client-side ML-KEM keypair
        // and uses its own public key for encapsulation.
        return null
    }

    // ──── /api/v1/auth/profile/download ────

    suspend fun downloadProfile(
        sessionId: String,
        domainId: String,
        encryptedRequest: ByteArray
    ): ProfileResponse {
        delay(400L)
        // Echo the client-encrypted request back as the "encrypted profile".
        Log.d(TAG, "[Mock] downloadProfile → echo encrypted request (${encryptedRequest.size} bytes)")

        // 每次认证生成唯一手机号（尾号递增）和唯一 ICCID
        val phoneNumber: String
        val iccid: String
        synchronized(this) {
            val counter: Int
            val prefix: String
            when {
                domainId.contains("CMCC", ignoreCase = true) -> {
                    counter = cmccCounter++
                    prefix = "+86 138-0001"
                }
                domainId.contains("CUCC", ignoreCase = true) -> {
                    counter = cuccCounter++
                    prefix = "+86 186-0002"
                }
                domainId.contains("CTCC", ignoreCase = true) -> {
                    counter = ctccCounter++
                    prefix = "+86 189-0003"
                }
                else -> {
                    counter = 0
                    prefix = "+86 138-0000"
                }
            }
            phoneNumber = "${prefix}-${counter.toString().padStart(4, '0')}"
            iccid = "8986000000000000${(iccidCounter++).toString().padStart(4, '0')}"
        }

        return ProfileResponse(
            encryptedProfile = encryptedRequest,
            iccid       = iccid,
            phoneNumber = phoneNumber
        )
    }
}
