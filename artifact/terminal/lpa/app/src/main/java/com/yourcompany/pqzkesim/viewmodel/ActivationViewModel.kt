package com.yourcompany.pqzkesim.viewmodel

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.yourcompany.pqzkesim.NativeLib
import com.yourcompany.pqzkesim.OperatorPrefsManager
import com.yourcompany.pqzkesim.ProtocolConstants
import com.yourcompany.pqzkesim.data.local.OperatorPreferencesDataStore
import com.yourcompany.pqzkesim.data.model.OperatorConfig
import com.yourcompany.pqzkesim.data.remote.PqcNetworkClient
import com.yourcompany.pqzkesim.repository.ActivationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

sealed class AuthState {
    object Idle : AuthState()
    data class SelectOperator(val operators: List<com.yourcompany.pqzkesim.data.model.OperatorInfo>) : AuthState()
    object BiometricVerify : AuthState()
    data class PrepareTEE(val progress: Int, val label: String) : AuthState()
    data class GenerateProof(val progress: Int, val label: String) : AuthState()
    data class RequestChallenge(val progress: Int) : AuthState()
    data class VerifyChallenge(val progress: Int) : AuthState()
    data class DownloadProfile(val progress: Int) : AuthState()
    data class WriteEUICC(val progress: Int) : AuthState()
    data class Activated(
        val durationMs: Long,
        val sessionId: String,
        val counter: Long,
        val phoneNumber: String = "",
        val operatorName: String = "",
        val activatedAt: String = ""
    ) : AuthState()

    data class BiometricFailed(val reason: String) : AuthState()
    data class NetworkError(val phase: String, val detail: String) : AuthState()
    data class VerifyFailed(val code: Int) : AuthState()
    data class WriteFailed(val reason: String) : AuthState()
    data class ProfileConflict(val detail: String) : AuthState()
}

class ActivationViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "PQZK-AuthVM"
    }

    private val _authState = MutableLiveData<AuthState>(AuthState.Idle)
    val authState: LiveData<AuthState> = _authState

    private val _progressValue = MutableLiveData(0)
    val progressValue: LiveData<Int> = _progressValue

    private val _logMessage = MutableLiveData<String>()
    val logMessage: LiveData<String> = _logMessage

    private val operatorPrefs = OperatorPreferencesDataStore(application)

    private val _timelinePhase = MutableLiveData(0)
    val timelinePhase: LiveData<Int> = _timelinePhase

    fun postLog(msg: String) { _logMessage.postValue(msg) }

    /**
     */
    fun startAuthFlow(
        rBio: ByteArray,
        nvramDirPath: String,
        activeDomainId: String
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            val domainId = activeDomainId.ifEmpty { ProtocolConstants.DOMAIN_ID }
            val startTime = System.currentTimeMillis()

            try {
                _authState.postValue(AuthState.PrepareTEE(5, "Verifying the device GSMA certificate..."))
                _progressValue.postValue(5)
                _logMessage.postValue("🔐 Starting GSMA certificate verification...")

                val phase0Json = NativeLib.phase0_GSMAVerify(nvramDirPath, domainId)
                val eid = phase0Json.optString("eid", "unknown")
                val pkTHex = phase0Json.optString("pk_t_hex", "")
                // Decode the 2336-byte public key from hex for use as T_new in APDU payload
                val pkT: ByteArray = if (pkTHex.isNotEmpty()) {
                    com.yourcompany.pqzkesim.CryptoUtils.hexToBytes(pkTHex)
                } else {
                    ByteArray(ProtocolConstants.PK_BYTES)  // fallback: zero-filled 2336 bytes
                }
                _logMessage.postValue("✅ GSMA certificate verification passed [EID: ${eid.take(8)}...]")

                // ============ Phase 1-2: Commit + PreCompute ============
                _authState.postValue(AuthState.GenerateProof(30, "Generating commitment and precomputation..."))
                _progressValue.postValue(30)
                _timelinePhase.postValue(0)
                _logMessage.postValue("⚙️ Phase 1-2: Commit + PreCompute...")

                val (ret12, pre) = NativeLib.phase12_CommitPrecompute(nvramDirPath, rBio, domainId)
                if (ret12 != 0 || pre == null) {
                    throw ActivationException("Phase1-2 JNI Failed: code=$ret12")
                }
                _logMessage.postValue("✅ Commitment and precomputation complete, ctr_local=${pre.ctrLocal}")

                _authState.postValue(AuthState.RequestChallenge(50))
                _progressValue.postValue(50)
                _timelinePhase.postValue(1)
                _logMessage.postValue("🌐 Requesting backend challenge parameters...")

                val (cSeed, sessionId, m1Index) = fetchChallenge(
                    pre.wTotal, pre.wSec, pre.macW, pre.rDynamic, domainId, rBio
                )
                _logMessage.postValue("✅ Challenge seed received, session=${sessionId.take(8)}...")

                _authState.postValue(AuthState.VerifyChallenge(70))
                _progressValue.postValue(70)
                _timelinePhase.postValue(2)
                _logMessage.postValue("🔬 Phase 3-5: Executing post-quantum proof...")

                val (ret345, prv) = NativeLib.phase345_ProveResponse(
                    nvramDirPath, pre.wTotal, cSeed, m1Index, pre.seedY
                )
                if (ret345 != 0 || prv == null) {
                    throw ActivationException("Phase3-5 JNI Failed: code=$ret345")
                }
                _logMessage.postValue("✅ Post-quantum proof generated")

                _progressValue.postValue(80)
                _timelinePhase.postValue(3)
                _logMessage.postValue("📤 Submitting proof to backend verification...")

                val verifyResult = withContext(Dispatchers.IO) {
                    PqcNetworkClient.submitVerify(
                        prv.zFinal, prv.m2Path, sessionId, domainId
                    )
                }

                if (!verifyResult.verified) {
                    _authState.postValue(AuthState.VerifyFailed(verifyResult.code))
                    _logMessage.postValue("❌ Backend verification failed: ${verifyResult.reason} (code=${verifyResult.code})")
                    return@launch
                }
                _logMessage.postValue("✅ Backend post-quantum verification passed")

                _authState.postValue(AuthState.DownloadProfile(85))
                _progressValue.postValue(85)
                _timelinePhase.postValue(4)
                _logMessage.postValue("📥 Establishing ML-KEM secure tunnel and downloading eSIM profile...")

                val serverPk = withContext(Dispatchers.IO) {
                    PqcNetworkClient.fetchServerPk()
                }
                val effectiveServerPk: ByteArray
                if (serverPk != null && serverPk.size == ProtocolConstants.MLKEM_PK_BYTES) {
                    effectiveServerPk = serverPk
                    _logMessage.postValue("✅ Server ML-KEM public key received")
                } else {
                    val (tmpPk, _) = NativeLib.mlkemKeygen()
                        ?: throw ActivationException("ML-KEM key-pair generation failed")
                    effectiveServerPk = tmpPk
                    _logMessage.postValue("⚠️ Server public key unavailable; using self-encapsulation mode")
                }

                val encapsResult = NativeLib.mlkemEncapsulate(effectiveServerPk)
                    ?: throw ActivationException("ML-KEM encapsulation failed")
                val (_, ct, sessionKey) = encapsResult

                val requestPayload = NativeLib.apduSerializePayload(
                    rBio, rBio, rBio,
                    ByteArray(ProtocolConstants.MLDSA_SIG_BYTES), ByteArray(ProtocolConstants.CERT_BYTES),
                    eid.toByteArray(Charsets.UTF_8).copyOf(16),
                    pkT  // T_new expects PQ_ZK_PUBLICKEY_BYTES (2336 bytes), not 32-byte seedY
                ) ?: throw ActivationException("APDU payload serialization failed")

                val encryptedRequest = NativeLib.apduEncrypt(sessionKey, requestPayload)
                    ?: throw ActivationException("APDU encryption failed")

                val profileResp = withContext(Dispatchers.IO) {
                    PqcNetworkClient.downloadProfile(sessionId, domainId, encryptedRequest)
                } ?: throw ActivationException("Profile download failed: server unreachable")

                val phoneNumber = profileResp.phoneNumber
                _logMessage.postValue("✅ Profile download succeeded [ICCID: ${profileResp.iccid.take(8)}...] [MSISDN: $phoneNumber]")

                _authState.postValue(AuthState.WriteEUICC(92))
                _progressValue.postValue(92)
                _timelinePhase.postValue(5)
                _logMessage.postValue("💾 Decrypting and writing to eUICC NVRAM...")

                val decryptedProfile = NativeLib.apduDecrypt(sessionKey, profileResp.encryptedProfile)
                    ?: throw ActivationException("Profile decryption failed")

                val profileFile = java.io.File(nvramDirPath, "active_profile.bin")
                profileFile.writeBytes(decryptedProfile)
                _logMessage.postValue("✅ Profile written to eUICC NVRAM (${decryptedProfile.size} bytes)")

                val nowStr = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
                    .format(java.util.Date())
                val mnoName = com.yourcompany.pqzkesim.data.model.OperatorConfig
                    .getOperatorByAnyDomain(domainId)?.name ?: domainId

                val esimProfile = com.yourcompany.pqzkesim.data.model.EsimProfile(
                    iccid = profileResp.iccid,
                    mnoId = domainId,
                    mnoName = mnoName,
                    phoneNumber = phoneNumber,
                    state = com.yourcompany.pqzkesim.data.model.EsimProfileState.ACTIVE,
                    activatedAt = nowStr,
                    pkT = pre.seedY
                )

                operatorPrefs.setOperatorProfile(
                    domainId = domainId,
                    iccid = profileResp.iccid,
                    phoneNumber = phoneNumber,
                    operatorName = mnoName,
                    activatedAt = nowStr
                )
                // Legacy fallback for existing consumers during transition
                operatorPrefs.setPhoneNumber(phoneNumber)
                operatorPrefs.setCardActivated(true)
                // Also save to SharedPreferences for HomeFragment log display
                val ctx = getApplication<Application>()
                OperatorPrefsManager.setPhoneNumber(ctx, phoneNumber)
                OperatorPrefsManager.setCardActivated(ctx, true)
                OperatorPrefsManager.setActiveOperator(ctx, mnoName)
                _logMessage.postValue("✅ Profile Bound: $mnoName [$phoneNumber] [ICCID: ${profileResp.iccid.take(8)}...]")

                _progressValue.postValue(100)
                _timelinePhase.postValue(6)
                val duration = System.currentTimeMillis() - startTime
                _authState.postValue(AuthState.Activated(
                    duration, sessionId, pre.ctrLocal,
                    phoneNumber = phoneNumber,
                    operatorName = mnoName,
                    activatedAt = nowStr
                ))

            } catch (e: ActivationException) {
                Log.e(TAG, "Auth flow failed: ${e.message}")
                _logMessage.postValue("❌ ${e.message}")
                _authState.postValue(AuthState.NetworkError("JNI", e.message ?: "unknown"))
            } catch (e: Exception) {
                Log.e(TAG, "Auth flow error: ${e.message}", e)
                _logMessage.postValue("❌ Authentication error: ${e.message}")
                _authState.postValue(AuthState.NetworkError("Unknown", e.message ?: "unknown"))
            }
        }
    }

    /**
     */
    private suspend fun fetchChallenge(
        wTotal: ByteArray, wSec: ByteArray, macW: ByteArray,
        rDynamic: ByteArray, domainId: String, rBio: ByteArray
    ): Triple<ByteArray, String, Int> = withContext(Dispatchers.IO) {
        val response = PqcNetworkClient.getChallenge(wTotal, wSec, macW, rDynamic, domainId)
            ?: throw ActivationException("Backend challenge request failed: server unreachable")
        Triple(response.cSeed, response.sessionId, response.m1Index)
    }

    /**
     * Switch eUICC binding from current operator to a new operator.
     * Uses ML-KEM APDU tunnel for secure payload transport.
     */
    fun switchOperator(
        nvramDirPath: String,
        targetDomainId: String,
        targetDomainIdBytes: ByteArray,
        currentMnoIdBytes: ByteArray
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _logMessage.postValue("🔄 Starting operator switch: → ${OperatorConfig.getOperatorByAnyDomain(targetDomainId)?.name ?: targetDomainId}")
                val ret = NativeLib.modeSwitch(
                    nvramDirPath, targetDomainIdBytes,
                    currentMnoIdBytes
                )
                if (ret == 0) {
                    _logMessage.postValue("✅ Operator switch succeeded")
                } else {
                    _logMessage.postValue("❌ Operator switch failed: code=$ret")
                }
            } catch (e: Exception) {
                _logMessage.postValue("❌ Operator switch error: ${e.message}")
            }
        }
    }

    fun resetState() {
        _authState.value = AuthState.Idle
        _progressValue.value = 0
        _timelinePhase.value = 0
    }
}
