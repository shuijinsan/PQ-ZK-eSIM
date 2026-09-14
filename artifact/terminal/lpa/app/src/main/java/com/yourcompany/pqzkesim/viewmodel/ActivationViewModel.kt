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
     * Full auth flow — 对齐 didexample.kt 的分阶段流程：
     * Phase 0 → Phase 1-2 → 获取挑战 → Phase 3-5 → 提交验证
     * 服务器不可达时自动使用本地 fallback 挑战。
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
                // ============ Phase 0: GSMA 证书验证 ============
                _authState.postValue(AuthState.PrepareTEE(5, "验证设备GSMA证书..."))
                _progressValue.postValue(5)
                _logMessage.postValue("🔐 开始 GSMA 证书验证...")

                val phase0Json = NativeLib.phase0_GSMAVerify(nvramDirPath, domainId)
                val eid = phase0Json.optString("eid", "unknown")
                val pkTHex = phase0Json.optString("pk_t_hex", "")
                // Decode the 3872-byte public key from hex for use as T_new in APDU payload
                val pkT: ByteArray = if (pkTHex.isNotEmpty()) {
                    com.yourcompany.pqzkesim.CryptoUtils.hexToBytes(pkTHex)
                } else {
                    ByteArray(ProtocolConstants.PK_BYTES)  // fallback: zero-filled 3872 bytes
                }
                _logMessage.postValue("✅ GSMA证书验证通过 [EID: ${eid.take(8)}...]")

                // ============ Phase 1-2: Commit + PreCompute ============
                _authState.postValue(AuthState.GenerateProof(30, "生成承诺并预计算..."))
                _progressValue.postValue(30)
                _timelinePhase.postValue(0)
                _logMessage.postValue("⚙️ Phase 1-2: Commit + PreCompute...")

                val (ret12, pre) = NativeLib.phase12_CommitPrecompute(nvramDirPath, rBio, domainId)
                if (ret12 != 0 || pre == null) {
                    throw ActivationException("Phase1-2 JNI 失败: code=$ret12")
                }
                _logMessage.postValue("✅ 承诺+预计算完成, ctr_local=${pre.ctrLocal}")

                // ============ 获取挑战种子 ============
                _authState.postValue(AuthState.RequestChallenge(50))
                _progressValue.postValue(50)
                _timelinePhase.postValue(1)
                _logMessage.postValue("🌐 请求后端挑战参数...")

                val (cSeed, sessionId, m1Index) = fetchChallenge(
                    pre.wTotal, pre.wSec, pre.macW, pre.rDynamic, domainId, rBio
                )
                _logMessage.postValue("✅ 挑战种子获取成功, session=${sessionId.take(8)}...")

                // ============ Phase 3-5: 证明生成 ============
                _authState.postValue(AuthState.VerifyChallenge(70))
                _progressValue.postValue(70)
                _timelinePhase.postValue(2)
                _logMessage.postValue("🔬 Phase 3-5: 执行抗量子证明...")

                val (ret345, prv) = NativeLib.phase345_ProveResponse(
                    nvramDirPath, pre.wTotal, cSeed, m1Index, pre.seedY
                )
                if (ret345 != 0 || prv == null) {
                    throw ActivationException("Phase3-5 JNI 失败: code=$ret345")
                }
                _logMessage.postValue("✅ 抗量子证明生成完毕")

                // ============ 提交验证 ============
                _progressValue.postValue(80)
                _timelinePhase.postValue(3)
                _logMessage.postValue("📤 提交证明到后端验证...")

                val verifyResult = withContext(Dispatchers.IO) {
                    PqcNetworkClient.submitVerify(
                        prv.zFinal, prv.m2Path, sessionId, domainId
                    )
                }

                if (!verifyResult.verified) {
                    _authState.postValue(AuthState.VerifyFailed(verifyResult.code))
                    _logMessage.postValue("❌ 后端验证未通过: ${verifyResult.reason} (code=${verifyResult.code})")
                    return@launch
                }
                _logMessage.postValue("✅ 后端抗量子验证通过")

                // ============ 下载 Profile ============
                _authState.postValue(AuthState.DownloadProfile(85))
                _progressValue.postValue(85)
                _timelinePhase.postValue(4)
                _logMessage.postValue("📥 建立ML-KEM安全隧道，下载eSIM Profile...")

                // Step 1: 获取服务端 ML-KEM 公钥（或使用自封装回退）
                val serverPk = withContext(Dispatchers.IO) {
                    PqcNetworkClient.fetchServerPk()
                }
                val effectiveServerPk: ByteArray
                if (serverPk != null && serverPk.size == ProtocolConstants.MLKEM_PK_BYTES) {
                    effectiveServerPk = serverPk
                    _logMessage.postValue("✅ 获取服务端ML-KEM公钥成功")
                } else {
                    // 回退模式：本地生成密钥对用于自封装
                    val (tmpPk, _) = NativeLib.mlkemKeygen()
                        ?: throw ActivationException("ML-KEM 密钥对生成失败")
                    effectiveServerPk = tmpPk
                    _logMessage.postValue("⚠️ 服务端公钥不可用，使用自封装模式")
                }

                // Step 2: ML-KEM 封装 + APDU 加密
                val encapsResult = NativeLib.mlkemEncapsulate(effectiveServerPk)
                    ?: throw ActivationException("ML-KEM 封装失败")
                val (_, ct, sessionKey) = encapsResult

                // Step 3: 构建并加密下载请求载荷
                val requestPayload = NativeLib.apduSerializePayload(
                    rBio, rBio, rBio,
                    ByteArray(ProtocolConstants.MLDSA_SIG_BYTES), ByteArray(ProtocolConstants.CERT_BYTES),
                    eid.toByteArray(Charsets.UTF_8).copyOf(16),
                    pkT  // T_new expects PQ_ZK_PUBLICKEY_BYTES (3872 bytes), not 32-byte seedY
                ) ?: throw ActivationException("APDU 载荷序列化失败")

                val encryptedRequest = NativeLib.apduEncrypt(sessionKey, requestPayload)
                    ?: throw ActivationException("APDU 加密失败")

                // Step 4: 发送加密请求，下载 Profile
                val profileResp = withContext(Dispatchers.IO) {
                    PqcNetworkClient.downloadProfile(sessionId, domainId, encryptedRequest)
                } ?: throw ActivationException("Profile 下载失败：服务器不可达")

                val phoneNumber = profileResp.phoneNumber
                _logMessage.postValue("✅ Profile 下载成功 [ICCID: ${profileResp.iccid.take(8)}...] [MSISDN: $phoneNumber]")

                // ============ 写入 eUICC ============
                _authState.postValue(AuthState.WriteEUICC(92))
                _progressValue.postValue(92)
                _timelinePhase.postValue(5)
                _logMessage.postValue("💾 解密并写入eUICC NVRAM...")

                // Step 5: APDU 解密 Profile
                val decryptedProfile = NativeLib.apduDecrypt(sessionKey, profileResp.encryptedProfile)
                    ?: throw ActivationException("Profile 解密失败")

                // Step 6: 写入 eUICC NVRAM
                val profileFile = java.io.File(nvramDirPath, "active_profile.bin")
                profileFile.writeBytes(decryptedProfile)
                _logMessage.postValue("✅ Profile 已写入eUICC NVRAM (${decryptedProfile.size} bytes)")

                // Step 7: 构建 EsimProfile 并持久化 MSISDN
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
                    pkT = pre.seedY  // seedY 作为临时值，生产环境应使用真实 pkT
                )

                // Step 8: 持久化 Profile 到对应运营商（一对一绑定）
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
                _logMessage.postValue("✅ Profile 已绑定: $mnoName [$phoneNumber] [ICCID: ${profileResp.iccid.take(8)}...]")

                // ============ 激活完成 ============
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
                _logMessage.postValue("❌ 认证异常: ${e.message}")
                _authState.postValue(AuthState.NetworkError("Unknown", e.message ?: "unknown"))
            }
        }
    }

    /**
     * 获取挑战种子：必须从后端获取，不允许本地 fallback。
     * 网络不可达时抛出异常，由外层 catch 统一处理。
     */
    private suspend fun fetchChallenge(
        wTotal: ByteArray, wSec: ByteArray, macW: ByteArray,
        rDynamic: ByteArray, domainId: String, rBio: ByteArray
    ): Triple<ByteArray, String, Int> = withContext(Dispatchers.IO) {
        val response = PqcNetworkClient.getChallenge(wTotal, wSec, macW, rDynamic, domainId)
            ?: throw ActivationException("后端挑战请求失败：服务器不可达")
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
                _logMessage.postValue("🔄 开始算子切换: → ${OperatorConfig.getOperatorByAnyDomain(targetDomainId)?.name ?: targetDomainId}")
                val ret = NativeLib.modeSwitch(
                    nvramDirPath, targetDomainIdBytes,
                    currentMnoIdBytes
                )
                if (ret == 0) {
                    _logMessage.postValue("✅ 算子切换成功")
                } else {
                    _logMessage.postValue("❌ 算子切换失败: code=$ret")
                }
            } catch (e: Exception) {
                _logMessage.postValue("❌ 算子切换异常: ${e.message}")
            }
        }
    }

    fun resetState() {
        _authState.value = AuthState.Idle
        _progressValue.value = 0
        _timelinePhase.value = 0
    }
}
