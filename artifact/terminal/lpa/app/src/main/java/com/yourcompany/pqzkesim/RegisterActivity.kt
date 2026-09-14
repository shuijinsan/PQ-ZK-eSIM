package com.yourcompany.pqzkesim

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.*

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.yourcompany.pqzkesim.repository.UserRepository
import com.yourcompany.pqzkesim.data.remote.PqcNetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.opencv.android.CameraBridgeViewBase
import org.opencv.android.OpenCVLoader
import org.opencv.core.Core
import org.opencv.core.Mat
import java.io.File

class RegisterActivity : BaseLocaleActivity(), CameraBridgeViewBase.CvCameraViewListener2 {

    companion object {
        private const val TAG = "PQZK-Register"
    }

    // ──── Step state machine ────
    private enum class RegisterStep(val num: Int) {
        USER_INFO(1),
        TEE_CHECK(2),
        KYBER_KEYGEN(3),
        FINGERPRINT(4),
        FACE(5),
        SECURITY_BIND(6),
        DONE(7)
    }

    private fun RegisterStep.getLabel(): String = when (this) {
        RegisterStep.USER_INFO -> getString(R.string.register_step_1_label)
        RegisterStep.TEE_CHECK -> getString(R.string.register_step_2_label)
        RegisterStep.KYBER_KEYGEN -> getString(R.string.register_step_3_label)
        RegisterStep.FINGERPRINT -> getString(R.string.register_step_4_label)
        RegisterStep.FACE -> getString(R.string.register_step_5_label)
        RegisterStep.SECURITY_BIND -> getString(R.string.register_step_6_label)
        RegisterStep.DONE -> getString(R.string.register_step_7_label)
    }

    private var currentStep = RegisterStep.USER_INFO

    // ──── Collected data ────
    private var faceFeature: ByteArray? = null
    private var kyberPk: ByteArray? = null
    private var kyberSk: ByteArray? = null

    // ──── Camera ────
    private var isProcessing = false
    private var captureRequest = false
    private var hasScheduledCapture = false
    private val nvramDirPath by lazy { filesDir.absolutePath + "/euicc_nvram" }

    // ──── Views ────
    private lateinit var tvStepIndicator: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var layoutUserInfo: LinearLayout
    private lateinit var etUserName: EditText
    private lateinit var layoutStepInit: LinearLayout
    private lateinit var progressInit: ProgressBar
    private lateinit var tvInitStatus: TextView
    private lateinit var tvInitResult: TextView
    private lateinit var layoutStepFace: FrameLayout
    private lateinit var cameraView: CameraBridgeViewBase
    private lateinit var btnNextStep: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_register)

        bindViews()
        showStep(RegisterStep.USER_INFO)

        btnNextStep.setOnClickListener { onNextClicked() }
    }

    // ──── View binding ────

    private fun bindViews() {
        tvStepIndicator = findViewById(R.id.tv_step_indicator)
        tvStatusDetail   = findViewById(R.id.tv_status_detail)
        layoutUserInfo   = findViewById(R.id.layout_step_user_info)
        etUserName       = findViewById(R.id.et_user_name)
        layoutStepInit   = findViewById(R.id.layout_step_init)
        progressInit     = findViewById(R.id.progress_init)
        tvInitStatus     = findViewById(R.id.tv_init_status)
        tvInitResult     = findViewById(R.id.tv_init_result)
        layoutStepFace   = findViewById(R.id.layout_step_face)
        cameraView       = findViewById(R.id.register_camera_view)
        btnNextStep      = findViewById(R.id.btn_next_step)

        cameraView.setCvCameraViewListener(this)
        cameraView.setCameraPermissionGranted()
    }

    // ──── Step UI ────

    private fun showStep(step: RegisterStep) {
        tvStepIndicator.text = getString(R.string.register_step_indicator, step.num, step.getLabel())

        // Hide all content panels
        layoutUserInfo.visibility = View.GONE
        layoutStepInit.visibility = View.GONE
        layoutStepFace.visibility = View.GONE
        tvInitResult.visibility = View.GONE
        tvStatusDetail.visibility = View.VISIBLE
        btnNextStep.isEnabled = true
        btnNextStep.text = "下一步"

        when (step) {
            RegisterStep.USER_INFO -> {
                tvStatusDetail.text = "请输入您的昵称"
                layoutUserInfo.visibility = View.VISIBLE
            }
            RegisterStep.TEE_CHECK -> {
                tvStatusDetail.text = "正在检测 TEE 安全环境..."
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "正在验证 TEE 安全环境..."
                btnNextStep.isEnabled = false
            }
            RegisterStep.KYBER_KEYGEN -> {
                tvStatusDetail.text = "正在生成抗量子密钥..."
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "正在生成 Kyber-768 主密钥..."
                btnNextStep.isEnabled = false
            }
            RegisterStep.FINGERPRINT -> {
                tvStatusDetail.text = "请点击按钮采集指纹特征"
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "准备采集指纹..."
                tvInitResult.visibility = View.GONE
                btnNextStep.text = "开始采集指纹"
            }
            RegisterStep.FACE -> {
                tvStatusDetail.text = "请正对摄像头完成人脸采集"
                layoutStepFace.visibility = View.VISIBLE
                btnNextStep.text = "准备中..."
                btnNextStep.isEnabled = false
                enableCamera()
            }
            RegisterStep.SECURITY_BIND -> {
                tvStatusDetail.text = "正在执行安全绑定..."
                layoutStepInit.visibility = View.VISIBLE
                layoutStepFace.visibility = View.GONE
                tvInitStatus.text = "正在融合生物特征并注册设备..."
                tvInitResult.visibility = View.GONE
                btnNextStep.isEnabled = false
            }
            RegisterStep.DONE -> {
                tvStatusDetail.text = ""
                tvStatusDetail.visibility = View.GONE
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "✅ 所有安全模块已就绪"
                tvInitResult.visibility = View.VISIBLE
                tvInitResult.text = "设备已成功注册，请点击下方按钮进入主页"
                btnNextStep.text = "进入主页"
            }
        }
    }

    // ──── Next button ────

    private fun onNextClicked() {
        when (currentStep) {
            RegisterStep.USER_INFO -> {
                val name = etUserName.text.toString().trim()
                if (name.isEmpty()) {
                    Toast.makeText(this, getString(R.string.register_toast_enter_name), Toast.LENGTH_SHORT).show()
                    return
                }
                lifecycleScope.launch(Dispatchers.IO) {
                    val repo = UserRepository(filesDir, File(nvramDirPath))
                    repo.saveNickname(name)
                    withContext(Dispatchers.Main) {
                        advanceTo(RegisterStep.TEE_CHECK)
                    }
                }
            }
            RegisterStep.FINGERPRINT -> {
                btnNextStep.isEnabled = false
                btnNextStep.text = "请在对话框中验证指纹..."
                showFingerprintPrompt()
            }
            RegisterStep.DONE -> {
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            }
            else -> {} // auto-advancing steps are handled in advanceTo()
        }
    }

    private fun advanceTo(next: RegisterStep) {
        currentStep = next
        showStep(next)
        when (next) {
            RegisterStep.TEE_CHECK    -> performTeeCheck()
            RegisterStep.KYBER_KEYGEN -> performKyberKeygen()
            RegisterStep.SECURITY_BIND -> performSecurityBind()
            else -> {}
        }
    }

    // ──── Step 2: TEE environment check ────

    private fun performTeeCheck() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Ensure NVRAM directory
                val nvram = File(nvramDirPath)
                if (!nvram.exists()) nvram.mkdirs()

                // Preload face detection model
                val modelFile = File(filesDir, "haarcascade_frontalface_alt.xml")
                if (!modelFile.exists()) {
                    assets.open("haarcascade_frontalface_alt.xml").use { input ->
                        modelFile.outputStream().use { output -> input.copyTo(output) }
                    }
                }
                val detectorOk = NativeLib.initDetector(modelFile.absolutePath)

                withContext(Dispatchers.Main) {
                    if (detectorOk) {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "✅ TEE 环境正常，人脸模型已加载"
                    } else {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "⚠️ 模型加载失败，人脸采集可能不可用"
                    }
                    delay(800)
                    advanceTo(RegisterStep.KYBER_KEYGEN)
                }
            } catch (e: Exception) {
                Log.e(TAG, "TEE check failed", e)
                withContext(Dispatchers.Main) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "⚠️ TEE 检测异常: ${e.message}"
                    delay(1000)
                    advanceTo(RegisterStep.KYBER_KEYGEN)
                }
            }
        }
    }

    // ──── Step 3: Kyber-768 key generation ────

    private fun performKyberKeygen() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val result = NativeLib.mlkemKeygen()
                if (result != null) {
                    kyberPk = result.first
                    kyberSk = result.second
                    Log.d(TAG, "✅ Kyber-768 密钥对生成成功 (pk=${kyberPk!!.size}B, sk=${kyberSk!!.size}B)")
                } else {
                    Log.e(TAG, "Kyber 密钥对生成返回 null")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Kyber keygen error", e)
            }

            withContext(Dispatchers.Main) {
                if (kyberPk != null) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "✅ Kyber-768 主密钥已生成"
                } else {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "⚠️ 密钥生成失败，将使用备用方案"
                }
                delay(600)
                advanceTo(RegisterStep.FINGERPRINT)
            }
        }
    }

    // ──── Fingerprint prompt ────

    private fun showFingerprintPrompt() {
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    Log.d(TAG, "指纹认证成功")
                    tvInitStatus.text = getString(R.string.register_fingerprint_ok)
                    advanceTo(RegisterStep.FACE)
                }
                override fun onAuthenticationFailed() {
                    Log.d(TAG, "指纹不匹配")
                    Toast.makeText(this@RegisterActivity, getString(R.string.register_toast_fingerprint_mismatch), Toast.LENGTH_SHORT).show()
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "开始采集指纹"
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.e(TAG, "指纹认证错误 [$errorCode]: $errString")
                    Toast.makeText(this@RegisterActivity, getString(R.string.register_toast_auth_error, errString), Toast.LENGTH_SHORT).show()
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "开始采集指纹"
                }
            })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.register_biometric_title))
                .setDescription(getString(R.string.register_biometric_desc))
                .setNegativeButtonText(getString(R.string.register_biometric_cancel))
                .build()
        )
    }

    // ──── Camera (Step 5: Face) ────

    private fun enableCamera() {
        if (!OpenCVLoader.initLocal()) {
            Log.e(TAG, "OpenCV 初始化失败")
        }
        layoutStepFace.visibility = View.VISIBLE
        cameraView.postDelayed({
            cameraView.enableView()
            btnNextStep.text = "请正对摄像头..."
            btnNextStep.isEnabled = false
        }, 300)

        // Auto-capture after 2 seconds
        cameraView.postDelayed({
            if (currentStep == RegisterStep.FACE && !isProcessing) {
                isProcessing = true
                captureRequest = true
            }
        }, 2000)
    }

    private fun disableCamera() {
        try { cameraView.disableView() } catch (_: Exception) {}
    }

    override fun onCameraViewStarted(width: Int, height: Int) {}
    override fun onCameraViewStopped() {}

    override fun onCameraFrame(inputFrame: CameraBridgeViewBase.CvCameraViewFrame): Mat {
        val rgba = inputFrame.rgba()
        if (rgba.empty()) return rgba

        // 采集帧与主界面认证保持完全一致的方向处理：旋转90° + 镜像
        if (isProcessing && currentStep == RegisterStep.FACE && captureRequest) {
            captureRequest = false
            hasScheduledCapture = false
            val frameMat = rgba.clone()
            Core.rotate(frameMat, frameMat, Core.ROTATE_90_COUNTERCLOCKWISE)
            Core.flip(frameMat, frameMat, 1)

            lifecycleScope.launch(Dispatchers.Default) {
                val bmp = Bitmap.createBitmap(frameMat.cols(), frameMat.rows(), Bitmap.Config.ARGB_8888)
                org.opencv.android.Utils.matToBitmap(frameMat, bmp)
                frameMat.release()
                withContext(Dispatchers.Main) { handleFaceCaptured(bmp) }
            }
        } else if (isProcessing && currentStep == RegisterStep.FACE && !hasScheduledCapture) {
            hasScheduledCapture = true
            cameraView.postDelayed({ captureRequest = true }, 1000)
        }

        // 预览镜像，与手机自拍看到的一致
        val preview = rgba.clone()
        Core.flip(preview, preview, 1)
        return preview
    }

    private fun handleFaceCaptured(faceBitmap: Bitmap) {
        isProcessing = false
        disableCamera()
        layoutStepFace.visibility = View.GONE

        lifecycleScope.launch(Dispatchers.Default) {
            try {
                val face = NativeLib.extractFaceFeature(faceBitmap)
                faceFeature = face
                NativeLib.saveFaceTemplate(nvramDirPath, face)
                Log.d(TAG, "✅ 人脸特征采集完成")
                withContext(Dispatchers.Main) { advanceTo(RegisterStep.SECURITY_BIND) }
            } catch (e: Exception) {
                Log.e(TAG, "Face extraction failed", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@RegisterActivity, "人脸采集失败", Toast.LENGTH_SHORT).show()
                    showStep(RegisterStep.FACE)
                }
            }
        }
    }

    // ──── Step 6: Security bind (Merkle root + device registration) ────

    private fun performSecurityBind() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val ff = faceFeature
                if (ff == null) {
                    withContext(Dispatchers.Main) {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "❌ 生物特征数据缺失，请重试"
                        btnNextStep.isEnabled = true
                        btnNextStep.text = "重新开始"
                    }
                    return@launch
                }

                // Step 1: Get device salt
                val salt = NativeLib.getDeviceStaticSalt()
                Log.d(TAG, "Salt obtained: ${salt.size} bytes")

                // Step 2: Build Merkle root from the face feature
                val rBio = NativeLib.buildMerkleRoot(arrayOf(ff), salt)
                Log.d(TAG, "Merkle root r_bio: ${rBio.size} bytes")

                // Step 3: Register device — binds r_bio + master key + device identity + NVRAM
                val regResult = NativeLib.nativeRegisterDevice(rBio, salt, nvramDirPath)
                Log.d(TAG, "nativeRegisterDevice result: $regResult")

                // Step 4: Verify registration
                val verified = NativeLib.isRegistered(nvramDirPath) == 1
                Log.d(TAG, "isRegistered verification: $verified")

                withContext(Dispatchers.Main) {
                    if (regResult == 0 && verified) {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "✅ 安全绑定完成 | r_bio + 主密钥 + 设备身份已落盘"
                        // 后台注册到后端 SM-DP+
                        lifecycleScope.launch(Dispatchers.IO) { registerToBackend() }
                        delay(800)
                        advanceTo(RegisterStep.DONE)
                    } else {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "❌ 设备注册失败 (code=$regResult, verified=$verified)"
                        btnNextStep.isEnabled = true
                        btnNextStep.text = "重试"
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Security bind failed", e)
                withContext(Dispatchers.Main) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "❌ 安全绑定异常: ${e.message}"
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "重试"
                }
            }
        }
    }

    private fun registerToBackend() {
        try {
            val info = NativeLib.getRegisterInfo(nvramDirPath)
            val resp = PqcNetworkClient.register(
                info.optString("e_uicc_id"),
                info.optString("public_key_t"),
                info.optString("k_sym"),
                info.optString("r_bio"),
                info.optString("salt")
            )
            Log.d(TAG, "后端注册结果: $resp")
        } catch (e: Throwable) {
            Log.e(TAG, "后端注册失败", e)
        }
    }

    // ──── Lifecycle ────

    override fun onResume() {
        super.onResume()
        if (currentStep == RegisterStep.FACE && OpenCVLoader.initLocal()) {
            cameraView.enableView()
        }
    }

    override fun onPause() {
        super.onPause()
        if (currentStep == RegisterStep.FACE) {
            disableCamera()
        }
    }

    override fun onDestroy() {
        try { cameraView.disableView() } catch (_: Exception) {}
        super.onDestroy()
    }
}
