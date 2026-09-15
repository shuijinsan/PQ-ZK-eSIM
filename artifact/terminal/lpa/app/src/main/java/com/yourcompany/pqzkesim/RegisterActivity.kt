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
        btnNextStep.text = "Next"

        when (step) {
            RegisterStep.USER_INFO -> {
                tvStatusDetail.text = "Enter your nickname"
                layoutUserInfo.visibility = View.VISIBLE
            }
            RegisterStep.TEE_CHECK -> {
                tvStatusDetail.text = "Checking the TEE secure environment..."
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "Verifying the TEE secure environment..."
                btnNextStep.isEnabled = false
            }
            RegisterStep.KYBER_KEYGEN -> {
                tvStatusDetail.text = "Generating post-quantum keys..."
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "Generating the Kyber-768 master key..."
                btnNextStep.isEnabled = false
            }
            RegisterStep.FINGERPRINT -> {
                tvStatusDetail.text = "Tap the button to collect the fingerprint feature"
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "Preparing fingerprint capture..."
                tvInitResult.visibility = View.GONE
                btnNextStep.text = "Start fingerprint capture"
            }
            RegisterStep.FACE -> {
                tvStatusDetail.text = "Face the camera to capture your face"
                layoutStepFace.visibility = View.VISIBLE
                btnNextStep.text = "Preparing..."
                btnNextStep.isEnabled = false
                enableCamera()
            }
            RegisterStep.SECURITY_BIND -> {
                tvStatusDetail.text = "Performing secure binding..."
                layoutStepInit.visibility = View.VISIBLE
                layoutStepFace.visibility = View.GONE
                tvInitStatus.text = "Binding biometrics and registering the device..."
                tvInitResult.visibility = View.GONE
                btnNextStep.isEnabled = false
            }
            RegisterStep.DONE -> {
                tvStatusDetail.text = ""
                tvStatusDetail.visibility = View.GONE
                layoutStepInit.visibility = View.VISIBLE
                tvInitStatus.text = "All security modules are ready"
                tvInitResult.visibility = View.VISIBLE
                tvInitResult.text = "Device registered successfully. Tap below to continue."
                btnNextStep.text = "Enter home"
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
                btnNextStep.text = "Verify your fingerprint in the dialog..."
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
                        tvInitResult.text = "TEE environment ready; face model loaded"
                    } else {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "Model loading failed; face capture may be unavailable"
                    }
                    delay(800)
                    advanceTo(RegisterStep.KYBER_KEYGEN)
                }
            } catch (e: Exception) {
                Log.e(TAG, "TEE check failed", e)
                withContext(Dispatchers.Main) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "⚠️ TEE check error: ${e.message}"
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
                    Log.d(TAG, "✅ Kyber-768 key pair generated (pk=${kyberPk!!.size}B, sk=${kyberSk!!.size}B)")
                } else {
                    Log.e(TAG, "Kyber key-pair generation returned null")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Kyber keygen error", e)
            }

            withContext(Dispatchers.Main) {
                if (kyberPk != null) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "✅ Kyber-768 master key generated"
                } else {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "Key generation failed; fallback will be used"
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
                    Log.d(TAG, "Fingerprint authentication succeeded")
                    tvInitStatus.text = getString(R.string.register_fingerprint_ok)
                    advanceTo(RegisterStep.FACE)
                }
                override fun onAuthenticationFailed() {
                    Log.d(TAG, "Fingerprint mismatch")
                    Toast.makeText(this@RegisterActivity, getString(R.string.register_toast_fingerprint_mismatch), Toast.LENGTH_SHORT).show()
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "Start fingerprint capture"
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.e(TAG, "Fingerprint authentication error [$errorCode]: $errString")
                    Toast.makeText(this@RegisterActivity, getString(R.string.register_toast_auth_error, errString), Toast.LENGTH_SHORT).show()
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "Start fingerprint capture"
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
            Log.e(TAG, "OpenCV initialization failed")
        }
        layoutStepFace.visibility = View.VISIBLE
        cameraView.postDelayed({
            cameraView.enableView()
            btnNextStep.text = "Face the camera..."
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
                Log.d(TAG, "✅ Face Feature CollectionDone")
                withContext(Dispatchers.Main) { advanceTo(RegisterStep.SECURITY_BIND) }
            } catch (e: Exception) {
                Log.e(TAG, "Face extraction failed", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@RegisterActivity, "Face capture failed", Toast.LENGTH_SHORT).show()
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
                        tvInitResult.text = "Biometric data missing; please retry"
                        btnNextStep.isEnabled = true
                        btnNextStep.text = "Restart"
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
                        tvInitResult.text = "Secure binding complete; r_bio, master key, and device identity stored"
                        lifecycleScope.launch(Dispatchers.IO) { registerToBackend() }
                        delay(800)
                        advanceTo(RegisterStep.DONE)
                    } else {
                        tvInitResult.visibility = View.VISIBLE
                        tvInitResult.text = "❌ Device registration failed (code=$regResult, verified=$verified)"
                        btnNextStep.isEnabled = true
                        btnNextStep.text = "Retry"
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Security bind failed", e)
                withContext(Dispatchers.Main) {
                    tvInitResult.visibility = View.VISIBLE
                    tvInitResult.text = "❌ Secure-binding error: ${e.message}"
                    btnNextStep.isEnabled = true
                    btnNextStep.text = "Retry"
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
            Log.d(TAG, "Backend registration result: $resp")
        } catch (e: Throwable) {
            Log.e(TAG, "Backend registration failed", e)
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
