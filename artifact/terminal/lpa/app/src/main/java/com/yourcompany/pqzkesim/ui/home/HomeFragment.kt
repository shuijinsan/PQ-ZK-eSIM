package com.yourcompany.pqzkesim.ui.home

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.widget.SwitchCompat
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.yourcompany.pqzkesim.ProtocolConstants
import androidx.fragment.app.activityViewModels
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.opencv.android.CameraBridgeViewBase
import org.opencv.android.JavaCameraView
import org.opencv.android.OpenCVLoader
import org.opencv.core.Core
import org.opencv.core.Mat
import com.yourcompany.pqzkesim.NativeLib
import com.yourcompany.pqzkesim.R
import com.yourcompany.pqzkesim.OperatorPrefsManager
import com.yourcompany.pqzkesim.mock.MockConfig
import com.yourcompany.pqzkesim.mock.MockPqcNetworkClient
import com.yourcompany.pqzkesim.TimelineAnimator
import com.yourcompany.pqzkesim.ProgressRingDrawable
import android.widget.RadioGroup
import com.yourcompany.pqzkesim.data.model.AuthLogItem
import com.yourcompany.pqzkesim.data.model.OperatorConfig
import com.yourcompany.pqzkesim.viewmodel.ActivationViewModel
import com.yourcompany.pqzkesim.viewmodel.AuthState
import com.yourcompany.pqzkesim.viewmodel.LogViewModel
import java.io.File
import java.io.FileOutputStream

class HomeFragment : Fragment(), CameraBridgeViewBase.CvCameraViewListener2 {

    companion object {
        private const val TAG = "PQZK-Home"
        private const val CAMERA_PERMISSION = 100
        private const val FACE_TIMEOUT_MS = 60000L
        private const val CONSECUTIVE_THRESHOLD = 3
        private const val TAG_SUCCESS_DIALOG = "activation_success_dialog"
    }

    private val activationVM: ActivationViewModel by viewModels()
    private val logVM: LogViewModel by activityViewModels()

    // Camera
    private var cameraView: JavaCameraView? = null
    private var cameraContainer: FrameLayout? = null
    private var faceOverlay: View? = null
    private var isCameraRunning = false
    @Volatile private var isAuthStarting = false
    @Volatile private var isFaceExtracted = false
    @Volatile private var isProcessingFrame = false
    private var consecutiveFaceFrames = 0
    private var lastFaceTime = 0L

    // Face feature (thread-safe)
    private val latestRBioLock = Any()
    private var _latestRBio = ByteArray(32)
    private var latestRBio: ByteArray
        get() = synchronized(latestRBioLock) { _latestRBio.copyOf() }
        set(value) = synchronized(latestRBioLock) { _latestRBio = value.copyOf() }

    // UI
    private lateinit var tvStatus: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var tvProgressPct: TextView
    private lateinit var tvAuditLog: TextView
    private lateinit var btnRunAuth: Button
    private lateinit var layoutConsole: LinearLayout
    private lateinit var tvConsoleArrow: TextView
    private var isConsoleExpanded = false
    private lateinit var scrollAudit: ScrollView
    private lateinit var rgOperator: RadioGroup
    private lateinit var switchMock: SwitchCompat

    // Timeline
    private var timelineAnimator: TimelineAnimator? = null

    private val nvramDirPath by lazy { requireContext().filesDir.absolutePath + "/euicc_nvram" }
    private var faceModelPath: String = ""
    private val mainHandler = Handler(Looper.getMainLooper())

    // 确保 UI 操作始终在主线程执行
    private fun runOnUiThread(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
        } else {
            mainHandler.post(block)
        }
    }

    // ──── Lifecycle ────

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_home, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        if (!OpenCVLoader.initDebug()) {
            Toast.makeText(requireContext(), getString(R.string.home_opencv_init_failed), Toast.LENGTH_LONG).show()
            return
        }

        bindViews(view)
        initModel()
        observeViewModel()
        setupConsoleToggle(view)

        btnRunAuth.setOnClickListener { onLaunchAuth() }

        // Mock mode toggle
        switchMock.isChecked = MockConfig.isEnabled
        switchMock.setOnCheckedChangeListener { _, checked ->
            MockConfig.isEnabled = checked
            if (checked) MockPqcNetworkClient.resetSession()
            appendLog(if (checked) getString(R.string.home_log_mock_enabled) else getString(R.string.home_log_mock_disabled))
        }

        // Timeline attaches to the progress bar
        timelineAnimator = TimelineAnimator(requireActivity() as androidx.appcompat.app.AppCompatActivity, progressBar)
        timelineAnimator?.bind()
        timelineAnimator?.resetVisuals()  // 每次进入主页清理上次认证的残留状态
    }

    override fun onResume() {
        super.onResume()
    }

    override fun onPause() {
        super.onPause()
        // 仅设置标志位停止人脸检测，不直接操作相机硬件
        isAuthStarting = false
        isFaceExtracted = false
    }

    override fun onDestroyView() {
        // 先关闭相机再销毁视图，防止在已销毁的视图上操作
        try { cameraView?.disableView() } catch (_: Exception) {}
        try {
            cameraView?.setCvCameraViewListener(null as CameraBridgeViewBase.CvCameraViewListener2?)
        } catch (_: Exception) {}
        cameraView = null
        cameraContainer = null
        faceOverlay = null
        super.onDestroyView()
    }

    // ──── View binding ────

    private fun bindViews(view: View) {
        cameraContainer = view.findViewById(R.id.camera_container)
        cameraView = view.findViewById(R.id.java_camera_view)
        faceOverlay = view.findViewById(R.id.face_scan_overlay)

        // 将相机预览裁剪为与蓝色识别框一致的圆角
        cameraContainer?.apply {
            clipToOutline = true
            outlineProvider = object : android.view.ViewOutlineProvider() {
                override fun getOutline(view: View, outline: android.graphics.Outline) {
                    val radius = 20f * resources.displayMetrics.density
                    outline.setRoundRect(0, 0, view.width, view.height, radius)
                }
            }
        }

        tvStatus = view.findViewById(R.id.tv_reg_status)
        progressBar = view.findViewById(R.id.auth_progress)
        // 替换圆环 drawable：从 12 点钟方向开始顺时针填充
        val ringStrokePx = 4f * resources.displayMetrics.density
        progressBar.progressDrawable = ProgressRingDrawable(strokePx = ringStrokePx)
        tvProgressPct = view.findViewById(R.id.tv_progress_pct)
        tvAuditLog = view.findViewById(R.id.tv_audit_log)
        btnRunAuth = view.findViewById(R.id.btn_run_test)
        layoutConsole = view.findViewById(R.id.layout_console)
        tvConsoleArrow = view.findViewById(R.id.tv_console_arrow)
        scrollAudit = view.findViewById(R.id.scroll_audit)
        rgOperator = view.findViewById(R.id.rg_operator)
        switchMock = view.findViewById(R.id.switch_mock_mode)

        cameraView?.apply {
            @Suppress("RemoveExplicitTypeArguments")
            setCvCameraViewListener(this@HomeFragment as CameraBridgeViewBase.CvCameraViewListener2)
            visibility = View.GONE
            // 禁止保存相机内部状态到 Bundle，防止 TransactionTooLargeException
            isSaveEnabled = false
            setCameraIndex(1)
            setCameraPermissionGranted()
            setMaxFrameSize(480, 640)
        }
        faceOverlay?.visibility = View.GONE
        cameraContainer?.visibility = View.GONE
    }

    // ──── Model init ────

    private fun initModel() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val modelName = "haarcascade_frontalface_alt.xml"
                val destFile = File(requireContext().filesDir, modelName)
                if (!destFile.exists()) {
                    requireContext().assets.open(modelName).use { input ->
                        FileOutputStream(destFile).use { output -> input.copyTo(output) }
                    }
                }
                faceModelPath = destFile.absolutePath
                val ok = NativeLib.initDetector(faceModelPath)
                withContext(Dispatchers.Main) {
                    if (!ok) {
                        appendLog(getString(R.string.home_log_model_fail))
                        btnRunAuth.isEnabled = false
                    } else appendLog(getString(R.string.home_log_model_ok))
                }
            } catch (e: Exception) {
                Log.e(TAG, "Model init failed", e)
            }
        }
    }

    // ──── ViewModel observation ────

    private fun observeViewModel() {
        activationVM.authState.observe(viewLifecycleOwner) { state ->
            try {
                when (state) {
                    is AuthState.Idle -> {}
                    is AuthState.PrepareTEE -> updateUI(state.label, state.progress)
                    is AuthState.GenerateProof -> updateUI(state.label, state.progress)
                    is AuthState.RequestChallenge -> updateUI(getString(R.string.auth_label_request_challenge), state.progress)
                    is AuthState.VerifyChallenge -> updateUI(getString(R.string.auth_label_verify_challenge), state.progress)
                    is AuthState.DownloadProfile -> updateUI(getString(R.string.auth_label_download_profile), state.progress)
                    is AuthState.WriteEUICC -> updateUI(getString(R.string.auth_label_write_euicc), state.progress)
                    is AuthState.Activated -> {
                        updateUI(getString(R.string.home_auth_success_label), 100)
                        timelineAnimator?.markSuccess()
                        appendLog(getString(R.string.home_log_auth_success))
                        logVM.insertLog("SUCCESS", state.durationMs, state.sessionId,
                            state.counter,
                            operatorInfo = state.operatorName,
                            phoneNumber = state.phoneNumber)
                        cleanupAfterAuth()

                        // 将后端硬编码的运营商名映射为当前语言的显示名
                        val localizedOpName = localizedOperatorName(state.operatorName)

                        // 弹出开通成功结果弹窗（基于真实认证状态，无模拟数据）
                        showActivationSuccessDialog(
                            phoneNumber = state.phoneNumber,
                            activatedAt = state.activatedAt,
                            operatorName = localizedOpName
                        )
                        // 重置状态为 Idle，防止切页返回后 LiveData 重新触发弹窗
                        activationVM.resetState()
                        // 清空运营商选择框，恢复初始未选中状态
                        rgOperator.clearCheck()
                    }
                    is AuthState.BiometricFailed -> {
                        updateUI(getString(R.string.home_auth_biometric_failed), 0)
                        timelineAnimator?.markError()
                        appendLog("❌ ${state.reason}")
                    }
                    is AuthState.NetworkError -> {
                        updateUI(getString(R.string.home_auth_network_error), 0)
                        timelineAnimator?.markError()
                        appendLog("❌ ${state.detail}")
                        try { logVM.insertLog("FAILED", 0, "unknown", 0) } catch (_: Exception) {}
                        cleanupAfterAuth()
                    }
                    is AuthState.VerifyFailed -> {
                        updateUI(getString(R.string.home_auth_verify_failed), 0)
                        timelineAnimator?.markError()
                        appendLog(getString(R.string.home_auth_verify_failed_detail, state.code))
                        try { logVM.insertLog("FAILED", 0, "unknown", 0) } catch (_: Exception) {}
                        cleanupAfterAuth()
                    }
                    is AuthState.WriteFailed -> appendLog("❌ ${state.reason}")
                    is AuthState.ProfileConflict -> appendLog("⚠️ ${state.detail}")
                    else -> {}
                }
            } catch (e: Exception) {
                Log.e(TAG, "Observer error: ${e.message}", e)
            }
        }

        activationVM.progressValue.observe(viewLifecycleOwner) { p ->
            progressBar.progress = p
            tvProgressPct.text = "$p%"
        }

        activationVM.logMessage.observe(viewLifecycleOwner) { msg ->
            appendLog(msg)
        }
    }

    // ──── Auth launch ────

    private fun onLaunchAuth() {
        // 检查运营商选择
        val selectedId = rgOperator.checkedRadioButtonId
        if (selectedId == -1) {
            Toast.makeText(requireContext(), getString(R.string.home_toast_select_operator), Toast.LENGTH_SHORT).show()
            return
        }
        val operatorName = when (selectedId) {
            R.id.rb_cmcc -> getString(R.string.operator_china_mobile)
            R.id.rb_cucc -> getString(R.string.operator_china_unicom)
            R.id.rb_ct   -> getString(R.string.operator_china_telecom)
            else -> ""
        }
        val operatorDomain = when (selectedId) {
            R.id.rb_cmcc -> OperatorConfig.CHINA_MOBILE.domainId
            R.id.rb_cucc -> OperatorConfig.CHINA_UNICOM.domainId
            R.id.rb_ct   -> OperatorConfig.CHINA_TELECOM.domainId
            else -> ""
        }

        // 保存运营商选择
        OperatorPrefsManager.setActiveOperator(requireContext(), operatorName)
        OperatorPrefsManager.setActiveDomainId(requireContext(), operatorDomain)

        appendLog(getString(R.string.home_log_operator_selected, operatorName, operatorDomain))

        synchronized(latestRBioLock) { _latestRBio.fill(0) }
        isFaceExtracted = false
        isProcessingFrame = false
        isAuthStarting = true
        consecutiveFaceFrames = 0

        activationVM.resetState()
        timelineAnimator?.start()

        // Show biometric prompt → on success, enable camera → start face detection
        showBiometricPrompt {
            enableCamera()
            lifecycleScope.launch(Dispatchers.Default) {
                waitForFace()
            }
        }
    }

    private fun enableCamera() = runOnUiThread {
        cameraView?.apply {
            visibility = View.VISIBLE
            cameraContainer?.visibility = View.VISIBLE
            faceOverlay?.visibility = View.VISIBLE
            postDelayed({ enableView() }, 200)
        }
    }

    private fun disableCamera() = runOnUiThread {
        try {
            cameraView?.apply {
                if (visibility == View.VISIBLE) disableView()
                visibility = View.GONE
            }
            cameraContainer?.visibility = View.GONE
            faceOverlay?.visibility = View.GONE
        } catch (e: Exception) {
            Log.e(TAG, "disableCamera error", e)
        }
    }

    private fun cleanupAfterAuth() {
        isAuthStarting = false
        isProcessingFrame = false
        disableCamera()
    }

    private suspend fun waitForFace() {
        var waitCount = 0
        while (!isCameraRunning && waitCount < 50) {
            delay(100); waitCount++
        }
        if (!isCameraRunning) {
            withContext(Dispatchers.Main) { appendLog(getString(R.string.home_log_camera_timeout)) }
            return
        }
        appendLog(getString(R.string.home_log_camera_ready))

        val timeout = FACE_TIMEOUT_MS / 100
        for (i in 1..timeout.toInt()) {
            if (!isAuthStarting || isFaceExtracted) break
            delay(100)
            if (i % 15 == 0) appendLog(getString(R.string.home_log_waiting_face, i * 100))
        }

        if (!isFaceExtracted) {
            val data = latestRBio
            if (data.any { it != 0.toByte() } && data.count { it != 0.toByte() } >= 10) {
                isFaceExtracted = true
            }
        }

        isAuthStarting = false

        if (!isFaceExtracted) {
            // cleanupAfterAuth 涉及 View 操作，必须在主线程执行
            withContext(Dispatchers.Main) {
                appendLog(getString(R.string.home_log_face_not_detected))
                cleanupAfterAuth()
            }
            return
        }

        // disableCamera() 涉及 View 操作，必须在主线程执行
        withContext(Dispatchers.Main) {
            appendLog(getString(R.string.home_log_face_captured))
            disableCamera()
        }

        // 同人校验：比对当前人脸与注册时保存的人脸模板
        if (NativeLib.verifyFace(nvramDirPath, latestRBio) != 1) {
            withContext(Dispatchers.Main) {
                appendLog("❌ 人脸比对未通过，与注册用户不一致")
                cleanupAfterAuth()
            }
            return
        }
        withContext(Dispatchers.Main) {
            appendLog("✅ 人脸比对通过")
        }

        // Start the PQC auth flow
        val activeDomainId = try {
            OperatorPrefsManager.getActiveDomainId(requireContext())
                ?.takeIf { it.isNotEmpty() } ?: ProtocolConstants.DOMAIN_ID
        } catch (_: Exception) { ProtocolConstants.DOMAIN_ID }

        activationVM.startAuthFlow(latestRBio, nvramDirPath, activeDomainId)
    }

    // ──── BiometricPrompt ────

    private fun showBiometricPrompt(onSuccess: () -> Unit) {
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(requireContext()),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
                override fun onAuthenticationFailed() {
                    appendLog(getString(R.string.home_log_biometric_mismatch))
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    appendLog(getString(R.string.home_log_biometric_error, errString))
                }
            })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.home_biometric_title))
                .setNegativeButtonText(getString(R.string.home_biometric_cancel))
                .build()
        )
    }

    // ──── Camera callbacks ────

    override fun onCameraViewStarted(width: Int, height: Int) { isCameraRunning = true }
    override fun onCameraViewStopped() { isCameraRunning = false }

    override fun onCameraFrame(inputFrame: CameraBridgeViewBase.CvCameraViewFrame): Mat {
        val rgba = inputFrame.rgba()
        if (!isAuthStarting || isFaceExtracted || isProcessingFrame) {
            val preview = rgba.clone()
            Core.flip(preview, preview, 1)
            return preview
        }

        isProcessingFrame = true
        // 在相机回调线程上立即 clone，防止后台线程访问已释放的相机缓冲区导致 SIGSEGV 闪退
        val frame = rgba.clone()
        lifecycleScope.launch(Dispatchers.Default) {
            try {
                Core.rotate(frame, frame, Core.ROTATE_90_COUNTERCLOCKWISE)
                Core.flip(frame, frame, 1)

                val tempRBio = ByteArray(32)
                val ret = NativeLib.processFaceAndGetRbio(frame.nativeObjAddr, tempRBio)

                if (ret == 0 && tempRBio.any { it != 0.toByte() }) {
                    val now = System.currentTimeMillis()
                    if (now - lastFaceTime > 100) {
                        consecutiveFaceFrames++
                        lastFaceTime = now
                        if (consecutiveFaceFrames >= CONSECUTIVE_THRESHOLD) {
                            delay(500)
                            synchronized(latestRBioLock) { _latestRBio = tempRBio.copyOf() }
                            isFaceExtracted = true
                            Log.d(TAG, "✅ 人脸特征提取成功 (连续${consecutiveFaceFrames}帧)")
                        }
                    }
                } else {
                    if (System.currentTimeMillis() - lastFaceTime > 2000) {
                        consecutiveFaceFrames = 0
                    }
                }
                frame.release()
            } catch (e: Exception) {
                Log.e(TAG, "Frame processing error", e)
                try { frame.release() } catch (_: Exception) {}
            } finally { isProcessingFrame = false }
        }

        val preview = rgba.clone()
        Core.flip(preview, preview, 1)
        return preview
    }

    // ──── Console ────

    private fun setupConsoleToggle(view: View) {
        view.findViewById<LinearLayout>(R.id.btn_console_toggle)?.setOnClickListener {
            isConsoleExpanded = !isConsoleExpanded
            layoutConsole.visibility = if (isConsoleExpanded) View.VISIBLE else View.GONE
            tvConsoleArrow.rotation = if (isConsoleExpanded) 180f else 0f
        }
    }

    // ──── UI helpers ────

    private fun updateUI(text: String, progress: Int) {
        lifecycleScope.launch(Dispatchers.Main) {
            try {
                tvStatus.text = text
                progressBar.progress = progress
                tvProgressPct.text = "$progress%"
            } catch (e: Exception) {
                Log.e(TAG, "updateUI error: ${e.message}")
            }
        }
    }

    private fun appendLog(msg: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            try {
                tvAuditLog.append("> $msg\n")
                scrollAudit.post { scrollAudit.fullScroll(ScrollView.FOCUS_DOWN) }
            } catch (e: Exception) {
                Log.e(TAG, "appendLog error: ${e.message}")
            }
        }
    }

    // ──── 开通成功弹窗 ────

    /** 将 OperatorConfig 中硬编码的中文运营商名映射为当前语言资源 */
    private fun localizedOperatorName(rawName: String): String = when (rawName) {
        "中国移动" -> getString(R.string.operator_china_mobile)
        "中国联通" -> getString(R.string.operator_china_unicom)
        "中国电信" -> getString(R.string.operator_china_telecom)
        else -> rawName
    }

    /**
     * 在认证流程完整成功后展示 eSIM 开通结果弹窗。
     * 所有数据来自 ViewModel 传递的真实认证结果，无模拟/硬编码。
     */
    private fun showActivationSuccessDialog(
        phoneNumber: String,
        activatedAt: String,
        operatorName: String
    ) {
        // 防止重复弹窗
        val existing = childFragmentManager.findFragmentByTag(TAG_SUCCESS_DIALOG)
        if (existing != null) return

        // 监听弹窗【完成】按钮，关闭后立即重置主界面动画
        childFragmentManager.setFragmentResultListener(
            ActivationSuccessDialog.REQUEST_KEY_DONE,
            viewLifecycleOwner
        ) { _, _ ->
            timelineAnimator?.resetVisuals()
            tvStatus.text = getString(R.string.home_system_ready)
            progressBar.progress = 0
            tvProgressPct.text = "0%"
        }

        ActivationSuccessDialog.newInstance(
            phoneNumber = phoneNumber,
            activatedAt = activatedAt,
            operatorName = operatorName
        ).show(childFragmentManager, TAG_SUCCESS_DIALOG)
    }

}
