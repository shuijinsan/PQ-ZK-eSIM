package com.yourcompany.pqzkesim.ui.profile

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Outline
import android.graphics.Paint
import android.graphics.Shader
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewOutlineProvider
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.yalantis.ucrop.UCrop
import com.yourcompany.pqzkesim.LocaleManager
import com.yourcompany.pqzkesim.R
import com.yourcompany.pqzkesim.RegisterActivity
import com.yourcompany.pqzkesim.viewmodel.ProfileViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

class ProfileFragment : Fragment() {

    private val viewModel: ProfileViewModel by viewModels()

    private lateinit var tvUserName: TextView
    private lateinit var tvUserId: TextView
    private lateinit var tvRegisterTime: TextView
    private lateinit var tvDeviceCount: TextView
    private lateinit var tvCurrentLanguage: TextView
    private lateinit var ivUserAvatar: ImageView

    private val avatarDrawables = intArrayOf(
        R.drawable.ic_user_default,
        R.drawable.ic_fingerprint,
        R.drawable.ic_camera
    )

    // 保存当前裁剪的目标 URI，用于在 cropLauncher 回调中直接读取结果
    private var currentCropDestUri: Uri? = null

    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            launchCrop(uri)
        }
    }

    private val cropLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val destUri = currentCropDestUri
        currentCropDestUri = null
        if (result.resultCode == Activity.RESULT_OK) {
            // 优先用 UCrop.getOutput，失败则回退到我们传入的 destUri
            val outputUri = result.data?.let { UCrop.getOutput(it) } ?: destUri
            if (outputUri != null) {
                viewModel.saveCustomAvatar(outputUri)
            } else {
                Toast.makeText(requireContext(), getString(R.string.profile_toast_crop_lost), Toast.LENGTH_SHORT).show()
            }
        } else if (result.resultCode == UCrop.RESULT_ERROR) {
            val cropError = result.data?.let { UCrop.getError(it) }
            val errMsg = cropError?.message
            if (errMsg != null)
                Toast.makeText(requireContext(), getString(R.string.profile_toast_crop_failed, errMsg), Toast.LENGTH_SHORT).show()
            else
                Toast.makeText(requireContext(), getString(R.string.profile_toast_crop_unknown), Toast.LENGTH_SHORT).show()
        }
        // RESULT_CANCELED: 用户取消，不做任何处理
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_profile, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        bindViews(view)
        setupClickListeners(view)
        observeViewModel()
    }

    private fun bindViews(view: View) {
        tvUserName      = view.findViewById(R.id.tv_user_name)
        tvUserId        = view.findViewById(R.id.tv_user_id)
        tvRegisterTime  = view.findViewById(R.id.tv_register_time)
        tvDeviceCount   = view.findViewById(R.id.tv_device_count)
        tvCurrentLanguage = view.findViewById(R.id.tv_current_language)
        ivUserAvatar      = view.findViewById(R.id.iv_user_avatar)
        applyCircularClip(ivUserAvatar)
    }

    private fun applyCircularClip(view: ImageView) {
        view.clipToOutline = true
        view.outlineProvider = object : ViewOutlineProvider() {
            override fun getOutline(view: View, outline: Outline) {
                val size = minOf(view.width, view.height)
                val left = (view.width - size) / 2
                val top = (view.height - size) / 2
                outline.setOval(left, top, left + size, top + size)
            }
        }
    }

    private fun setupClickListeners(view: View) {
        view.findViewById<View>(R.id.menu_change_name)?.setOnClickListener {
            showChangeNicknameDialog()
        }
        view.findViewById<View>(R.id.menu_change_avatar)?.setOnClickListener {
            showChangeAvatarDialog()
        }
        view.findViewById<View>(R.id.menu_language)?.setOnClickListener {
            showLanguageDialog()
        }
        view.findViewById<View>(R.id.menu_logout)?.setOnClickListener {
            showLogoutDialog()
        }
    }

    private fun observeViewModel() {
        viewModel.userProfile.observe(viewLifecycleOwner) { profile ->
            tvUserName.text      = profile.nickname
            tvUserId.text        = profile.userId
            tvRegisterTime.text  = profile.registerTime.replaceFirst(" ", "\n")
            tvDeviceCount.text   = getString(R.string.profile_device_count_format, profile.deviceCount)
        }

        viewModel.customAvatarPath.observe(viewLifecycleOwner) {
            updateAvatarDisplay()
        }

        viewModel.avatarIndex.observe(viewLifecycleOwner) {
            updateAvatarDisplay()
        }

        viewModel.logoutEvent.observe(viewLifecycleOwner) { shouldLogout ->
            if (shouldLogout) {
                startActivity(Intent(requireContext(), RegisterActivity::class.java))
                requireActivity().finish()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateLanguageDisplay()
    }

    private fun updateLanguageDisplay() {
        val lang = LocaleManager.getCurrentLanguage(requireContext())
        tvCurrentLanguage.text = LocaleManager.getLanguageDisplayName(lang, requireContext())
    }

    private fun updateAvatarDisplay() {
        val customPath = viewModel.customAvatarPath.value
        if (!customPath.isNullOrEmpty() && File(customPath).exists()) {
            viewLifecycleOwner.lifecycleScope.launch(Dispatchers.IO) {
                val options = BitmapFactory.Options().apply {
                    inSampleSize = 2
                }
                val rawBitmap = BitmapFactory.decodeFile(customPath, options)
                val circleBitmap = rawBitmap?.let { getCircleBitmap(it) }
                withContext(Dispatchers.Main) {
                    ivUserAvatar.setImageBitmap(circleBitmap)
                }
            }
        } else {
            val index = viewModel.avatarIndex.value ?: 0
            if (index in avatarDrawables.indices) {
                ivUserAvatar.setImageResource(avatarDrawables[index])
            }
        }
    }

    /** 将 Bitmap 裁剪为圆形，确保无论 ImageView 设置如何都显示为圆形 */
    private fun getCircleBitmap(source: Bitmap): Bitmap {
        val size = minOf(source.width, source.height)
        val output = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(output)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = BitmapShader(source, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP)
        }
        val radius = size / 2f
        canvas.drawCircle(radius, radius, radius, paint)
        return output
    }

    private fun showChangeNicknameDialog() {
        val input = android.widget.EditText(requireContext()).apply {
            setText(tvUserName.text)
        }
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.profile_dialog_change_name_title))
            .setView(input)
            .setPositiveButton(getString(R.string.profile_dialog_confirm)) { _, _ ->
                viewModel.saveNickname(input.text.toString().trim())
            }
            .setNegativeButton(getString(R.string.profile_dialog_cancel), null)
            .show()
    }

    private fun showChangeAvatarDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.profile_dialog_change_avatar_title))
            .setItems(arrayOf(
                getString(R.string.profile_dialog_from_gallery),
                getString(R.string.profile_dialog_preset_avatar)
            )) { _, which ->
                when (which) {
                    0 -> galleryLauncher.launch("image/*")
                    1 -> viewModel.cycleAvatar()
                }
            }
            .show()
    }

    /**
     * 语言选择对话框
     * 显示中文/English 选项，当前选中项高亮 ✓
     */
    private fun showLanguageDialog() {
        val currentLang = LocaleManager.getCurrentLanguage(requireContext())

        // 用自定义布局实现带选中标记的单选列表
        val layout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 16, 0, 16)
        }

        val rg = RadioGroup(requireContext()).apply {
            orientation = RadioGroup.VERTICAL
        }
        layout.addView(rg)

        val options = listOf(
            LocaleManager.LANG_ZH_CN to getString(R.string.lang_zh_cn),
            LocaleManager.LANG_EN to getString(R.string.lang_en)
        )

        options.forEach { (code, name) ->
            val rb = RadioButton(requireContext()).apply {
                text = name
                // 选中/未选中统一黑色文字，按钮圆点统一 #1677FF，覆盖系统默认紫色
                setTextColor(
                    android.content.res.ColorStateList(
                        arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                        intArrayOf(Color.parseColor("#1F2937"), Color.parseColor("#1F2937"))
                    )
                )
                buttonTintList = android.content.res.ColorStateList(
                    arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                    intArrayOf(Color.parseColor("#1677FF"), Color.parseColor("#9CA3AF"))
                )
                textSize = 16f
                setPadding(24, 20, 24, 20)
                isChecked = code == currentLang
                id = code.hashCode()
                tag = code
            }
            rg.addView(rb)
        }

        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.lang_title))
            .setView(layout)
            .setPositiveButton(getString(R.string.generic_confirm)) { _, _ ->
                val selectedRb = rg.checkedRadioButtonId
                val selectedCode = rg.findViewById<RadioButton>(selectedRb)?.tag as? String
                    ?: return@setPositiveButton
                if (selectedCode != currentLang) {
                    applyLanguageChange(selectedCode)
                }
            }
            .setNegativeButton(getString(R.string.generic_cancel), null)
            .show()
    }

    private fun applyLanguageChange(language: String) {
        val activity = requireActivity()
        // 切换语言
        LocaleManager.switchLanguage(activity, language)
        // 重建 Activity 以刷新全部界面
        activity.recreate()
    }

    /**
     * 启动 uCrop 裁剪。
     * 源 URI 直接传入 uCrop（uCrop 内部处理跨 Activity 权限），
     * 目标使用 FileProvider 生成可写入的 URI。
     */
    private fun launchCrop(sourceUri: Uri) {
        try {
            val cacheDir = File(requireContext().cacheDir, "crop")
            if (!cacheDir.exists()) cacheDir.mkdirs()

            // 目标文件：uCrop 裁剪后将结果写入此处
            val destFile = File(cacheDir, "crop_${UUID.randomUUID()}.jpg")
            val destUri = FileProvider.getUriForFile(
                requireContext(),
                "${requireContext().packageName}.fileprovider",
                destFile
            )
            currentCropDestUri = destUri

            val options = UCrop.Options().apply {
                setCompressionFormat(android.graphics.Bitmap.CompressFormat.JPEG)
                setCompressionQuality(90)
                setHideBottomControls(false)
                setFreeStyleCropEnabled(false)
                setToolbarColor(ContextCompat.getColor(requireContext(), R.color.pqc_primary))
                setStatusBarColor(ContextCompat.getColor(requireContext(), R.color.pqc_primary))
                setShowCropFrame(true)
                setShowCropGrid(true)
                setCircleDimmedLayer(true)
                setCropFrameColor(Color.WHITE)
                withAspectRatio(1f, 1f)
                withMaxResultSize(512, 512)
            }

            val intent = UCrop.of(sourceUri, destUri)
                .withOptions(options)
                .getIntent(requireContext())
            // 显式授予读写权限，确保 uCrop 能访问源图和写入目标
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)

            // 确认 uCrop Activity 可用后再启动
            if (intent.resolveActivity(requireContext().packageManager) != null) {
                cropLauncher.launch(intent)
            } else {
                Toast.makeText(requireContext(), getString(R.string.profile_toast_crop_unavailable), Toast.LENGTH_LONG).show()
            }

        } catch (e: Exception) {
            android.util.Log.e("ProfileFragment", "launchCrop error", e)
            Toast.makeText(requireContext(), getString(R.string.profile_toast_crop_open_failed, e.message), Toast.LENGTH_LONG).show()
        }
    }

    private fun showLogoutDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.profile_dialog_logout_title))
            .setMessage(getString(R.string.profile_dialog_logout_message))
            .setPositiveButton(getString(R.string.generic_confirm)) { _, _ ->
                viewModel.logout()
            }
            .setNegativeButton(getString(R.string.generic_cancel), null)
            .show()
    }
}
