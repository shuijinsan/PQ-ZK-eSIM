package com.yourcompany.pqzkesim.ui.home

import android.animation.Animator
import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.animation.AccelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.DialogFragment
import com.google.android.material.button.MaterialButton
import com.yourcompany.pqzkesim.R

/**
 * eSIM 开通成功结果弹窗
 *
 * 在认证流程成功结束后，展示运营商开通结果：
 *   - 手机号（脱敏显示）
 *   - 开通时间
 *   - 运营商名称
 *
 * 动画：
 *   1. 背景从透明渐变至半透明黑色
 *   2. 卡片从底部滑入
 *   3. 成功图标先以缩放动画出现
 *   4. 文字信息随后淡入
 */
class ActivationSuccessDialog : DialogFragment() {

    companion object {
        const val REQUEST_KEY_DONE = "activation_dialog_done"

        private const val ARG_PHONE_NUMBER = "phone_number"
        private const val ARG_ACTIVATED_AT = "activated_at"
        private const val ARG_OPERATOR_NAME = "operator_name"

        fun newInstance(
            phoneNumber: String,
            activatedAt: String,
            operatorName: String
        ): ActivationSuccessDialog {
            return ActivationSuccessDialog().apply {
                arguments = Bundle().apply {
                    putString(ARG_PHONE_NUMBER, phoneNumber)
                    putString(ARG_ACTIVATED_AT, activatedAt)
                    putString(ARG_OPERATOR_NAME, operatorName)
                }
            }
        }
    }

    private val phoneNumber: String get() = arguments?.getString(ARG_PHONE_NUMBER) ?: ""
    private val activatedAt: String get() = arguments?.getString(ARG_ACTIVATED_AT) ?: ""
    private val operatorName: String get() = arguments?.getString(ARG_OPERATOR_NAME) ?: ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 使用透明主题：无 dim 层、无窗口背景、无标题栏，彻底消除多余的黑色半透明方块
        setStyle(STYLE_NO_FRAME, R.style.TransparentDialogTheme)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = Dialog(requireContext(), theme)
        // 禁止点击外部蒙层关闭弹窗 — 仅【完成】按钮可关闭
        dialog.setCanceledOnTouchOutside(false)
        dialog.setCancelable(false)
        dialog.window?.apply {
            // 确保 dim 量为零，消除系统默认 Dialog 的暗色遮罩
            setDimAmount(0f)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            // 全屏透明窗口，卡片在 XML 中通过 margin 控制尺寸与居中
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT
            )
            setWindowAnimations(R.style.ActivationSuccessDialogAnimation)
        }
        return dialog
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.dialog_activation_success, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // 填充数据
        val tvPhoneNumber = view.findViewById<TextView>(R.id.tv_phone_number)
        val tvActivatedAt = view.findViewById<TextView>(R.id.tv_activated_at)
        val tvOperatorName = view.findViewById<TextView>(R.id.tv_operator_name)
        val btnDone = view.findViewById<MaterialButton>(R.id.btn_done)

        tvPhoneNumber.text = maskPhoneNumber(phoneNumber)
        tvActivatedAt.text = activatedAt
        tvOperatorName.text = operatorName

        // 根据运营商名称动态设置对应图标（移动/联通/电信）
        val ivOperatorIcon = view.findViewById<ImageView>(R.id.iv_operator_icon)
        ivOperatorIcon.setImageResource(operatorIconRes(operatorName))

        // 完成按钮 — 关闭弹窗（唯一关闭途径），通知主界面重置动画
        btnDone.setOnClickListener {
            parentFragmentManager.setFragmentResult(REQUEST_KEY_DONE, Bundle())
            dismissWithAnimation()
        }

        // 卡片区域不穿透点击
        view.findViewById<View>(R.id.dialog_card_container)?.setOnClickListener { /* consume */ }

        // 启动入场动画
        startEnterAnimation(view)
    }

    // ──── 入场动画 ────

    private fun startEnterAnimation(view: View) {
        val iconLayout = view.findViewById<View>(R.id.layout_success_icon)
        val textLayout = view.findViewById<View>(R.id.layout_success_text)
        val dividerTop = view.findViewById<View>(R.id.divider_top)
        val infoLayout = view.findViewById<View>(R.id.layout_info)
        val dividerBottom = view.findViewById<View>(R.id.divider_bottom)
        val btnDone = view.findViewById<View>(R.id.btn_done)
        val card = view.findViewById<View>(R.id.dialog_card_container)

        // 初始状态：全部透明/缩放
        iconLayout.scaleX = 0.8f
        iconLayout.scaleY = 0.8f
        iconLayout.alpha = 0f
        textLayout.alpha = 0f
        dividerTop.alpha = 0f
        infoLayout.alpha = 0f
        dividerBottom.alpha = 0f
        btnDone.alpha = 0f

        // 卡片从底部偏移（附加到滑动效果之上）
        card.translationY = 200f
        card.alpha = 0f

        // 阶段 0（即刻）：卡片滑入 + 淡入
        val cardSlide = ObjectAnimator.ofFloat(card, "translationY", 200f, 0f).apply {
            duration = 400
            interpolator = DecelerateInterpolator()
        }
        val cardFadeIn = ObjectAnimator.ofFloat(card, "alpha", 0f, 1f).apply {
            duration = 350
            interpolator = DecelerateInterpolator()
        }

        // 阶段 1（150ms 后）：成功图标缩放 + 淡入
        val iconScaleX = ObjectAnimator.ofFloat(iconLayout, "scaleX", 0.8f, 1.0f).apply {
            duration = 350
            interpolator = DecelerateInterpolator()
            startDelay = 150
        }
        val iconScaleY = ObjectAnimator.ofFloat(iconLayout, "scaleY", 0.8f, 1.0f).apply {
            duration = 350
            interpolator = DecelerateInterpolator()
            startDelay = 150
        }
        val iconFadeIn = ObjectAnimator.ofFloat(iconLayout, "alpha", 0f, 1f).apply {
            duration = 250
            startDelay = 150
        }

        // 阶段 2（400ms 后）：标题文字淡入
        val textFadeIn = ObjectAnimator.ofFloat(textLayout, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 400
        }

        // 阶段 3（550ms 后）：分割线 + 信息区域淡入
        val dividerTFade = ObjectAnimator.ofFloat(dividerTop, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 550
        }
        val infoFadeIn = ObjectAnimator.ofFloat(infoLayout, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 550
        }

        // 阶段 4（700ms 后）：底部按钮淡入
        val dividerBFade = ObjectAnimator.ofFloat(dividerBottom, "alpha", 0f, 1f).apply {
            duration = 250
            startDelay = 700
        }
        val btnFadeIn = ObjectAnimator.ofFloat(btnDone, "alpha", 0f, 1f).apply {
            duration = 250
            startDelay = 700
        }

        AnimatorSet().apply {
            playTogether(
                cardSlide, cardFadeIn,
                iconScaleX, iconScaleY, iconFadeIn,
                textFadeIn,
                dividerTFade, infoFadeIn,
                dividerBFade, btnFadeIn
            )
            start()
        }
    }

    // ──── 退场动画 ────

    private fun dismissWithAnimation() {
        val card = view?.findViewById<View>(R.id.dialog_card_container) ?: run {
            dismissAllowingStateLoss()
            return
        }

        val cardSlideOut = ObjectAnimator.ofFloat(card, "translationY", 0f, 300f).apply {
            duration = 250
            interpolator = AccelerateInterpolator()
        }
        val cardFadeOut = ObjectAnimator.ofFloat(card, "alpha", 1f, 0f).apply {
            duration = 200
        }

        AnimatorSet().apply {
            playTogether(cardSlideOut, cardFadeOut)
            addListener(object : Animator.AnimatorListener {
                override fun onAnimationStart(animation: Animator) {}
                override fun onAnimationEnd(animation: Animator) {
                    dismissAllowingStateLoss()
                }
                override fun onAnimationCancel(animation: Animator) {
                    dismissAllowingStateLoss()
                }
                override fun onAnimationRepeat(animation: Animator) {}
            })
            start()
        }
    }

    // ──── 工具 ────

    /** 根据运营商名称映射对应图标资源 */
    private fun operatorIconRes(name: String): Int = when (name) {
        "中国移动", "China Mobile"     -> R.drawable.ic_mobile
        "中国联通", "China Unicom"     -> R.drawable.ic_unicom
        "中国电信", "China Telecom"    -> R.drawable.ic_telecom
        else                           -> R.drawable.ic_mobile // fallback
    }

    /**
     * 手机号脱敏显示
     * 输入如 "8613812348888" 或 "+8613812348888" → 输出 "+86 138 **** 8888"
     */
    private fun maskPhoneNumber(raw: String): String {
        if (raw.isBlank()) return raw

        val digits = raw.filter { it.isDigit() }
        if (digits.length < 7) return raw // 太短不处理

        // 提取国家码和本地号码
        val (cc, local) = when {
            digits.startsWith("86") && digits.length >= 13 -> Pair("+86", digits.drop(2))
            else -> Pair("", digits)
        }

        if (local.length < 7) return raw

        val prefix = local.take(3)
        val suffix = local.takeLast(4)

        return if (cc.isNotEmpty()) {
            "$cc $prefix **** $suffix"
        } else {
            "$prefix **** $suffix"
        }
    }
}
