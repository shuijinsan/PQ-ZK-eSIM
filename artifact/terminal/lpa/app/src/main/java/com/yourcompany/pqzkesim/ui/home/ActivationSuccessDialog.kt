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
 *
 *   - Activation Time
 *
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
        setStyle(STYLE_NO_FRAME, R.style.TransparentDialogTheme)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = Dialog(requireContext(), theme)
        dialog.setCanceledOnTouchOutside(false)
        dialog.setCancelable(false)
        dialog.window?.apply {
            setDimAmount(0f)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
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

        val tvPhoneNumber = view.findViewById<TextView>(R.id.tv_phone_number)
        val tvActivatedAt = view.findViewById<TextView>(R.id.tv_activated_at)
        val tvOperatorName = view.findViewById<TextView>(R.id.tv_operator_name)
        val btnDone = view.findViewById<MaterialButton>(R.id.btn_done)

        tvPhoneNumber.text = maskPhoneNumber(phoneNumber)
        tvActivatedAt.text = activatedAt
        tvOperatorName.text = operatorName

        val ivOperatorIcon = view.findViewById<ImageView>(R.id.iv_operator_icon)
        ivOperatorIcon.setImageResource(operatorIconRes(operatorName))

        btnDone.setOnClickListener {
            parentFragmentManager.setFragmentResult(REQUEST_KEY_DONE, Bundle())
            dismissWithAnimation()
        }

        view.findViewById<View>(R.id.dialog_card_container)?.setOnClickListener { /* consume */ }

        startEnterAnimation(view)
    }


    private fun startEnterAnimation(view: View) {
        val iconLayout = view.findViewById<View>(R.id.layout_success_icon)
        val textLayout = view.findViewById<View>(R.id.layout_success_text)
        val dividerTop = view.findViewById<View>(R.id.divider_top)
        val infoLayout = view.findViewById<View>(R.id.layout_info)
        val dividerBottom = view.findViewById<View>(R.id.divider_bottom)
        val btnDone = view.findViewById<View>(R.id.btn_done)
        val card = view.findViewById<View>(R.id.dialog_card_container)

        iconLayout.scaleX = 0.8f
        iconLayout.scaleY = 0.8f
        iconLayout.alpha = 0f
        textLayout.alpha = 0f
        dividerTop.alpha = 0f
        infoLayout.alpha = 0f
        dividerBottom.alpha = 0f
        btnDone.alpha = 0f

        card.translationY = 200f
        card.alpha = 0f

        val cardSlide = ObjectAnimator.ofFloat(card, "translationY", 200f, 0f).apply {
            duration = 400
            interpolator = DecelerateInterpolator()
        }
        val cardFadeIn = ObjectAnimator.ofFloat(card, "alpha", 0f, 1f).apply {
            duration = 350
            interpolator = DecelerateInterpolator()
        }

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

        val textFadeIn = ObjectAnimator.ofFloat(textLayout, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 400
        }

        val dividerTFade = ObjectAnimator.ofFloat(dividerTop, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 550
        }
        val infoFadeIn = ObjectAnimator.ofFloat(infoLayout, "alpha", 0f, 1f).apply {
            duration = 300
            startDelay = 550
        }

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


    private fun operatorIconRes(name: String): Int = when (name) {
        "China Mobile", "China Mobile"     -> R.drawable.ic_mobile
        "China Unicom", "China Unicom"     -> R.drawable.ic_unicom
        "China Telecom", "China Telecom"    -> R.drawable.ic_telecom
        else                           -> R.drawable.ic_mobile // fallback
    }

    /**
     */
    private fun maskPhoneNumber(raw: String): String {
        if (raw.isBlank()) return raw

        val digits = raw.filter { it.isDigit() }
        if (digits.length < 7) return raw

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
