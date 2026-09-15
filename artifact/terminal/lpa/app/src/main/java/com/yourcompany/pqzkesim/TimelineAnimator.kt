package com.yourcompany.pqzkesim

import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.animation.AnimationUtils
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 *
 *
 *
 */
class TimelineAnimator(
    private val activity: AppCompatActivity,
    private val progressBar: ProgressBar
) {
    // ── View ───────────────────────────────────────────────────
    private val nodes = arrayOfNulls<View>(4)
    private val lines = arrayOfNulls<View>(3)
    private val names = arrayOfNulls<TextView>(4)

    private var isRunning = false
    private var currentPhase = -1
    private var generation = 0

    companion object {
        private const val T_ACTIVATE      =   0L
        private const val T_PULSE         = 340L
        private const val T_LINE          = 560L
        private const val T_DONE          = 980L
        private const val T_NEXT_PHASE    = 1270L

        private const val T_RIPPLE_STEP   = 280L
    }

    private val colorActive     = 0xFF2563EB.toInt()
    private val colorDone       = 0xFF10B981.toInt()
    private val colorGray       = 0xFF9CA3AF.toInt()
    private val colorLineIdle   = 0xFFE5E7EB.toInt()
    private val colorLineActive = 0xFF2563EB.toInt()

    private val handler = Handler(Looper.getMainLooper())

    // ── Drawables ───────────────────────────────────────────────
    private val drawableActive get() = activity.getDrawable(R.drawable.shape_circle_active)
    private val drawableDone   get() = activity.getDrawable(R.drawable.shape_circle_done)
    private val drawableError  get() = activity.getDrawable(R.drawable.shape_circle_error)
    private val drawableGray   get() = activity.getDrawable(R.drawable.shape_circle_gray)

    // ═══════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════

    fun bind() {
        nodes[0] = activity.findViewById(R.id.tl_node_0)
        nodes[1] = activity.findViewById(R.id.tl_node_1)
        nodes[2] = activity.findViewById(R.id.tl_node_2)
        nodes[3] = activity.findViewById(R.id.tl_node_3)
        lines[0] = activity.findViewById(R.id.tl_line_0)
        lines[1] = activity.findViewById(R.id.tl_line_1)
        lines[2] = activity.findViewById(R.id.tl_line_2)
        names[0] = activity.findViewById(R.id.tl_name_0)
        names[1] = activity.findViewById(R.id.tl_name_1)
        names[2] = activity.findViewById(R.id.tl_name_2)
        names[3] = activity.findViewById(R.id.tl_name_3)
        for (node in nodes) node?.let { it.scaleX = 1f; it.scaleY = 1f }
        for (line in lines) line?.let { it.scaleX = 1f; it.scaleY = 1f }
    }

    fun resetVisuals() {
        cancelAllPending()
        isRunning = false
        currentPhase = -1
        resetAllGray()
    }

    fun start() {
        cancelAllPending()
        resetAllGray()
        isRunning = true
        currentPhase = -1
        for (p in 0..3) schedulePhase(p)
    }

    fun markSuccess() {
        cancelAllPending()
        isRunning = false
        stopPulse()
        rippleAllToDone(0)
    }

    fun markError() {
        cancelAllPending()
        isRunning = false
        stopPulse()
        val errorIdx = currentPhase.coerceIn(0, 3)
        nodes[errorIdx]?.let {
            it.clearAnimation(); it.background = drawableError
            it.scaleX = 1f; it.scaleY = 1f
        }
        names[errorIdx]?.setTextColor(0xFFEF4444.toInt())
    }

    // ═══════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════

    private fun schedulePhase(phase: Int) {
        val base = phase * T_NEXT_PHASE

        schedule(base + T_ACTIVATE) {
            currentPhase = phase
            activateNode(phase)
        }
        schedule(base + T_PULSE) {
            startPulse(phase)
        }
        if (phase < 3) {
            schedule(base + T_LINE) {
                expandLine(phase)
            }
        }
        if (phase > 0) {
            val prevBase = (phase - 1) * T_NEXT_PHASE
            schedule(prevBase + T_DONE) {
                markNodeDone(phase - 1)
                markLineDone(phase - 1)
                stopPulse()
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════

    private fun activateNode(index: Int) {
        nodes[index]?.let { node ->
            node.background = drawableActive
            node.pivotX = node.width / 2f; node.pivotY = node.height / 2f
            node.startAnimation(AnimationUtils.loadAnimation(activity, R.anim.node_activate))
        }
        names[index]?.setTextColor(colorActive)
    }

    private fun markNodeDone(index: Int) {
        nodes[index]?.let { node ->
            node.clearAnimation()
            node.background = drawableDone
            node.pivotX = node.width / 2f; node.pivotY = node.height / 2f
            node.animate().scaleX(1.25f).scaleY(1.25f).setDuration(150)
                .withEndAction {
                    node.animate().scaleX(1f).scaleY(1f).setDuration(120).start()
                }.start()
        }
        names[index]?.setTextColor(colorDone)
    }

    private fun markLineDone(index: Int) {
        lines[index]?.setBackgroundColor(colorDone)
    }

    private fun expandLine(index: Int) {
        lines[index]?.let { line ->
            line.setBackgroundColor(colorLineActive)
            line.startAnimation(AnimationUtils.loadAnimation(activity, R.anim.line_slide_in))
        }
    }

    private fun startPulse(index: Int) {
        val node = nodes[index] ?: return
        node.pivotX = node.width / 2f; node.pivotY = node.height / 2f
        node.startAnimation(AnimationUtils.loadAnimation(activity, R.anim.node_pulse))
    }

    private fun stopPulse() {
        for (i in 0..3) nodes[i]?.clearAnimation()
    }

    // ═══════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════

    private fun rippleAllToDone(index: Int) {
        if (index > 3) return
        markNodeDone(index)
        if (index < 3) markLineDone(index)
        if (index < 3) {
            handler.postDelayed({ rippleAllToDone(index + 1) }, T_RIPPLE_STEP)
        }
    }

    // ═══════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════

    private fun schedule(delayMs: Long, action: () -> Unit) {
        val gen = generation
        handler.postDelayed({
            if (generation == gen) action()
        }, delayMs)
    }

    private fun cancelAllPending() {
        generation++
    }

    private fun resetAllGray() {
        for (i in 0..3) {
            nodes[i]?.let {
                it.background = drawableGray
                it.clearAnimation()
                it.scaleX = 1f; it.scaleY = 1f
            }
            names[i]?.setTextColor(colorGray)
        }
        for (i in 0..2) {
            lines[i]?.setBackgroundColor(colorLineIdle)
            lines[i]?.clearAnimation()
        }
    }
}
