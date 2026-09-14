package com.yourcompany.pqzkesim

import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.animation.AnimationUtils
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * 时间线动画控制器 — 基于预编程固定时间线，按固定节奏顺序播放四个阶段的动画。
 *
 * 每阶段约 1.1 秒，四个阶段总计约 4.4 秒完成全部节点激活。
 * 动画节奏固定、确定、不依赖进度条轮询——进度条仅用于在 HomeFragment 中
 * 显示百分比数字，不与动画时序耦合。
 *
 * 阶段：
 *   Phase 0: Commitment   → 节点 0 弹出 → 脉冲 → 连线展开 → 完成变绿
 *   Phase 1: Challenge    → 节点 1 同样流程
 *   Phase 2: Proof        → 节点 2 同样流程
 *   Phase 3: Verification → 节点 3 同样流程（无后续连线）
 *
 * 所有通过 handler.postDelayed 调度的任务都被追踪，确保 markSuccess/markError
 * 调用时可以干净地取消所有待执行动画并立即切换到终态。
 */
class TimelineAnimator(
    private val activity: AppCompatActivity,
    private val progressBar: ProgressBar
) {
    // ── View ───────────────────────────────────────────────────
    private val nodes = arrayOfNulls<View>(4)
    private val lines = arrayOfNulls<View>(3)
    private val names = arrayOfNulls<TextView>(4)

    // ── 状态 ───────────────────────────────────────────────────
    private var isRunning = false
    private var currentPhase = -1         // 当前正在播放的阶段 (-1 = 未开始)
    private var generation = 0            // 递增以批量作废所有已调度回调

    // ── 时间线常量（毫秒）─────────────────────────────────────
    companion object {
        // 单阶段内部时序
        private const val T_ACTIVATE      =   0L   // 激活节点（pop-in 320ms）
        private const val T_PULSE         = 340L   // 开始脉冲
        private const val T_LINE          = 560L   // 连线展开（slide 400ms）
        private const val T_DONE          = 980L   // 标记完成（缩放弹跳 270ms）
        private const val T_NEXT_PHASE    = 1270L  // 进入下一阶段

        // 成功涟漪
        private const val T_RIPPLE_STEP   = 280L  // 每个节点的涟漪间隔
    }

    // ── 颜色 ───────────────────────────────────────────────────
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
    // 公开 API
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

    /** 仅重置节点为灰色初始态，不启动动画（用于页面进入时清理残留状态） */
    fun resetVisuals() {
        cancelAllPending()
        isRunning = false
        currentPhase = -1
        resetAllGray()
    }

    /** 启动：重置全部为灰色，一次性预排全部 4 个阶段的时间线 */
    fun start() {
        cancelAllPending()
        resetAllGray()
        isRunning = true
        currentPhase = -1
        for (p in 0..3) schedulePhase(p)
    }

    /** 成功：取消时间线，按顺序涟漪将所有节点变绿 */
    fun markSuccess() {
        cancelAllPending()
        isRunning = false
        stopPulse()
        // 找出哪些节点还不是绿色，按涟漪逐一完成
        rippleAllToDone(0)
    }

    /** 失败：取消时间线，当前节点标红 */
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
    // 预编程时间线 — 在 start() 中一次性全部预排，所有时间相对 t=0
    // ═══════════════════════════════════════════════════════════

    private fun schedulePhase(phase: Int) {
        val base = phase * T_NEXT_PHASE       // 本阶段起始偏移

        // 激活：base + 0ms
        schedule(base + T_ACTIVATE) {
            currentPhase = phase
            activateNode(phase)
        }
        // 脉冲：base + 340ms
        schedule(base + T_PULSE) {
            startPulse(phase)
        }
        // 连线：base + 560ms（最后一个节点无连线）
        if (phase < 3) {
            schedule(base + T_LINE) {
                expandLine(phase)
            }
        }
        // 前节点完成变绿：前节点 base + 980ms
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
    // 节点动画原语
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
    // 成功涟漪
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
    // 任务调度 & 取消 — 通过 generation 计数器批量作废
    // ═══════════════════════════════════════════════════════════

    private fun schedule(delayMs: Long, action: () -> Unit) {
        val gen = generation
        handler.postDelayed({
            if (generation == gen) action()
        }, delayMs)
    }

    private fun cancelAllPending() {
        generation++  // 所有已调度回调看到 generation 不匹配，自动跳过
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
