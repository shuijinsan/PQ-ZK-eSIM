package com.yourcompany.pqzkesim

import android.graphics.Canvas
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.RectF
import android.graphics.drawable.Drawable

/**
 * 环形进度 Drawable — 从 12 点钟方向（顶部）开始顺时针填充。
 *
 * 直接替代 ProgressBar 的 progressDrawable，
 * 同时绘制背景轨道和前景进度弧，不依赖 View.rotation。
 * 起点固定为 -90°（12 点钟），level 0~10000 映射到 0°~360°。
 */
class ProgressRingDrawable(
    trackColor: Int = 0xFFE5E7EB.toInt(),
    progressColor: Int = 0xFF2563EB.toInt(),
    private val strokePx: Float = 4f
) : Drawable() {

    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        color = trackColor
        strokeWidth = strokePx
    }
    private val progressPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        color = progressColor
        strokeWidth = strokePx
    }

    companion object {
        private const val START_ANGLE = -90f   // 12 点钟方向
        private const val FULL_SWEEP  = 360f
    }

    override fun draw(canvas: Canvas) {
        val half = strokePx / 2f
        val rect = RectF(
            bounds.left.toFloat() + half,
            bounds.top.toFloat() + half,
            bounds.right.toFloat() - half,
            bounds.bottom.toFloat() - half
        )

        // 背景轨道：完整圆环
        canvas.drawArc(rect, 0f, FULL_SWEEP, false, trackPaint)

        // 进度弧：level 0~10000 → 0°~360°
        val sweep = FULL_SWEEP * level.coerceIn(0, 10000) / 10000f
        if (sweep > 0f) {
            canvas.drawArc(rect, START_ANGLE, sweep, false, progressPaint)
        }
    }

    override fun onLevelChange(level: Int): Boolean {
        invalidateSelf()
        return true
    }

    override fun setAlpha(alpha: Int) {
        trackPaint.alpha = alpha
        progressPaint.alpha = alpha
    }

    override fun setColorFilter(colorFilter: ColorFilter?) {
        trackPaint.colorFilter = colorFilter
        progressPaint.colorFilter = colorFilter
    }

    @Deprecated("Deprecated in Java")
    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
}
