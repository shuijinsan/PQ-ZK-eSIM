package com.yourcompany.pqzkesim

import android.app.Application
import android.content.Context

/**
 * Application 基类 — 在应用启动时应用保存的语言设置。
 *
 * 所有继承 BaseLocaleActivity 的 Activity 会在 attachBaseContext 中
 * 自动应用当前语言偏好，实现全应用覆盖。
 */
class App : Application() {

    companion object {
        /** 用于需要 Context 以获取字符串资源的静态场景 */
        @Volatile
        private lateinit var instance: App

        fun getInstance(): App = instance
    }

    override fun onCreate() {
        instance = this
        super.onCreate()
    }

    override fun attachBaseContext(base: Context) {
        // 在 Application 层面先应用一次语言设置
        super.attachBaseContext(LocaleManager.applyLanguage(base))
    }
}

/**
 * 带语言感知的 Activity 基类。
 * 每个 Activity 继承此类即可自动获得语言切换能力。
 */
open class BaseLocaleActivity : androidx.appcompat.app.AppCompatActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleManager.applyLanguage(newBase))
    }
}
