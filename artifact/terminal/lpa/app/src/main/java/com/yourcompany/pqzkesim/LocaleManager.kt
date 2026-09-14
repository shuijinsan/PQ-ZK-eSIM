package com.yourcompany.pqzkesim

import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import java.util.Locale

/**
 * 全局语言管理器
 *
 * 使用 Android 标准国际化方案：
 *   - 中文：values/strings.xml（默认）
 *   - 英文：values-en/strings.xml
 *
 * 语言偏好通过 SharedPreferences 持久化，应用重启后自动读取。
 */
object LocaleManager {

    private const val PREFS_NAME = "locale_prefs"
    private const val KEY_LANGUAGE = "app_language"

    /** 支持的语言 */
    const val LANG_ZH_CN = "zh_CN"
    const val LANG_EN = "en"

    /** 默认语言（中文） */
    const val DEFAULT_LANGUAGE = LANG_ZH_CN

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * 获取当前保存的语言偏好
     */
    fun getCurrentLanguage(context: Context): String {
        return getPrefs(context).getString(KEY_LANGUAGE, DEFAULT_LANGUAGE) ?: DEFAULT_LANGUAGE
    }

    /**
     * 保存语言偏好
     */
    fun setLanguage(context: Context, language: String) {
        getPrefs(context).edit().putString(KEY_LANGUAGE, language).apply()
    }

    /**
     * 获取语言对应的 Locale
     */
    fun getLocale(language: String): Locale = when (language) {
        LANG_EN -> Locale.ENGLISH
        else -> Locale.SIMPLIFIED_CHINESE
    }

    /**
     * 获取语言显示名称
     */
    fun getLanguageDisplayName(language: String, context: Context): String = when (language) {
        LANG_EN -> context.getString(R.string.lang_en)
        else -> context.getString(R.string.lang_zh_cn)
    }

    /**
     * 在 Application.onCreate() 或 Activity.attachBaseContext() 中调用，
     * 应用保存的语言设置到 Context。
     *
     * @param base 原始 Context
     * @return 应用了语言设置的 Context
     */
    fun applyLanguage(base: Context): Context {
        val language = getCurrentLanguage(base)
        return updateContextLocale(base, language)
    }

    /**
     * 切换语言并返回新的 Context
     */
    fun switchLanguage(context: Context, language: String): Context {
        setLanguage(context, language)
        return updateContextLocale(context, language)
    }

    private fun updateContextLocale(context: Context, language: String): Context {
        val locale = getLocale(language)
        Locale.setDefault(locale)

        val resources: Resources = context.resources
        val config = Configuration(resources.configuration)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            config.setLocale(locale)
            config.setLocales(android.os.LocaleList(locale))
        } else {
            @Suppress("DEPRECATION")
            config.locale = locale
        }

        return context.createConfigurationContext(config)
    }
}
