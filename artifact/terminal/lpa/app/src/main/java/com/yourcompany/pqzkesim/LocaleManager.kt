package com.yourcompany.pqzkesim

import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import java.util.Locale

/**
 *
 *
 */
object LocaleManager {

    private const val PREFS_NAME = "locale_prefs"
    private const val KEY_LANGUAGE = "app_language"

    const val LANG_ZH_CN = "zh_CN"
    const val LANG_EN = "en"

    const val DEFAULT_LANGUAGE = LANG_ZH_CN

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     */
    fun getCurrentLanguage(context: Context): String {
        return getPrefs(context).getString(KEY_LANGUAGE, DEFAULT_LANGUAGE) ?: DEFAULT_LANGUAGE
    }

    /**
     */
    fun setLanguage(context: Context, language: String) {
        getPrefs(context).edit().putString(KEY_LANGUAGE, language).apply()
    }

    /**
     */
    fun getLocale(language: String): Locale = when (language) {
        LANG_EN -> Locale.ENGLISH
        else -> Locale.SIMPLIFIED_CHINESE
    }

    /**
     */
    fun getLanguageDisplayName(language: String, context: Context): String = when (language) {
        LANG_EN -> context.getString(R.string.lang_en)
        else -> context.getString(R.string.lang_zh_cn)
    }

    /**
     *
     */
    fun applyLanguage(base: Context): Context {
        val language = getCurrentLanguage(base)
        return updateContextLocale(base, language)
    }

    /**
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
