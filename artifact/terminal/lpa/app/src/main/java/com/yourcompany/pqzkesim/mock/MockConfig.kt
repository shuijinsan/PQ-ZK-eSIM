package com.yourcompany.pqzkesim.mock

import android.content.Context

/**
 * Global Mock mode toggle (persisted via SharedPreferences).
 *
 * Usage:
 *   1. Call MockConfig.init(applicationContext) once in MainActivity.onCreate()
 *   2. Check MockConfig.isEnabled anywhere to decide mock vs. real behavior
 *   3. Toggle via MockConfig.isEnabled = true/false or from UI switch
 */
object MockConfig {

    private const val PREFS_NAME = "pqzk_mock_config"
    private const val KEY_ENABLED = "mock_enabled"

    private lateinit var appContext: Context

    /** Must be called once at app startup with the application Context. */
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** Read/write the mock toggle. Survives app restart. */
    var isEnabled: Boolean
        get() = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)
        set(value) {
            appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_ENABLED, value).apply()
        }
}
