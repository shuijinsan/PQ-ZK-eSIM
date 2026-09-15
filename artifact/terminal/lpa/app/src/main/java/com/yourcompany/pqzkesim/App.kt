package com.yourcompany.pqzkesim

import android.app.Application
import android.content.Context

/**
 *
 */
class App : Application() {

    companion object {
        @Volatile
        private lateinit var instance: App

        fun getInstance(): App = instance
    }

    override fun onCreate() {
        instance = this
        super.onCreate()
    }

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(LocaleManager.applyLanguage(base))
    }
}

/**
 */
open class BaseLocaleActivity : androidx.appcompat.app.AppCompatActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleManager.applyLanguage(newBase))
    }
}
