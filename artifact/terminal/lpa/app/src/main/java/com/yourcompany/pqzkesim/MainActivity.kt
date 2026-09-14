package com.yourcompany.pqzkesim

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast

import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.yourcompany.pqzkesim.mock.MockConfig
import java.io.File

/**
 * MainActivity — MVVM refactored thin NavHost container.
 * All UI logic lives in Fragments (Home, Comm, Log, Profile).
 * All business logic lives in ViewModels + Repositories.
 */
class MainActivity : BaseLocaleActivity() {

    companion object {
        private const val TAG = "PQZK-Main"
    }

    private lateinit var navController: NavController
    private val nvramDirPath by lazy { filesDir.absolutePath + "/euicc_nvram" }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize Mock config (must be called once at startup)
        MockConfig.init(applicationContext)

        // Ensure NVRAM directory exists
        File(nvramDirPath).let { if (!it.exists()) it.mkdirs() }

        // Setup Navigation Component
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navController = navHostFragment.navController

        val bottomNav = findViewById<BottomNavigationView>(R.id.bottom_navigation)
        bottomNav.setupWithNavController(navController)

        // Check registration — redirect if needed
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val registered = NativeLib.isRegistered(nvramDirPath) == 1
                if (!registered) {
                    withContext(Dispatchers.Main) {
                        startActivity(Intent(this@MainActivity, RegisterActivity::class.java))
                        finish()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Registration check failed, defaulting to register", e)
                withContext(Dispatchers.Main) {
                    startActivity(Intent(this@MainActivity, RegisterActivity::class.java))
                    finish()
                }
            }
        }
    }
}
