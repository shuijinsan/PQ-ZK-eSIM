package com.yourcompany.pqzkesim // 确保包名与项目一致

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.TextView


import androidx.core.content.ContextCompat
import com.yourcompany.pqzkesim.NativeLib.isRegistered
import java.io.File

class SplashActivity : BaseLocaleActivity() {
    private val CAMERA_PERMISSION_REQUEST = 200

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        val tvStatus = findViewById<TextView>(R.id.tv_init_status)

        // Check camera permission before proceeding
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED) {
            tvStatus.text = getString(R.string.app_apply_permission)
            requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_PERMISSION_REQUEST)
        } else {
            startInitSequence(tvStatus)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_REQUEST) {
            val tvStatus = findViewById<TextView>(R.id.tv_init_status)
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startInitSequence(tvStatus)
            } else {
                tvStatus.text = getString(R.string.app_camera_permission_denied)
                // Still proceed — face registration can be skipped
                startInitSequence(tvStatus)
            }
        }
    }

    private fun startInitSequence(tvStatus: TextView) {
        Handler(Looper.getMainLooper()).postDelayed({
            tvStatus.text = getString(R.string.app_loading_pqc_lib)

            val nvram = File(filesDir, "euicc_nvram")
            if (!nvram.exists()) {
                val created = nvram.mkdirs()
                Log.d("PQZK", "NVRAM目录创建: $created")
            }

            tvStatus.text = getString(R.string.app_secure_env_ready)

            Handler(Looper.getMainLooper()).postDelayed({
                try {
                    val nvramPath = filesDir.absolutePath + "/euicc_nvram"
                    val isRegistered = NativeLib.isRegistered(nvramPath)

                    val target = if (isRegistered == 1) {
                        MainActivity::class.java
                    } else {
                        RegisterActivity::class.java
                    }

                    startActivity(Intent(this, target))
                    finish()
                } catch (e: Exception) {
                    Log.e("PQZK", "Native判断注册状态失败，强制跳注册页", e)
                    startActivity(Intent(this, RegisterActivity::class.java))
                    finish()
                }
            }, 1000)

        }, 1500)
    }

}