package com.example.pqzkesim

import android.util.Log
import com.yourcompany.pqzkesim.CryptoUtils
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * PQ-ZK-eSIM 网络通信客户端 (v5.0 最终集成版)
 * 实现了抗量子零知识证明全流程以及基于 Token 的快速业务授权
 */
object PqcNetworkClient {

    // 考虑到抗量子算法生成的 1536 字节向量在网络传输和后端解盲计算需要时间，超时设为 15秒
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    // 务必确保 BASE_URL 结尾没有多余的反斜杠，并在 AndroidManifest 中开启 CleartextTraffic (如果是 http)
    private const val BASE_URL = "http://192.168.254.129:8000"
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    /**
     * 阶段零] 注册设备资产
     * 将 eUICC 生成的公钥 T 和 TEE 生成的根哈希同步至后端
     */
    fun register(eUiccId: String, pkT: ByteArray, kSym: String, rBio: String, salt: String): String? {
        val json = JSONObject().apply {
            put("eid", eUiccId)
            put("pk_t", CryptoUtils.bytesToHex(pkT))
            put("k_sym", kSym)
            put("r_bio", rBio)
            put("salt", salt)
        }
        return doPost("/register", json)
    }

    /**
     * [阶段一/二] 预计算载荷同步与挑战获取
     * 发送 LPA 预计算生成的 W_pub，换取后端的 c_seed
     */
    fun getChallenge(eUiccId: String, wPub: ByteArray): String? {
        val json = JSONObject().apply {
            put("eid", eUiccId)
            put("w_pub", CryptoUtils.bytesToHex(wPub))
        }
        return doPost("/challenge", json)
    }

    /**
     * 阶段六] 提交聚合响应 Z 进行验证
     * 验证通过后，后端通常会下发用于后续业务办理的 Session Token
     */
    fun verify(eUiccId: String, zFinal: ByteArray, rDynamic: ByteArray): String? {
        val json = JSONObject().apply {
            put("eid", eUiccId)
            put("z", CryptoUtils.bytesToHex(zFinal))
            put("r_dynamic", CryptoUtils.bytesToHex(rDynamic))
        }
        return doPost("/verify", json)
    }

    /**
     * 新增业务功能] 快速办理业务 (免证明)
     * 对应“一次认证，多次信任”逻辑。在首次 ZKP 认证成功后，
     * 仅需携带会话 Token 即可办理业务，无需再次进行复杂的抗量子运算。
     */
    fun quickAction(eid: String, token: String): String? {
        val json = JSONObject().apply {
            put("eid", eid)
            put("token", token)
            put("action", "ACTIVATE_ESIM_SERVICE") // 模拟办理的具体业务操作
        }
        return doPost("/quick_biz", json)
    }

    /**
     * 通用 POST 提交逻辑
     * 自动处理请求体构建、执行与资源释放
     */
    private fun doPost(path: String, json: JSONObject): String? {
        val url = "$BASE_URL$path"
        return try {
            val body = json.toString().toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(url)
                .post(body)
                .build()

            // 使用 use 块确保 ResponseBody 被正确关闭，防止内存泄漏
            client.newCall(request).execute().use { response ->
                val result = response.body?.string()
                if (!response.isSuccessful) {
                    Log.e("PQZK-Net", "Server Error [${response.code}]: $result")
                }
                result
            }
        } catch (e: Exception) {
            Log.e("PQZK-Net", "Network Exception at $path: ${e.message}")
            null
        }
    }
}