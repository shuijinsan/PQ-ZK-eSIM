package com.yourcompany.pqzkesim

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    /**
     * 将 Long 类型的计数器转换为 8 字节的小端序 ByteArray
     * 规范要求：ctr 传输与哈希时必须采用 Little-Endian
     */
    fun longToLittleEndian(value: Long): ByteArray {
        return ByteBuffer.allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(value)
            .array()
    }

    /**
     * SHA-256 哈希
     * 用于生成 r_dynamic: SHA-256(r_bio || ctr)
     */
    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * HMAC-SHA256 签名
     * 用于生成 AuthToken: HMAC(K_TEE, c_agg || ctr || r_dyn || h_M2)
     */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key, "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    // --- 进制转换工具 ---

    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // 报错解决：添加缺失的 hexToBytes
    fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in 0 until hex.length step 2) {
            val firstDigit = Character.digit(hex[i], 16)
            val secondDigit = Character.digit(hex[i + 1], 16)
            result[i / 2] = ((firstDigit shl 4) + secondDigit).toByte()
        }
        return result
    }
}