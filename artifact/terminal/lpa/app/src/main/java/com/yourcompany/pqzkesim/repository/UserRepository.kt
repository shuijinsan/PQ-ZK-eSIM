package com.yourcompany.pqzkesim.repository

import com.yourcompany.pqzkesim.data.model.UserProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * User profile persistence — file-based for nickname and avatar index.
 * NVRAM directory interrogation for device count and security level.
 */
class UserRepository(private val filesDir: File, private val nvramDir: File) {

    private val userNameFile get() = File(filesDir, "user_name.txt")
    private val avatarIndexFile get() = File(filesDir, "avatar_index.txt")
    private val avatarImageFile get() = File(filesDir, "avatar.jpg")

    suspend fun loadProfile(): UserProfile = withContext(Dispatchers.IO) {
        val nickname = loadNickname()
        val avatarIdx = loadAvatarIndex()
        val deviceCount = countDevices()
        val securityLevel = if (isPqcEnabled()) "抗量子国防级" else "标准生物级"
        val customPath = if (avatarImageFile.exists()) avatarImageFile.absolutePath else null

        UserProfile(
            nickname = nickname,
            userId = "eUICC-${deviceCount.toString().padStart(4, '0')}",
            registerTime = "2025-06-01 12:00:00", // would read from NVRAM in production
            deviceCount = deviceCount,
            securityLevel = securityLevel,
            avatarIndex = avatarIdx,
            customAvatarPath = customPath
        )
    }

    suspend fun saveNickname(nickname: String): Boolean = withContext(Dispatchers.IO) {
        try {
            userNameFile.writeText(nickname)
            true
        } catch (e: Exception) { false }
    }

    suspend fun saveAvatarIndex(index: Int): Boolean = withContext(Dispatchers.IO) {
        try {
            avatarIndexFile.writeText(index.toString())
            true
        } catch (e: Exception) { false }
    }

    suspend fun saveCustomAvatar(sourceFile: File): Boolean = withContext(Dispatchers.IO) {
        try {
            avatarImageFile.parentFile?.mkdirs()
            sourceFile.copyTo(avatarImageFile, overwrite = true)
            true
        } catch (e: Exception) { false }
    }

    suspend fun clearCustomAvatar(): Boolean = withContext(Dispatchers.IO) {
        try {
            avatarImageFile.delete()
            true
        } catch (e: Exception) { false }
    }

    suspend fun logout(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Delete NVRAM directory tree
            nvramDir.deleteRecursively()
            // Delete user files
            userNameFile.delete()
            avatarIndexFile.delete()
            avatarImageFile.delete()
            true
        } catch (e: Exception) { false }
    }

    private fun loadNickname(): String {
        return if (userNameFile.exists()) userNameFile.readText().trim()
        else "PQ-ZK User"
    }

    private fun loadAvatarIndex(): Int {
        return if (avatarIndexFile.exists()) {
            avatarIndexFile.readText().trim().toIntOrNull() ?: 0
        } else 0
    }

    private fun countDevices(): Int {
        return if (nvramDir.exists() && nvramDir.isDirectory) {
            nvramDir.listFiles()?.size ?: 0
        } else 0
    }

    private fun isPqcEnabled(): Boolean = nvramDir.exists() && nvramDir.isDirectory
}
