package com.yourcompany.pqzkesim.viewmodel

// 用户资料视图模型

import android.app.Application
import android.net.Uri
import android.widget.Toast
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.yourcompany.pqzkesim.data.local.AppPreferences
import com.yourcompany.pqzkesim.data.model.UserProfile
import com.yourcompany.pqzkesim.repository.UserRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ProfileViewModel(application: Application) : AndroidViewModel(application) {

    private val filesDir = application.filesDir
    private val nvramDir = File(filesDir, "euicc_nvram")
    private val repository = UserRepository(filesDir, nvramDir)
    private val appPrefs = AppPreferences(application)

    private val _userProfile = MutableLiveData<UserProfile>()
    val userProfile: LiveData<UserProfile> = _userProfile

    private val _avatarIndex = MutableLiveData(0)
    val avatarIndex: LiveData<Int> = _avatarIndex

    private val _customAvatarPath = MutableLiveData<String?>()
    val customAvatarPath: LiveData<String?> = _customAvatarPath

    private val _logoutEvent = MutableLiveData<Boolean>()
    val logoutEvent: LiveData<Boolean> = _logoutEvent

    init { loadProfile() }

    fun loadProfile() {
        viewModelScope.launch(Dispatchers.IO) {
            val profile = repository.loadProfile()
            _userProfile.postValue(profile)
            _avatarIndex.postValue(profile.avatarIndex)
            _customAvatarPath.postValue(profile.customAvatarPath)
        }
    }

    fun saveNickname(nickname: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.saveNickname(nickname)
            loadProfile()
        }
    }

    fun cycleAvatar() {
        val current = _avatarIndex.value ?: 0
        val next = (current + 1) % 3
        _avatarIndex.value = next
        _customAvatarPath.value = null
        viewModelScope.launch(Dispatchers.IO) {
            repository.saveAvatarIndex(next)
            repository.clearCustomAvatar()
        }
    }

    fun saveCustomAvatar(resultUri: Uri?) {
        if (resultUri == null) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val tempFile = File(filesDir, "crop_temp.jpg")
                val inputOpened = getApplication<Application>().contentResolver
                    .openInputStream(resultUri)?.use { input ->
                        tempFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                        true
                    } ?: false

                if (!inputOpened) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(getApplication(), "无法读取裁剪结果", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                val saved = repository.saveCustomAvatar(tempFile)
                tempFile.delete()
                if (saved) {
                    _customAvatarPath.postValue(File(filesDir, "avatar.jpg").absolutePath)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(getApplication(), "头像已更新", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(getApplication(), "保存头像失败", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "保存头像失败: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    fun updateSecurityLevel() {
        viewModelScope.launch(Dispatchers.IO) {
            val profile = repository.loadProfile()
            appPrefs.setSecurityLevel(profile.securityLevel)
        }
    }

    fun logout() {
        viewModelScope.launch(Dispatchers.IO) {
            repository.logout()
            appPrefs.setInitialized(false)
            _logoutEvent.postValue(true)
        }
    }
}
