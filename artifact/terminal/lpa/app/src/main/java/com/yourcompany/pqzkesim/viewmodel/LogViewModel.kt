package com.yourcompany.pqzkesim.viewmodel

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yourcompany.pqzkesim.data.model.AuthLogItem
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class LogViewModel : ViewModel() {

    private val _allLogs = MutableLiveData<List<AuthLogItem>>(emptyList())
    val allLogs: LiveData<List<AuthLogItem>> = _allLogs

    private val logItems = mutableListOf<AuthLogItem>()
    private var nextId: Long = 0L
    private val lock = Any()

    companion object {
        private val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    }

    fun insertLog(
        status: String, durationMs: Long, sessionId: String,
        counter: Long, operatorInfo: String = "", phoneNumber: String = ""
    ) {
        synchronized(lock) {
            val now = LocalDateTime.now().format(DATE_FORMATTER)
            val item = AuthLogItem(
                id = nextId++,
                status = status,
                time = now,
                durationMs = durationMs,
                sessionId = sessionId,
                counter = counter,
                operatorInfo = operatorInfo,
                phoneNumber = phoneNumber
            )
            logItems.add(0, item)
            if (logItems.size > 500) {
                logItems.removeAt(logItems.lastIndex)
            }
            _allLogs.postValue(logItems.toList())
        }
    }

    fun clearAll() {
        synchronized(lock) {
            logItems.clear()
            _allLogs.postValue(emptyList())
        }
    }
}
