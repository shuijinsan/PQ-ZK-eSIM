package com.yourcompany.pqzkesim.data.model

// 认证日志条目（Room 实体）

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "auth_logs")
data class AuthLogItem(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val status: String,           // "SUCCESS", "FAILED", "ERROR"
    val time: String,             // ISO datetime string from LogViewModel
    val durationMs: Long,         // auth duration in milliseconds
    val sessionId: String,        // server session ID (full)
    val counter: Long,            // eUICC ctr_local value
    val operatorInfo: String = "", // active operator name, empty if none
    val phoneNumber: String = ""  // 开通的手机号
)
