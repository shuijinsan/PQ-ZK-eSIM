package com.yourcompany.pqzkesim.repository


import com.yourcompany.pqzkesim.data.local.AuthLogDao
import com.yourcompany.pqzkesim.data.model.AuthLogItem
import kotlinx.coroutines.flow.Flow

class LogRepository(private val authLogDao: AuthLogDao) {

    val allLogs: Flow<List<AuthLogItem>> = authLogDao.getAll()

    fun getRecentLogs(limit: Int = 50): Flow<List<AuthLogItem>> =
        authLogDao.getRecent(limit)

    suspend fun insert(status: String, time: String, durationMs: Long,
                       sessionId: String, counter: Long, operatorInfo: String = ""): Long {
        val log = AuthLogItem(
            status = status,
            time = time,
            durationMs = durationMs,
            sessionId = sessionId,
            counter = counter,
            operatorInfo = operatorInfo
        )
        return authLogDao.insert(log)
    }

    suspend fun deleteAll() = authLogDao.deleteAll()

    suspend fun count(): Int = authLogDao.count()
}
