package com.yourcompany.pqzkesim.data.local

// 认证日志数据访问对象（Room DAO）

import androidx.room.*
import com.yourcompany.pqzkesim.data.model.AuthLogItem
import kotlinx.coroutines.flow.Flow

@Dao
interface AuthLogDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(log: AuthLogItem): Long

    @Query("SELECT * FROM auth_logs ORDER BY id DESC")
    fun getAll(): Flow<List<AuthLogItem>>

    @Query("SELECT * FROM auth_logs ORDER BY id DESC LIMIT :limit")
    fun getRecent(limit: Int = 50): Flow<List<AuthLogItem>>

    @Query("DELETE FROM auth_logs")
    suspend fun deleteAll()

    @Query("SELECT COUNT(*) FROM auth_logs")
    suspend fun count(): Int
}
