package com.yourcompany.pqzkesim.data.local


import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.yourcompany.pqzkesim.data.model.AuthLogItem

@Database(entities = [AuthLogItem::class], version = 1, exportSchema = false)
abstract class AuthLogDatabase : RoomDatabase() {
    abstract fun authLogDao(): AuthLogDao

    companion object {
        @Volatile
        private var INSTANCE: AuthLogDatabase? = null

        fun getInstance(context: Context): AuthLogDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AuthLogDatabase::class.java,
                    "pqzk_auth_logs.db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
