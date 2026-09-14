package com.yourcompany.pqzkesim.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.appPrefsStore: DataStore<Preferences> by preferencesDataStore(name = "app_prefs")

/**
 * Application-level preferences: first-launch state, security level, current operator.
 */
class AppPreferences(private val context: Context) {

    companion object Keys {
        val KEY_IS_INITIALIZED   = booleanPreferencesKey("is_initialized")
        val KEY_SECURITY_LEVEL   = stringPreferencesKey("security_level")
        val KEY_CURRENT_OPERATOR = stringPreferencesKey("current_operator")
    }

    val isInitialized: Flow<Boolean> = context.appPrefsStore.data.map { prefs ->
        prefs[KEY_IS_INITIALIZED] ?: false
    }

    val securityLevel: Flow<String> = context.appPrefsStore.data.map { prefs ->
        prefs[KEY_SECURITY_LEVEL] ?: "标准生物级"
    }

    val currentOperator: Flow<String> = context.appPrefsStore.data.map { prefs ->
        prefs[KEY_CURRENT_OPERATOR] ?: ""
    }

    suspend fun setInitialized(initialized: Boolean = true) {
        context.appPrefsStore.edit { prefs ->
            prefs[KEY_IS_INITIALIZED] = initialized
        }
    }

    suspend fun setSecurityLevel(level: String) {
        context.appPrefsStore.edit { prefs ->
            prefs[KEY_SECURITY_LEVEL] = level
        }
    }

    suspend fun setCurrentOperator(operatorName: String) {
        context.appPrefsStore.edit { prefs ->
            prefs[KEY_CURRENT_OPERATOR] = operatorName
        }
    }
}
