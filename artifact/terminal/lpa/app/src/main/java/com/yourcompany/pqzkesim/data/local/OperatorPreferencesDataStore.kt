package com.yourcompany.pqzkesim.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.yourcompany.pqzkesim.data.model.OperatorConfig
import com.yourcompany.pqzkesim.data.model.OperatorInfo
import com.yourcompany.pqzkesim.data.model.OperatorStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "operator_prefs")

/**
 * Per-operator profile data persisted after successful eSIM activation.
 * Each auth for the same operator creates a new entry (appended, not replaced).
 */
data class OperatorProfileData(
    val iccid: String = "",
    val phoneNumber: String = "",
    val activatedAt: String = "",
    val operatorName: String = ""
)

class OperatorPreferencesDataStore(private val context: Context) {

    companion object Keys {
        val KEY_IS_CARD_ACTIVATED = booleanPreferencesKey("is_card_activated")
        val KEY_ACTIVE_OPERATOR   = stringPreferencesKey("active_operator")
        val KEY_ACTIVE_DOMAIN_ID  = stringPreferencesKey("active_domain_id")
        val KEY_PHONE_NUMBER      = stringPreferencesKey("active_phone_number")
        val KEY_OPERATOR_PROFILES = stringPreferencesKey("operator_profiles")
    }

    val isCardActivated: Flow<Boolean> = context.dataStore.data.map { prefs ->
        prefs[KEY_IS_CARD_ACTIVATED] ?: false
    }

    val activeOperator: Flow<String> = context.dataStore.data.map { prefs ->
        prefs[KEY_ACTIVE_OPERATOR] ?: ""
    }

    val activeDomainId: Flow<String> = context.dataStore.data.map { prefs ->
        prefs[KEY_ACTIVE_DOMAIN_ID] ?: ""
    }

    val phoneNumber: Flow<String> = context.dataStore.data.map { prefs ->
        prefs[KEY_PHONE_NUMBER] ?: ""
    }

    suspend fun setCardActivated(activated: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[KEY_IS_CARD_ACTIVATED] = activated
        }
    }

    suspend fun setActiveOperator(operatorName: String, domainId: String) {
        val canonical = OperatorConfig.resolveDomainId(domainId)
        context.dataStore.edit { prefs ->
            prefs[KEY_ACTIVE_OPERATOR] = operatorName
            prefs[KEY_ACTIVE_DOMAIN_ID] = canonical
        }
    }

    suspend fun bindOperator(operatorInfo: OperatorInfo) {
        val canonical = OperatorConfig.resolveDomainId(operatorInfo.domainId)
        context.dataStore.edit { prefs ->
            prefs[KEY_IS_CARD_ACTIVATED] = true
            prefs[KEY_ACTIVE_OPERATOR]   = operatorInfo.name
            prefs[KEY_ACTIVE_DOMAIN_ID]  = canonical
        }
    }

    suspend fun setPhoneNumber(number: String) {
        context.dataStore.edit { prefs ->
            prefs[KEY_PHONE_NUMBER] = number
        }
    }

    suspend fun unbindOperator() {
        context.dataStore.edit { prefs ->
            prefs.remove(KEY_IS_CARD_ACTIVATED)
            prefs.remove(KEY_ACTIVE_OPERATOR)
            prefs.remove(KEY_ACTIVE_DOMAIN_ID)
        }
    }

    // ──── Per-operator profile list storage (operator_profiles JSON) ────

    /** Flow of all per-operator profile LISTS, keyed by domainId. */
    val operatorProfilesFlow: Flow<Map<String, List<OperatorProfileData>>> = context.dataStore.data.map { prefs ->
        val json = prefs[KEY_OPERATOR_PROFILES] ?: "{}"
        parseProfilesJson(json)
    }

    /**
     * APPEND a new profile for the operator — never overwrites existing entries.
     * Same operator authenticating multiple times → multiple phone numbers accumulated.
     */
    suspend fun setOperatorProfile(
        domainId: String,
        iccid: String,
        phoneNumber: String,
        operatorName: String,
        activatedAt: String
    ) {
        val canonical = OperatorConfig.resolveDomainId(domainId)
        context.dataStore.edit { prefs ->
            val json = prefs[KEY_OPERATOR_PROFILES] ?: "{}"
            val map = parseProfilesJson(json).toMutableMap()
            val list = map[canonical]?.toMutableList() ?: mutableListOf()
            list.add(OperatorProfileData(iccid, phoneNumber, activatedAt, operatorName))
            map[canonical] = list
            prefs[KEY_OPERATOR_PROFILES] = profilesToJson(map)
            // Also set as active domain + latest phone
            prefs[KEY_ACTIVE_DOMAIN_ID] = canonical
            prefs[KEY_PHONE_NUMBER] = phoneNumber
        }
    }

    /** Remove all profiles for a single operator. */
    suspend fun removeOperatorProfile(domainId: String) {
        val canonical = OperatorConfig.resolveDomainId(domainId)
        context.dataStore.edit { prefs ->
            val json = prefs[KEY_OPERATOR_PROFILES] ?: "{}"
            val map = parseProfilesJson(json).toMutableMap()
            map.remove(canonical)
            prefs[KEY_OPERATOR_PROFILES] = profilesToJson(map)
        }
    }

    private fun parseProfilesJson(json: String): Map<String, List<OperatorProfileData>> {
        return try {
            val root = JSONObject(json)
            val map = mutableMapOf<String, List<OperatorProfileData>>()
            for (domainId in root.keys()) {
                val arr = root.optJSONArray(domainId) ?: continue
                val list = mutableListOf<OperatorProfileData>()
                for (i in 0 until arr.length()) {
                    val obj = arr.optJSONObject(i) ?: continue
                    list.add(OperatorProfileData(
                        iccid = obj.optString("iccid", ""),
                        phoneNumber = obj.optString("phoneNumber", ""),
                        activatedAt = obj.optString("activatedAt", ""),
                        operatorName = obj.optString("operatorName", "")
                    ))
                }
                if (list.isNotEmpty()) map[domainId] = list
            }
            map
        } catch (_: Exception) {
            emptyMap()
        }
    }

    private fun profilesToJson(map: Map<String, List<OperatorProfileData>>): String {
        val root = JSONObject()
        for ((domainId, profiles) in map) {
            val arr = JSONArray()
            for (p in profiles) {
                arr.put(JSONObject().apply {
                    put("iccid", p.iccid)
                    put("phoneNumber", p.phoneNumber)
                    put("activatedAt", p.activatedAt)
                    put("operatorName", p.operatorName)
                })
            }
            root.put(domainId, arr)
        }
        return root.toString()
    }

    fun getOperatorStatus(operatorInfo: OperatorInfo): Flow<OperatorStatus> =
        context.dataStore.data.map { prefs ->
            val isActivated = prefs[KEY_IS_CARD_ACTIVATED] ?: false
            val storedDomainId = prefs[KEY_ACTIVE_DOMAIN_ID] ?: ""
            val canonical = OperatorConfig.resolveDomainId(storedDomainId)
            if (isActivated && canonical == operatorInfo.domainId) OperatorStatus.BOUND
            else OperatorStatus.UNBOUND
        }

    suspend fun clearAll() {
        context.dataStore.edit { it.clear() }
    }
}
