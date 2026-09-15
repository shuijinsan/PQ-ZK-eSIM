package com.yourcompany.pqzkesim


import android.content.Context
import android.content.SharedPreferences
import com.yourcompany.pqzkesim.data.model.OperatorConfig
import com.yourcompany.pqzkesim.data.model.OperatorInfo
import com.yourcompany.pqzkesim.data.model.OperatorStatus

object OperatorPrefsManager {
    private const val PREFS_NAME = "operator_prefs"
    private const val KEY_CARD_ACTIVATED = "is_card_activated"
    private const val KEY_ACTIVE_OPERATOR = "active_operator"
    private const val KEY_ACTIVE_DOMAIN_ID = "active_domain_id"
    private const val KEY_PHONE_NUMBER = "active_phone_number"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun isCardActivated(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_CARD_ACTIVATED, false)
    }

    fun setCardActivated(context: Context, activated: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_CARD_ACTIVATED, activated).apply()
    }

    fun getActiveOperator(context: Context): String? {
        return getPrefs(context).getString(KEY_ACTIVE_OPERATOR, null)
    }

    fun setActiveOperator(context: Context, operatorName: String) {
        getPrefs(context).edit().putString(KEY_ACTIVE_OPERATOR, operatorName).apply()
    }

    fun getActiveDomainId(context: Context): String? {
        return getPrefs(context).getString(KEY_ACTIVE_DOMAIN_ID, null)
    }

    fun setActiveDomainId(context: Context, domainId: String) {
        val canonical = OperatorConfig.resolveDomainId(domainId)
        getPrefs(context).edit().putString(KEY_ACTIVE_DOMAIN_ID, canonical).apply()
    }

    fun bindOperator(context: Context, operatorInfo: OperatorInfo) {
        val prefs = getPrefs(context).edit()
        prefs.putBoolean(KEY_CARD_ACTIVATED, true)
        prefs.putString(KEY_ACTIVE_OPERATOR, operatorInfo.name)
        prefs.putString(KEY_ACTIVE_DOMAIN_ID, operatorInfo.domainId)
        prefs.apply()
    }

    fun unbindOperator(context: Context) {
        val prefs = getPrefs(context).edit()
        prefs.putBoolean(KEY_CARD_ACTIVATED, false)
        prefs.remove(KEY_ACTIVE_OPERATOR)
        prefs.remove(KEY_ACTIVE_DOMAIN_ID)
        prefs.apply()
    }

    fun getOperatorStatus(context: Context, operatorInfo: OperatorInfo): OperatorStatus {
        val storedDomainId = getActiveDomainId(context)
        val canonical = OperatorConfig.resolveDomainId(storedDomainId ?: "")
        return if (canonical == operatorInfo.domainId && isCardActivated(context)) {
            OperatorStatus.BOUND
        } else {
            OperatorStatus.UNBOUND
        }
    }

    fun getPhoneNumber(context: Context): String? {
        return getPrefs(context).getString(KEY_PHONE_NUMBER, null)
    }

    fun setPhoneNumber(context: Context, number: String) {
        getPrefs(context).edit().putString(KEY_PHONE_NUMBER, number).apply()
    }

    fun clearAll(context: Context) {
        getPrefs(context).edit().clear().apply()
    }
}
