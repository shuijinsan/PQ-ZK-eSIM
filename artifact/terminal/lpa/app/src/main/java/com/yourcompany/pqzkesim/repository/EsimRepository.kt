package com.yourcompany.pqzkesim.repository

import com.yourcompany.pqzkesim.data.local.OperatorPreferencesDataStore
import com.yourcompany.pqzkesim.data.local.OperatorProfileData
import com.yourcompany.pqzkesim.data.model.OperatorConfig
import com.yourcompany.pqzkesim.data.model.OperatorInfo
import com.yourcompany.pqzkesim.data.model.OperatorStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine

class EsimRepository(private val prefs: OperatorPreferencesDataStore) {

    val isCardActivated: Flow<Boolean> = prefs.isCardActivated
    val activeOperatorName: Flow<String> = prefs.activeOperator
    val activeDomainId: Flow<String> = prefs.activeDomainId
    val storedPhoneNumber: Flow<String> = prefs.phoneNumber

    /** Per-operator profiles keyed by domainId (list of profiles → multiple phone numbers). */
    val operatorProfiles: Flow<Map<String, List<OperatorProfileData>>> = prefs.operatorProfilesFlow

    /**
     * Combined flow of all operators with per-operator binding status.
     * An operator is BOUND if its domainId exists in the operator_profiles map.
     */
    val operatorCards: Flow<List<OperatorInfo>> = combine(
        prefs.isCardActivated,
        prefs.activeDomainId,
        prefs.operatorProfilesFlow
    ) { activated, domainId, profiles ->
        OperatorConfig.ALL_OPERATORS.map { op ->
            val status = when {
                profiles.containsKey(op.domainId) -> OperatorStatus.BOUND
                activated && domainId == op.domainId -> OperatorStatus.BOUND
                else -> OperatorStatus.UNBOUND
            }
            op.copy(status = status)
        }
    }

    /**
     * Returns all phone numbers for a specific operator from its profile list.
     */
    fun getPhoneNumbers(
        domainId: String,
        profiles: Map<String, List<OperatorProfileData>>
    ): List<String> {
        val list = profiles[domainId] ?: return emptyList()
        return list.map { it.phoneNumber }.filter { it.isNotEmpty() }
    }

    suspend fun bindProfile(
        domainId: String,
        iccid: String,
        phoneNumber: String,
        operatorName: String,
        activatedAt: String
    ) = prefs.setOperatorProfile(domainId, iccid, phoneNumber, operatorName, activatedAt)

    suspend fun bindOperator(operatorInfo: OperatorInfo) = prefs.bindOperator(operatorInfo)
    suspend fun unbindOperator() = prefs.unbindOperator()
    suspend fun setActiveOperator(name: String, domainId: String) = prefs.setActiveOperator(name, domainId)
    suspend fun clearAll() = prefs.clearAll()

    fun getOperatorStatus(operatorInfo: OperatorInfo): Flow<OperatorStatus> =
        prefs.getOperatorStatus(operatorInfo)
}
