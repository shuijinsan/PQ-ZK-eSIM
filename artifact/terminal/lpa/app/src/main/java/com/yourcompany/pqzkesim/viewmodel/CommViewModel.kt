package com.yourcompany.pqzkesim.viewmodel

// 通信与运营商视图模型

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.asLiveData
import androidx.lifecycle.viewModelScope
import com.yourcompany.pqzkesim.data.local.OperatorPreferencesDataStore
import com.yourcompany.pqzkesim.data.model.OperatorInfo
import com.yourcompany.pqzkesim.repository.EsimRepository
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

data class OperatorCardUiState(
    val operatorInfo: OperatorInfo,
    val phoneNumbers: List<String>,
    val iccids: List<String> = emptyList(),
    val activatedAts: List<String> = emptyList(),
    val isExpanded: Boolean = false
)

class CommViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = OperatorPreferencesDataStore(application)
    private val repository = EsimRepository(prefs)

    val isCardActivated = repository.isCardActivated.asLiveData()
    val activeOperatorName = repository.activeOperatorName.asLiveData()

    val uiCards: LiveData<List<OperatorCardUiState>> = combine(
        repository.operatorCards,
        repository.operatorProfiles
    ) { operators, profiles ->
        operators.map { op ->
            val list = profiles[op.domainId] ?: emptyList()
            OperatorCardUiState(
                operatorInfo = op,
                phoneNumbers = list.map { it.phoneNumber }.filter { it.isNotEmpty() },
                iccids = list.map { it.iccid }.filter { it.isNotEmpty() },
                activatedAts = list.map { it.activatedAt }.filter { it.isNotEmpty() }
            )
        }
    }.asLiveData()

    private val _expandedCardIndex = MutableLiveData(-1)
    val expandedCardIndex: LiveData<Int> = _expandedCardIndex

    fun toggleExpand(cardIndex: Int) {
        val current = _expandedCardIndex.value ?: -1
        _expandedCardIndex.value = if (current == cardIndex) -1 else cardIndex
    }

    fun bindOperator(operatorInfo: OperatorInfo) {
        viewModelScope.launch { repository.bindOperator(operatorInfo) }
    }

    fun unbindOperator() {
        viewModelScope.launch { repository.unbindOperator() }
    }
}
