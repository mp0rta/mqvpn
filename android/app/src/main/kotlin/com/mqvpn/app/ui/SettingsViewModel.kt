// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Backs the settings screen. Scoped to the settings NavBackStackEntry (not
 * app-singleton like [MqvpnViewModel]) — it must never call
 * [MqvpnManager.destroy]; destroying the shared manager instance is
 * exclusively [MqvpnViewModel]'s job.
 */
@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val repository: SettingsRepository,
    manager: MqvpnManager,
) : ViewModel() {

    private val _loaded = MutableStateFlow<DemoSettings?>(null)
    val loaded: StateFlow<DemoSettings?> = _loaded.asStateFlow()

    private val _loadError = MutableStateFlow<String?>(null)
    val loadError: StateFlow<String?> = _loadError.asStateFlow()

    // Eagerly (not WhileSubscribed): save() reads isEditable.value directly
    // as a synchronous guard, so it must be live even with no UI collector
    // attached.
    val isEditable: StateFlow<Boolean> = manager.vpnState
        .map { it.isEditableState() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, manager.vpnState.value.isEditableState())

    private val _isSaving = MutableStateFlow(false)
    val isSaving: StateFlow<Boolean> = _isSaving.asStateFlow()

    private val _saveError = MutableStateFlow<String?>(null)
    val saveError: StateFlow<String?> = _saveError.asStateFlow()

    private val _saveDone = MutableStateFlow(false)
    val saveDone: StateFlow<Boolean> = _saveDone.asStateFlow()

    init {
        viewModelScope.launch {
            try {
                repository.settings.collect { _loaded.value = it }
            } catch (e: CancellationException) {
                throw e
            } catch (t: Throwable) {
                _loadError.value = "Load failed: ${t.message}"
            }
        }
    }

    fun save(draft: DemoSettings) {
        if (_isSaving.value || !isEditable.value || !draft.isValid()) return
        _isSaving.value = true
        _saveError.value = null
        _saveDone.value = false
        viewModelScope.launch {
            try {
                repository.save(draft)
                _saveDone.value = true
            } catch (e: CancellationException) {
                throw e
            } catch (t: Throwable) {
                _saveError.value = "Save failed: ${t.message}"
            } finally {
                _isSaving.value = false
            }
        }
    }

    fun consumeSaveDone() {
        _saveDone.value = false
    }
}

private fun MqvpnState.isEditableState(): Boolean = when (this) {
    MqvpnState.Disconnected, is MqvpnState.Error -> true
    MqvpnState.Connecting, is MqvpnState.Reconnecting, is MqvpnState.Connected -> false
}
