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
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
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
    /** A failed DataStore write; the draft keeps the edit. */
    val saveError: StateFlow<String?> = _saveError.asStateFlow()

    private val _saveDone = MutableStateFlow(false)
    val saveDone: StateFlow<Boolean> = _saveDone.asStateFlow()

    private val _draft = MutableStateFlow<DemoSettings?>(null)
    /** Source of truth once set: first repository emission, then local edits (later echoes ignored). */
    val draft: StateFlow<DemoSettings?> = _draft.asStateFlow()

    private val _fieldErrors = MutableStateFlow<Map<String, String>>(emptyMap())
    val fieldErrors: StateFlow<Map<String, String>> = _fieldErrors.asStateFlow()

    // G6: the only path to repository.save. Conflated, so the latest draft wins.
    private val queue = Channel<Pair<Long, DemoSettings>>(Channel.CONFLATED)
    private var requestedGen = 0L
    private val landedGen = MutableStateFlow(0L)
    private var lastPersisted: DemoSettings? = null

    init {
        viewModelScope.launch {
            try {
                repository.settings.collect {
                    _loaded.value = it
                    if (_draft.value == null) _draft.value = it
                }
            } catch (e: CancellationException) {
                throw e
            } catch (t: Throwable) {
                _loadError.value = "Load failed: ${t.message}"
            }
        }
        viewModelScope.launch {
            for ((gen, d) in queue) {
                // Same value already on disk (e.g. a duplicate save()): nothing to do.
                if (d != lastPersisted) persist(d)
                landedGen.value = gen
            }
        }
    }

    private suspend fun persist(d: DemoSettings) {
        _isSaving.value = true
        _saveError.value = null
        _saveDone.value = false
        try {
            repository.save(d)
            lastPersisted = d
            _saveDone.value = true
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            lastPersisted = null
            _saveError.value = "Save failed: ${t.message}"
        } finally {
            _isSaving.value = false
        }
    }

    /**
     * Applies [transform] to the draft at once; persists the whole draft only while
     * every field is valid (any invalid field blocks all persists, its error is in [fieldErrors]).
     */
    fun update(transform: (DemoSettings) -> DemoSettings) {
        val next = transform(_draft.value ?: return)
        _draft.value = next
        _fieldErrors.value = next.fieldErrors()
        if (next.isValid()) queue.trySend(++requestedGen to next)
    }

    /**
     * Returns once the latest queued save has landed (success or failure). With an
     * invalid draft nothing was queued, so it returns after any earlier save drains
     * and persists nothing; it never hangs.
     */
    suspend fun flush() {
        val target = requestedGen
        landedGen.first { it >= target }
    }

    /** Legacy entry point for the old screen; funnels into the single writer. */
    fun save(draft: DemoSettings) {
        // Belt-and-braces: re-check the old screen's gates so a stale/racy caller can never
        // save over an unloaded or failed-to-load baseline.
        if (_loaded.value == null || _loadError.value != null) return
        if (!isEditable.value || !draft.isValid()) return
        _draft.value = draft
        _fieldErrors.value = draft.fieldErrors()
        queue.trySend(++requestedGen to draft)
    }

    fun consumeSaveDone() {
        _saveDone.value = false
    }
}

private fun DemoSettings.fieldErrors(): Map<String, String> = buildMap {
    if (!hostValid()) put("serverAddress", "Enter a server address")
    if (!portValid()) put("serverPort", "Port must be 1-65535")
    if (!reorderPortsValid()) put("reorderPorts", "Enter at least one valid port")
    if (redundantEnabled && !redundantPortsValid()) put("redundantPorts", "Enter ports as a comma-separated list (1-65535)")
    if (!pathPolicyValid()) put("paths", "Turn on at least one connection type")
}

private fun MqvpnState.isEditableState(): Boolean = when (this) {
    MqvpnState.Disconnected, is MqvpnState.Error -> true
    MqvpnState.Connecting, is MqvpnState.Reconnecting, is MqvpnState.Connected -> false
}
