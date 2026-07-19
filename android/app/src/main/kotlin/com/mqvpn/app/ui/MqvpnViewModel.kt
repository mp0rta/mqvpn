// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MqvpnViewModel @Inject constructor(
    private val manager: MqvpnManager,
    private val repository: SettingsRepository,
) : ViewModel() {

    // Test-only seam: production always uses the wall clock via the
    // @Inject constructor above; tests substitute a fixed clock through
    // this internal constructor so event timestamps are deterministic.
    // See G6: this is a pre-approved injectable-clock exception, not a
    // test-only production flag.
    internal constructor(
        manager: MqvpnManager,
        repository: SettingsRepository,
        clock: () -> Long,
    ) : this(manager, repository) {
        this.clock = clock
    }

    private var clock: () -> Long = System::currentTimeMillis

    private val eventLog = EventLog()

    private val _events = MutableStateFlow<List<LogEvent>>(emptyList())
    val events: StateFlow<List<LogEvent>> = _events.asStateFlow()

    private val _connectPending = MutableStateFlow(false)
    val connectPending: StateFlow<Boolean> = _connectPending.asStateFlow()

    private val _connectError = MutableStateFlow<String?>(null)
    val connectError: StateFlow<String?> = _connectError.asStateFlow()

    val vpnState: StateFlow<MqvpnState> = manager.vpnState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), MqvpnState.Disconnected)

    val stats: StateFlow<VpnStats> = manager.stats
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), VpnStats())

    val paths: StateFlow<List<PathInfo>> = manager.paths
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val reorderStats: StateFlow<ReorderStats> = manager.reorderStats
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ReorderStats())

    init {
        viewModelScope.launch {
            manager.vpnState.collect {
                eventLog.ingestState(it, clock())
                _events.value = eventLog.events
            }
        }
        viewModelScope.launch {
            manager.paths.collect {
                eventLog.ingestPaths(it, clock())
                _events.value = eventLog.events
            }
        }
    }

    fun connect(config: MqvpnConfig) {
        manager.connect(config, MyVpnService::class.java)
    }

    fun connectWithSavedSettings() {
        if (_connectPending.value) return
        _connectPending.value = true
        _connectError.value = null
        viewModelScope.launch {
            try {
                val cfg = repository.settings.first().toMqvpnConfig()
                manager.connect(cfg, MyVpnService::class.java)
            } catch (t: Throwable) {
                _connectError.value = "Connect failed: ${t.message}"
            } finally {
                _connectPending.value = false
            }
        }
    }

    fun disconnect() {
        manager.disconnect()
    }

    fun prepareVpn(): Intent? = manager.prepareVpn()

    override fun onCleared() {
        manager.destroy()
    }
}
