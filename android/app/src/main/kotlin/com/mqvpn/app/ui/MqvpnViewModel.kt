// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MqvpnViewModel(
    private val manager: MqvpnManager,
    private val repository: SettingsRepository,
    private val clock: () -> Long,
    private val nanoClock: () -> Long,
) : ViewModel() {

    // Primary constructor takes clock/nanoClock as immutable vals so they
    // are set before init{} launches the collectors below — a `var`
    // mutated by a secondary constructor's body runs AFTER init{} on the
    // primary constructor, which happened to work only because
    // StandardTestDispatcher queues launched coroutines instead of running
    // them inline; an UnconfinedTestDispatcher would start the collectors
    // synchronously and silently observe the wall clock instead. Hilt only
    // sees this @Inject-annotated secondary constructor, so DI is
    // unaffected; tests use the primary constructor directly with fixed
    // clocks. See G6: injectable-clock is a pre-approved exception, not a
    // test-only production flag.
    @Inject constructor(manager: MqvpnManager, repository: SettingsRepository) :
        this(manager, repository, System::currentTimeMillis, System::nanoTime)

    private val eventLog = EventLog()

    private val _events = MutableStateFlow<List<LogEvent>>(emptyList())
    val events: StateFlow<List<LogEvent>> = _events.asStateFlow()

    private val _connectPending = MutableStateFlow(false)
    val connectPending: StateFlow<Boolean> = _connectPending.asStateFlow()

    private val _connectError = MutableStateFlow<String?>(null)
    val connectError: StateFlow<String?> = _connectError.asStateFlow()

    private val bandwidth = BandwidthHistory()
    private var latestPaths: List<PathInfo> = emptyList()
    private var tickerJob: Job? = null

    private val _bandwidthHistory = MutableStateFlow(BandwidthHistoryState())
    val bandwidthHistory: StateFlow<BandwidthHistoryState> = _bandwidthHistory.asStateFlow()

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
                publishEvents()
                when (it) {
                    is MqvpnState.Connected, is MqvpnState.Reconnecting -> {
                        if (tickerJob?.isActive != true) {
                            tickerJob = viewModelScope.launch { bandwidthTickerLoop() }
                        }
                    }
                    is MqvpnState.Disconnected, is MqvpnState.Error -> {
                        tickerJob?.cancel()
                        tickerJob = null
                        bandwidth.clear()
                        _bandwidthHistory.value = BandwidthHistoryState()
                    }
                    is MqvpnState.Connecting -> Unit // nothing to start or clear
                }
            }
        }
        viewModelScope.launch {
            manager.paths.collect {
                latestPaths = it
                eventLog.ingestPaths(it, clock())
                publishEvents()
            }
        }
    }

    private fun publishEvents() {
        _events.value = eventLog.events
    }

    private suspend fun bandwidthTickerLoop() {
        while (true) {
            delay(1_000)
            val samples = bandwidth.onTick(latestPaths, nanoClock())
            _bandwidthHistory.value = BandwidthHistoryState(samples, bandwidth.ifaceSlots())
        }
    }

    fun connectWithSavedSettings() {
        if (_connectPending.value) return
        _connectPending.value = true
        _connectError.value = null
        viewModelScope.launch {
            try {
                val cfg = repository.settings.first().toMqvpnConfig()
                manager.connect(cfg, MyVpnService::class.java)
            } catch (e: CancellationException) {
                throw e
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
