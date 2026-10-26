// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import com.mqvpn.sdk.network.PathType
import com.mqvpn.sdk.network.TransportAvailability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MqvpnViewModel(
    private val manager: MqvpnManager,
    transportAvailability: TransportAvailability,
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
    @Inject constructor(
        manager: MqvpnManager,
        transportAvailability: TransportAvailability,
    ) : this(manager, transportAvailability, System::currentTimeMillis, System::nanoTime)

    /** Transports with a connected network now; valid with or without a tunnel. */
    val availableTransports: StateFlow<Set<PathType>> = transportAvailability.available

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

    // Ticker inputs come from eagerly collected manager flows (see init); the
    // stateIn(WhileSubscribed) views below freeze when no tab subscribes.
    private var latestStats: VpnStats = VpnStats()
    private var latestReorderStats: ReorderStats = ReorderStats()
    private val reorder = ReorderHistory()
    private val dgramLoss = DgramLossWindow()
    private var connectedAt: Long? = null

    private val _reorderHistory = MutableStateFlow(ReorderHistoryState())
    val reorderHistory: StateFlow<ReorderHistoryState> = _reorderHistory.asStateFlow()

    private val _lossPct = MutableStateFlow<Double?>(null)
    val lossPct: StateFlow<Double?> = _lossPct.asStateFlow()

    private val _elapsedSec = MutableStateFlow<Long?>(null)
    val elapsedSec: StateFlow<Long?> = _elapsedSec.asStateFlow()

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
        // Re-attach to a VPN service that kept running while the UI was gone
        // (task swiped away, activity destroyed in background): without this
        // the graph gets no path updates and disconnect() cannot reach the
        // service. No-op when nothing is running.
        manager.attach(MyVpnService::class.java)
        viewModelScope.launch {
            manager.vpnState.collect {
                eventLog.ingestState(it, clock())
                publishEvents()
                when (it) {
                    is MqvpnState.Connected, is MqvpnState.Reconnecting -> {
                        if (it is MqvpnState.Connected) {
                            // Prefer the service's timestamp: a re-attached UI
                            // (activity recreated, task swiped away) then shows
                            // the session's real elapsed time, not time-since-replay.
                            if (connectedAt == null) {
                                connectedAt = it.tunnelInfo.connectedAtMs
                                    .takeIf { ms -> ms > 0 } ?: clock()
                            }
                        } else {
                            connectedAt = null
                            _elapsedSec.value = null
                        }
                        if (tickerJob?.isActive != true) {
                            tickerJob = viewModelScope.launch { bandwidthTickerLoop() }
                        }
                    }
                    is MqvpnState.Disconnected, is MqvpnState.Error -> {
                        tickerJob?.cancel()
                        tickerJob = null
                        bandwidth.clear()
                        _bandwidthHistory.value = BandwidthHistoryState()
                        reorder.clear()
                        dgramLoss.clear()
                        connectedAt = null
                        _reorderHistory.value = ReorderHistoryState()
                        _lossPct.value = null
                        _elapsedSec.value = null
                    }
                    is MqvpnState.Connecting -> {
                        // mid-session handshake re-emits Connecting: pause ticks, keep history
                        tickerJob?.cancel()
                        tickerJob = null
                        connectedAt = null
                        _elapsedSec.value = null
                    }
                }
            }
        }
        viewModelScope.launch { manager.stats.collect { latestStats = it } }
        viewModelScope.launch { manager.reorderStats.collect { latestReorderStats = it } }
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
            val now = clock()
            val samples = bandwidth.onTick(latestPaths, nanoClock(), now)
            _bandwidthHistory.value = BandwidthHistoryState(samples, bandwidth.ifaceSlots())
            _reorderHistory.value = reorder.onTick(latestReorderStats, now)
            _lossPct.value = dgramLoss.onTick(latestStats.dgramSent, latestStats.dgramLost, now)
            _elapsedSec.value = connectedAt?.let { (now - it) / 1000 }
        }
    }

    fun connect(settings: DemoSettings) {
        if (_connectPending.value) return
        _connectPending.value = true
        _connectError.value = null
        viewModelScope.launch {
            try {
                val cfg = settings.toMqvpnConfig()
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

    // No onCleared teardown: the manager is a process-wide singleton and the
    // service outlives this ViewModel. Destroying the manager here severed the
    // service binding permanently (frozen stats, disconnect no-op) whenever
    // the activity was destroyed while the VPN kept running.
}
