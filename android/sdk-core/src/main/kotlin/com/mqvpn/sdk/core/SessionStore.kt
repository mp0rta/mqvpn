// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * The session's observable state, process-wide. The live service instance is
 * the only writer (from its engine thread, through [publish]); [MqvpnManager]
 * only reads. The service and the UI share the process, so a recreated UI
 * or ViewModel sees the live state at once, with no binding to keep alive
 * or replay.
 *
 * Ownership spans onCreate → onDestroy, not the engine thread's life: the
 * stop join is bounded (2 s), so a destroyed service's engine can still run
 * — and finish a queued start or its teardown — after a replacement
 * instance took over. Once retired, nothing it does reaches the store or
 * the app callbacks.
 */
internal object SessionStore {
    val state = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    val stats = MutableStateFlow(VpnStats())
    val paths = MutableStateFlow<List<PathInfo>>(emptyList())
    val reorderStats = MutableStateFlow(ReorderStats())

    /** The created service instance, for [MqvpnManager.disconnect]; main thread only. */
    var service: MqvpnVpnService? = null

    private val lock = Any()
    private var owner: Any? = null // guarded by lock

    /** [service] (just created) becomes the only writer. Main thread. */
    fun claim(service: Any) = synchronized(lock) { owner = service }

    /**
     * Runs [write] only while [from] owns the store; false = retired or
     * superseded. [write] runs under the lock, app callbacks included, so a
     * retire cannot slip between the check and the callback.
     */
    fun publish(from: Any, write: SessionStore.() -> Unit): Boolean =
        synchronized(lock) { (owner === from).also { if (it) write() } }

    /**
     * [service] is destroyed: it gives the store up. A teardown that has not
     * finished by now (the stop join timed out) never will for the UI, so a
     * live state becomes Disconnected; a terminal Error stays. Main thread.
     */
    fun retire(service: Any) = synchronized(lock) {
        if (owner !== service) return@synchronized
        if (state.value !is MqvpnState.Error) state.value = MqvpnState.Disconnected
        resetMetrics()
        owner = null
    }

    fun resetMetrics() {
        stats.value = VpnStats()
        paths.value = emptyList()
        reorderStats.value = ReorderStats()
    }
}
