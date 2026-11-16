// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * The session's observable state, process-wide. The running session is the
 * only writer (from its engine thread, through [publish]); [MqvpnManager]
 * only reads. The service and the UI share the process, so a recreated UI
 * or ViewModel sees the live state at once, with no binding to keep alive
 * or replay.
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

    /** Makes [session] the only writer: the last session to start owns the store. */
    fun claim(session: Any) = synchronized(lock) { owner = session }

    /** Gives the store up if [session] still owns it (its last writes are done). */
    fun release(session: Any) = synchronized(lock) { if (owner === session) owner = null }

    /**
     * Runs [write] only while [session] owns the store; false = superseded.
     * A destroyed service's engine thread can outlive the 2 s stop join and
     * finish its teardown after a replacement session started: its writes
     * must not overwrite the live session's state.
     */
    fun publish(session: Any, write: SessionStore.() -> Unit): Boolean =
        synchronized(lock) { (owner === session).also { if (it) write() } }

    fun resetMetrics() {
        stats.value = VpnStats()
        paths.value = emptyList()
        reorderStats.value = ReorderStats()
    }
}
