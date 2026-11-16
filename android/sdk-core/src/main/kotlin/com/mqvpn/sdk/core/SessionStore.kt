// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * The session's observable state, process-wide. [MqvpnVpnService] is the only
 * writer (from its engine thread); [MqvpnManager] only reads. The service and
 * the UI share the process, so a recreated UI or ViewModel sees the live
 * state at once, with no binding to keep alive or replay.
 */
internal object SessionStore {
    val state = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    val stats = MutableStateFlow(VpnStats())
    val paths = MutableStateFlow<List<PathInfo>>(emptyList())
    val reorderStats = MutableStateFlow(ReorderStats())

    /** The created service instance, for [MqvpnManager.disconnect]; main thread only. */
    var service: MqvpnVpnService? = null

    fun resetMetrics() {
        stats.value = VpnStats()
        paths.value = emptyList()
        reorderStats.value = ReorderStats()
    }
}
