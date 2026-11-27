// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.annotation.MainThread
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Public-facing manager for the mqvpn SDK.
 *
 * Provides [StateFlow]-based observation of VPN state, stats, and paths. The
 * flows are process-wide and written only by the running [MqvpnVpnService],
 * so any number of managers, created at any time, see the live session.
 */
class MqvpnManager(private val context: Context) {

    val vpnState: StateFlow<MqvpnState> = SessionStore.state.asStateFlow()
    val stats: StateFlow<VpnStats> = SessionStore.stats.asStateFlow()
    val paths: StateFlow<List<PathInfo>> = SessionStore.paths.asStateFlow()
    val reorderStats: StateFlow<ReorderStats> = SessionStore.reorderStats.asStateFlow()

    /**
     * Prepare VPN permission. Returns null if already granted,
     * otherwise returns an Intent to launch the system VPN dialog.
     */
    fun prepareVpn(): Intent? = VpnService.prepare(context)

    /**
     * Start VPN with the given config: starts [serviceClass] in the
     * foreground, which then calls [MqvpnVpnService.startTunnel]. [vpnState]
     * turns Connecting once the service picks the config up.
     *
     * While a session is running the service refuses a second connect and
     * keeps that session; call [disconnect] first.
     *
     * @throws IllegalArgumentException when [MqvpnConfig.serverAddress] or
     *   [MqvpnConfig.tlsServerName] is not a bare ASCII identifier (see
     *   [MqvpnConfig.hostIdentifierError]). Thrown before the service starts.
     */
    @MainThread
    fun connect(config: MqvpnConfig, serviceClass: Class<out MqvpnVpnService>) {
        // synchronous: a bad host must fail here, not inside the service
        config.hostIdentifierError()?.let { throw IllegalArgumentException(it) }
        context.startForegroundService(
            Intent(context, serviceClass).putExtra(EXTRA_CONFIG_JSON, config.toJson()),
        )
    }

    /** Disconnect the VPN; [vpnState] turns Disconnected once the session is torn down. */
    @MainThread
    fun disconnect() {
        SessionStore.service?.stopTunnel()
    }

    /** Get libmqvpn version string. */
    fun getVersion(): String = MqvpnSdk.getVersion()

    /** Generate a random PSK key. */
    fun generateKey(): String = MqvpnSdk.generateKey()

    companion object {
        internal const val EXTRA_CONFIG_JSON = "mqvpn_config_json"
    }
}
