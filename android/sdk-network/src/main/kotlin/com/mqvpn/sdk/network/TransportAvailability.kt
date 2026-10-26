// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.core.content.getSystemService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Which transports have a connected network right now, for the UI while no
 * tunnel runs. One passive callback, no holds: it never keeps a network up.
 */
class TransportAvailability(context: Context) {

    private val cm = context.getSystemService<ConnectivityManager>()!!
    private val types = HashMap<Network, PathType>()
    private val _available = MutableStateFlow<Set<PathType>>(emptySet())
    val available: StateFlow<Set<PathType>> = _available.asStateFlow()

    private var callback: ConnectivityManager.NetworkCallback? = null

    @Synchronized
    fun start() {
        if (callback != null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                update { it[network] = NetworkMonitor.classifyTransport(caps) }

            override fun onLost(network: Network) = update { it.remove(network) }
        }
        cm.registerNetworkCallback(
            NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
            cb,
        )
        callback = cb
    }

    @Synchronized
    fun stop() {
        callback?.let { cm.unregisterNetworkCallback(it) }
        callback = null
        update { it.clear() }
    }

    @Synchronized
    private fun update(change: (MutableMap<Network, PathType>) -> Unit) {
        change(types)
        _available.value = types.values.toSet()
    }
}
