// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import androidx.core.content.getSystemService
import java.util.concurrent.ConcurrentHashMap

/**
 * Monitors WiFi / Cellular / Ethernet / Bluetooth availability via
 * ConnectivityManager.
 *
 * Uses NET_CAPABILITY_VALIDATED to filter out captive portals and
 * unvalidated networks that would cause packet loss if used as VPN paths.
 *
 * Android keeps a network connected only while a request is served by it,
 * and the default request is served by one network at a time. The monitor
 * therefore holds one request per transport while it runs: without them an
 * Ethernet adapter takes Wi-Fi down, and a Bluetooth tether never comes up
 * next to Wi-Fi. The holds only keep networks connected; paths still come
 * from the listening callback.
 *
 * @param holdBluetooth Also hold a Bluetooth-tethered network. When false it
 *   is still used as a path whenever Android connects it on its own.
 */
class NetworkMonitor(
    private val context: Context,
    private val holdBluetooth: Boolean = false,
) {

    private val cm = context.getSystemService<ConnectivityManager>()!!

    private val _activeNetworks = ConcurrentHashMap<Network, NetworkPath>()
    val activeNetworks: Map<Network, NetworkPath> get() = _activeNetworks

    private var callback: ConnectivityManager.NetworkCallback? = null
    private val holds = mutableListOf<ConnectivityManager.NetworkCallback>()

    fun start(listener: (NetworkEvent) -> Unit) {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                /* capabilities may not be available yet; wait for onCapabilitiesChanged */
            }

            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) {
                val type = classifyTransport(capabilities)
                val name = networkName(network, type)
                val metered = !capabilities.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_NOT_METERED,
                )
                val path = NetworkPath(network, type, name, metered)
                val isNew = _activeNetworks.put(network, path) == null
                if (isNew) {
                    Log.d(TAG, "Available: $path")
                    listener(NetworkEvent.Available(path))
                }
            }

            override fun onLost(network: Network) {
                val path = _activeNetworks.remove(network) ?: return
                Log.d(TAG, "Lost: $path")
                listener(NetworkEvent.Lost(path))
            }
        }

        callback = cb
        cm.registerNetworkCallback(request, cb)

        for (transport in holdTransports(holdBluetooth)) {
            val hold = ConnectivityManager.NetworkCallback()
            cm.requestNetwork(
                NetworkRequest.Builder()
                    .addTransportType(transport)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                hold,
            )
            holds += hold
        }
    }

    /** Remove a network so the next onCapabilitiesChanged treats it as new. */
    fun removeNetwork(network: Network) {
        _activeNetworks.remove(network)
    }

    fun stop() {
        callback?.let { cm.unregisterNetworkCallback(it) }
        callback = null
        holds.forEach { cm.unregisterNetworkCallback(it) }
        holds.clear()
        _activeNetworks.clear()
    }

    companion object {
        private const val TAG = "NetworkMonitor"

        internal fun classifyTransport(caps: NetworkCapabilities): PathType = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> PathType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> PathType.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> PathType.ETHERNET
            caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> PathType.BLUETOOTH
            else -> PathType.OTHER
        }

        /** Transports whose network is held while the monitor runs. */
        internal fun holdTransports(holdBluetooth: Boolean): List<Int> = buildList {
            add(NetworkCapabilities.TRANSPORT_WIFI)
            add(NetworkCapabilities.TRANSPORT_CELLULAR)
            add(NetworkCapabilities.TRANSPORT_ETHERNET)
            if (holdBluetooth) add(NetworkCapabilities.TRANSPORT_BLUETOOTH)
        }

        internal fun networkName(network: Network, type: PathType): String =
            "${type.name.lowercase()}-${network.networkHandle and 0xFFF}"
    }
}
