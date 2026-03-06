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
 * Monitors WiFi / Cellular / Ethernet availability via ConnectivityManager.
 *
 * Uses NET_CAPABILITY_VALIDATED to filter out captive portals and
 * unvalidated networks that would cause packet loss if used as VPN paths.
 */
class NetworkMonitor(private val context: Context) {

    private val cm = context.getSystemService<ConnectivityManager>()!!

    private val _activeNetworks = ConcurrentHashMap<Network, NetworkPath>()
    val activeNetworks: Map<Network, NetworkPath> get() = _activeNetworks

    private var callback: ConnectivityManager.NetworkCallback? = null

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
    }

    fun stop() {
        callback?.let { cm.unregisterNetworkCallback(it) }
        callback = null
        _activeNetworks.clear()
    }

    companion object {
        private const val TAG = "NetworkMonitor"

        internal fun classifyTransport(caps: NetworkCapabilities): PathType = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> PathType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> PathType.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> PathType.ETHERNET
            else -> PathType.OTHER
        }

        internal fun networkName(network: Network, type: PathType): String =
            "${type.name.lowercase()}-${network.networkHandle and 0xFFF}"
    }
}
