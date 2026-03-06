package com.mqvpn.sdk.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.system.OsConstants
import androidx.core.content.getSystemService
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Utility for searching networks by transport type and address family.
 */
object NetworkSelector {

    /**
     * Find the first network with the given transport type.
     * @param transport One of [NetworkCapabilities.TRANSPORT_WIFI], etc.
     */
    fun findFirst(context: Context, transport: Int): Network? {
        val cm = context.getSystemService<ConnectivityManager>() ?: return null
        return cm.allNetworks.firstOrNull { net ->
            cm.getNetworkCapabilities(net)?.hasTransport(transport) == true
        }
    }

    /**
     * Find a validated network that is NOT the active default network.
     * Useful for adding a secondary path (e.g., cellular when WiFi is primary).
     */
    fun findNonPrimary(context: Context): Network? {
        val cm = context.getSystemService<ConnectivityManager>() ?: return null
        val active = cm.activeNetwork
        return cm.allNetworks.firstOrNull { net ->
            net != active && cm.getNetworkCapabilities(net)?.let { caps ->
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true
        }
    }

    /**
     * Get an address from the given network matching the requested address family.
     *
     * @param af [OsConstants.AF_INET] or [OsConstants.AF_INET6]
     * @return A matching [InetAddress], or null if the network has no address
     *         of the requested family.
     */
    fun getMatchingAddress(context: Context, network: Network, af: Int): InetAddress? {
        val cm = context.getSystemService<ConnectivityManager>() ?: return null
        val lp = cm.getLinkProperties(network) ?: return null
        return lp.linkAddresses.firstOrNull { la ->
            when (af) {
                OsConstants.AF_INET -> la.address is Inet4Address
                OsConstants.AF_INET6 -> la.address is Inet6Address &&
                    !la.address.isLinkLocalAddress
                else -> false
            }
        }?.address
    }
}
