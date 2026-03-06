package com.mqvpn.sdk.network

import android.net.Network

/**
 * Transport type classification for a network path.
 */
enum class PathType {
    WIFI,
    CELLULAR,
    ETHERNET,
    OTHER,
}

/**
 * Represents a usable network path for VPN traffic.
 */
data class NetworkPath(
    val network: Network,
    val type: PathType,
    val name: String,
    val isMetered: Boolean,
)
