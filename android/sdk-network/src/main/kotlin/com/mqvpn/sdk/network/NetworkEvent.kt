package com.mqvpn.sdk.network

/**
 * Events emitted by [NetworkMonitor] when network availability changes.
 */
sealed interface NetworkEvent {
    data class Available(val path: NetworkPath) : NetworkEvent
    data class Lost(val path: NetworkPath) : NetworkEvent
}
