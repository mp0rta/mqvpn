package com.mqvpn.sdk.core.model

/**
 * Aggregate VPN statistics from libmqvpn.
 */
data class VpnStats(
    val bytesTx: Long = 0,
    val bytesRx: Long = 0,
    val dgramSent: Long = 0,
    val dgramRecv: Long = 0,
    val dgramLost: Long = 0,
    val dgramAcked: Long = 0,
    val srttMs: Int = 0,
)
