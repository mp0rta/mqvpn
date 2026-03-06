package com.mqvpn.sdk.core.model

/**
 * Per-path information from libmqvpn.
 */
data class PathInfo(
    val handle: Long,
    val status: Int,
    val iface: String,
    val bytesTx: Long,
    val bytesRx: Long,
    val srttMs: Long,
)
