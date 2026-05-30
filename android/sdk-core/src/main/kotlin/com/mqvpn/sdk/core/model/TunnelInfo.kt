// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

/**
 * Tunnel configuration received from server after QUIC handshake.
 */
data class TunnelInfo(
    val assignedIp: String,
    val prefix: Int,
    val serverIp: String,
    val serverPrefix: Int,
    val mtu: Int,
    val assignedIp6: String? = null,
    val prefix6: Int = 0,
    val hasV6: Boolean = false,
)
