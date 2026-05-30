// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

/**
 * VPN tunnel state, observed via [MqvpnManager.vpnState].
 */
sealed interface MqvpnState {
    data object Disconnected : MqvpnState
    data object Connecting : MqvpnState
    data class Reconnecting(val info: ReconnectInfo) : MqvpnState
    data class Connected(val tunnelInfo: TunnelInfo) : MqvpnState
    data class Error(val error: MqvpnError) : MqvpnState
}
