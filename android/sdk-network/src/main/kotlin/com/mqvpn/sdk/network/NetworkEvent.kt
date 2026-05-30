// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

/**
 * Events emitted by [NetworkMonitor] when network availability changes.
 */
sealed interface NetworkEvent {
    data class Available(val path: NetworkPath) : NetworkEvent
    data class Lost(val path: NetworkPath) : NetworkEvent
}
