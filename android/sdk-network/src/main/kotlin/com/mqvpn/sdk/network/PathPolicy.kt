// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

/**
 * Which transports may carry VPN paths. Fixed when the tunnel starts; a
 * disallowed transport is neither held nor announced, even if Android
 * connects it on its own.
 */
data class PathPolicy(
    val wifi: Boolean = true,
    val cellular: Boolean = true,
    val ethernet: Boolean = true,
    val bluetooth: Boolean = false,
) {
    fun allows(type: PathType): Boolean = when (type) {
        PathType.WIFI -> wifi
        PathType.CELLULAR -> cellular
        PathType.ETHERNET -> ethernet
        PathType.BLUETOOTH -> bluetooth
        PathType.OTHER -> true
    }
}
