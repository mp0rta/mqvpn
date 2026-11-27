// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

import android.net.NetworkCapabilities
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PathPolicyTest {

    @Test
    fun `default policy allows everything but bluetooth`() {
        val p = PathPolicy()
        assertTrue(p.allows(PathType.WIFI))
        assertTrue(p.allows(PathType.CELLULAR))
        assertTrue(p.allows(PathType.ETHERNET))
        assertFalse(p.allows(PathType.BLUETOOTH))
    }

    @Test
    fun `allows follows each flag and OTHER is always allowed`() {
        val none = PathPolicy(wifi = false, cellular = false, ethernet = false, bluetooth = false)
        assertFalse(none.allows(PathType.WIFI))
        assertFalse(none.allows(PathType.CELLULAR))
        assertFalse(none.allows(PathType.ETHERNET))
        assertFalse(none.allows(PathType.BLUETOOTH))
        assertTrue(none.allows(PathType.OTHER))
        assertTrue(PathPolicy(bluetooth = true).allows(PathType.BLUETOOTH))
    }

    @Test
    fun `holdTransports excludes a disallowed transport`() {
        assertEquals(
            listOf(NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_ETHERNET),
            NetworkMonitor.holdTransports(PathPolicy(cellular = false)),
        )
    }

    @Test
    fun `holdTransports includes bluetooth only when the policy allows it`() {
        assertFalse(
            NetworkCapabilities.TRANSPORT_BLUETOOTH in NetworkMonitor.holdTransports(PathPolicy()),
        )
        assertTrue(
            NetworkCapabilities.TRANSPORT_BLUETOOTH in
                NetworkMonitor.holdTransports(PathPolicy(bluetooth = true)),
        )
    }
}
