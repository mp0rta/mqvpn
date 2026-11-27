// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** The bridge's backpressure wait ends only here: lose the call and the uplink stops for good. */
class PollerInterestTest {
    @Test
    fun `tun_readable tells the bridge, and only then`() {
        var resumed = 0
        val blocked = pollerInterest(MqvpnTunnel.Interest(7, false, true), 5) { resumed++ }
        assertEquals(0, resumed)
        assertArrayEquals(intArrayOf(5, 0, 1), blocked)

        val readable = pollerInterest(MqvpnTunnel.Interest(7, true, false), 5) { resumed++ }
        assertEquals(1, resumed)
        assertArrayEquals(intArrayOf(5, 1, 0), readable)
    }
}
