// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.ceilNice
import com.mqvpn.app.ui.formatBps
import org.junit.Assert.assertEquals
import org.junit.Test

class BandwidthFormatTest {

    @Test
    fun `ceilNice rounds up to 1-2-5 decades with 10 Kbps floor`() {
        assertEquals(10_000L, ceilNice(0L))
        assertEquals(10_000L, ceilNice(9_999L))
        assertEquals(10_000L, ceilNice(10_000L))
        assertEquals(20_000L, ceilNice(10_001L))
        assertEquals(50_000L, ceilNice(20_001L))
        assertEquals(100_000L, ceilNice(50_001L))
        assertEquals(50_000_000L, ceilNice(42_100_000L))
        assertEquals(2_000_000_000L, ceilNice(1_500_000_000L))
    }

    @Test
    fun `formatBps switches units and trims trailing zero decimal`() {
        assertEquals("0", formatBps(0L))
        assertEquals("750 bps", formatBps(750L))
        assertEquals("1 Kbps", formatBps(1_000L))
        assertEquals("12.5 Kbps", formatBps(12_500L))
        assertEquals("250 Kbps", formatBps(250_000L))
        assertEquals("42.1 Mbps", formatBps(42_100_000L))
        assertEquals("1.5 Gbps", formatBps(1_500_000_000L))
    }
}
