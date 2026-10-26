// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.BandwidthSample
import com.mqvpn.app.ui.Direction
import com.mqvpn.app.ui.ReorderSample
import com.mqvpn.app.ui.rateChart
import com.mqvpn.app.ui.reorderBars
import com.mqvpn.app.ui.waitLines
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ChartGeometryTest {
    private val now = 100_000L

    private fun bw(ms: Long, dl: Long, ul: Long, wl: Long? = null) = BandwidthSample(
        ms, dl, ul,
        if (wl != null) mapOf("wlan0" to wl, "rmnet0" to dl - wl) else mapOf("rmnet0" to dl),
        mapOf("wlan0" to ul),
    )

    private fun rs(ms: Long, rec: Double, lost: Double, p50: Double?, p99: Double?) =
        ReorderSample(ms, rec, lost, p50, p99)

    @Test fun `rate chart maps known samples to label and points`() {
        val c = rateChart(
            listOf(bw(70_000, 1_000_000, 0), bw(85_000, 4_000_000, 500_000, wl = 1_000_000), bw(100_000, 0, 0)),
            mapOf("wlan0" to 0, "rmnet0" to 1), Direction.DOWNLOAD, now, 300f, 100f,
        )
        assertEquals("5 Mbps", c.yMaxLabel)
        assertEquals(3, c.total.size)
        assertEquals(0f, c.total[0].x, 0.01f)
        assertEquals(150f, c.total[1].x, 0.01f)
        assertEquals(300f, c.total[2].x, 0.01f)
        assertEquals(20f, c.total[1].y, 0.01f)   // 4 of 5 Mbps from the top
        assertEquals(100f, c.total[2].y, 0.01f)  // zero line at bottom
        assertEquals(listOf(0f, 50f, 100f), c.gridYs)
        assertEquals(2, c.series.size)
        assertNull(c.series[0][0])               // wlan0 absent in first dl sample -> gap
        assertNotNull(c.series[0][1])
        assertEquals("total", c.legend[0].label)
    }

    @Test fun `upload direction uses upload fields`() {
        val c = rateChart(listOf(bw(100_000, 9_000_000, 20_000)), mapOf("wlan0" to 0), Direction.UPLOAD, now, 300f, 100f)
        assertEquals("20 Kbps", c.yMaxLabel)
    }

    @Test fun `samples older than the window are dropped`() {
        val c = rateChart(listOf(bw(60_000, 1, 1), bw(100_000, 1, 1)), emptyMap(), Direction.DOWNLOAD, now, 300f, 100f)
        assertEquals(1, c.total.size)
    }

    @Test fun `null percentile breaks the series`() {
        val c = waitLines(
            listOf(rs(98_000, 0.0, 0.0, 4.0, 8.0), rs(99_000, 0.0, 0.0, null, null), rs(100_000, 0.0, 0.0, 4.0, 8.0)),
            now, 300f, 100f,
        )
        assertEquals("10 ms", c.yMaxLabel)
        assertEquals(3, c.series[0].size)
        assertNull(c.series[0][1])
        assertNull(c.series[1][1])
        assertEquals(60f, c.series[0][0]!!.y, 0.01f)
    }

    @Test fun `missing tick renders as time gap`() {
        // a reset tick emits no sample: x positions keep the real time spacing
        val c = waitLines(
            listOf(rs(90_000, 0.0, 0.0, 1.0, 2.0), rs(100_000, 0.0, 0.0, 1.0, 2.0)), now, 300f, 100f,
        )
        assertEquals(3, c.series[0].size) // point, break, point
        assertNull(c.series[0][1])
        assertEquals(200f, c.series[0][0]!!.x, 0.01f)
        assertEquals(300f, c.series[0][2]!!.x, 0.01f)
    }

    @Test fun `overflow percentile is drawn at the overflow bound`() {
        val c = waitLines(listOf(rs(100_000, 0.0, 0.0, 1.0, Double.POSITIVE_INFINITY)), now, 300f, 100f)
        assertEquals("1000 ms", c.yMaxLabel)
        assertEquals(">512 ms", c.legend[1].valueText)
    }

    @Test fun `reorder bars stack recovered and lost`() {
        val c = reorderBars(listOf(rs(100_000, 6.0, 2.0, null, null), rs(99_000, 1.0, 0.0, null, null)), now, 300f, 80f)
        assertEquals("8/s", c.yMaxLabel)
        assertEquals(2, c.bars.size)
        assertEquals(60f, c.bars[0].greenH, 0.01f)
        assertEquals(20f, c.bars[0].redH, 0.01f)
    }
}
