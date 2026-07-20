// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.BandwidthHistory
import com.mqvpn.sdk.core.model.PathInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BandwidthHistoryTest {

    private fun path(iface: String, tx: Long, rx: Long) =
        PathInfo(handle = 1L, status = 0, iface = iface, bytesTx = tx, bytesRx = rx, srttMs = 10L)

    private val second = 1_000_000_000L

    @Test
    fun `first tick establishes baseline and emits zero`() {
        val h = BandwidthHistory()
        val s = h.onTick(listOf(path("wlan0", 1000, 2000)), second)
        assertEquals(1, s.size)
        assertEquals(0L, s.last().totalBps)
        assertEquals(0L, s.last().perPathBps["wlan0"])
    }

    @Test
    fun `second tick computes bps from delta bytes over measured elapsed time`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 0, 0)), second)
        // +1250 bytes over 1 s = 10_000 bps
        val s = h.onTick(listOf(path("wlan0", 1000, 250)), 2 * second)
        assertEquals(10_000L, s.last().perPathBps["wlan0"])
        assertEquals(10_000L, s.last().totalBps)
    }

    @Test
    fun `elapsed time longer than one second scales rate down`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 0, 0)), second)
        // +2500 bytes over 2 s = 10_000 bps
        val s = h.onTick(listOf(path("wlan0", 2500, 0)), 3 * second)
        assertEquals(10_000L, s.last().perPathBps["wlan0"])
    }

    @Test
    fun `total sums multiple paths`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 0, 0), path("rmnet0", 0, 0)), second)
        val s = h.onTick(listOf(path("wlan0", 1250, 0), path("rmnet0", 250, 0)), 2 * second)
        assertEquals(10_000L, s.last().perPathBps["wlan0"])
        assertEquals(2_000L, s.last().perPathBps["rmnet0"])
        assertEquals(12_000L, s.last().totalBps)
    }

    @Test
    fun `duplicate ifaces are summed before delta`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 100, 0), path("wlan0", 200, 0)), second)
        val s = h.onTick(listOf(path("wlan0", 600, 0), path("wlan0", 325, 0)), 2 * second)
        // (925 - 300) * 8 = 5000 bps
        assertEquals(5_000L, s.last().perPathBps["wlan0"])
    }

    @Test
    fun `counter regression re-baselines and emits zero`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 9999, 0)), second)
        val s = h.onTick(listOf(path("wlan0", 10, 0)), 2 * second)
        assertEquals(0L, s.last().perPathBps["wlan0"])
        // and the new baseline is used afterwards
        val s2 = h.onTick(listOf(path("wlan0", 1260, 0)), 3 * second)
        assertEquals(10_000L, s2.last().perPathBps["wlan0"])
    }

    @Test
    fun `disappeared iface drops baseline and restarts at zero on return`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 1000, 0)), second)
        val gone = h.onTick(emptyList(), 2 * second)
        assertTrue(gone.last().perPathBps.isEmpty())
        val back = h.onTick(listOf(path("wlan0", 9_000_000, 0)), 3 * second)
        assertEquals(0L, back.last().perPathBps["wlan0"])
    }

    @Test
    fun `non-positive elapsed is ignored`() {
        val h = BandwidthHistory()
        h.onTick(listOf(path("wlan0", 0, 0)), second)
        val s = h.onTick(listOf(path("wlan0", 999_999, 0)), second)
        assertEquals(1, s.size)
        assertEquals(0L, s.last().totalBps)
    }

    @Test
    fun `ring buffer caps at maxSamples`() {
        val h = BandwidthHistory(maxSamples = 3)
        for (i in 1..5) h.onTick(listOf(path("wlan0", i * 100L, 0)), i * second)
        assertEquals(3, h.onTick(listOf(path("wlan0", 600, 0)), 6 * second).size)
    }

    @Test
    fun `iface slots are stable across window scroll and cleared by clear`() {
        val h = BandwidthHistory(maxSamples = 2)
        h.onTick(listOf(path("wlan0", 0, 0)), second)
        h.onTick(listOf(path("wlan0", 0, 0), path("rmnet0", 0, 0)), 2 * second)
        assertEquals(0, h.ifaceSlots()["wlan0"])
        assertEquals(1, h.ifaceSlots()["rmnet0"])
        // wlan0 scrolls out of the window; slot must not shift
        h.onTick(listOf(path("rmnet0", 0, 0)), 3 * second)
        h.onTick(listOf(path("rmnet0", 0, 0)), 4 * second)
        assertEquals(1, h.ifaceSlots()["rmnet0"])
        h.clear()
        assertTrue(h.ifaceSlots().isEmpty())
        assertEquals(0, h.onTick(listOf(path("rmnet0", 500, 0)), 5 * second).last().totalBps)
        assertEquals(0, h.ifaceSlots()["rmnet0"])
    }
}
