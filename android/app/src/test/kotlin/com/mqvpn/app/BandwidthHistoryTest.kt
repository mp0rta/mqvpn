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

    private fun BandwidthHistory.tick(p: List<PathInfo>, nanos: Long) = onTick(p, nanos, nanos / 1_000_000)

    @Test
    fun `first tick establishes baseline and emits zero`() {
        val h = BandwidthHistory()
        val s = h.tick(listOf(path("wlan0", 1000, 2000)), second)
        assertEquals(1, s.size)
        assertEquals(0L, s.last().dlBps)
        assertEquals(0L, s.last().ulBps)
        assertEquals(0L, s.last().perPathUlBps["wlan0"])
        assertEquals(second / 1_000_000, s.last().wallMs)
    }

    @Test
    fun `second tick computes bps from delta bytes over measured elapsed time`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 0, 0)), second)
        // +1250 bytes over 1 s = 10_000 bps
        val s = h.tick(listOf(path("wlan0", 1000, 250)), 2 * second)
        // tx 1000 B -> 8000 bps up; rx 250 B -> 2000 bps down
        assertEquals(8_000L, s.last().perPathUlBps["wlan0"])
        assertEquals(2_000L, s.last().perPathDlBps["wlan0"])
        assertEquals(8_000L, s.last().ulBps)
        assertEquals(2_000L, s.last().dlBps)
    }

    @Test
    fun `elapsed time longer than one second scales rate down`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 0, 0)), second)
        // +2500 bytes over 2 s = 10_000 bps
        val s = h.tick(listOf(path("wlan0", 2500, 0)), 3 * second)
        assertEquals(10_000L, s.last().perPathUlBps["wlan0"])
    }

    @Test
    fun `total sums multiple paths`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 0, 0), path("rmnet0", 0, 0)), second)
        val s = h.tick(listOf(path("wlan0", 1250, 0), path("rmnet0", 250, 0)), 2 * second)
        assertEquals(10_000L, s.last().perPathUlBps["wlan0"])
        assertEquals(2_000L, s.last().perPathUlBps["rmnet0"])
        assertEquals(12_000L, s.last().ulBps)
    }

    @Test
    fun `duplicate ifaces are summed before delta`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 100, 0), path("wlan0", 200, 0)), second)
        val s = h.tick(listOf(path("wlan0", 600, 0), path("wlan0", 325, 0)), 2 * second)
        // (925 - 300) * 8 = 5000 bps
        assertEquals(5_000L, s.last().perPathUlBps["wlan0"])
    }

    @Test
    fun `counter regression re-baselines and emits zero`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 9999, 0)), second)
        val s = h.tick(listOf(path("wlan0", 10, 0)), 2 * second)
        assertEquals(0L, s.last().perPathUlBps["wlan0"])
        // and the new baseline is used afterwards
        val s2 = h.tick(listOf(path("wlan0", 1260, 0)), 3 * second)
        assertEquals(10_000L, s2.last().perPathUlBps["wlan0"])
    }

    @Test
    fun `disappeared iface drops baseline and restarts at zero on return`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 1000, 0)), second)
        val gone = h.tick(emptyList<PathInfo>(), 2 * second)
        assertTrue(gone.last().perPathUlBps.isEmpty())
        assertTrue(gone.last().perPathDlBps.isEmpty())
        val back = h.tick(listOf(path("wlan0", 9_000_000, 0)), 3 * second)
        assertEquals(0L, back.last().perPathUlBps["wlan0"])
    }

    @Test
    fun `non-positive elapsed is ignored`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 0, 0)), second)
        val s = h.tick(listOf(path("wlan0", 999_999, 0)), second)
        assertEquals(1, s.size)
        assertEquals(0L, s.last().ulBps)
    }

    @Test
    fun `samples expire by timestamp`() {
        val h = BandwidthHistory(windowMs = 3_000)
        for (i in 1..5) h.tick(listOf(path("wlan0", i * 100L, 0)), i * second)
        // at now=6 s keep wallMs >= 3000
        val s = h.tick(listOf(path("wlan0", 600, 0)), 6 * second)
        assertEquals(listOf(3_000L, 4_000L, 5_000L, 6_000L), s.map { it.wallMs })
    }

    @Test
    fun `download and upload keep separate baselines`() {
        val h = BandwidthHistory()
        h.tick(listOf(path("wlan0", 500, 500)), second)
        // rx resets (decrease) but tx keeps growing: dl restarts at 0, ul unaffected
        val s = h.tick(listOf(path("wlan0", 1750, 10)), 2 * second)
        assertEquals(0L, s.last().dlBps)
        assertEquals(10_000L, s.last().ulBps)
    }

    @Test
    fun `iface slots are stable across window scroll and cleared by clear`() {
        val h = BandwidthHistory(windowMs = 1_500)
        h.tick(listOf(path("wlan0", 0, 0)), second)
        h.tick(listOf(path("wlan0", 0, 0), path("rmnet0", 0, 0)), 2 * second)
        assertEquals(0, h.ifaceSlots()["wlan0"])
        assertEquals(1, h.ifaceSlots()["rmnet0"])
        // wlan0 scrolls out of the window; slot must not shift
        h.tick(listOf(path("rmnet0", 0, 0)), 3 * second)
        h.tick(listOf(path("rmnet0", 0, 0)), 4 * second)
        assertEquals(1, h.ifaceSlots()["rmnet0"])
        h.clear()
        assertTrue(h.ifaceSlots().isEmpty())
        assertEquals(0, h.tick(listOf(path("rmnet0", 500, 0)), 5 * second).last().ulBps)
        assertEquals(0, h.ifaceSlots()["rmnet0"])
    }
}
