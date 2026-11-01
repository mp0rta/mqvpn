// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.DgramLossWindow
import com.mqvpn.app.ui.ReorderHistory
import com.mqvpn.sdk.core.model.ReorderStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReorderHistoryTest {

    private fun buckets(vararg at: Pair<Int, Long>): List<Long> =
        MutableList(12) { 0L }.also { l -> at.forEach { (i, v) -> l[i] = v } }

    private fun stats(
        delivered: Long = 0, gapCount: Long = 0, filled: Long = 0, timeout: Long = 0,
        b: List<Long> = buckets(),
    ) = ReorderStats(
        delivered = delivered, gapCount = gapCount, gapFilled = filled, gapTimeout = timeout,
        residenceBuckets = b,
    )

    @Test
    fun `first tick baselines and emits no sample`() {
        val h = ReorderHistory()
        val s = h.onTick(stats(delivered = 100), 1_000)
        assertTrue(s.samples.isEmpty())
        assertEquals(100L, s.cumulative.delivered)
    }

    @Test
    fun `rates are per second deltas`() {
        val h = ReorderHistory()
        h.onTick(stats(filled = 10, timeout = 1), 1_000)
        val s = h.onTick(stats(filled = 15, timeout = 3), 2_000).samples.single()
        assertEquals(5.0, s.recoveredPerSec, 1e-9)
        assertEquals(2.0, s.lostPerSec, 1e-9)
        assertEquals(2_000L, s.wallMs)
    }

    @Test
    fun `late tick divides by real elapsed time`() {
        val h = ReorderHistory()
        h.onTick(stats(filled = 0), 1_000)
        val s = h.onTick(stats(filled = 30), 4_000).samples.single()
        assertEquals(10.0, s.recoveredPerSec, 1e-9)
    }

    @Test
    fun `counter reset re-baselines without a sample or negative rate`() {
        val h = ReorderHistory()
        h.onTick(stats(delivered = 500, filled = 50), 1_000)
        val r = h.onTick(stats(delivered = 10, filled = 2), 2_000)
        assertTrue(r.samples.isEmpty())
        assertEquals(10L, r.cumulative.delivered)
        val s = h.onTick(stats(delivered = 20, filled = 4), 3_000).samples.single()
        assertEquals(2.0, s.recoveredPerSec, 1e-9)
    }

    @Test
    fun `reset masked by larger delivered still re-baselines on gapCount decrease`() {
        val h = ReorderHistory()
        h.onTick(stats(delivered = 100, gapCount = 9), 1_000)
        assertTrue(h.onTick(stats(delivered = 900, gapCount = 1), 2_000).samples.isEmpty())
    }

    @Test
    fun `reset masked by larger delivered still re-baselines on one bucket decrease`() {
        val h = ReorderHistory()
        h.onTick(stats(delivered = 100, b = buckets(3 to 10, 4 to 10)), 1_000)
        val r = h.onTick(stats(delivered = 900, b = buckets(3 to 50, 4 to 9)), 2_000)
        assertTrue(r.samples.isEmpty())
    }

    @Test
    fun `bucket 0 only tick has null percentiles`() {
        val h = ReorderHistory()
        h.onTick(stats(b = buckets(0 to 5)), 1_000)
        val s = h.onTick(stats(b = buckets(0 to 500)), 2_000).samples.single()
        assertNull(s.p50Ms)
        assertNull(s.p99Ms)
    }

    @Test
    fun `percentiles interpolate inside the bucket`() {
        val h = ReorderHistory()
        h.onTick(stats(b = buckets(0 to 1000)), 1_000)
        // deltas: b1=50 (0..1ms), b2=40 (1..2ms), b3=10 (2..4ms); N=100
        // p50: rank 50 ends exactly at b1 -> 1 ms
        // p99: rank 99 -> b3, (99-90)/10 = 0.9 -> 2 + 0.9*2 = 3.8 ms
        val s = h.onTick(stats(b = buckets(0 to 2000, 1 to 50, 2 to 40, 3 to 10)), 2_000)
            .samples.single()
        assertEquals(1.0, s.p50Ms!!, 1e-9)
        assertEquals(3.8, s.p99Ms!!, 1e-9)
    }

    @Test
    fun `percentile in overflow bucket is positive infinity`() {
        val h = ReorderHistory()
        h.onTick(stats(), 1_000)
        val s = h.onTick(stats(b = buckets(1 to 90, 11 to 10)), 2_000).samples.single()
        assertEquals(Double.POSITIVE_INFINITY, s.p99Ms!!, 0.0)
        assertTrue(s.p50Ms!! < 1.0 + 1e-9)
    }

    @Test
    fun `empty bucket list (stale lib) gives null percentiles without crashing`() {
        val h = ReorderHistory()
        h.onTick(ReorderStats(gapFilled = 1), 1_000)
        val s = h.onTick(ReorderStats(gapFilled = 3), 2_000).samples.single()
        assertEquals(2.0, s.recoveredPerSec, 1e-9)
        assertNull(s.p50Ms)
        assertNull(s.p99Ms)
    }

    @Test
    fun `samples expire by timestamp`() {
        val h = ReorderHistory(windowMs = 3_000)
        h.onTick(stats(), 0)
        var last = ReorderHistory().onTick(stats(), 0)
        for (t in 1..5) last = h.onTick(stats(filled = t.toLong()), t * 1_000L)
        // at now=5000 keep wallMs >= 2000
        assertEquals(listOf(2_000L, 3_000L, 4_000L, 5_000L), last.samples.map { it.wallMs })
    }

    @Test
    fun `clear forgets baseline`() {
        val h = ReorderHistory()
        h.onTick(stats(filled = 5), 1_000)
        h.clear()
        assertTrue(h.onTick(stats(filled = 50), 2_000).samples.isEmpty())
    }

    @Test
    fun `dgram loss is null with no sends and delta ratio otherwise`() {
        val w = DgramLossWindow()
        assertNull(w.onTick(100, 1, 1_000))
        assertNull(w.onTick(100, 1, 2_000))
        assertEquals(0.1, w.onTick(200, 11, 3_000)!!, 1e-9)
    }

    @Test
    fun `dgram loss window drops old points and survives reset`() {
        val w = DgramLossWindow(windowMs = 2_000)
        w.onTick(0, 0, 0)
        w.onTick(100, 50, 1_000)
        // window now [2000..4000]: baseline is the newest point at/before cutoff (1000)
        assertEquals(0.0, w.onTick(300, 50, 4_000)!!, 1e-9)
        assertNull(w.onTick(10, 0, 5_000)) // reset
        assertEquals(0.5, w.onTick(20, 5, 6_000)!!, 1e-9)
    }
}
