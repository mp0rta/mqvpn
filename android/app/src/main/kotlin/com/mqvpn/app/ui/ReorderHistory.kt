// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.ReorderStats

/** Mirrors reorder_lat_bound_us[] in src/reorder_rx.c — keep in sync by hand. */
internal val REORDER_LAT_BOUND_US = longArrayOf(
    0, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000,
    128_000, 256_000, 512_000, Long.MAX_VALUE)

data class ReorderSample(
    val wallMs: Long,
    val recoveredPerSec: Double,   // Δ gapFilled / Δt
    val lostPerSec: Double,        // Δ gapTimeout / Δt
    val p50Ms: Double?,            // this tick's bucket-delta percentile; null = no buffered pkts
    val p99Ms: Double?,            // Double.POSITIVE_INFINITY = overflow bucket (render ">512 ms")
)

data class ReorderHistoryState(
    val samples: List<ReorderSample> = emptyList(),
    val cumulative: ReorderStats = ReorderStats(),
)

/**
 * Turns cumulative ReorderStats into a rolling window of per-second samples.
 * Pure logic, single writer (the ViewModel ticker).
 */
class ReorderHistory(private val windowMs: Long = 30_000) {

    private var prev: ReorderStats? = null
    private var prevMs = 0L
    private val samples = ArrayDeque<ReorderSample>()

    fun onTick(stats: ReorderStats, nowMs: Long): ReorderHistoryState {
        val p = prev
        if (p != null && nowMs <= prevMs) return ReorderHistoryState(samples.toList(), stats)
        if (p == null || stats.resetFrom(p)) {
            // first tick or a new native session: baseline only, no sample
            prev = stats
            prevMs = nowMs
            return ReorderHistoryState(samples.toList(), stats)
        }
        val sec = (nowMs - prevMs) / 1000.0
        samples.addLast(ReorderSample(
            wallMs = nowMs,
            recoveredPerSec = (stats.gapFilled - p.gapFilled) / sec,
            lostPerSec = (stats.gapTimeout - p.gapTimeout) / sec,
            p50Ms = percentileMs(p.residenceBuckets, stats.residenceBuckets, 0.50),
            p99Ms = percentileMs(p.residenceBuckets, stats.residenceBuckets, 0.99),
        ))
        prev = stats
        prevMs = nowMs
        while (samples.isNotEmpty() && samples.first().wallMs < nowMs - windowMs) samples.removeFirst()
        return ReorderHistoryState(samples.toList(), stats)
    }

    fun clear() {
        prev = null
        prevMs = 0
        samples.clear()
    }

    /** A decrease in ANY counter or bucket means the native stats were recreated. */
    private fun ReorderStats.resetFrom(p: ReorderStats): Boolean =
        delivered < p.delivered || gapCount < p.gapCount || gapFilled < p.gapFilled ||
            gapTimeout < p.gapTimeout || ackDemote < p.ackDemote ||
            (residenceBuckets.size == p.residenceBuckets.size &&
                residenceBuckets.indices.any { residenceBuckets[it] < p.residenceBuckets[it] })

    /** Percentile of bucket deltas 1..11 (bucket 0 = in-order pass-through is excluded). */
    private fun percentileMs(old: List<Long>, new: List<Long>, q: Double): Double? {
        val n = REORDER_LAT_BOUND_US.size
        if (old.size != n || new.size != n) return null // stale lib / no bucket data
        val d = LongArray(n) { new[it] - old[it] }
        val total = (1 until n).sumOf { d[it] }
        if (total <= 0) return null
        val rank = q * total
        var cum = 0L
        for (i in 1 until n) {
            if (d[i] > 0 && cum + d[i] >= rank) {
                if (i == n - 1) return Double.POSITIVE_INFINITY
                val lo = REORDER_LAT_BOUND_US[i - 1].toDouble()
                val hi = REORDER_LAT_BOUND_US[i].toDouble()
                return (lo + (hi - lo) * (rank - cum) / d[i]) / 1000.0
            }
            cum += d[i]
        }
        return null // unreachable: total > 0
    }
}

/** Upload DATAGRAM loss over a rolling window from cumulative sent/lost counters. */
class DgramLossWindow(private val windowMs: Long = 30_000) {

    private data class Point(val ms: Long, val sent: Long, val lost: Long)

    private val points = ArrayDeque<Point>()

    /** Upload loss over the window: Δlost/Δsent; null when Δsent == 0. */
    fun onTick(dgramSent: Long, dgramLost: Long, nowMs: Long): Double? {
        val last = points.lastOrNull()
        if (last != null && (dgramSent < last.sent || dgramLost < last.lost)) points.clear()
        points.addLast(Point(nowMs, dgramSent, dgramLost))
        // keep the newest point at/before the cutoff as the baseline
        while (points.size > 1 && points[1].ms <= nowMs - windowMs) points.removeFirst()
        val ds = dgramSent - points.first().sent
        return if (ds > 0) (dgramLost - points.first().lost).toDouble() / ds else null
    }

    fun clear() = points.clear()
}
