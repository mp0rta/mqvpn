// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.PathInfo

/** One 1 s chart sample: per-direction total and per-iface throughput in bits per second. */
data class BandwidthSample(
    val wallMs: Long,                      // time axis
    val dlBps: Long, val ulBps: Long,      // totals per direction
    val perPathDlBps: Map<String, Long>,
    val perPathUlBps: Map<String, Long>,
)

/** History + stable per-iface palette slots, published together for the chart. */
data class BandwidthHistoryState(
    val samples: List<BandwidthSample> = emptyList(),
    val ifaceSlots: Map<String, Int> = emptyMap(),
)

/**
 * Converts cumulative PathInfo byte counters into a rolling window of
 * per-second bps samples. Pure logic — no coroutines, no Android types.
 * Single-writer: only the ViewModel ticker calls into this class.
 */
class BandwidthHistory(private val windowMs: Long = 30_000) {

    private var lastNanos: Long? = null
    private val rxBase = mutableMapOf<String, Long>() // iface -> cumulative rx bytes (download)
    private val txBase = mutableMapOf<String, Long>() // iface -> cumulative tx bytes (upload)
    private val slots = mutableMapOf<String, Int>()   // iface -> palette slot, first-ever order
    private val samples = ArrayDeque<BandwidthSample>()

    fun onTick(paths: List<PathInfo>, nowNanos: Long, nowMs: Long): List<BandwidthSample> {
        val prevNanos = lastNanos
        if (prevNanos != null && nowNanos <= prevNanos) return samples.toList()

        val byIface = paths.groupBy { it.iface }
        for (iface in byIface.keys) slots.getOrPut(iface) { slots.size }
        val dl = rates(byIface.mapValues { (_, ps) -> ps.sumOf { it.bytesRx } }, rxBase, prevNanos, nowNanos)
        val ul = rates(byIface.mapValues { (_, ps) -> ps.sumOf { it.bytesTx } }, txBase, prevNanos, nowNanos)
        lastNanos = nowNanos

        samples.addLast(BandwidthSample(nowMs, dl.values.sum(), ul.values.sum(), dl, ul))
        while (samples.isNotEmpty() && samples.first().wallMs < nowMs - windowMs) samples.removeFirst()
        return samples.toList()
    }

    private fun rates(
        bytes: Map<String, Long>, base: MutableMap<String, Long>, prevNanos: Long?, nowNanos: Long,
    ): Map<String, Long> {
        val out = mutableMapOf<String, Long>()
        for ((iface, b) in bytes) {
            val prev = base[iface]
            out[iface] = if (prevNanos == null || prev == null || b < prev) {
                0L // first tick, reappeared path, or counter reset: (re-)baseline only
            } else {
                ((b - prev) * 8.0 * NANOS_PER_SEC / (nowNanos - prevNanos)).toLong()
            }
            base[iface] = b
        }
        base.keys.retainAll(bytes.keys)
        return out
    }

    fun ifaceSlots(): Map<String, Int> = slots.toMap()

    fun clear() {
        lastNanos = null
        rxBase.clear()
        txBase.clear()
        slots.clear()
        samples.clear()
    }

    companion object {
        /** Samples visible in the default 30 s window at 1 Hz (chart x-scale). */
        const val MAX_SAMPLES = 30
        private const val NANOS_PER_SEC = 1e9
    }
}
