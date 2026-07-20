// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.PathInfo

/** One 1 s chart sample: total and per-iface throughput in bits per second. */
data class BandwidthSample(
    val totalBps: Long,
    val perPathBps: Map<String, Long>,
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
class BandwidthHistory(private val maxSamples: Int = MAX_SAMPLES) {

    private var lastNanos: Long? = null
    private val baselines = mutableMapOf<String, Long>() // iface -> cumulative tx+rx bytes
    private val slots = mutableMapOf<String, Int>()      // iface -> palette slot, first-ever order
    private val samples = ArrayDeque<BandwidthSample>()

    fun onTick(paths: List<PathInfo>, nowNanos: Long): List<BandwidthSample> {
        val prevNanos = lastNanos
        if (prevNanos != null && nowNanos <= prevNanos) return samples.toList()

        val bytesByIface = paths
            .groupBy { it.iface }
            .mapValues { (_, ps) -> ps.sumOf { it.bytesTx + it.bytesRx } }

        val perPath = mutableMapOf<String, Long>()
        for ((iface, bytes) in bytesByIface) {
            slots.getOrPut(iface) { slots.size }
            val base = baselines[iface]
            perPath[iface] = if (prevNanos == null || base == null || bytes < base) {
                0L // first tick, reappeared path, or counter reset: (re-)baseline only
            } else {
                ((bytes - base) * 8.0 * NANOS_PER_SEC / (nowNanos - prevNanos)).toLong()
            }
            baselines[iface] = bytes
        }
        baselines.keys.retainAll(bytesByIface.keys)
        lastNanos = nowNanos

        samples.addLast(BandwidthSample(perPath.values.sum(), perPath))
        while (samples.size > maxSamples) samples.removeFirst()
        return samples.toList()
    }

    fun ifaceSlots(): Map<String, Int> = slots.toMap()

    fun clear() {
        lastNanos = null
        baselines.clear()
        slots.clear()
        samples.clear()
    }

    companion object {
        const val MAX_SAMPLES = 60
        private const val NANOS_PER_SEC = 1e9
    }
}
