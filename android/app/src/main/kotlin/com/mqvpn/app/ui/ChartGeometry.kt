// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import java.util.Locale
import kotlin.math.ceil

// Pure chart layout: no Compose types. Charts.kt only draws what these return.

data class ChartPoint(val x: Float, val y: Float)
data class LegendEntry(val label: String, val slot: Int, val valueText: String)
data class LineChart(
    val yMaxLabel: String,
    val gridYs: List<Float>,               // top, mid, zero line
    val total: List<ChartPoint?>,          // null = gap; empty when the chart has no total series
    val series: List<List<ChartPoint?>>,   // per slot; null = gap (break the polyline)
    val legend: List<LegendEntry>,
)
data class StackedBar(val x: Float, val greenH: Float, val redH: Float)
data class BarChart(val yMaxLabel: String, val bars: List<StackedBar>, val legend: List<LegendEntry>)
data class PairedBar(val x: Float, val h0: Float?, val h1: Float?)   // null = no data that tick
data class PairedBarChart(val yMaxLabel: String, val bars: List<PairedBar>, val legend: List<LegendEntry>)
enum class Direction { DOWNLOAD, UPLOAD }

const val CHART_WINDOW_MS = 30_000L
const val TOTAL_SLOT = -1
/** Residence above the last finite bucket bound; drawn at this height and labelled ">512 ms". */
private const val OVERFLOW_MS = 512.0
const val TICK_MS = 1_000L
/** Samples further apart than this (1.5 ticks: tolerates jitter, catches one missed tick) break the polyline. */
const val GAP_MS = TICK_MS * 3 / 2

/** One entry per sample, with a null inserted wherever a tick is missing between two samples. */
private fun <S, T> List<S>.withGaps(wallMs: (S) -> Long, map: (S) -> T?): List<T?> {
    val out = ArrayList<T?>()
    var prev: Long? = null
    for (s in this) {
        if (prev != null && wallMs(s) - prev > GAP_MS) out.add(null)
        prev = wallMs(s)
        out.add(map(s))
    }
    return out
}

private fun xFor(wallMs: Long, nowMs: Long, w: Float): Float =
    (wallMs - (nowMs - CHART_WINDOW_MS)).toFloat() / CHART_WINDOW_MS * w

private fun gridYs(h: Float) = listOf(0f, h / 2, h)

fun rateChart(
    samples: List<BandwidthSample>, slots: Map<String, Int>,
    dir: Direction, nowMs: Long, w: Float, h: Float,
): LineChart {
    val vis = samples.filter { it.wallMs >= nowMs - CHART_WINDOW_MS }
    fun tot(s: BandwidthSample) = if (dir == Direction.DOWNLOAD) s.dlBps else s.ulBps
    fun per(s: BandwidthSample) = if (dir == Direction.DOWNLOAD) s.perPathDlBps else s.perPathUlBps
    val top = ceilNice(vis.maxOfOrNull { s -> maxOf(tot(s), per(s).values.maxOrNull() ?: 0L) } ?: 0L)
    fun y(bps: Long) = h - bps.toFloat() / top * h
    val slotCount = (slots.values.maxOrNull() ?: -1) + 1
    val series = List(slotCount) { slot ->
        val iface = slots.entries.firstOrNull { it.value == slot }?.key
        vis.withGaps({ it.wallMs }) { s -> per(s)[iface]?.let { ChartPoint(xFor(s.wallMs, nowMs, w), y(it)) } }
    }
    val last = vis.lastOrNull()
    val legend = listOf(LegendEntry("total", TOTAL_SLOT, formatBps(last?.let(::tot) ?: 0L))) +
        slots.entries.sortedBy { it.value }.map { (iface, slot) ->
            LegendEntry(iface, slot, formatBps(last?.let { per(it)[iface] } ?: 0L))
        }
    return LineChart(
        formatBps(top), gridYs(h),
        vis.withGaps({ it.wallMs }) { ChartPoint(xFor(it.wallMs, nowMs, w), y(tot(it))) }, series, legend,
    )
}

fun reorderBars(samples: List<ReorderSample>, nowMs: Long, w: Float, h: Float): BarChart {
    val vis = samples.filter { it.wallMs >= nowMs - CHART_WINDOW_MS }
    val top = maxOf(1.0, ceil(vis.maxOfOrNull { it.recoveredPerSec + it.lostPerSec } ?: 0.0))
    val last = vis.lastOrNull()
    return BarChart(
        "${top.toLong()}/s",
        vis.map {
            StackedBar(
                xFor(it.wallMs, nowMs, w),
                (it.recoveredPerSec / top * h).toFloat(), (it.lostPerSec / top * h).toFloat(),
            )
        },
        listOf(
            LegendEntry("recovered", 0, fmtRate(last?.recoveredPerSec)),
            LegendEntry("lost", 1, fmtRate(last?.lostPerSec)),
        ),
    )
}

fun waitBars(samples: List<ReorderSample>, nowMs: Long, w: Float, h: Float): PairedBarChart {
    val vis = samples.filter { it.wallMs >= nowMs - CHART_WINDOW_MS }
    fun capped(v: Double?) = v?.let { if (it.isInfinite()) OVERFLOW_MS else it }
    val maxMs = vis.maxOfOrNull { maxOf(capped(it.p50Ms) ?: 0.0, capped(it.p99Ms) ?: 0.0) } ?: 0.0
    var top = 1.0
    search@ while (true) {
        for (m in doubleArrayOf(1.0, 2.0, 5.0)) if (maxMs <= top * m) { top *= m; break@search }
        top *= 10
    }
    fun bar(v: Double?): Float? = capped(v)?.let { (it / top * h).toFloat() }
    val last = vis.lastOrNull()
    fun txt(v: Double?) = when {
        v == null -> "-"
        v.isInfinite() -> ">512 ms"
        else -> String.format(Locale.US, "%.1f ms", v)
    }
    return PairedBarChart(
        "${top.toLong().coerceAtLeast(1)} ms",
        vis.map { PairedBar(xFor(it.wallMs, nowMs, w), bar(it.p50Ms), bar(it.p99Ms)) },
        listOf(LegendEntry("p50", 0, txt(last?.p50Ms)), LegendEntry("p99", 1, txt(last?.p99Ms))),
    )
}

private fun fmtRate(v: Double?) = if (v == null) "-" else String.format(Locale.US, "%.1f/s", v)
