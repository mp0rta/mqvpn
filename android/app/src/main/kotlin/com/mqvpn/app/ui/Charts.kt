// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.app.ui.theme.MqColors

// Composables only draw what ChartGeometry.kt returns; no layout math here
// beyond handing it the canvas size.

private val CHART_HEIGHT = 120.dp

@Composable
fun RateChartCard(
    title: String, history: BandwidthHistoryState, dir: Direction, nowMs: Long,
    modifier: Modifier = Modifier,
) {
    val mq = LocalMqColors.current
    ChartCard(title, modifier) { w, h ->
        val chart = rateChart(history.samples, history.ifaceSlots, dir, nowMs, w, h)
        Legend(chart.legend, mq) { if (it == TOTAL_SLOT) mq.text else slotColor(it) }
        LineCanvas(chart, mq, { if (it == TOTAL_SLOT) mq.text else slotColor(it) }, nowMs)
    }
}

@Composable
fun ReorderRateCard(history: ReorderHistoryState, nowMs: Long, modifier: Modifier = Modifier) {
    val mq = LocalMqColors.current
    ChartCard("Reorder recovery", modifier) { w, h ->
        val chart = reorderBars(history.samples, nowMs, w, h)
        val color = { slot: Int -> if (slot == 0) mq.green else mq.red }
        Legend(chart.legend, mq, color)
        val measurer = rememberTextMeasurer()
        Canvas(Modifier.fillMaxWidth().height(CHART_HEIGHT)) {
            drawGrid(mq)
            val barW = (size.width / 30f * 0.6f)
            chart.bars.forEach { b ->
                drawRect(mq.green, Offset(b.x - barW / 2, size.height - b.greenH), Size(barW, b.greenH))
                drawRect(mq.red, Offset(b.x - barW / 2, size.height - b.greenH - b.redH), Size(barW, b.redH))
            }
            drawText(measurer.measure(chart.yMaxLabel, axisStyle(mq)), topLeft = Offset(4.dp.toPx(), 0f))
        }
    }
}

@Composable
fun BufferWaitCard(history: ReorderHistoryState, nowMs: Long, modifier: Modifier = Modifier) {
    val mq = LocalMqColors.current
    ChartCard("Buffer wait", modifier) { w, h ->
        val chart = waitBars(history.samples, nowMs, w, h)
        val color = { slot: Int -> if (slot == 0) mq.accent else mq.orange }
        Legend(chart.legend, mq, color)
        val measurer = rememberTextMeasurer()
        Canvas(Modifier.fillMaxWidth().height(CHART_HEIGHT)) {
            drawGrid(mq)
            // Same footprint as the stacked bars (0.6 of a 1 s slot), split into
            // a p50|p99 pair around the sample's x.
            val barW = (size.width / 30f * 0.3f)
            chart.bars.forEach { b ->
                b.h0?.let { drawRect(mq.accent, Offset(b.x - barW, size.height - it), Size(barW, it)) }
                b.h1?.let { drawRect(mq.orange, Offset(b.x, size.height - it), Size(barW, it)) }
            }
            drawText(measurer.measure(chart.yMaxLabel, axisStyle(mq)), topLeft = Offset(4.dp.toPx(), 0f))
        }
    }
}

// The canvas fills the card width; geometry needs pixel size, so measure it once
// via a fixed-size layout pass instead of reading it back from DrawScope.
@Composable
private fun ChartCard(title: String, modifier: Modifier, content: @Composable (Float, Float) -> Unit) {
    val mq = LocalMqColors.current
    androidx.compose.foundation.layout.BoxWithConstraints(
        modifier.fillMaxWidth().background(mq.card, RoundedCornerShape(12.dp)).padding(12.dp),
    ) {
        val density = androidx.compose.ui.platform.LocalDensity.current
        val (w, h) = with(density) { maxWidth.toPx() to CHART_HEIGHT.toPx() }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, color = mq.text, fontSize = 15.sp)
            content(w, h)
        }
    }
}

@Composable
private fun Legend(entries: List<LegendEntry>, mq: MqColors, colorOf: (Int) -> Color) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        entries.forEach { e ->
            androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).background(colorOf(e.slot), RoundedCornerShape(4.dp)))
                Text(" ${e.label} ${e.valueText}", color = mq.t2, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun LineCanvas(chart: LineChart, mq: MqColors, colorOf: (Int) -> Color, nowMs: Long) {
    val measurer = rememberTextMeasurer()
    Canvas(Modifier.fillMaxWidth().height(CHART_HEIGHT)) {
        drawGrid(mq, chart.gridYs)
        chart.series.forEachIndexed { slot, pts -> drawPolyline(pts, colorOf(slot), 1.5.dp.toPx()) }
        if (chart.total.isNotEmpty()) drawPolyline(chart.total, colorOf(TOTAL_SLOT), 2.5.dp.toPx())
        drawText(measurer.measure(chart.yMaxLabel, axisStyle(mq)), topLeft = Offset(4.dp.toPx(), 0f))
    }
}

private fun axisStyle(mq: MqColors) = TextStyle(color = mq.t2, fontSize = 10.sp)

private fun DrawScope.drawGrid(mq: MqColors, ys: List<Float> = listOf(0f, size.height / 2, size.height)) {
    val dash = PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 6.dp.toPx()))
    ys.forEachIndexed { i, y ->
        val zero = i == ys.lastIndex
        drawLine(mq.sep, Offset(0f, y), Offset(size.width, y), pathEffect = if (zero) null else dash)
    }
}

/** Draws consecutive non-null points as segments; a null breaks the line (never interpolated). */
private fun DrawScope.drawPolyline(pts: List<ChartPoint?>, color: Color, strokePx: Float) {
    for (i in 1 until pts.size) {
        val a = pts[i - 1] ?: continue
        val b = pts[i] ?: continue
        drawLine(color, Offset(a.x, a.y), Offset(b.x, b.y), strokeWidth = strokePx)
    }
}
