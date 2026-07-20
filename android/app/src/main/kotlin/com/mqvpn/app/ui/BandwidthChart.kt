// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp

private val PATH_PALETTE = listOf(
    Color(0xFF26A69A), // teal
    Color(0xFFFF9800), // orange
    Color(0xFFAB47BC), // purple
    Color(0xFF42A5F5), // blue
    Color(0xFFEF5350), // red
    Color(0xFF9CCC65), // light green
)

private fun slotColor(slot: Int): Color = PATH_PALETTE[slot % PATH_PALETTE.size]

@Composable
fun BandwidthChart(state: BandwidthHistoryState) {
    val samples = state.samples
    if (samples.isEmpty()) return

    val activeIfaces = samples.asSequence().flatMap { it.perPathBps.keys }.distinct().toList()
    val totalColor = MaterialTheme.colorScheme.primary
    val surfaceColor = MaterialTheme.colorScheme.surfaceVariant
    val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
    val labelStyle = MaterialTheme.typography.labelSmall
        .copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
    val textMeasurer = rememberTextMeasurer()

    Column {
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            LegendEntry("total", totalColor, thick = true)
            activeIfaces.forEach { iface ->
                LegendEntry(iface, slotColor(state.ifaceSlots[iface] ?: 0), thick = false)
            }
        }

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(140.dp),
        ) {
            drawRect(surfaceColor)

            val windowMax = samples.maxOf { s ->
                maxOf(s.totalBps, s.perPathBps.values.maxOrNull() ?: 0L)
            }
            val top = ceilNice(windowMax)

            // inset by half the widest stroke so peaks/zeros aren't clipped at the edges;
            // gridlines and labels share this scale so lines sit exactly on their values
            val strokeInset = 1.5.dp.toPx()
            fun yFor(bps: Long): Float =
                size.height - strokeInset - (bps.toFloat() / top) * (size.height - 2 * strokeInset)

            drawGridLines(gridColor, strokeInset)

            fun drawSeries(values: List<Long?>, color: Color, strokeDp: Float) {
                val stepX = size.width / (BandwidthHistory.MAX_SAMPLES - 1)
                val startOffset = (BandwidthHistory.MAX_SAMPLES - values.size) * stepX
                for (i in 1 until values.size) {
                    val a = values[i - 1] ?: continue
                    val b = values[i] ?: continue
                    drawLine(
                        color,
                        Offset(startOffset + (i - 1) * stepX, yFor(a)),
                        Offset(startOffset + i * stepX, yFor(b)),
                        strokeWidth = strokeDp.dp.toPx(),
                    )
                }
            }

            activeIfaces.forEach { iface ->
                drawSeries(
                    samples.map { it.perPathBps[iface] },
                    slotColor(state.ifaceSlots[iface] ?: 0),
                    strokeDp = 1.5f,
                )
            }
            drawSeries(samples.map { it.totalBps }, totalColor, strokeDp = 3f)

            drawGridLabels(top, strokeInset, textMeasurer, labelStyle)
        }
    }
}

@Composable
private fun LegendEntry(label: String, color: Color, thick: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Canvas(modifier = Modifier.size(width = 14.dp, height = if (thick) 3.dp else 1.5.dp)) {
            drawRect(color)
        }
        Text(" $label", style = MaterialTheme.typography.labelSmall)
    }
}

// Lines are drawn beneath the series, labels above it (see call order in BandwidthChart).

// frac 0 = top value, 1 = zero baseline, both on the stroke-inset scale used by the series
private fun DrawScope.gridY(frac: Float, inset: Float): Float =
    inset + frac * (size.height - 2 * inset)

private fun DrawScope.drawGridLines(gridColor: Color, inset: Float) {
    val dashPx = 6.dp.toPx()
    val dash = PathEffect.dashPathEffect(floatArrayOf(dashPx, dashPx))

    // dashed gridlines at top and mid; solid baseline at 0
    for (frac in listOf(0f, 0.5f)) {
        val y = gridY(frac, inset)
        drawLine(gridColor, Offset(0f, y), Offset(size.width, y), pathEffect = dash)
    }
    val y0 = gridY(1f, inset)
    drawLine(gridColor, Offset(0f, y0), Offset(size.width, y0))
}

private fun DrawScope.drawGridLabels(
    top: Long,
    inset: Float,
    textMeasurer: TextMeasurer,
    labelStyle: TextStyle,
) {
    val pad = 4.dp.toPx()

    for ((frac, bps) in listOf(0f to top, 0.5f to top / 2)) {
        drawText(
            textMeasurer.measure(formatBps(bps), labelStyle),
            topLeft = Offset(pad, gridY(frac, inset) + pad / 2),
        )
    }
    val zeroLayout = textMeasurer.measure("0", labelStyle)
    drawText(
        zeroLayout,
        topLeft = Offset(pad, size.height - zeroLayout.size.height - pad / 2),
    )

    // time labels: -60s (left), -30s (mid), now (right)
    val nowLayout = textMeasurer.measure("now", labelStyle)
    val midLayout = textMeasurer.measure("-30s", labelStyle)
    val yTime = size.height - nowLayout.size.height - pad / 2
    drawText(
        textMeasurer.measure("-60s", labelStyle),
        topLeft = Offset(size.width * 0.02f + pad * 8, yTime),
    )
    drawText(midLayout, topLeft = Offset((size.width - midLayout.size.width) / 2f, yTime))
    drawText(nowLayout, topLeft = Offset(size.width - nowLayout.size.width - pad, yTime))
}
