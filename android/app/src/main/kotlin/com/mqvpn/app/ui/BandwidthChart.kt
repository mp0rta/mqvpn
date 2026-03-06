package com.mqvpn.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.mqvpn.sdk.core.model.PathInfo

private const val MAX_SAMPLES = 60
private val WIFI_COLOR = Color(0xFF26A69A)      // teal
private val CELLULAR_COLOR = Color(0xFFFF9800)   // orange

@Composable
fun BandwidthChart(paths: List<PathInfo>) {
    val wifiSamples = remember { mutableStateListOf<Long>() }
    val cellSamples = remember { mutableStateListOf<Long>() }

    LaunchedEffect(paths) {
        val wifiBytes = paths
            .filter { it.iface.startsWith("wlan") }
            .sumOf { it.bytesTx + it.bytesRx }
        val cellBytes = paths
            .filter { it.iface.startsWith("rmnet") || it.iface.startsWith("ccmni") }
            .sumOf { it.bytesTx + it.bytesRx }

        wifiSamples.add(wifiBytes)
        cellSamples.add(cellBytes)
        if (wifiSamples.size > MAX_SAMPLES) wifiSamples.removeAt(0)
        if (cellSamples.size > MAX_SAMPLES) cellSamples.removeAt(0)
    }

    val surfaceColor = MaterialTheme.colorScheme.surfaceVariant

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(120.dp),
    ) {
        drawRect(surfaceColor)

        fun drawLine(samples: List<Long>, color: Color) {
            if (samples.size < 2) return
            val maxVal = samples.max().coerceAtLeast(1)
            val stepX = size.width / (MAX_SAMPLES - 1)
            val startOffset = (MAX_SAMPLES - samples.size) * stepX

            for (i in 1 until samples.size) {
                val x0 = startOffset + (i - 1) * stepX
                val x1 = startOffset + i * stepX
                val y0 = size.height - (samples[i - 1].toFloat() / maxVal) * size.height
                val y1 = size.height - (samples[i].toFloat() / maxVal) * size.height
                drawLine(color, Offset(x0, y0), Offset(x1, y1), strokeWidth = 2.dp.toPx())
            }
        }

        drawLine(wifiSamples.toList(), WIFI_COLOR)
        drawLine(cellSamples.toList(), CELLULAR_COLOR)
    }
}
