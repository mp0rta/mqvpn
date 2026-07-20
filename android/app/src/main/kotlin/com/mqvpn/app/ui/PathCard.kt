// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.mqvpn.sdk.core.model.PathInfo

private val PATH_STATUS_NAMES = mapOf(
    0 to "Pending",
    1 to "Active",
    2 to "Degraded",
    3 to "Standby",
    4 to "Closed",
)

fun pathStatusName(status: Int): String = PATH_STATUS_NAMES[status] ?: "Unknown"

/** Port of iOS PathCardView.statusColor. */
fun pathStatusColor(status: Int): Color = when (status) {
    1 -> Color(0xFF4CAF50) // Active — green
    0, 3 -> Color(0xFFFFC107) // Pending/Standby — yellow/amber
    2 -> Color(0xFFFF9800) // Degraded — orange
    4 -> Color.Gray // Closed
    else -> Color(0xFFF44336) // Unknown — red
}

@Composable
fun PathCard(path: PathInfo) {
    val icon = when {
        path.iface.startsWith("wifi") || path.iface.startsWith("wlan") -> Icons.Default.Wifi
        path.iface.startsWith("cellular") || path.iface.startsWith("rmnet") || path.iface.startsWith("ccmni") ->
            Icons.Default.SignalCellularAlt
        else -> Icons.Default.Cable
    }
    val statusName = pathStatusName(path.status)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(imageVector = icon, contentDescription = path.iface)
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text("${path.iface} — $statusName")
                Text(
                    "RTT: ${path.srttMs}ms | TX: ${path.bytesTx / 1024}KB | RX: ${path.bytesRx / 1024}KB",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
