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
import androidx.compose.ui.unit.dp
import com.mqvpn.sdk.core.model.PathInfo

private val PATH_STATUS_NAMES = mapOf(
    0 to "Pending",
    1 to "Active",
    2 to "Degraded",
    3 to "Standby",
    4 to "Closed",
)

@Composable
fun PathCard(path: PathInfo) {
    val icon = when {
        path.iface.startsWith("wlan") -> Icons.Default.Wifi
        path.iface.startsWith("rmnet") || path.iface.startsWith("ccmni") ->
            Icons.Default.SignalCellularAlt
        else -> Icons.Default.Cable
    }
    val statusName = PATH_STATUS_NAMES[path.status] ?: "Unknown"

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
