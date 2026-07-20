// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RemoveCircle
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.ReorderStats
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: MqvpnViewModel,
    onOpenSettings: () -> Unit,
) {
    val state by viewModel.vpnState.collectAsStateWithLifecycle()
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val paths by viewModel.paths.collectAsStateWithLifecycle()
    val reorderStats by viewModel.reorderStats.collectAsStateWithLifecycle()
    val connectPending by viewModel.connectPending.collectAsStateWithLifecycle()
    val connectError by viewModel.connectError.collectAsStateWithLifecycle()
    val events by viewModel.events.collectAsStateWithLifecycle()
    val bandwidthHistory by viewModel.bandwidthHistory.collectAsStateWithLifecycle()

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.connectWithSavedSettings()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("mqvpn") },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            // Connect/Disconnect button
            Button(
                onClick = {
                    when (state) {
                        is MqvpnState.Connected,
                        is MqvpnState.Reconnecting -> viewModel.disconnect()

                        is MqvpnState.Disconnected,
                        is MqvpnState.Error -> {
                            val prepareIntent = viewModel.prepareVpn()
                            if (prepareIntent != null) {
                                vpnPermissionLauncher.launch(prepareIntent)
                            } else {
                                viewModel.connectWithSavedSettings()
                            }
                        }

                        else -> {}
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = state !is MqvpnState.Connecting && !connectPending,
            ) {
                Text(
                    when (state) {
                        is MqvpnState.Connected -> "Disconnect"
                        is MqvpnState.Connecting -> "Connecting..."
                        is MqvpnState.Reconnecting -> "Reconnecting..."
                        else -> "Connect"
                    }
                )
            }
            if (connectError != null) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    connectError.orEmpty(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Status
            when (val s = state) {
                is MqvpnState.Connected -> {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                "Connected",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                            Text("IP: ${s.tunnelInfo.assignedIp}/${s.tunnelInfo.prefix}")
                            if (s.tunnelInfo.hasV6 && s.tunnelInfo.assignedIp6 != null) {
                                Text("IPv6: ${s.tunnelInfo.assignedIp6}/${s.tunnelInfo.prefix6}")
                            }
                            Text("MTU: ${s.tunnelInfo.mtu}")
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("RTT: ${stats.srttMs}ms")
                            Text("TX: ${formatBytes(stats.bytesTx)} | RX: ${formatBytes(stats.bytesRx)}")
                            Text(
                                "Dgram: ${stats.dgramSent} sent, ${stats.dgramRecv} recv, ${stats.dgramLost} lost",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }

                    if (paths.isNotEmpty() || bandwidthHistory.samples.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("Paths", style = MaterialTheme.typography.titleSmall)
                        BandwidthChart(bandwidthHistory)
                        Spacer(modifier = Modifier.height(4.dp))
                        paths.forEach { path -> PathCard(path) }
                    }

                    if (reorderStats.delivered > 0 || reorderStats.gapCount > 0) {
                        Spacer(modifier = Modifier.height(12.dp))
                        ReorderStatsCard(reorderStats)
                    }
                }

                is MqvpnState.Reconnecting -> {
                    Text(
                        "Reconnecting in ${s.info.delaySec}s...",
                        color = MaterialTheme.colorScheme.tertiary,
                    )
                }

                is MqvpnState.Error -> {
                    Text(
                        "Error: ${s.error.message}",
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                else -> {}
            }

            Spacer(modifier = Modifier.height(16.dp))
            Text("Events", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            if (events.isEmpty()) {
                Text("—", style = MaterialTheme.typography.bodySmall)
            } else {
                val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }
                events.forEach { event -> EventRow(event, timeFormat) }
            }
        }
    }
}

@Composable
private fun EventRow(event: LogEvent, timeFormat: SimpleDateFormat) {
    val (icon, tint) = eventIconAndTint(event.kind)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(16.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(timeFormat.format(Date(event.time)), style = MaterialTheme.typography.bodySmall)
        Spacer(modifier = Modifier.width(8.dp))
        Text(eventText(event.kind), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun eventIconAndTint(kind: LogEvent.Kind): Pair<ImageVector, Color> = when (kind) {
    is LogEvent.Kind.CoreState -> Icons.Filled.Bolt to MaterialTheme.colorScheme.primary
    is LogEvent.Kind.PathAdded -> Icons.Filled.AddCircle to Color(0xFF4CAF50)
    is LogEvent.Kind.PathRemoved -> Icons.Filled.RemoveCircle to Color.Gray
    is LogEvent.Kind.PathStatus -> Icons.Filled.Autorenew to pathStatusColor(kind.to)
    is LogEvent.Kind.Error -> Icons.Filled.ErrorOutline to MaterialTheme.colorScheme.error
    is LogEvent.Kind.Reconnecting -> Icons.Filled.Refresh to MaterialTheme.colorScheme.tertiary
}

@Composable
private fun ReorderStatsCard(rs: ReorderStats) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("Reorder Buffer", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            val fillRate = if (rs.gapCount > 0) {
                "%.1f%%".format(rs.gapFilled * 100.0 / rs.gapCount)
            } else "—"
            Text("Delivered: ${rs.delivered} | Gaps: ${rs.gapCount} (filled $fillRate)")
            Text(
                "Timeout: ${rs.gapTimeout} | ACK demote: ${rs.ackDemote}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Buffered latency: p50=${rs.bufferedP50Ms}ms p99=${rs.bufferedP99Ms}ms",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_000_000_000 -> "%.1f GB".format(bytes / 1_000_000_000.0)
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000 -> "%.1f KB".format(bytes / 1_000.0)
        else -> "$bytes B"
    }
}
