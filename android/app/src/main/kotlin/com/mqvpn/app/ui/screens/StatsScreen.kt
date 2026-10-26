// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.ui.BufferWaitCard
import com.mqvpn.app.ui.Direction
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.app.ui.RateChartCard
import com.mqvpn.app.ui.ReorderRateCard
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.fmtElapsed
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.sdk.core.model.MqvpnState
import java.util.Locale

// Copy: mqvpn-desktop/src/screens/Stats.svelte; reorder panel rows per the approved Android mock.
@Composable
fun StatsScreen(
    vm: MqvpnViewModel,
    settingsVm: SettingsViewModel,
    onGoHome: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = LocalMqColors.current
    val state by vm.vpnState.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val history by vm.bandwidthHistory.collectAsStateWithLifecycle()
    val reorder by vm.reorderHistory.collectAsStateWithLifecycle()
    val loss by vm.lossPct.collectAsStateWithLifecycle()
    val elapsed by vm.elapsedSec.collectAsStateWithLifecycle()
    val draft by settingsVm.draft.collectAsStateWithLifecycle()
    // Charts take the wall clock; a new sample (1 Hz) is what triggers recomposition.
    val nowMs = remember(history, reorder) { System.currentTimeMillis() }

    Column(
        modifier.fillMaxSize().background(c.win).verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Statistics", color = c.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        // Reconnecting keeps the session's history (the VM holds it): show the
        // charts through an outage instead of dropping to the empty state.
        if (state is MqvpnState.Connected || state is MqvpnState.Reconnecting) {
            if (state is MqvpnState.Reconnecting) {
                Text("Reconnecting…", color = c.orange, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            }
            RateChartCard("Download", history, Direction.DOWNLOAD, nowMs)
            RateChartCard("Upload", history, Direction.UPLOAD, nowMs)
            MqCard(padding = PaddingValuesRows) {
                Column {
                    // elapsed is null while Reconnecting (it restarts on the new session)
                    KvRow("Session time", elapsed?.let(::fmtElapsed) ?: "—", c, false)
                    KvRow("Data received", fmtBytes(stats.bytesRx), c, false)
                    KvRow("Data sent", fmtBytes(stats.bytesTx), c, false)
                    KvRow("Latency", "${stats.srttMs} ms", c, false)
                    // lossPct is a fraction (0.02 = 2%)
                    KvRow("Packet loss", loss?.let { String.format(Locale.US, "%.1f%%", it * 100) } ?: "—", c, true)
                }
            }
            if (draft?.reorderEnabled == true) {
                ReorderRateCard(reorder, nowMs)
                BufferWaitCard(reorder, nowMs)
                val r = reorder.cumulative
                MqCard(padding = PaddingValuesRows) {
                    Column {
                        KvRow("Packets delivered", "%,d".format(r.delivered), c, false)
                        KvRow("Out-of-order gaps", "%,d".format(r.gapCount), c, false)
                        KvRow("Recovered in buffer", "%,d".format(r.gapFilled), c, false)
                        KvRow("Lost to timeout", "%,d".format(r.gapTimeout), c, true)
                    }
                }
            }
        } else {
            Column(
                Modifier.fillMaxSize().padding(top = 80.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(Icons.Filled.BarChart, null, tint = c.t2, modifier = Modifier.padding(4.dp))
                Text("Connect to see live statistics", color = c.t2, fontSize = 13.sp)
                Text("Go to Home", color = c.accent, fontSize = 13.sp, fontWeight = FontWeight.Medium,
                    modifier = Modifier.clickable(onClick = onGoHome).padding(8.dp))
            }
        }
    }
}

/** desktop fmtMB: whole MB under 1000, else GB with two decimals. */
private fun fmtBytes(bytes: Long): String {
    val mb = bytes / 1_000_000.0
    return if (mb < 1000) String.format(Locale.US, "%.0f MB", mb) else String.format(Locale.US, "%.2f GB", mb / 1000)
}
