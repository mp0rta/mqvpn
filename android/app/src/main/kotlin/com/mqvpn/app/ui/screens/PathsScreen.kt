// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.components.LAST_PATH_CAPTION
import com.mqvpn.app.ui.components.UseOffSegmented
import com.mqvpn.app.ui.fmtMbps
import com.mqvpn.app.ui.pathCardViews
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.network.PathType

// Copy and structure: mqvpn-desktop/src/screens/Paths.svelte; four fixed rows per the approved Android mock.
@Composable
fun PathsScreen(vm: MqvpnViewModel, settingsVm: SettingsViewModel, modifier: Modifier = Modifier) {
    val c = LocalMqColors.current
    val state by vm.vpnState.collectAsStateWithLifecycle()
    val paths by vm.paths.collectAsStateWithLifecycle()
    val history by vm.bandwidthHistory.collectAsStateWithLifecycle()
    val available by vm.availableTransports.collectAsStateWithLifecycle()
    val draft by settingsVm.draft.collectAsStateWithLifecycle()
    val editable by settingsVm.isEditable.collectAsStateWithLifecycle()
    val s = draft ?: return
    var blocked by remember { mutableStateOf(false) }
    val cards = pathCardViews(paths, available, history.samples.lastOrNull())

    Column(
        modifier.fillMaxSize().background(c.win).verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Paths", color = c.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Text(
            "Use carries your traffic. If one connection fails, the others take over. Off leaves it out.",
            color = c.t2, fontSize = 12.5.sp, lineHeight = 19.sp,
        )
        for (card in cards) {
            val t = TRANSPORTS.first { it.type == card.type }
            val on = t.get(s)
            val live = state is MqvpnState.Connected
            val (label, dot) = when {
                !card.available -> "Unavailable" to c.sep
                !on -> "Off" to c.t2
                card.active -> "Active" to c.green
                else -> "Ready" to c.t2
            }
            MqCard(Modifier.alpha(if (card.available) 1f else 0.55f), PaddingValues14) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Icon(card.type.icon(), contentDescription = null, tint = if (on && card.available) c.accent else c.t2, modifier = Modifier.size(22.dp))
                        Column(Modifier.weight(1f)) {
                            Text(card.name, color = c.text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                            Text(card.sub, color = c.t2, fontSize = 11.sp)
                        }
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Box(Modifier.size(8.dp).clip(CircleShape).background(dot))
                            Text(label, color = c.t2, fontSize = 12.sp)
                        }
                    }
                    if (live && card.available && on) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Box(Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(3.dp)).background(c.fill)) {
                                Box(Modifier.fillMaxHeight().fillMaxWidth(card.barFraction.coerceIn(0f, 1f)).clip(RoundedCornerShape(3.dp)).background(c.accent))
                            }
                            Text("${fmtMbps(card.rateBps)} Mbps", color = c.t2, fontSize = 11.sp, textAlign = TextAlign.End, modifier = Modifier.width(78.dp))
                        }
                    }
                    if (card.available) UseOffSegmented(on, editable) { want ->
                        // Turning the last connection Off would leave no path (never persistable): refuse.
                        if (want || t.set(s, false).pathPolicyValid()) {
                            blocked = false
                            settingsVm.update { t.set(it, want) }
                        } else blocked = true
                    }
                }
            }
        }
        if (blocked) Text(LAST_PATH_CAPTION, color = c.red, fontSize = 12.sp)
    }
}

private fun PathType.icon() = when (this) {
    PathType.WIFI -> Icons.Filled.Wifi
    PathType.CELLULAR -> Icons.Filled.SignalCellularAlt
    PathType.BLUETOOTH -> Icons.Filled.Bluetooth
    else -> Icons.Filled.Cable
}
