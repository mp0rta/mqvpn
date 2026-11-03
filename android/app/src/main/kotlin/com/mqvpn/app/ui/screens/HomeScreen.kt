// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.data.SplitChoice
import com.mqvpn.app.data.splitChoice
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.Tone
import com.mqvpn.app.ui.fmtElapsed
import com.mqvpn.app.ui.fmtMbps
import com.mqvpn.app.ui.pathCardViews
import com.mqvpn.app.ui.serverSchedulerLine
import com.mqvpn.app.ui.statusView
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.app.ui.theme.MqColors
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.network.PathType
import kotlinx.coroutines.launch

// Copy and structure: mqvpn-desktop/src/screens/Home.svelte; info card per the approved Android mock.
@Composable
fun HomeScreen(
    vm: MqvpnViewModel,
    settingsVm: SettingsViewModel,
    onManage: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = LocalMqColors.current
    val state by vm.vpnState.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val paths by vm.paths.collectAsStateWithLifecycle()
    val history by vm.bandwidthHistory.collectAsStateWithLifecycle()
    val available by vm.availableTransports.collectAsStateWithLifecycle()
    val elapsed by vm.elapsedSec.collectAsStateWithLifecycle()
    val pending by vm.connectPending.collectAsStateWithLifecycle()
    val connectError by vm.connectError.collectAsStateWithLifecycle()
    val saveError by settingsVm.saveError.collectAsStateWithLifecycle()
    val draft by settingsVm.draft.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // Flush first so an edit still queued in autosave is what we connect with; a null or
    // invalid draft connects nothing (the button is disabled for both). An unparsable
    // address box also blocks: the draft then holds a server the user already typed over.
    val addrInvalid by settingsVm.addressTextInvalid.collectAsStateWithLifecycle()
    val connectNow = {
        scope.launch {
            settingsVm.flush()
            if (!settingsVm.addressTextInvalid.value) {
                settingsVm.draft.value?.takeIf { it.isValid() }?.let(vm::connect)
            }
        }
        Unit
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) connectNow()
    }

    val startConnectFlow = {
        val prepareIntent = vm.prepareVpn()
        if (prepareIntent != null) vpnPermissionLauncher.launch(prepareIntent) else connectNow()
    }

    // The VPN status notification needs POST_NOTIFICATIONS on 13+; ask when
    // the user starts a connection, and proceed whether or not it is granted
    // (the tunnel must work without it).
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { _ -> startConnectFlow() }

    val isOn = state is MqvpnState.Connected
    val isConnecting = state is MqvpnState.Connecting || pending
    val status = statusView(state, elapsed?.let(::fmtElapsed))
    val last = history.samples.lastOrNull()
    val cards = pathCardViews(paths, available, last).filter { it.available && it.active }
    val usingCount = cards.count { it.rateBps > 1_000_000 }
    val canConnect = draft?.isValid() == true && !addrInvalid

    Column(
        modifier.fillMaxSize().background(c.win).verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = 26.dp, bottom = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val btnColor = if (isOn) c.green else c.accent
        Box(contentAlignment = Alignment.Center) {
            Box(
                Modifier.size(148.dp).shadow(14.dp, CircleShape, ambientColor = btnColor, spotColor = btnColor)
                    .clip(CircleShape).background(btnColor)
                    .alpha(if (!isOn && !canConnect) 0.5f else 1f)
                    .clickable(enabled = !isConnecting && (state is MqvpnState.Connected || state is MqvpnState.Reconnecting || canConnect)) {
                        when (state) {
                            is MqvpnState.Connected, is MqvpnState.Reconnecting -> vm.disconnect()
                            is MqvpnState.Disconnected, is MqvpnState.Error -> {
                                val needsNotificationPermission =
                                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                        ContextCompat.checkSelfPermission(
                                            context, Manifest.permission.POST_NOTIFICATIONS,
                                        ) != PackageManager.PERMISSION_GRANTED
                                if (needsNotificationPermission) {
                                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                } else {
                                    startConnectFlow()
                                }
                            }
                            else -> {}
                        }
                    },
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.PowerSettingsNew, contentDescription = if (isOn) "Disconnect" else "Connect",
                    tint = Color.White, modifier = Modifier.size(52.dp))
            }
            if (isConnecting) CircularProgressIndicator(Modifier.size(164.dp), color = c.accent, strokeWidth = 3.dp)
        }
        Text(status.title, color = c.text, fontSize = 22.sp, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 22.dp))
        Text(
            status.sub, fontSize = 13.sp, textAlign = TextAlign.Center,
            color = when (status.tone) { Tone.OK -> c.green; Tone.WARN -> c.orange; Tone.MUTED -> c.t2 },
            modifier = Modifier.padding(top = 5.dp).alpha(if (status.pulsing) 0.7f else 1f),
        )
        connectError?.let {
            Text(it, color = c.red, fontSize = 12.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 6.dp))
        }
        // Connect still goes ahead (the service runs on the config it is handed), but a
        // failed save means the next launch shows the older settings: say so here too.
        saveError?.let {
            Text(it, color = c.red, fontSize = 12.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 6.dp))
        }

        val connected = state as? MqvpnState.Connected
        if (connected != null) {
            Row(Modifier.fillMaxWidth().padding(top = 22.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                RateTile("↓", c.accent, "Download", last?.dlBps ?: 0L, Modifier.weight(1f))
                RateTile("↑", c.green, "Upload", last?.ulBps ?: 0L, Modifier.weight(1f))
            }
            MqCard(Modifier.padding(top = 10.dp), PaddingValues14) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Using $usingCount of ${cards.size} connections", color = c.text, fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Text("Manage", color = c.accent, fontSize = 12.sp, modifier = Modifier.clickable(onClick = onManage))
                    }
                    cards.forEach { p ->
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(p.name, color = c.text, fontSize = 12.sp, modifier = Modifier.width(62.dp))
                            Box(Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(3.dp)).background(c.fill)) {
                                Box(Modifier.fillMaxWidth(p.barFraction.coerceIn(0f, 1f)).height(6.dp)
                                    .background(if (p.type == PathType.CELLULAR) c.green else c.accent))
                            }
                            Text("${fmtMbps(p.rateBps)} Mbps", color = c.t2, fontSize = 11.sp,
                                textAlign = TextAlign.End, modifier = Modifier.width(66.dp))
                        }
                    }
                }
            }
            val info = connected.tunnelInfo
            val applied = info.requestedScheduler != null && info.serverScheduler == info.requestedScheduler
            MqCard(Modifier.padding(top = 10.dp), PaddingValuesRows) {
                Column {
                    KvRow("VPN address", info.assignedIp, c, last = false)
                    info.assignedIp6?.let { KvRow("IPv6 address", it, c, last = false) }
                    KvRow("How traffic is split", draft?.splitChoice()?.label() ?: "—", c, last = false, tick = applied)
                    KvRow("Ping", "${stats.srttMs} ms", c, last = false)
                    KvRow("MTU", "%,d".format(info.mtu), c, last = true)
                }
            }
            if (!applied) serverSchedulerLine(info)?.takeIf { info.requestedScheduler != null }?.let {
                Text(it, color = c.t2, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }

        if (state is MqvpnState.Disconnected || state is MqvpnState.Error) {
            MqCard(Modifier.padding(top = 22.dp), PaddingValues14) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Top) {
                    Icon(Icons.Filled.GppBad, null, tint = c.t2, modifier = Modifier.size(20.dp).padding(top = 1.dp))
                    Text(buildAnnotatedString {
                        append("Your traffic is ")
                        withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.SemiBold)) { append("not encrypted") }
                        append(" right now. Connect to protect it and combine your connections.")
                    }, color = c.t2, fontSize = 12.5.sp, lineHeight = 18.sp)
                }
            }
        }

        Spacer(Modifier.weight(1f))
        Text(
            buildAnnotatedString {
                append("Server ")
                withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.Medium)) { append(draft?.serverAddress.orEmpty()) }
                append(" ")
                withStyle(SpanStyle(color = c.accent)) { append("Change") }
            },
            color = c.t2, fontSize = 12.sp,
            modifier = Modifier.padding(top = 12.dp).clickable(onClick = onOpenSettings).padding(8.dp),
        )
    }
}

private fun SplitChoice.label() = when (this) {
    SplitChoice.THROUGHPUT -> "Throughput"
    SplitChoice.LOW_LATENCY -> "Low latency"
    SplitChoice.REDUNDANT -> "Redundant"
}

internal val PaddingValues14 = PaddingValues(horizontal = 14.dp, vertical = 12.dp)
internal val PaddingValuesRows = PaddingValues(horizontal = 14.dp, vertical = 4.dp)

@Composable
internal fun MqCard(
    modifier: Modifier = Modifier,
    padding: PaddingValues,
    content: @Composable () -> Unit,
) {
    val c = LocalMqColors.current
    Box(modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(c.card).padding(padding)) { content() }
}

@Composable
private fun RateTile(arrow: String, arrowColor: Color, label: String, bps: Long, modifier: Modifier) {
    val c = LocalMqColors.current
    MqCard(modifier, PaddingValues14) {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(buildAnnotatedString {
                withStyle(SpanStyle(color = arrowColor, fontWeight = FontWeight.Bold)) { append(arrow) }
                append(" $label")
            }, color = c.t2, fontSize = 11.sp)
            Text(buildAnnotatedString {
                append(fmtMbps(bps))
                withStyle(SpanStyle(fontSize = 11.sp, fontWeight = FontWeight.Medium, color = c.t2)) { append(" Mbps") }
            }, color = c.text, fontSize = 19.sp, fontWeight = FontWeight.Bold)
        }
    }
}

/** Label/value row with a hairline below (desktop detailRow). [tick] appends the green applied check. */
@Composable
internal fun KvRow(label: String, value: String, c: MqColors, last: Boolean, tick: Boolean = false) {
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            Text(label, color = c.t2, fontSize = 12.5.sp, modifier = Modifier.weight(1f))
            Text(buildAnnotatedString {
                append(value)
                if (tick) withStyle(SpanStyle(color = c.green)) { append(" ✓") }
            }, color = c.text, fontSize = 12.5.sp, fontWeight = FontWeight.Medium)
        }
        if (!last) Box(Modifier.fillMaxWidth().height(1.dp).background(c.sep))
    }
}
