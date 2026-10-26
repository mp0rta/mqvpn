// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.data.ServerAddressField
import com.mqvpn.app.data.SplitChoice
import com.mqvpn.app.data.applySplitChoice
import com.mqvpn.app.data.splitChoice
import com.mqvpn.app.ui.LogEvent
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.components.Hairline
import com.mqvpn.app.ui.components.LAST_PATH_CAPTION
import com.mqvpn.app.ui.components.SectionLabel
import com.mqvpn.app.ui.components.ToggleRow
import com.mqvpn.app.ui.eventText
import com.mqvpn.app.ui.serverSchedulerLine
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.app.ui.theme.MqColors
import com.mqvpn.sdk.core.MqvpnSdk
import com.mqvpn.sdk.core.model.MqvpnState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val PRIVACY_POLICY_URL = "https://docs.mqvpn.org/privacy"

// Copy: mqvpn-desktop/src/screens/Settings.svelte (Private DNS / IPv6 rows dropped: no Android equivalent);
// Advanced rows and Event log per the approved Android mock. Everything is locked while a session is live.
@Composable
fun SettingsScreen(
    vm: MqvpnViewModel,
    settingsVm: SettingsViewModel,
    onNavigate: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = LocalMqColors.current
    val draft by settingsVm.draft.collectAsStateWithLifecycle()
    val errors by settingsVm.fieldErrors.collectAsStateWithLifecycle()
    val saveError by settingsVm.saveError.collectAsStateWithLifecycle()
    val editable by settingsVm.isEditable.collectAsStateWithLifecycle()
    val state by vm.vpnState.collectAsStateWithLifecycle()
    val events by vm.events.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    val s = draft ?: return

    var addr by rememberSaveable {
        mutableStateOf(if (s.serverAddress.isBlank()) "" else ServerAddressField.format(s.serverAddress, s.serverPort))
    }
    var addrFocused by remember { mutableStateOf(false) }
    // Re-seed after the stored server changes elsewhere (setup assistant); never while typing.
    LaunchedEffect(s.serverAddress, s.serverPort) {
        if (!addrFocused && ServerAddressField.parse(addr) != ServerAddressField.Parsed(s.serverAddress, s.serverPort)) {
            addr = if (s.serverAddress.isBlank()) "" else ServerAddressField.format(s.serverAddress, s.serverPort)
        }
    }
    var keyShown by rememberSaveable { mutableStateOf(false) }
    var advOpen by rememberSaveable { mutableStateOf(false) }
    var logOpen by rememberSaveable { mutableStateOf(false) }
    var btBlocked by rememberSaveable { mutableStateOf(false) }
    val parsed = ServerAddressField.parse(addr)
    val info = (state as? MqvpnState.Connected)?.tunnelInfo
    val applied = info?.takeIf { it.requestedScheduler != null }?.let { it.serverScheduler == it.requestedScheduler }

    Column(
        modifier.fillMaxSize().background(c.win).verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Settings", color = c.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        if (!editable) Text("Disconnect to change settings.", color = c.t2, fontSize = 12.5.sp, lineHeight = 19.sp)
        saveError?.let { Text(it, color = c.red, fontSize = 12.sp) }

        Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
            SectionLabel("Server")
            MqCard(padding = PaddingValuesRows) {
                Column {
                    Column(Modifier.padding(vertical = 8.dp)) {
                        OutlinedTextField(
                            value = addr,
                            onValueChange = { t ->
                                addr = t
                                // Single logical field: the address and port come from one text box.
                                ServerAddressField.parse(t)?.let { p ->
                                    settingsVm.update { it.copy(serverAddress = p.address, serverPort = p.port) }
                                }
                            },
                            label = { Text("Address") },
                            isError = parsed == null || errors.containsKey("serverAddress") || errors.containsKey("serverPort"),
                            supportingText = {
                                if (parsed == null) Text("Enter a server address, e.g. vpn.example.com:443")
                                else (errors["serverAddress"] ?: errors["serverPort"])?.let { Text(it) }
                            },
                            singleLine = true,
                            enabled = editable,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            modifier = Modifier.fillMaxWidth().onFocusChanged { addrFocused = it.isFocused },
                        )
                    }
                    Hairline()
                    Column(Modifier.padding(vertical = 8.dp)) {
                        OutlinedTextField(
                            value = s.tlsServerName,
                            onValueChange = { t -> settingsVm.update { it.copy(tlsServerName = t) } },
                            label = { Text("TLS server name") },
                            placeholder = { Text("Same as the address") },
                            supportingText = { Text("The name on the server's certificate, if you connect by IP address") },
                            singleLine = true,
                            enabled = editable,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Hairline()
                    Column(Modifier.padding(vertical = 8.dp)) {
                        OutlinedTextField(
                            value = s.authKey,
                            onValueChange = { t -> settingsVm.update { it.copy(authKey = t) } },
                            label = { Text("Access key") },
                            singleLine = true,
                            enabled = editable,
                            visualTransformation = if (keyShown) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            trailingIcon = { TextButton({ keyShown = !keyShown }) { Text(if (keyShown) "Hide" else "Show", color = c.accent, fontSize = 12.sp) } },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Hairline()
                    ToggleRow("Trust self-signed certificate", "Only for test servers you own", s.insecure, editable, last = true) { v ->
                        settingsVm.update { it.copy(insecure = v) }
                    }
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
            SectionLabel("Protection")
            MqCard(padding = PaddingValuesRows) {
                Column {
                    ToggleRow("Kill switch", "If the VPN drops, block all traffic so nothing leaks", s.killSwitch, editable, last = false) { v ->
                        settingsVm.update { it.copy(killSwitch = v) }
                    }
                    ToggleRow("Reconnect automatically", "Retry every 5 seconds if the server is unreachable", s.autoReconnect, editable, last = true) { v ->
                        settingsVm.update { it.copy(autoReconnect = v) }
                    }
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Disclosure("Advanced", advOpen) { advOpen = !advOpen }
            if (advOpen) MqCard(padding = PaddingValuesRows) {
                Column {
                    Column(Modifier.padding(vertical = 11.dp).selectableGroup(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("How traffic is split", color = c.text, fontSize = 13.sp)
                        val choice = s.splitChoice()
                        for ((opt, label, dim) in SPLIT_OPTIONS) {
                            SplitRadio(opt == choice, editable, label, dim, c) {
                                // Re-clicking the shown option must not rewrite a preserved legacy combo.
                                if (opt != choice) settingsVm.update { it.applySplitChoice(opt) }
                            }
                            if (opt == choice && applied != null) {
                                val note = if (applied) "✓ applied by the server" else info?.let(::serverSchedulerLine) ?: "not applied by the server"
                                Text(note, color = if (applied) c.t2 else c.orange, fontSize = 11.sp, modifier = Modifier.padding(start = 26.dp))
                            }
                            if (opt == SplitChoice.REDUNDANT && opt == choice) {
                                Text(
                                    "Choose UDP ports ›", color = c.accent, fontSize = 12.sp,
                                    modifier = Modifier.padding(start = 26.dp).clickable { onNavigate("redundantDetail") },
                                )
                            }
                        }
                    }
                    Hairline()
                    ToggleRow(
                        "Smooth out packet order",
                        "Re-order packets that arrive mixed-up across connections" +
                            s.reorderPorts.trim().takeIf { it.isNotEmpty() }
                                ?.let { " (UDP port${if (',' in it) "s" else ""} $it)" }.orEmpty(),
                        s.reorderEnabled, editable, last = false, onOpen = { onNavigate("reorderDetail") },
                    ) { v -> settingsVm.update { it.copy(reorderEnabled = v) } }
                    errors["reorderPorts"]?.let { Text(it, color = c.red, fontSize = 11.sp, modifier = Modifier.padding(bottom = 8.dp)) }
                    ToggleRow(
                        "TCP boost",
                        "Carry TCP over its own lane — " + s.hybridTcpModeEnum().name.lowercase().replaceFirstChar(Char::uppercase),
                        s.hybridEnabled, editable, last = false, onOpen = { onNavigate("hybridDetail") },
                    ) { v -> settingsVm.update { it.copy(hybridEnabled = v) } }
                    ToggleRow("Bluetooth connections", "Allow a paired phone's internet as an extra path", s.bluetoothPathEnabled, editable, last = true) { v ->
                        // Same rule as Paths: never leave zero enabled connections.
                        if (v || s.copy(bluetoothPathEnabled = false).pathPolicyValid()) {
                            btBlocked = false
                            settingsVm.update { it.copy(bluetoothPathEnabled = v) }
                        } else btBlocked = true
                    }
                    if (btBlocked) Text(LAST_PATH_CAPTION, color = c.red, fontSize = 11.sp, modifier = Modifier.padding(bottom = 8.dp))
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Disclosure("Event log (${events.size})", logOpen) { logOpen = !logOpen }
            if (logOpen) MqCard(padding = PaddingValuesRows) {
                Column {
                    if (events.isEmpty()) Text("No events.", color = c.t2, fontSize = 12.sp, modifier = Modifier.padding(vertical = 11.dp))
                    events.forEachIndexed { i, e ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(clock(e.time), color = c.t2, fontSize = 11.sp)
                            Box(Modifier.size(7.dp).clip(CircleShape).background(levelDot(e.kind, c)))
                            Text(eventText(e.kind), color = c.text, fontSize = 12.sp, lineHeight = 17.sp, modifier = Modifier.weight(1f))
                        }
                        if (i != events.lastIndex) Hairline()
                    }
                }
            }
        }

        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(c.card)
                .clickable(enabled = editable) { onNavigate("setup") }.padding(12.dp),
            contentAlignment = Alignment.Center,
        ) { Text("Run setup assistant again", color = if (editable) c.accent else c.t2, fontSize = 13.sp, fontWeight = FontWeight.Medium) }

        // Google Play's User Data policy requires a privacy policy link inside the app.
        TextButton({ uriHandler.openUri(PRIVACY_POLICY_URL) }, Modifier.fillMaxWidth()) { Text("Privacy policy", color = c.accent, fontSize = 12.sp) }
        Text(
            "mqvpn ${runCatching { MqvpnSdk.getVersion() }.getOrDefault("—")} · MASQUE over Multipath QUIC",
            color = c.t2, fontSize = 10.5.sp, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
        )
    }
}

private val SPLIT_OPTIONS = listOf(
    Triple(SplitChoice.THROUGHPUT, "Throughput", "(recommended) — by each connection’s capacity"),
    Triple(SplitChoice.LOW_LATENCY, "Low latency", "— always pick the fastest-responding path"),
    Triple(
        SplitChoice.REDUNDANT, "Redundant",
        "— sends UDP uploads on every connection at once, for streams that tolerate duplicates (SRT, RIST, RTP); uses more data",
    ),
)

@Composable
private fun SplitRadio(selected: Boolean, enabled: Boolean, label: String, dim: String, c: MqColors, onClick: () -> Unit) {
    val ring = if (selected) c.accent else c.t2
    Row(
        Modifier.fillMaxWidth().selectable(selected, enabled = enabled, role = Role.RadioButton, onClick = onClick).padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(Modifier.padding(top = 1.dp).size(16.dp).border(1.5.dp, ring, CircleShape), contentAlignment = Alignment.Center) {
            if (selected) Box(Modifier.size(8.dp).clip(CircleShape).background(c.accent))
        }
        Text(
            buildAnnotatedString {
                append("$label ")
                pushStyle(SpanStyle(color = c.t2)); append(dim); pop()
            },
            color = c.text, fontSize = 12.5.sp, lineHeight = 17.sp,
        )
    }
}

@Composable
private fun Disclosure(label: String, open: Boolean, onToggle: () -> Unit) {
    Row(Modifier.clickable(onClick = onToggle).padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        SectionLabel(label)
        Text(if (open) "▼" else "▶", color = LocalMqColors.current.t2, fontSize = 10.sp)
    }
}

private fun clock(ms: Long): String = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(ms))

private fun levelDot(kind: LogEvent.Kind, c: MqColors): Color = when (kind) {
    is LogEvent.Kind.Error -> c.red
    is LogEvent.Kind.Reconnecting, is LogEvent.Kind.PathRemoved -> c.orange
    else -> c.t2
}
