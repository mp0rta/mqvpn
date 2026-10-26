// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.ServerAddressField
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.sdk.network.PathType

// Copy: mqvpn-desktop/src/screens/Setup.svelte; headline and VPN-permission note per the approved Android mock.
@Composable
fun SetupScreen(vm: MqvpnViewModel, settingsVm: SettingsViewModel, onDone: () -> Unit, modifier: Modifier = Modifier) {
    val c = LocalMqColors.current
    var step by rememberSaveable { mutableStateOf(0) }
    val draft by settingsVm.draft.collectAsStateWithLifecycle()
    val errors by settingsVm.fieldErrors.collectAsStateWithLifecycle()
    val available by vm.availableTransports.collectAsStateWithLifecycle()
    val s = draft ?: return

    var addr by rememberSaveable {
        mutableStateOf(if (s.serverAddress.isBlank()) "" else ServerAddressField.format(s.serverAddress, s.serverPort))
    }
    var keyShown by rememberSaveable { mutableStateOf(false) }
    val parsed = ServerAddressField.parse(addr)

    Column(
        modifier.fillMaxSize().background(c.win).windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 20.dp),
    ) {
        Text("Step ${step + 1} of 3", color = c.t2, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            when (step) {
                0 -> {
                    Column(Modifier.fillMaxWidth().padding(top = 28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(18.dp)) {
                        MqvpnMark(Modifier.size(96.dp))
                        Text(
                            "All your connections.\nOne stronger connection.", color = c.text, fontSize = 22.sp,
                            fontWeight = FontWeight.Bold, textAlign = TextAlign.Center,
                        )
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Bullet("Uses Wi‑Fi and Cellular at the same time for more speed")
                        Bullet("If one connection drops, the others take over instantly — calls and downloads keep going")
                        Bullet("All traffic is encrypted, end to end")
                    }
                }
                1 -> {
                    Heading("Connect to your server")
                    Text(
                        "Your server admin gives you these two values. On your own server, run mqvpn --genkey to create a key.",
                        color = c.t2, fontSize = 13.sp, lineHeight = 19.sp,
                    )
                    OutlinedTextField(
                        value = addr,
                        onValueChange = { t ->
                            addr = t
                            // Single logical field: the address and port come from one text box.
                            ServerAddressField.parse(t)?.let { p ->
                                settingsVm.update { it.copy(serverAddress = p.address, serverPort = p.port) }
                            }
                        },
                        label = { Text("Server address") },
                        isError = addr.isNotEmpty() && parsed == null,
                        supportingText = { if (addr.isNotEmpty() && parsed == null) Text("Enter a server address, e.g. vpn.example.com:443") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = s.authKey,
                        onValueChange = { t -> settingsVm.update { it.copy(authKey = t) } },
                        label = { Text("Access key") },
                        singleLine = true,
                        visualTransformation = if (keyShown) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = { TextButton({ keyShown = !keyShown }) { Text(if (keyShown) "Hide" else "Show", color = c.accent, fontSize = 12.sp) } },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    MqCard(padding = PaddingValues14) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Column(Modifier.weight(1f)) {
                                Text("Trust self-signed certificate", color = c.text, fontSize = 13.sp)
                                Text(
                                    "Only for test servers you own. Turn off once your server has a real certificate.",
                                    color = c.t2, fontSize = 11.sp, lineHeight = 15.sp,
                                )
                            }
                            Switch(s.insecure, { v -> settingsVm.update { it.copy(insecure = v) } })
                        }
                    }
                    Text("Android will ask for VPN permission the first time you connect.", color = c.t2, fontSize = 12.sp, lineHeight = 17.sp)
                }
                else -> {
                    Heading("Your connections")
                    Text(
                        "We found these on your device. Use carries traffic; Off leaves a connection out. Change this anytime in Paths.",
                        color = c.t2, fontSize = 13.sp, lineHeight = 19.sp,
                    )
                    for (t in TRANSPORTS) {
                        val found = t.type in available
                        val on = t.get(s)
                        MqCard(Modifier.alpha(if (found) 1f else 0.5f), PaddingValues14) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Column {
                                    Text(t.name, color = c.text, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                    Text(if (found) t.sub else "Not available", color = c.t2, fontSize = 11.sp)
                                }
                                if (found) UseOff(on) { want ->
                                    // Turning the last connection Off would leave no path (never persistable): refuse.
                                    if (want || t.set(s, false).pathPolicyValid()) settingsVm.update { t.set(it, want) }
                                }
                            }
                        }
                    }
                    errors["paths"]?.let { Text(it, color = c.red, fontSize = 12.sp) }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            if (step == 0) {
                PrimaryButton("Get Started", true) { step = 1 }
                TextButton(onDone, Modifier.fillMaxWidth()) { Text("Skip setup", color = c.t2, fontSize = 13.sp) }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        { step -= 1 },
                        colors = ButtonDefaults.buttonColors(containerColor = c.fill, contentColor = c.text),
                        shape = RoundedCornerShape(10.dp),
                    ) { Text("Back") }
                    if (step == 1) PrimaryButton("Continue", parsed != null, Modifier.weight(1f)) { step = 2 }
                    else PrimaryButton("Finish Setup", s.pathPolicyValid(), Modifier.weight(1f), onDone)
                }
            }
        }
    }
}

private class Transport(
    val type: PathType, val name: String, val sub: String,
    val get: (DemoSettings) -> Boolean, val set: (DemoSettings, Boolean) -> DemoSettings,
)

private val TRANSPORTS = listOf(
    Transport(PathType.WIFI, "Wi‑Fi", "Wireless network", { it.pathWifi }, { d, v -> d.copy(pathWifi = v) }),
    Transport(PathType.CELLULAR, "Cellular", "May use mobile data", { it.pathCellular }, { d, v -> d.copy(pathCellular = v) }),
    Transport(PathType.ETHERNET, "Ethernet", "Wired or USB network", { it.pathEthernet }, { d, v -> d.copy(pathEthernet = v) }),
    Transport(PathType.BLUETOOTH, "Bluetooth", "A paired phone's internet", { it.bluetoothPathEnabled }, { d, v -> d.copy(bluetoothPathEnabled = v) }),
)

@Composable
private fun Heading(text: String) =
    Text(text, color = LocalMqColors.current.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)

@Composable
private fun Bullet(text: String) {
    val c = LocalMqColors.current
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("✓", color = c.green, fontWeight = FontWeight.Bold)
        Text(text, color = c.text, fontSize = 13.sp, lineHeight = 19.sp)
    }
}

@Composable
private fun PrimaryButton(label: String, enabled: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val c = LocalMqColors.current
    Button(
        onClick, modifier.fillMaxWidth(), enabled = enabled, shape = RoundedCornerShape(10.dp),
        colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
    ) { Text(label, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(vertical = 4.dp)) }
}

@Composable
private fun UseOff(use: Boolean, onChange: (Boolean) -> Unit) {
    val c = LocalMqColors.current
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(c.fill).padding(2.dp)) {
        for ((label, v) in listOf("Use" to true, "Off" to false)) {
            val sel = use == v
            Box(
                Modifier.weight(1f).clip(RoundedCornerShape(6.dp))
                    .background(if (sel) c.card else Color.Transparent)
                    .clickable { onChange(v) }.padding(vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) { Text(label, color = c.text, fontSize = 13.sp, fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal) }
        }
    }
}

/** The mqvpn mark without its tile (geometry from ic_launcher_foreground.xml, 64x64 source). */
@Composable
private fun MqvpnMark(modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val k = size.width / 64f
        fun pill(x: Float, y: Float, brush: Brush? = null, color: Color = Color.Unspecified) {
            val tl = Offset(x * k, y * k); val sz = Size(34f * k, 14f * k); val r = CornerRadius(7f * k)
            if (brush != null) drawRoundRect(brush, tl, sz, r) else drawRoundRect(color, tl, sz, r)
        }
        pill(8f, 14f, color = Color(0xFFB8A3F6))
        pill(
            22f, 36f,
            Brush.linearGradient(listOf(Color(0xFF8B5CF6), Color(0xFF5B21B6)), Offset(22f * k, 36f * k), Offset(56f * k, 50f * k)),
        )
        drawCircle(Color(0xFFFBFAFF), 4f * k, Offset(32f * k, 32f * k))
    }
}
