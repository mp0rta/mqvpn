package com.mqvpn.app.ui

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState

@Composable
fun ConnectScreen(
    modifier: Modifier = Modifier,
    viewModel: MqvpnViewModel = hiltViewModel(),
) {
    val state by viewModel.vpnState.collectAsStateWithLifecycle()
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val paths by viewModel.paths.collectAsStateWithLifecycle()

    var serverAddress by rememberSaveable { mutableStateOf("160.251.143.149") }
    var serverPort by rememberSaveable { mutableStateOf("443") }
    var authKey by rememberSaveable { mutableStateOf("tiiUC0/Fx51w5XuxAnpOgdRZb19SLqglwFdhxbbsbnM=") }
    var insecure by rememberSaveable { mutableStateOf(true) }
    var killSwitch by rememberSaveable { mutableStateOf(false) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.connect(buildConfig(serverAddress, serverPort, authKey, insecure, killSwitch))
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Text("mqvpn", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))

        // Server config inputs
        val isDisconnected = state is MqvpnState.Disconnected || state is MqvpnState.Error
        OutlinedTextField(
            value = serverAddress,
            onValueChange = { serverAddress = it },
            label = { Text("Server Address") },
            modifier = Modifier.fillMaxWidth(),
            enabled = isDisconnected,
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = serverPort,
            onValueChange = { serverPort = it },
            label = { Text("Port") },
            modifier = Modifier.fillMaxWidth(),
            enabled = isDisconnected,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = authKey,
            onValueChange = { authKey = it },
            label = { Text("Auth Key") },
            modifier = Modifier.fillMaxWidth(),
            enabled = isDisconnected,
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
        )
        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Insecure (skip TLS verify)", modifier = Modifier.weight(1f))
            Switch(checked = insecure, onCheckedChange = { insecure = it }, enabled = isDisconnected)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Kill Switch", modifier = Modifier.weight(1f))
            Switch(checked = killSwitch, onCheckedChange = { killSwitch = it }, enabled = isDisconnected)
        }
        Spacer(modifier = Modifier.height(16.dp))

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
                            viewModel.connect(
                                buildConfig(serverAddress, serverPort, authKey, insecure, killSwitch)
                            )
                        }
                    }

                    else -> {}
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = state !is MqvpnState.Connecting,
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

                if (paths.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Paths", style = MaterialTheme.typography.titleSmall)
                    BandwidthChart(paths)
                    Spacer(modifier = Modifier.height(4.dp))
                    paths.forEach { path -> PathCard(path) }
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
    }
}

private fun buildConfig(
    address: String,
    port: String,
    key: String,
    insecure: Boolean,
    killSwitch: Boolean,
): MqvpnConfig {
    return MqvpnConfig(
        serverAddress = address.trim(),
        serverPort = port.trim().toIntOrNull() ?: 443,
        authKey = key.trim(),
        insecure = insecure,
        killSwitch = killSwitch,
    )
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_000_000_000 -> "%.1f GB".format(bytes / 1_000_000_000.0)
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000 -> "%.1f KB".format(bytes / 1_000.0)
        else -> "$bytes B"
    }
}
