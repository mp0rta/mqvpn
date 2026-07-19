// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.sdk.core.model.MqvpnConfig

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateUp: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val loaded by viewModel.loaded.collectAsStateWithLifecycle()
    val loadError by viewModel.loadError.collectAsStateWithLifecycle()
    val isEditable by viewModel.isEditable.collectAsStateWithLifecycle()
    val isSaving by viewModel.isSaving.collectAsStateWithLifecycle()
    val saveError by viewModel.saveError.collectAsStateWithLifecycle()
    val saveDone by viewModel.saveDone.collectAsStateWithLifecycle()

    // Decide at event time from the ViewModel's StateFlow, not the composed
    // `isSaving` snapshot: a back press in the frame before recomposition
    // catches up could otherwise pop mid-save.
    BackHandler(enabled = true) {
        if (!viewModel.isSaving.value) onNavigateUp()
    }

    LaunchedEffect(saveDone) {
        if (saveDone) {
            viewModel.consumeSaveDone()
            onNavigateUp()
        }
    }

    var seeded by rememberSaveable { mutableStateOf(false) }
    var serverAddress by rememberSaveable { mutableStateOf("") }
    var serverPortText by rememberSaveable { mutableStateOf("") }
    var tlsServerName by rememberSaveable { mutableStateOf("") }
    var authKey by rememberSaveable { mutableStateOf("") }
    var insecure by rememberSaveable { mutableStateOf(true) }
    var killSwitch by rememberSaveable { mutableStateOf(false) }
    var reorderEnabled by rememberSaveable { mutableStateOf(false) }
    var reorderProfileName by rememberSaveable {
        mutableStateOf(MqvpnConfig.ReorderProfile.CELLULAR_BOND.name)
    }
    var reorderPorts by rememberSaveable { mutableStateOf("") }
    var hybridEnabled by rememberSaveable { mutableStateOf(false) }
    var hybridTcpModeName by rememberSaveable {
        mutableStateOf(MqvpnConfig.HybridTcpMode.AUTO.name)
    }

    // Seed during composition (not LaunchedEffect) to avoid a one-frame flash
    // of empty fields; seeded gate makes it write-once.
    val current = loaded
    if (current != null && !seeded) {
        serverAddress = current.serverAddress
        serverPortText = current.serverPort.toString()
        tlsServerName = current.tlsServerName
        authKey = current.authKey
        insecure = current.insecure
        killSwitch = current.killSwitch
        reorderEnabled = current.reorderEnabled
        reorderProfileName = current.reorderProfile
        reorderPorts = current.reorderPorts
        hybridEnabled = current.hybridEnabled
        hybridTcpModeName = current.hybridTcpMode
        seeded = true
    }

    val draft = DemoSettings(
        serverAddress = serverAddress,
        serverPort = serverPortText.toIntOrNull() ?: -1,
        tlsServerName = tlsServerName,
        authKey = authKey,
        insecure = insecure,
        killSwitch = killSwitch,
        reorderEnabled = reorderEnabled,
        reorderProfile = reorderProfileName,
        reorderPorts = reorderPorts,
        hybridEnabled = hybridEnabled,
        hybridTcpMode = hybridTcpModeName,
    )

    val fieldsEnabled = isEditable && !isSaving

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(
                        onClick = { if (!viewModel.isSaving.value) onNavigateUp() },
                        enabled = !isSaving,
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Cancel")
                    }
                },
                actions = {
                    TextButton(
                        onClick = { viewModel.save(draft) },
                        enabled = fieldsEnabled && draft.isValid() && loaded != null && loadError == null,
                    ) {
                        Text("Save")
                    }
                },
            )
        },
    ) { innerPadding ->
        if (loaded == null && loadError == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        if (loadError != null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .padding(16.dp),
            ) {
                Text(loadError.orEmpty(), color = MaterialTheme.colorScheme.error)
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            if (!isEditable) {
                Text(
                    "Disconnect to edit settings.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            Text("Server", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = serverAddress,
                onValueChange = { serverAddress = it },
                label = { Text("Server Address") },
                modifier = Modifier.fillMaxWidth(),
                enabled = fieldsEnabled,
                singleLine = true,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = serverPortText,
                onValueChange = { serverPortText = it },
                label = { Text("Port") },
                modifier = Modifier.fillMaxWidth(),
                enabled = fieldsEnabled,
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = tlsServerName,
                onValueChange = { tlsServerName = it },
                label = { Text("TLS Server Name") },
                supportingText = { Text("Empty = use server address") },
                modifier = Modifier.fillMaxWidth(),
                enabled = fieldsEnabled,
                singleLine = true,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = authKey,
                onValueChange = { authKey = it },
                label = { Text("Auth Key") },
                modifier = Modifier.fillMaxWidth(),
                enabled = fieldsEnabled,
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
            )
            Spacer(modifier = Modifier.height(8.dp))
            LabeledSwitchRow(
                label = "Insecure (skip TLS verify)",
                checked = insecure,
                onCheckedChange = { insecure = it },
                enabled = fieldsEnabled,
            )
            if (!draft.hostValid() || !draft.portValid()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Host required; port must be 1–65535.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            Text("Kill Switch", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            LabeledSwitchRow(
                label = "Kill Switch",
                checked = killSwitch,
                onCheckedChange = { killSwitch = it },
                enabled = fieldsEnabled,
            )
            Spacer(modifier = Modifier.height(16.dp))

            Text("Reorder Buffer", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            LabeledSwitchRow(
                label = "Reorder Buffer",
                checked = reorderEnabled,
                onCheckedChange = { reorderEnabled = it },
                enabled = fieldsEnabled,
            )
            if (reorderEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                EnumDropdownField(
                    label = "Reorder Profile",
                    options = MqvpnConfig.ReorderProfile.entries,
                    selected = draft.reorderProfileEnum(),
                    displayName = { it.name.replace("_", " ") },
                    onSelect = { reorderProfileName = it.name },
                    enabled = fieldsEnabled,
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = reorderPorts,
                    onValueChange = { reorderPorts = it },
                    label = { Text("Ports") },
                    supportingText = { Text("At least one port required") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = fieldsEnabled,
                    singleLine = true,
                )
                if (!draft.reorderPortsValid()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "At least one port required",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (draft.distinctValidPortCount() > DemoSettings.MAX_REORDER_PORTS) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Only the first ${DemoSettings.MAX_REORDER_PORTS} ports take effect",
                        style = MaterialTheme.typography.bodySmall,
                        color = WarningColor,
                    )
                }
                val invalidTokens = draft.invalidPortTokens()
                if (invalidTokens.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Invalid ports ignored: " + invalidTokens.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        color = WarningColor,
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

            Text("Hybrid Mode", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            LabeledSwitchRow(
                label = "Hybrid Mode",
                checked = hybridEnabled,
                onCheckedChange = { hybridEnabled = it },
                enabled = fieldsEnabled,
            )
            if (hybridEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                EnumDropdownField(
                    label = "TCP Mode",
                    options = MqvpnConfig.HybridTcpMode.entries,
                    selected = draft.hybridTcpModeEnum(),
                    displayName = { it.name },
                    onSelect = { hybridTcpModeName = it.name },
                    enabled = fieldsEnabled,
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Requires hybrid support on the server; TCP connections fail otherwise.",
                style = MaterialTheme.typography.bodySmall,
            )

            if (saveError != null) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(saveError.orEmpty(), color = MaterialTheme.colorScheme.error)
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
