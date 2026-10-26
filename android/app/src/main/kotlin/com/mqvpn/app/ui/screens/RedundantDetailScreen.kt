// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.components.DetailScreen
import com.mqvpn.app.ui.theme.LocalMqColors

@Composable
fun RedundantDetailScreen(settingsVm: SettingsViewModel, onBack: () -> Unit) {
    val c = LocalMqColors.current
    val s by settingsVm.draft.collectAsStateWithLifecycle()
    val errors by settingsVm.fieldErrors.collectAsStateWithLifecycle()
    val editable by settingsVm.isEditable.collectAsStateWithLifecycle()
    val d = s ?: return
    DetailScreen("Redundant", onBack) {
        Text(
            "Sends copies of UDP packets over more than one connection at once, which helps live streams " +
                "keep going when a connection drops. Uses up to twice the data with two connections, " +
                "three times with three.",
            color = c.t2, fontSize = 13.sp, lineHeight = 19.sp,
        )
        OutlinedTextField(
            value = d.redundantPorts,
            onValueChange = { t -> settingsVm.update { it.copy(redundantPorts = t) } },
            label = { Text("UDP ports") },
            supportingText = {
                Text(errors["redundantPorts"] ?: "Leave empty to copy all UDP. Up to ${DemoSettings.MAX_REDUNDANT_PORTS} ports, comma-separated.")
            },
            isError = errors.containsKey("redundantPorts"),
            singleLine = true,
            enabled = editable,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
