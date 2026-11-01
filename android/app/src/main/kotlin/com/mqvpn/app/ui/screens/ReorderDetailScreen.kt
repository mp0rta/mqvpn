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
import com.mqvpn.app.ui.EnumDropdownField
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.WarningColor
import com.mqvpn.app.ui.components.DetailScreen
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.sdk.core.model.MqvpnConfig

@Composable
fun ReorderDetailScreen(settingsVm: SettingsViewModel, onBack: () -> Unit) {
    val c = LocalMqColors.current
    val s by settingsVm.draft.collectAsStateWithLifecycle()
    val errors by settingsVm.fieldErrors.collectAsStateWithLifecycle()
    val editable by settingsVm.isEditable.collectAsStateWithLifecycle()
    val d = s ?: return
    DetailScreen("Smooth out packet order", onBack) {
        Text(
            "Re-orders packets that arrive mixed-up across connections, so apps see them in order. " +
                "It only touches UDP traffic on the ports below.",
            color = c.t2, fontSize = 13.sp, lineHeight = 19.sp,
        )
        EnumDropdownField(
            label = "Profile",
            options = MqvpnConfig.ReorderProfile.entries,
            selected = d.reorderProfileEnum(),
            displayName = { it.name.replace("_", " ") },
            onSelect = { p -> settingsVm.update { it.copy(reorderProfile = p.name) } },
            enabled = editable,
        )
        OutlinedTextField(
            value = d.reorderPorts,
            onValueChange = { t -> settingsVm.update { it.copy(reorderPorts = t) } },
            label = { Text("UDP ports") },
            supportingText = { Text(errors["reorderPorts"] ?: "Comma-separated, e.g. 443") },
            isError = errors.containsKey("reorderPorts"),
            singleLine = true,
            enabled = editable,
            modifier = Modifier.fillMaxWidth(),
        )
        if (d.distinctValidPortCount() > DemoSettings.MAX_REORDER_PORTS) {
            Text("Only the first ${DemoSettings.MAX_REORDER_PORTS} ports take effect", color = WarningColor, fontSize = 12.sp)
        }
        val invalid = d.invalidPortTokens()
        if (invalid.isNotEmpty()) {
            Text("Invalid ports ignored: " + invalid.joinToString(", "), color = WarningColor, fontSize = 12.sp)
        }
    }
}
