// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mqvpn.app.ui.EnumDropdownField
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.app.ui.components.DetailScreen
import com.mqvpn.app.ui.theme.LocalMqColors
import com.mqvpn.sdk.core.model.MqvpnConfig

@Composable
fun HybridDetailScreen(settingsVm: SettingsViewModel, onBack: () -> Unit) {
    val c = LocalMqColors.current
    val s by settingsVm.draft.collectAsStateWithLifecycle()
    val editable by settingsVm.isEditable.collectAsStateWithLifecycle()
    val d = s ?: return
    DetailScreen("TCP boost", onBack) {
        Text(
            "Carries TCP over its own lane so it can use several connections. Needs hybrid support on " +
                "the server; TCP connections fail otherwise.",
            color = c.t2, fontSize = 13.sp, lineHeight = 19.sp,
        )
        EnumDropdownField(
            label = "TCP mode",
            options = MqvpnConfig.HybridTcpMode.entries,
            selected = d.hybridTcpModeEnum(),
            displayName = { it.name.lowercase().replaceFirstChar(Char::uppercase) },
            onSelect = { m -> settingsVm.update { it.copy(hybridTcpMode = m.name) } },
            enabled = editable,
        )
        Text("Auto decides per connection. Stream always uses the lane. Raw never does.", color = c.t2, fontSize = 12.sp, lineHeight = 17.sp)
    }
}
