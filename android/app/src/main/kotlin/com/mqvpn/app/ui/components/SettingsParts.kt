// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mqvpn.app.ui.theme.LocalMqColors

/** Shown where the UI refuses to turn off the last enabled connection (backs DemoSettings.pathPolicyValid). */
const val LAST_PATH_CAPTION = "Keep at least one connection on."

/** Small uppercase section heading (desktop sectionLabel). */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(), color = LocalMqColors.current.t2, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.5.sp, modifier = modifier.padding(horizontal = 4.dp),
    )
}

@Composable
fun Hairline() {
    Box(Modifier.fillMaxWidth().height(1.dp).background(LocalMqColors.current.sep))
}

/**
 * Desktop toggleRow: title + caption and a trailing switch. [onOpen] makes the text part a
 * link to a detail screen (stays tappable while the switch is locked).
 */
@Composable
fun ToggleRow(
    title: String,
    caption: String?,
    on: Boolean,
    enabled: Boolean,
    last: Boolean,
    onOpen: (() -> Unit)? = null,
    onToggle: (Boolean) -> Unit,
) {
    val c = LocalMqColors.current
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 11.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                Modifier.weight(1f).then(if (onOpen != null) Modifier.clickable(onClick = onOpen) else Modifier),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(title, color = c.text, fontSize = 13.sp)
                    if (caption != null) Text(caption, color = c.t2, fontSize = 11.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 2.dp))
                }
                if (onOpen != null) Text("›", color = c.t2, fontSize = 18.sp, modifier = Modifier.padding(start = 8.dp))
            }
            Switch(on, onToggle, enabled = enabled)
        }
        if (!last) Hairline()
    }
}

/** Detail pages are NavHost destinations outside the shell Scaffold, so they apply the insets themselves. */
@Composable
fun DetailScreen(title: String, onBack: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    val c = LocalMqColors.current
    Column(
        Modifier.fillMaxSize().background(c.win).windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onBack) { Text("‹ Settings", color = c.accent, fontSize = 14.sp) }
        }
        Text(title, color = c.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        content()
    }
}
