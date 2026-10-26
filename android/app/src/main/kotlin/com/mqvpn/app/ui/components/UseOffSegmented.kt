// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mqvpn.app.ui.theme.LocalMqColors

/** Use / Off segmented control (desktop Segmented.svelte), shared by Setup and Paths. */
@Composable
fun UseOffSegmented(use: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    val c = LocalMqColors.current
    Row(
        Modifier.fillMaxWidth().alpha(if (enabled) 1f else 0.5f).selectableGroup()
            .clip(RoundedCornerShape(8.dp)).background(c.fill).padding(2.dp),
    ) {
        for ((label, v) in listOf("Use" to true, "Off" to false)) {
            val sel = use == v
            Box(
                Modifier.weight(1f).clip(RoundedCornerShape(6.dp))
                    .background(if (sel) c.card else Color.Transparent)
                    .selectable(selected = sel, enabled = enabled, role = Role.RadioButton) { onChange(v) }
                    .padding(vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) { Text(label, color = c.text, fontSize = 13.sp, fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal) }
        }
    }
}
