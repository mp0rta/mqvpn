// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mqvpn.app.ui.theme.LocalMqColors

// Stub: filled in by a later task.
@Composable
fun PathsScreen(modifier: Modifier = Modifier) {
    val c = LocalMqColors.current
    Column(modifier.fillMaxSize().background(c.win).verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("Paths", color = c.text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
    }
}
