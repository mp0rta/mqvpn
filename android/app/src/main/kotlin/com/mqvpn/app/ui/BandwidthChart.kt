// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.ui.graphics.Color

private val PATH_PALETTE = listOf(
    Color(0xFF26A69A), // teal
    Color(0xFFFF9800), // orange
    Color(0xFFAB47BC), // purple
    Color(0xFF42A5F5), // blue
    Color(0xFFEF5350), // red
    Color(0xFF9CCC65), // light green
)

internal fun slotColor(slot: Int): Color = PATH_PALETTE[slot % PATH_PALETTE.size]
