// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

// Design handoff tokens, verbatim from mqvpn-desktop/src/theme.css.
// segsh is the segmented-control shadow colour (offset 0,1 blur 3 is applied by the caller).
@Immutable
data class MqColors(
    val win: Color, val card: Color, val text: Color, val t2: Color, val sep: Color,
    val accent: Color, val green: Color, val red: Color, val orange: Color,
    val fill: Color, val fill2: Color, val segsh: Color,
)

object MqTokens {
    val light = MqColors(
        win = Color(0xFFF5F5F7), card = Color(0xFFFFFFFF), text = Color(0xFF1D1D1F),
        t2 = Color(0xFF86868B), sep = Color(0x14000000), accent = Color(0xFF0071E3),
        green = Color(0xFF34C759), red = Color(0xFFFF3B30), orange = Color(0xFFFF9500),
        fill = Color(0x1A787880), fill2 = Color(0x38787880), segsh = Color(0x29000000),
    )
    val dark = MqColors(
        win = Color(0xFF1E1E20), card = Color(0xFF2B2B2E), text = Color(0xFFF5F5F7),
        t2 = Color(0xFF98989D), sep = Color(0x1AFFFFFF), accent = Color(0xFF0A84FF),
        green = Color(0xFF30D158), red = Color(0xFFFF453A), orange = Color(0xFFFF9F0A),
        fill = Color(0x33787880), fill2 = Color(0x5C787880), segsh = Color(0x80000000),
    )
}

val LocalMqColors = staticCompositionLocalOf { MqTokens.light }

// No dynamic (Material You) color: the design pins the accent, and wallpaper
// palettes bleed into every M3 component default (Switch, text-field outlines).
private val DarkColorScheme = darkColorScheme(
    primary = MqTokens.dark.accent,
    onPrimary = Color.White,
    background = MqTokens.dark.win,
    onBackground = MqTokens.dark.text,
    surface = MqTokens.dark.card,
    onSurface = MqTokens.dark.text,
)
private val LightColorScheme = lightColorScheme(
    primary = MqTokens.light.accent,
    onPrimary = Color.White,
    background = MqTokens.light.win,
    onBackground = MqTokens.light.text,
    surface = MqTokens.light.card,
    onSurface = MqTokens.light.text,
)

@Composable
fun MqvpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    CompositionLocalProvider(LocalMqColors provides if (darkTheme) MqTokens.dark else MqTokens.light) {
        MaterialTheme(
            colorScheme = colorScheme,
            content = content,
        )
    }
}
