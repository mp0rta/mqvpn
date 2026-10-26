// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.ui.screens.HomeScreen
import com.mqvpn.app.ui.screens.PathsScreen
import com.mqvpn.app.ui.screens.SettingsScreen
import com.mqvpn.app.ui.screens.SetupScreen
import com.mqvpn.app.ui.screens.StatsScreen
import com.mqvpn.app.ui.theme.LocalMqColors

enum class Tab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Filled.Home),
    PATHS("Paths", Icons.Filled.Menu),
    STATS("Stats", Icons.Filled.BarChart),
    SETTINGS("Settings", Icons.Filled.Settings),
}

fun startDestination(settings: DemoSettings): String =
    if (settings.serverAddress.isBlank()) "setup" else "main"

@Composable
fun AppShell(vm: MqvpnViewModel, settingsVm: SettingsViewModel, nav: NavHostController) {
    // Wait for the persisted settings so an upgrader is never routed to Setup by defaults.
    val draft by settingsVm.draft.collectAsState()
    val settings = draft ?: return
    // Frozen at first load: saving a server later must not re-route the live NavHost.
    val start = rememberSaveable { startDestination(settings) }
    NavHost(nav, startDestination = start) {
        composable("setup") { SetupScreen() }
        composable("main") { MainTabs() }
        composable("reorderDetail") { DetailStub("Reorder") }
        composable("redundantDetail") { DetailStub("Redundant") }
        composable("hybridDetail") { DetailStub("Hybrid") }
    }
}

@Composable
private fun MainTabs() {
    val c = LocalMqColors.current
    var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
    Scaffold(
        containerColor = c.win,
        bottomBar = {
            NavigationBar(containerColor = c.card) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { androidx.compose.material3.Icon(t.icon, contentDescription = t.label) },
                        label = { Text(t.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = c.accent, selectedTextColor = c.accent,
                            unselectedIconColor = c.t2, unselectedTextColor = c.t2,
                            indicatorColor = c.fill,
                        ),
                    )
                }
            }
        },
    ) { pad ->
        val m = Modifier.padding(pad)
        when (tab) {
            Tab.HOME -> HomeScreen(m)
            Tab.PATHS -> PathsScreen(m)
            Tab.STATS -> StatsScreen(m)
            Tab.SETTINGS -> SettingsScreen(m)
        }
    }
}

@Composable
private fun DetailStub(title: String) {
    val c = LocalMqColors.current
    Box(Modifier.fillMaxSize().background(c.win)) { Text(title, color = c.text) }
}
