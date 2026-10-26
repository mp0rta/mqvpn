// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

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
import com.mqvpn.app.ui.screens.HybridDetailScreen
import com.mqvpn.app.ui.screens.RedundantDetailScreen
import com.mqvpn.app.ui.screens.ReorderDetailScreen
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
        composable("setup") {
            SetupScreen(vm, settingsVm, onDone = {
                // Never leave a dead Setup in the back stack; singleTop avoids a duplicate "main" when re-run from Settings.
                nav.navigate("main") { popUpTo("setup") { inclusive = true }; launchSingleTop = true }
            })
        }
        composable("main") { MainTabs(vm, settingsVm, nav) }
        composable("reorderDetail") { ReorderDetailScreen(settingsVm, onBack = { nav.popBackStack() }) }
        composable("redundantDetail") { RedundantDetailScreen(settingsVm, onBack = { nav.popBackStack() }) }
        composable("hybridDetail") { HybridDetailScreen(settingsVm, onBack = { nav.popBackStack() }) }
    }
}

@Composable
private fun MainTabs(vm: MqvpnViewModel, settingsVm: SettingsViewModel, nav: NavHostController) {
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
            Tab.HOME -> HomeScreen(vm, settingsVm, { tab = Tab.PATHS }, { tab = Tab.SETTINGS }, m)
            Tab.PATHS -> PathsScreen(vm, settingsVm, m)
            Tab.STATS -> StatsScreen(vm, settingsVm, { tab = Tab.HOME }, m)
            Tab.SETTINGS -> SettingsScreen(vm, settingsVm, { nav.navigate(it) }, m)
        }
    }
}
