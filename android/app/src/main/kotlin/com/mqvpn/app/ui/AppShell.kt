// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
    val loadError by settingsVm.loadError.collectAsState()
    val settings = draft ?: run {
        loadError?.let { LoadErrorScreen(it, settingsVm::retryLoad) }
        return
    }
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

/** Shown instead of a blank window when the stored settings cannot be read. */
@Composable
private fun LoadErrorScreen(message: String, onRetry: () -> Unit) {
    val c = LocalMqColors.current
    Column(
        // Scrolls so a long message can never push the only way out off a short window.
        Modifier.fillMaxSize().background(c.win).safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Couldn't load your settings", color = c.text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Text(
            message, color = c.t2, fontSize = 13.sp, textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 8.dp, bottom = 20.dp),
        )
        Button(
            onRetry, shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
        ) { Text("Try again", fontSize = 15.sp, fontWeight = FontWeight.SemiBold) }
    }
}
