// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.mqvpn.app.ui.theme.MqvpnTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MqvpnTheme {
                // Activity-scoped: resolved here, outside NavHost. MqvpnViewModel.onCleared
                // destroys the singleton manager, so it must never be scoped to a
                // NavBackStackEntry (it would be torn down on every back-navigation).
                val vm: MqvpnViewModel = hiltViewModel()
                val nav = rememberNavController()
                NavHost(nav, startDestination = "dashboard") {
                    composable("dashboard") {
                        DashboardScreen(vm, onOpenSettings = { nav.navigate("settings") })
                    }
                    composable("settings") {
                        SettingsScreen(onNavigateUp = { nav.navigateUp() })
                    }
                }
            }
        }
    }
}
