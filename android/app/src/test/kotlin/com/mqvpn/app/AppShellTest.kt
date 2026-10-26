// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.ui.startDestination
import org.junit.Assert.assertEquals
import org.junit.Test

class AppShellTest {
    @Test
    fun blankServerRoutesToSetup() {
        assertEquals("setup", startDestination(DemoSettings()))
        assertEquals("setup", startDestination(DemoSettings(serverAddress = "   ")))
    }

    @Test
    fun configuredServerRoutesToMain() {
        assertEquals("main", startDestination(DemoSettings(serverAddress = "vpn.example.com:443")))
    }
}
