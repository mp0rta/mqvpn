// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the view-independent [DemoSettings] model: tolerant enum
 * decode, reorder-port text parsing, conversion to [MqvpnConfig], and the
 * validation predicates.
 */
class DemoSettingsTest {

    // -- enum round-trip ----------------------------------------------------

    @Test
    fun `reorderProfileEnum round-trips known name`() {
        val settings = DemoSettings(reorderProfile = MqvpnConfig.ReorderProfile.FIBER_LTE.name)
        assertEquals(MqvpnConfig.ReorderProfile.FIBER_LTE, settings.reorderProfileEnum())
    }

    @Test
    fun `reorderProfileEnum falls back to CELLULAR_BOND on unknown name`() {
        val settings = DemoSettings(reorderProfile = "NOT_A_REAL_PROFILE")
        assertEquals(MqvpnConfig.ReorderProfile.CELLULAR_BOND, settings.reorderProfileEnum())
    }

    @Test
    fun `hybridTcpModeEnum round-trips known name`() {
        val settings = DemoSettings(hybridTcpMode = MqvpnConfig.HybridTcpMode.RAW.name)
        assertEquals(MqvpnConfig.HybridTcpMode.RAW, settings.hybridTcpModeEnum())
    }

    @Test
    fun `hybridTcpModeEnum falls back to AUTO on unknown name`() {
        val settings = DemoSettings(hybridTcpMode = "NOT_A_REAL_MODE")
        assertEquals(MqvpnConfig.HybridTcpMode.AUTO, settings.hybridTcpModeEnum())
    }

    // -- reorder port text parsing -------------------------------------------

    @Test
    fun `parsedReorderPorts parses a valid comma list`() {
        val settings = DemoSettings(reorderPorts = "443,8443,53")
        assertEquals(listOf(443, 8443, 53), settings.parsedReorderPorts())
    }

    @Test
    fun `parsedReorderPorts drops invalid tokens`() {
        val settings = DemoSettings(reorderPorts = "443,abc,53")
        assertEquals(listOf(443, 53), settings.parsedReorderPorts())
    }

    @Test
    fun `parsedReorderPorts on empty string yields empty list`() {
        val settings = DemoSettings(reorderPorts = "")
        assertEquals(emptyList<Int>(), settings.parsedReorderPorts())
    }

    @Test
    fun `parsedReorderPorts drops out-of-range values`() {
        val settings = DemoSettings(reorderPorts = "0,443,65536,65535,-1")
        assertEquals(listOf(443, 65535), settings.parsedReorderPorts())
    }

    @Test
    fun `parsedReorderPorts tolerates surrounding whitespace`() {
        val settings = DemoSettings(reorderPorts = " 443 , 8443 ")
        assertEquals(listOf(443, 8443), settings.parsedReorderPorts())
    }

    // -- toMqvpnConfig field mapping ------------------------------------------

    @Test
    fun `toMqvpnConfig trims address and auth key`() {
        val settings = DemoSettings(
            serverAddress = "  1.2.3.4  ",
            authKey = "  secret-key  ",
        )
        val config = settings.toMqvpnConfig()
        assertEquals("1.2.3.4", config.serverAddress)
        assertEquals("secret-key", config.authKey)
    }

    @Test
    fun `toMqvpnConfig maps blank tlsServerName to null`() {
        val settings = DemoSettings(tlsServerName = "   ")
        assertNull(settings.toMqvpnConfig().tlsServerName)
    }

    @Test
    fun `toMqvpnConfig passes through non-blank tlsServerName trimmed`() {
        val settings = DemoSettings(tlsServerName = "  example.com  ")
        assertEquals("example.com", settings.toMqvpnConfig().tlsServerName)
    }

    @Test
    fun `toMqvpnConfig leaves dnsServers at the MqvpnConfig default`() {
        val settings = DemoSettings()
        assertEquals(MqvpnConfig(serverAddress = "x", authKey = "y").dnsServers, settings.toMqvpnConfig().dnsServers)
    }

    @Test
    fun `toMqvpnConfig maps serverPort directly`() {
        val settings = DemoSettings(serverPort = 8443)
        assertEquals(8443, settings.toMqvpnConfig().serverPort)
    }

    // -- validation predicates ------------------------------------------------

    @Test
    fun `hostValid is false for blank host`() {
        assertFalse(DemoSettings(serverAddress = "   ").hostValid())
    }

    @Test
    fun `hostValid is true for non-blank host`() {
        assertTrue(DemoSettings(serverAddress = "1.2.3.4").hostValid())
    }

    @Test
    fun `portValid rejects 0 and 65536`() {
        assertFalse(DemoSettings(serverPort = 0).portValid())
        assertFalse(DemoSettings(serverPort = 65536).portValid())
    }

    @Test
    fun `portValid accepts 1 and 65535`() {
        assertTrue(DemoSettings(serverPort = 1).portValid())
        assertTrue(DemoSettings(serverPort = 65535).portValid())
    }

    @Test
    fun `reorderPortsValid is false when reorder enabled with no valid ports`() {
        val settings = DemoSettings(reorderEnabled = true, reorderPorts = "abc,99999")
        assertFalse(settings.reorderPortsValid())
    }

    @Test
    fun `reorderPortsValid is true when reorder disabled even with empty ports`() {
        val settings = DemoSettings(reorderEnabled = false, reorderPorts = "")
        assertTrue(settings.reorderPortsValid())
    }

    @Test
    fun `isValid combines all three predicates`() {
        val valid = DemoSettings(serverAddress = "1.2.3.4", serverPort = 443, reorderEnabled = false)
        assertTrue(valid.isValid())

        val invalidHost = valid.copy(serverAddress = "   ")
        assertFalse(invalidHost.isValid())

        val invalidPort = valid.copy(serverPort = 0)
        assertFalse(invalidPort.isValid())

        val invalidReorder = valid.copy(reorderEnabled = true, reorderPorts = "abc")
        assertFalse(invalidReorder.isValid())
    }

    // -- distinctValidPortCount -----------------------------------------------

    @Test
    fun `distinctValidPortCount counts 17 distinct valid ports`() {
        val ports = (1..17).joinToString(",")
        assertEquals(17, DemoSettings(reorderPorts = ports).distinctValidPortCount())
    }

    @Test
    fun `distinctValidPortCount collapses duplicates below the token count`() {
        // 17 tokens, but port 1 repeats twice, so only 16 distinct values.
        val tokens = (1..16).toList() + listOf(1)
        assertEquals(17, tokens.size)
        val ports = tokens.joinToString(",")
        assertEquals(16, DemoSettings(reorderPorts = ports).distinctValidPortCount())
    }
}
