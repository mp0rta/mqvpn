// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SplitChoice
import com.mqvpn.app.data.applySplitChoice
import com.mqvpn.app.data.splitChoice
import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the view-independent [DemoSettings] model: tolerant enum
 * decode, reorder-port text parsing, conversion to [MqvpnConfig], and the
 * validation predicates.
 */
class DemoSettingsTest {

    // -- defaults -----------------------------------------------------------

    @Test
    fun `insecure defaults to false, matching the MqvpnConfig default`() {
        assertFalse(DemoSettings().insecure)
        assertFalse(
            DemoSettings(serverAddress = "vpn.example.org", authKey = "k")
                .toMqvpnConfig().insecure,
        )
    }

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

    // -- invalidPortTokens ----------------------------------------------------

    @Test
    fun `invalidPortTokens is empty for an all-valid list`() {
        val settings = DemoSettings(reorderPorts = "443,8443,53")
        assertEquals(emptyList<String>(), settings.invalidPortTokens())
    }

    @Test
    fun `invalidPortTokens reports non-numeric and out-of-range tokens`() {
        val settings = DemoSettings(reorderPorts = "443,abc,0,65536,53")
        assertEquals(listOf("abc", "0", "65536"), settings.invalidPortTokens())
    }

    @Test
    fun `invalidPortTokens ignores blank tokens`() {
        val settings = DemoSettings(reorderPorts = "443,,  ,53")
        assertEquals(emptyList<String>(), settings.invalidPortTokens())
    }

    @Test
    fun `invalidPortTokens trims surrounding whitespace before reporting`() {
        val settings = DemoSettings(reorderPorts = " abc ,443")
        assertEquals(listOf("abc"), settings.invalidPortTokens())
    }

    // -- redundant mode ----------------------------------------------------------

    @Test
    fun `toMqvpnConfig maps redundant fields`() {
        val c = DemoSettings(redundantEnabled = true, redundantPorts = " 4200, 9000 ").toMqvpnConfig()
        assertTrue(c.redundantEnabled)
        assertEquals(listOf(4200, 9000), c.redundantPorts)
    }

    @Test
    fun `redundant mode sends with bbr, otherwise the default bbr2`() {
        assertEquals(MqvpnConfig.CongestionControl.BBR, DemoSettings(redundantEnabled = true).toMqvpnConfig().cc)
        assertEquals(MqvpnConfig.CongestionControl.BBR2, DemoSettings(redundantEnabled = false).toMqvpnConfig().cc)
    }

    @Test
    fun `blank redundantPorts is valid and maps to empty`() {
        val s = DemoSettings(serverAddress = "h", redundantEnabled = true, redundantPorts = "")
        assertTrue(s.redundantPortsValid())
        assertTrue(s.isValid())
        assertEquals(emptyList<Int>(), s.toMqvpnConfig().redundantPorts)
    }

    @Test
    fun `invalid redundantPorts are rejected, never degraded to all UDP`() {
        listOf("4200,abc", "4200,", "0", "65536", List(17) { "4200" }.joinToString(","), "4".repeat(300))
            .forEach { v ->
                assertFalse(v, DemoSettings(redundantPorts = v).redundantPortsValid())
                assertFalse(v, DemoSettings(serverAddress = "h", redundantEnabled = true, redundantPorts = v).isValid())
                // connecting with it fails instead of duplicating all UDP
                val enabled = DemoSettings(serverAddress = "h", redundantEnabled = true, redundantPorts = v)
                assertThrows(v, IllegalArgumentException::class.java) { enabled.toMqvpnConfig() }
                // ignored when the switch is off
                assertTrue(v, DemoSettings(serverAddress = "h", redundantEnabled = false, redundantPorts = v).isValid())
            }
    }

    @Test
    fun `sixteen tokens are valid and deduplicated`() {
        val s = DemoSettings(redundantPorts = List(16) { "4200" }.joinToString(","))
        assertTrue(s.redundantPortsValid())
        assertEquals(listOf(4200), s.parsedRedundantPorts())
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

    @Test
    fun `toMqvpnConfig passes bluetoothPathEnabled through`() {
        assertEquals(false, DemoSettings().toMqvpnConfig().bluetoothPathEnabled)
        assertEquals(true, DemoSettings(bluetoothPathEnabled = true).toMqvpnConfig().bluetoothPathEnabled)
    }

    @Test
    fun `path flags default on and reach the config`() {
        val c = DemoSettings().toMqvpnConfig()
        assertTrue(c.wifiPathEnabled && c.cellularPathEnabled && c.ethernetPathEnabled)
        val off = DemoSettings(pathWifi = false, pathCellular = false, pathEthernet = false).toMqvpnConfig()
        assertFalse(off.wifiPathEnabled || off.cellularPathEnabled || off.ethernetPathEnabled)
    }

    @Test
    fun `autoReconnect maps to reconnect`() {
        assertTrue(DemoSettings().toMqvpnConfig().reconnect)
        assertFalse(DemoSettings(autoReconnect = false).toMqvpnConfig().reconnect)
    }

    @Test
    fun `pathPolicyValid needs at least one of the four transports`() {
        val allOff = DemoSettings(
            serverAddress = "h", pathWifi = false, pathCellular = false,
            pathEthernet = false, bluetoothPathEnabled = false,
        )
        assertFalse(allOff.pathPolicyValid())
        assertFalse(allOff.isValid())
        val btOnly = allOff.copy(bluetoothPathEnabled = true)
        assertTrue(btOnly.pathPolicyValid())
        assertTrue(btOnly.isValid())
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

    // -- scheduler ----------------------------------------------------------

    @Test
    fun `scheduler choice maps to config scheduler and request flag`() {
        val c0 = DemoSettings().toMqvpnConfig()
        assertEquals(MqvpnConfig.Scheduler.MIN_RTT, c0.scheduler)
        assertFalse(c0.requestServerScheduler)
        val c1 = DemoSettings(scheduler = "MIN_RTT").toMqvpnConfig()
        assertEquals(MqvpnConfig.Scheduler.MIN_RTT, c1.scheduler)
        assertTrue(c1.requestServerScheduler)
        val c2 = DemoSettings(scheduler = "WLB").toMqvpnConfig()
        assertEquals(MqvpnConfig.Scheduler.WLB, c2.scheduler)
        assertTrue(c2.requestServerScheduler)
        val c3 = DemoSettings(scheduler = "FAILOVER").toMqvpnConfig()
        assertEquals(MqvpnConfig.Scheduler.FAILOVER, c3.scheduler)
        assertTrue(c3.requestServerScheduler)
    }

    @Test
    fun `schedulerChoice falls back to DEFAULT on unknown name`() {
        assertEquals(DemoSettings.SchedulerChoice.DEFAULT, DemoSettings(scheduler = "bogus").schedulerChoice())
    }

    // -- split choice -------------------------------------------------------

    @Test
    fun `splitChoice matrix`() {
        fun c(s: String, r: Boolean) = DemoSettings(scheduler = s, redundantEnabled = r).splitChoice()
        assertEquals(SplitChoice.THROUGHPUT, c("WLB", false))
        assertEquals(SplitChoice.LOW_LATENCY, c("MIN_RTT", false))
        assertEquals(SplitChoice.LOW_LATENCY, c("DEFAULT", false))
        assertEquals(SplitChoice.REDUNDANT, c("WLB", true))
        assertEquals(SplitChoice.REDUNDANT, c("MIN_RTT", true))
        assertEquals(SplitChoice.BACKUP, c("FAILOVER", false))
    }

    @Test
    fun `applySplitChoice writes scheduler and redundant`() {
        val b = DemoSettings(scheduler = "DEFAULT")
        assertEquals(DemoSettings(scheduler = "WLB"), b.applySplitChoice(SplitChoice.THROUGHPUT))
        assertEquals(DemoSettings(scheduler = "MIN_RTT"), b.applySplitChoice(SplitChoice.LOW_LATENCY))
        assertEquals(DemoSettings(scheduler = "MIN_RTT", redundantEnabled = true), b.applySplitChoice(SplitChoice.REDUNDANT))
        assertEquals(DemoSettings(scheduler = "FAILOVER"), b.applySplitChoice(SplitChoice.BACKUP))
    }
}
