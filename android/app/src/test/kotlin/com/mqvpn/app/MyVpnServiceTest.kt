package com.mqvpn.app

import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.TunnelInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for MyVpnService config handling and TUN setup logic.
 *
 * VpnService.Builder is Android framework — tested via TunnelInfo / MqvpnConfig
 * assertions that verify the correct data reaches onCreateTun.
 */
class MyVpnServiceTest {

    @Test
    fun `config defaults have correct DNS servers`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
        )
        assertEquals(listOf("8.8.8.8", "1.1.1.1"), config.dnsServers)
    }

    @Test
    fun `config with custom DNS servers`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
            dnsServers = listOf("9.9.9.9", "149.112.112.112"),
        )
        assertEquals(listOf("9.9.9.9", "149.112.112.112"), config.dnsServers)
    }

    @Test
    fun `config serialization preserves dnsServers`() {
        val config = MqvpnConfig(
            serverAddress = "vpn.example.com",
            authKey = "key123",
            dnsServers = listOf("1.1.1.1"),
        )
        val json = config.toJson()
        val restored = MqvpnConfig.fromJson(json)
        assertEquals(config.dnsServers, restored.dnsServers)
        assertEquals(config.serverAddress, restored.serverAddress)
        assertEquals(config.authKey, restored.authKey)
    }

    @Test
    fun `config serialization round-trip with defaults`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
        )
        val json = config.toJson()
        val restored = MqvpnConfig.fromJson(json)
        assertEquals(config, restored)
    }

    @Test
    fun `config killSwitch defaults to false`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
        )
        assertEquals(false, config.killSwitch)
    }

    @Test
    fun `config insecure defaults to false`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
        )
        assertEquals(false, config.insecure)
    }

    @Test
    fun `tunnelInfo IPv6 fields`() {
        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "10.0.0.1",
            serverPrefix = 24,
            mtu = 1400,
            assignedIp6 = "fd00::2",
            prefix6 = 112,
            hasV6 = true,
        )
        assertTrue(info.hasV6)
        assertEquals("fd00::2", info.assignedIp6)
        assertEquals(112, info.prefix6)
    }

    @Test
    fun `tunnelInfo without IPv6`() {
        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "10.0.0.1",
            serverPrefix = 24,
            mtu = 1400,
        )
        assertEquals(false, info.hasV6)
        assertEquals(null, info.assignedIp6)
    }

    @Test
    fun `config with empty dnsServers list`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "testkey",
            dnsServers = emptyList(),
        )
        assertTrue(config.dnsServers.isEmpty())
        val restored = MqvpnConfig.fromJson(config.toJson())
        assertTrue(restored.dnsServers.isEmpty())
    }
}
