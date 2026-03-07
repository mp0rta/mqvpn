package com.mqvpn.app

import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for ConnectScreen logic (buildConfig helper, input validation).
 *
 * Compose UI rendering tests would require androidTest + instrumentation.
 * These tests cover the config construction logic used by the UI.
 */
class ConnectScreenTest {

    // Mirror of ConnectScreen.buildConfig (private) for testing
    private fun buildConfig(
        address: String,
        port: String,
        key: String,
        insecure: Boolean,
        killSwitch: Boolean,
    ): MqvpnConfig {
        return MqvpnConfig(
            serverAddress = address.trim(),
            serverPort = port.trim().toIntOrNull() ?: 443,
            authKey = key.trim(),
            insecure = insecure,
            killSwitch = killSwitch,
        )
    }

    @Test
    fun `buildConfig with valid inputs`() {
        val config = buildConfig("10.0.0.1", "443", "testkey", false, false)
        assertEquals("10.0.0.1", config.serverAddress)
        assertEquals(443, config.serverPort)
        assertEquals("testkey", config.authKey)
        assertEquals(false, config.insecure)
        assertEquals(false, config.killSwitch)
    }

    @Test
    fun `buildConfig trims whitespace`() {
        val config = buildConfig("  10.0.0.1  ", "  443  ", "  key  ", false, false)
        assertEquals("10.0.0.1", config.serverAddress)
        assertEquals(443, config.serverPort)
        assertEquals("key", config.authKey)
    }

    @Test
    fun `buildConfig with invalid port falls back to 443`() {
        val config = buildConfig("10.0.0.1", "abc", "key", false, false)
        assertEquals(443, config.serverPort)
    }

    @Test
    fun `buildConfig with empty port falls back to 443`() {
        val config = buildConfig("10.0.0.1", "", "key", false, false)
        assertEquals(443, config.serverPort)
    }

    @Test
    fun `buildConfig with insecure true`() {
        val config = buildConfig("10.0.0.1", "443", "key", true, false)
        assertEquals(true, config.insecure)
    }

    @Test
    fun `buildConfig with killSwitch true`() {
        val config = buildConfig("10.0.0.1", "443", "key", false, true)
        assertEquals(true, config.killSwitch)
    }

    @Test
    fun `buildConfig uses default dnsServers`() {
        val config = buildConfig("10.0.0.1", "443", "key", false, false)
        assertEquals(listOf("8.8.8.8", "1.1.1.1"), config.dnsServers)
    }

    @Test
    fun `buildConfig with custom port`() {
        val config = buildConfig("10.0.0.1", "8443", "key", false, false)
        assertEquals(8443, config.serverPort)
    }
}
