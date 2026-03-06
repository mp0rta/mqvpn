package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MqvpnConfigTest {

    @Test
    fun `default config has expected values`() {
        val config = MqvpnConfig(
            serverAddress = "vpn.example.com",
            authKey = "test-key",
        )
        assertEquals(443, config.serverPort)
        assertFalse(config.insecure)
        assertTrue(config.multipathEnabled)
        assertEquals(MqvpnConfig.Scheduler.MIN_RTT, config.scheduler)
        assertEquals(MqvpnConfig.LogLevel.INFO, config.logLevel)
        assertTrue(config.reconnect)
        assertEquals(5, config.reconnectIntervalSec)
        assertFalse(config.killSwitch)
    }

    @Test
    fun `json round-trip preserves config`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            serverPort = 8443,
            authKey = "secret-key-123",
            insecure = true,
            multipathEnabled = false,
            scheduler = MqvpnConfig.Scheduler.WLB,
            logLevel = MqvpnConfig.LogLevel.DEBUG,
            reconnect = false,
            reconnectIntervalSec = 10,
            killSwitch = true,
        )

        val json = config.toJson()
        val restored = MqvpnConfig.fromJson(json)
        assertEquals(config, restored)
    }

    @Test
    fun `scheduler native values are correct`() {
        assertEquals(0, MqvpnConfig.Scheduler.MIN_RTT.native)
        assertEquals(1, MqvpnConfig.Scheduler.WLB.native)
    }

    @Test
    fun `log level native values are correct`() {
        assertEquals(0, MqvpnConfig.LogLevel.DEBUG.native)
        assertEquals(1, MqvpnConfig.LogLevel.INFO.native)
        assertEquals(2, MqvpnConfig.LogLevel.WARN.native)
        assertEquals(3, MqvpnConfig.LogLevel.ERROR.native)
    }
}
