// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.os.Parcel
import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MqvpnConfigTest {

    @Test
    fun `default config has expected values`() {
        val config = MqvpnConfig(
            serverAddress = "vpn.example.com",
            authKey = "test-key",
        )
        assertEquals(443, config.serverPort)
        assertEquals(null, config.tlsServerName)
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
            tlsServerName = "vpn.example.com",
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
        assertEquals(2, MqvpnConfig.Scheduler.BACKUP_FEC.native)
        assertEquals(3, MqvpnConfig.Scheduler.WLB_UDP_PIN.native)
    }

    @Test
    fun `log level native values are correct`() {
        assertEquals(0, MqvpnConfig.LogLevel.DEBUG.native)
        assertEquals(1, MqvpnConfig.LogLevel.INFO.native)
        assertEquals(2, MqvpnConfig.LogLevel.WARN.native)
        assertEquals(3, MqvpnConfig.LogLevel.ERROR.native)
    }

    @Test
    fun reorderFields_defaultsAreOff() {
        val c = MqvpnConfig(serverAddress = "h", authKey = "k")
        assertFalse(c.reorderEnabled)
        assertEquals(MqvpnConfig.ReorderProfile.CELLULAR_BOND, c.reorderProfile)
        assertTrue(c.reorderPorts.isEmpty())
    }

    @Test
    fun reorderFields_jsonRoundTrip() {
        val c = MqvpnConfig(serverAddress = "h", authKey = "k",
            reorderEnabled = true, reorderProfile = MqvpnConfig.ReorderProfile.FIBER_LTE,
            reorderPorts = listOf(443, 853))
        val back = MqvpnConfig.fromJson(c.toJson())
        assertEquals(c, back)
        assertEquals(4, back.reorderProfile.native)
    }

    @Test
    fun oldJsonWithoutReorderFields_decodesWithDefaults() {
        val oldJson = """{"serverAddress":"h","authKey":"k"}"""
        val c = MqvpnConfig.fromJson(oldJson)
        assertFalse(c.reorderEnabled)
        assertTrue(c.reorderPorts.isEmpty())
    }

    @Test
    fun reorderFields_parcelRoundTrip() {
        val c = MqvpnConfig(serverAddress = "h", authKey = "k",
            reorderEnabled = true, reorderProfile = MqvpnConfig.ReorderProfile.FIBER_LTE,
            reorderPorts = listOf(443, 853))
        val p = Parcel.obtain()
        p.writeParcelable(c, 0)
        p.setDataPosition(0)
        @Suppress("DEPRECATION")
        val back = p.readParcelable<MqvpnConfig>(MqvpnConfig::class.java.classLoader)
        p.recycle()
        assertEquals(c, back)
    }
}
