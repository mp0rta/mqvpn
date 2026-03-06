package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.core.model.VpnStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class MqvpnManagerTest {

    private lateinit var manager: MqvpnManager

    @Before
    fun setUp() {
        manager = MqvpnManager(RuntimeEnvironment.getApplication())
    }

    @Test
    fun `initial state is Disconnected`() {
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun `initial stats are zeros`() {
        val stats = manager.stats.value
        assertEquals(0L, stats.bytesTx)
        assertEquals(0L, stats.bytesRx)
        assertEquals(0, stats.srttMs)
    }

    @Test
    fun `initial paths are empty`() {
        assertTrue(manager.paths.value.isEmpty())
    }

    @Test
    fun `connect transitions to Connecting state`() {
        val config = MqvpnConfig(
            serverAddress = "10.0.0.1",
            authKey = "test-key",
        )
        manager.connect(config, MqvpnVpnService::class.java)
        assertEquals(MqvpnState.Connecting, manager.vpnState.value)
    }

    @Test
    fun `disconnect transitions to Disconnected state`() {
        manager.updateState(MqvpnState.Connecting)
        assertEquals(MqvpnState.Connecting, manager.vpnState.value)

        manager.disconnect()
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun `updateState changes vpnState flow`() {
        val tunnelInfo = TunnelInfo(
            assignedIp = "10.8.0.2",
            prefix = 24,
            serverIp = "10.8.0.1",
            serverPrefix = 24,
            mtu = 1400,
        )
        manager.updateState(MqvpnState.Connected(tunnelInfo))
        val state = manager.vpnState.value
        assertTrue(state is MqvpnState.Connected)
        assertEquals("10.8.0.2", (state as MqvpnState.Connected).tunnelInfo.assignedIp)
    }

    @Test
    fun `updateState with Error`() {
        val error = MqvpnError.AuthFailed("PSK authentication failed")
        manager.updateState(MqvpnState.Error(error))
        val state = manager.vpnState.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(error, (state as MqvpnState.Error).error)
    }

    @Test
    fun `updateStats changes stats flow`() {
        val newStats = VpnStats(
            bytesTx = 1000,
            bytesRx = 2000,
            dgramSent = 10,
            dgramRecv = 20,
            dgramLost = 1,
            dgramAcked = 9,
            srttMs = 50,
        )
        manager.updateStats(newStats)
        assertEquals(newStats, manager.stats.value)
    }

    @Test
    fun `updatePaths changes paths flow`() {
        val pathList = listOf(
            PathInfo(handle = 1, status = 1, iface = "wlan0", bytesTx = 500, bytesRx = 1000, srttMs = 30),
            PathInfo(handle = 2, status = 1, iface = "rmnet0", bytesTx = 200, bytesRx = 400, srttMs = 80),
        )
        manager.updatePaths(pathList)
        assertEquals(2, manager.paths.value.size)
        assertEquals("wlan0", manager.paths.value[0].iface)
        assertEquals("rmnet0", manager.paths.value[1].iface)
    }

    @Test
    fun `destroy clears service binding`() {
        manager.destroy()
        // Should not throw
        manager.destroy() // idempotent
    }
}
