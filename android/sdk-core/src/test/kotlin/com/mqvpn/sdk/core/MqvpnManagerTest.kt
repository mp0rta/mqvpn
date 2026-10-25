// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.ComponentName
import android.os.Looper
import android.os.ParcelFileDescriptor
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.core.model.VpnStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf

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
    fun connect_rejectsBadHostSynchronously() {
        val config = MqvpnConfig(
            serverAddress = "[2001:db8::1]",
            authKey = "test-key",
        )
        assertThrows(IllegalArgumentException::class.java) {
            manager.connect(config, MqvpnVpnService::class.java)
        }
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
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

    @Test
    fun reorderStats_initialValueIsAllZero() {
        val mgr = MqvpnManager(RuntimeEnvironment.getApplication())
        assertEquals(ReorderStats(), mgr.reorderStats.value)
    }

    @Test
    fun updateReorderStats_emitsToFlow() {
        val mgr = MqvpnManager(RuntimeEnvironment.getApplication())
        val s = ReorderStats(delivered = 10, gapFilled = 3)
        mgr.updateReorderStats(s)
        assertEquals(s, mgr.reorderStats.value)
    }

    // --- attach (re-bind to an already-running service) ---

    private class TestVpnService : MqvpnVpnService() {
        var stopTunnelCalls = 0

        override fun onCreateTun(info: TunnelInfo, config: MqvpnConfig): ParcelFileDescriptor =
            throw UnsupportedOperationException("not used in tests")

        override fun onVpnStateChanged(newState: MqvpnState) {}

        // the real one enqueues on the executor, which only exists after onCreate
        override fun stopTunnel() {
            stopTunnelCalls++
        }
    }

    /** A service instance whose LocalBinder the shadow hands to any bind. */
    private fun bindableService(): TestVpnService {
        val svc = TestVpnService()
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).setComponentNameAndServiceForBindService(
            ComponentName(app, TestVpnService::class.java),
            svc.LocalBinder(),
        )
        return svc
    }

    @Test
    fun attach_toMidSessionService_resyncsStateAndWiresService() {
        val svc = bindableService()
        svc.sessionEstablished = true
        svc.onNativeReconnectScheduled(3) // service's current state: Reconnecting

        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(3)), manager.vpnState.value)
        assertSame(manager, svc.manager)
    }

    @Test
    fun attach_toFreshService_keepsManagerState() {
        val svc = bindableService()
        manager.updateState(MqvpnState.Connecting)

        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        // a service that never emitted a state must not clobber Connecting
        assertEquals(MqvpnState.Connecting, manager.vpnState.value)
        assertSame(manager, svc.manager)
    }

    @Test
    fun disconnect_afterAttach_reachesTheRunningService() {
        val svc = bindableService()
        svc.sessionEstablished = true
        svc.onNativeReconnectScheduled(1)
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        manager.disconnect()

        assertEquals(1, svc.stopTunnelCalls)
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun connect_afterAttach_replacesTheBinding() {
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        val config = MqvpnConfig(serverAddress = "10.0.0.1", authKey = "test-key")
        manager.connect(config, TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        // the attach binding was released, exactly one live binding remains
        val shadow = shadowOf(RuntimeEnvironment.getApplication())
        assertEquals(1, shadow.boundServiceConnections.size)
        assertEquals(1, shadow.unboundServiceConnections.size)
        assertSame(manager, svc.manager)
    }

    @Test
    fun serviceDisconnectCallback_keepsTerminalError_resetsMetrics() {
        bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()
        val error = MqvpnState.Error(MqvpnError.AuthFailed("bad key"))
        manager.updateState(error)
        manager.updateStats(VpnStats(bytesTx = 7))

        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).boundServiceConnections.last()
            .onServiceDisconnected(ComponentName(app, TestVpnService::class.java))

        assertEquals(error, manager.vpnState.value)
        assertEquals(VpnStats(), manager.stats.value)
    }

    @Test
    fun bindingDied_releasesBindingAndAllowsReattach() {
        // no binder registered: the service "died" before publishing one
        val app = RuntimeEnvironment.getApplication()
        val config = MqvpnConfig(serverAddress = "10.0.0.1", authKey = "test-key")
        manager.connect(config, TestVpnService::class.java)
        assertEquals(MqvpnState.Connecting, manager.vpnState.value)

        shadowOf(app).boundServiceConnections.last()
            .onBindingDied(ComponentName(app, TestVpnService::class.java))

        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)

        // the dead binding is gone, so a later attach binds and resyncs
        val svc = bindableService()
        svc.sessionEstablished = true
        svc.onNativeReconnectScheduled(2)
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(2)), manager.vpnState.value)
    }

    @Test
    fun serviceDisconnectCallback_resetsStaleLiveState() {
        bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()
        manager.updateState(MqvpnState.Connecting)

        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).boundServiceConnections.last()
            .onServiceDisconnected(ComponentName(app, TestVpnService::class.java))

        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun attach_isNoOpWhileBindingExists() {
        bindableService()
        manager.attach(TestVpnService::class.java)
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        val app = RuntimeEnvironment.getApplication()
        assertEquals(1, shadowOf(app).boundServiceConnections.size)
    }

    // --- terminal vs. retryable close (Error emission is deferred until the
    //     native client reveals whether a reconnect follows) ---

    @Test
    fun neverEstablishedClose_showsTerminalErrorAndStopsSession() {
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        svc.onNativeTunnelClosed(-10)
        svc.onNativeReconnectScheduled(5)

        // retrying a server that never accepted us stays an Error, and the
        // session is torn down (which cancels the native reconnect timer)
        val state = manager.vpnState.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.ConnectionClosed("Connection to the server failed"),
            (state as MqvpnState.Error).error,
        )
        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun establishedClose_reconnectKeepsSessionAlive() {
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()
        svc.sessionEstablished = true

        svc.onNativeTunnelClosed(-10)
        svc.onNativeReconnectScheduled(5)

        // a session that was Connected reconnects: no Error, no teardown
        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(5)), manager.vpnState.value)
        assertEquals(0, svc.stopTunnelCalls)
    }

    @Test
    fun closedWithoutReconnect_showsCloseError() {
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        svc.onNativeTunnelClosed(-10)
        svc.onNativeStateChanged(2, 6) // CLOSED, no reconnect scheduled

        val state = manager.vpnState.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.ConnectionClosed("Connection to the server failed"),
            (state as MqvpnState.Error).error,
        )
    }

    @Test
    fun requestFailure_withoutFollowUpCallback_showsErrorAndStopsSession() {
        // e.g. the server rejects the CONNECT-IP request (bad key) but keeps
        // the QUIC connection open: no close/reconnect callback ever follows
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        svc.onNativeTunnelClosed(-5)

        val state = manager.vpnState.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.AuthFailed("PSK authentication failed"),
            (state as MqvpnState.Error).error,
        )
        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun terminalError_keepsTheFirstError() {
        val svc = bindableService()
        manager.attach(TestVpnService::class.java)
        shadowOf(Looper.getMainLooper()).idle()

        svc.onNativeTunnelClosed(-4) // terminal on arrival
        svc.onNativeTunnelClosed(-10) // close notify from the teardown
        svc.onNativeStateChanged(2, 6)

        val state = manager.vpnState.value as MqvpnState.Error
        assertEquals(MqvpnError.TlsError("TLS handshake failed"), state.error)
    }

    @Test
    fun resetMetrics_clearsAllFlows() {
        val mgr = MqvpnManager(RuntimeEnvironment.getApplication())
        mgr.updateStats(VpnStats(bytesTx = 1))
        mgr.updatePaths(listOf(PathInfo(handle = 1, status = 1, iface = "wlan0", bytesTx = 500, bytesRx = 1000, srttMs = 30)))
        mgr.updateReorderStats(ReorderStats(delivered = 5))
        mgr.resetMetrics()
        assertEquals(VpnStats(), mgr.stats.value)
        assertEquals(emptyList<PathInfo>(), mgr.paths.value)
        assertEquals(ReorderStats(), mgr.reorderStats.value)
    }
}
