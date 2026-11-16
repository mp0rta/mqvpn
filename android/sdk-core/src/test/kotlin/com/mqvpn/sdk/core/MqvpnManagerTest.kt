// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

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
import org.junit.Assert.assertNull
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
        // the store is process-wide: start every test from a fresh process
        SessionStore.state.value = MqvpnState.Disconnected
        SessionStore.resetMetrics()
        SessionStore.service = null
        manager = MqvpnManager(RuntimeEnvironment.getApplication())
    }

    @Test
    fun `initial state is Disconnected with empty metrics`() {
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
        assertEquals(VpnStats(), manager.stats.value)
        assertTrue(manager.paths.value.isEmpty())
        assertEquals(ReorderStats(), manager.reorderStats.value)
    }

    @Test
    fun connect_startsTheServiceWithTheConfig_withoutWritingState() {
        val config = MqvpnConfig(serverAddress = "10.0.0.1", authKey = "test-key")
        manager.connect(config, TestVpnService::class.java)

        val intent = shadowOf(RuntimeEnvironment.getApplication()).nextStartedService
        assertEquals(TestVpnService::class.java.name, intent.component?.className)
        assertEquals(config, MqvpnConfig.fromJson(intent.getStringExtra(MqvpnManager.EXTRA_CONFIG_JSON)!!))
        // the service is the only writer: Connecting comes from its startTunnel
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun connect_rejectsBadHostSynchronously() {
        val config = MqvpnConfig(serverAddress = "[2001:db8::1]", authKey = "test-key")
        assertThrows(IllegalArgumentException::class.java) {
            manager.connect(config, TestVpnService::class.java)
        }
        assertNull(shadowOf(RuntimeEnvironment.getApplication()).nextStartedService)
    }

    @Test
    fun disconnect_reachesTheRunningService() {
        val svc = TestVpnService()
        SessionStore.service = svc

        manager.disconnect()

        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun disconnect_withoutAServiceIsANoOp() {
        manager.disconnect()
        assertEquals(MqvpnState.Disconnected, manager.vpnState.value)
    }

    @Test
    fun aManagerCreatedMidSession_seesTheLiveSession() {
        // a recreated ViewModel (activity destroyed while the VPN kept
        // running) must see the session at once, with no re-attach
        val path = PathInfo(handle = 1, status = 1, iface = "wlan0", bytesTx = 5, bytesRx = 9, srttMs = 30)
        SessionStore.state.value = MqvpnState.Reconnecting(ReconnectInfo(3))
        SessionStore.stats.value = VpnStats(bytesTx = 7)
        SessionStore.paths.value = listOf(path)

        val late = MqvpnManager(RuntimeEnvironment.getApplication())

        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(3)), late.vpnState.value)
        assertEquals(VpnStats(bytesTx = 7), late.stats.value)
        assertEquals(listOf(path), late.paths.value)
    }

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

    // --- terminal vs. retryable close (Error emission is deferred until the
    //     native client reveals whether a reconnect follows) ---

    @Test
    fun neverEstablishedClose_showsTerminalErrorAndStopsSession() {
        val svc = TestVpnService()

        svc.onNativeTunnelClosed(-10)
        svc.onNativeReconnectScheduled(5)

        // retrying a server that never accepted us stays an Error, and the
        // session is torn down (which cancels the native reconnect timer)
        val state = SessionStore.state.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.ConnectionClosed("Connection to the server failed"),
            (state as MqvpnState.Error).error,
        )
        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun establishedClose_reconnectKeepsSessionAlive() {
        val svc = TestVpnService()
        svc.sessionEstablished = true

        svc.onNativeTunnelClosed(-10)
        svc.onNativeReconnectScheduled(5)

        // a session that was Connected reconnects: no Error, no teardown
        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(5)), SessionStore.state.value)
        assertEquals(0, svc.stopTunnelCalls)
    }

    @Test
    fun closedWithoutReconnect_showsCloseError() {
        val svc = TestVpnService()

        svc.onNativeTunnelClosed(-10)
        svc.onNativeStateChanged(2, 6) // CLOSED, no reconnect scheduled

        val state = SessionStore.state.value
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
        val svc = TestVpnService()

        svc.onNativeTunnelClosed(-5)

        val state = SessionStore.state.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.AuthFailed("Access key rejected by the server"),
            (state as MqvpnState.Error).error,
        )
        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun requestFailureDuringReconnect_keepsTerminalError() {
        // mid-session reconnect: the retried CONNECT-IP request fails (-6),
        // and the same native call then schedules another reconnect — the
        // schedule must not overwrite the terminal Error
        val svc = TestVpnService()
        svc.sessionEstablished = true

        svc.onNativeTunnelClosed(-6)
        svc.onNativeReconnectScheduled(3)

        val state = SessionStore.state.value
        assertTrue(state is MqvpnState.Error)
        assertEquals(
            MqvpnError.ProtocolError(-6, "Connection rejected — check the access key and server address"),
            (state as MqvpnState.Error).error,
        )
        assertEquals(1, svc.stopTunnelCalls)
    }

    @Test
    fun terminalError_keepsTheFirstError() {
        val svc = TestVpnService()

        svc.onNativeTunnelClosed(-4) // terminal on arrival
        svc.onNativeTunnelClosed(-10) // close notify from the teardown
        svc.onNativeStateChanged(2, 6)

        val state = SessionStore.state.value as MqvpnState.Error
        assertEquals(MqvpnError.TlsError("TLS handshake failed"), state.error)
    }
}
