// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.os.ParcelFileDescriptor
import com.mqvpn.sdk.core.model.MqvpnConfig
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
}
