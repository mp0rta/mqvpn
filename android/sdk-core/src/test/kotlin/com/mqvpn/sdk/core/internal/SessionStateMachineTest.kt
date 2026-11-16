// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import org.junit.Assert.assertEquals
import org.junit.Test

/** Terminal vs. retryable close: Error waits until the native client reveals whether a reconnect follows. */
class SessionStateMachineTest {
    private val emitted = mutableListOf<MqvpnState>()
    private var stops = 0
    private val reconnects = mutableListOf<Int>()
    private val m = SessionStateMachine(
        emit = { emitted += it },
        stop = { stops++ },
        onReconnectScheduled = { reconnects += it },
    )
    private val info = TunnelInfo(assignedIp = "10.0.0.2", prefix = 24, serverIp = "10.0.0.1", serverPrefix = 24, mtu = 1280)
    private val closed = MqvpnError.ConnectionClosed("Connection to the server failed")

    private val last get() = emitted.last()

    @Test
    fun neverEstablishedClose_showsTerminalErrorAndStopsSession() {
        m.started()
        m.tunnelClosed(-10)
        m.reconnectScheduled(5)

        // retrying a server that never accepted us stays an Error, and the
        // session is torn down (which cancels the native reconnect timer)
        assertEquals(MqvpnState.Error(closed), last)
        assertEquals(1, stops)
        assertEquals(emptyList<Int>(), reconnects)
    }

    @Test
    fun establishedClose_reconnectKeepsSessionAlive() {
        m.started()
        m.connected(info)
        m.tunnelClosed(-10)
        m.reconnectScheduled(5)

        // a session that was Connected reconnects: no Error, no teardown
        assertEquals(MqvpnState.Reconnecting(ReconnectInfo(5)), last)
        assertEquals(0, stops)
        assertEquals(listOf(5), reconnects)
    }

    @Test
    fun closedWithoutReconnect_showsCloseError() {
        m.started()
        m.tunnelClosed(-10)
        m.nativeStateChanged(6) // CLOSED, no reconnect scheduled

        assertEquals(MqvpnState.Error(closed), last)
    }

    @Test
    fun cleanClose_isNotAnError() {
        m.started()
        m.connected(info)
        m.nativeStateChanged(6)
        m.tearingDown()
        m.closed()

        assertEquals(MqvpnState.Disconnected, last)
    }

    @Test
    fun requestFailure_withoutFollowUpCallback_showsErrorAndStopsSession() {
        // e.g. the server rejects the CONNECT-IP request (bad key) but keeps
        // the QUIC connection open: no close/reconnect callback ever follows
        m.started()
        m.tunnelClosed(-5)

        assertEquals(MqvpnState.Error(MqvpnError.AuthFailed("Access key rejected by the server")), last)
        assertEquals(1, stops)
    }

    @Test
    fun requestFailureDuringReconnect_keepsTerminalError() {
        // mid-session reconnect: the retried CONNECT-IP request fails (-6),
        // and the same native call then schedules another reconnect — the
        // schedule must not overwrite the terminal Error
        m.started()
        m.connected(info)
        m.tunnelClosed(-6)
        m.reconnectScheduled(3)

        assertEquals(
            MqvpnState.Error(MqvpnError.ProtocolError(-6, "Connection rejected — check the access key and server address")),
            last,
        )
        assertEquals(1, stops)
    }

    @Test
    fun terminalError_keepsTheFirstError() {
        m.started()
        m.tunnelClosed(-4) // terminal on arrival
        m.tunnelClosed(-10) // close notify from the teardown
        m.nativeStateChanged(6)

        assertEquals(MqvpnState.Error(MqvpnError.TlsError("TLS handshake failed")), last)
    }

    @Test
    fun teardown_keepsTheErrorOnDisplay_andSilencesItsOwnCloses() {
        m.started()
        m.failed(MqvpnError.TunCreationFailed("VPN permission denied"))
        m.tearingDown()
        m.tunnelClosed(-5) // the teardown's own close is not a session error
        m.closed()

        assertEquals(MqvpnState.Error(MqvpnError.TunCreationFailed("VPN permission denied")), last)
    }

    @Test
    fun teardownWithoutError_endsDisconnected() {
        m.started()
        m.connected(info)
        m.tearingDown()
        m.tunnelClosed(-10)
        m.reconnectScheduled(2) // moot while tearing down
        m.closed()

        assertEquals(
            listOf(MqvpnState.Connecting, MqvpnState.Connected(info), MqvpnState.Disconnected),
            emitted,
        )
        assertEquals(0, stops)
    }
}
