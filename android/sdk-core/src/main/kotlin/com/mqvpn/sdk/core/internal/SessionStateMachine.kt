// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.TunnelInfo

/**
 * One session's native events → [MqvpnState]. No Android or JNI: the whole
 * close/reconnect policy is testable on the JVM. One instance per session,
 * so nothing carries over from the last one. Executor thread only.
 *
 * A close is reported before the native client reveals whether it will
 * retry, so the Error emit waits for that decision: the app stops the
 * service on Error, which must not kill a scheduled reconnect.
 */
internal class SessionStateMachine(
    private val emit: (MqvpnState) -> Unit,
    /** End the session (enqueues the teardown). */
    private val stop: () -> Unit,
    private val onReconnectScheduled: (Int) -> Unit,
) {
    private var last: MqvpnState? = null
    private var established = false
    private var pendingCloseError: MqvpnError? = null
    private var tearingDown = false

    fun started() = set(MqvpnState.Connecting)

    fun connected(info: TunnelInfo) {
        established = true
        pendingCloseError = null
        set(MqvpnState.Connected(info))
    }

    /** The session could not be built or its TUN created: terminal, no retry. */
    fun failed(error: MqvpnError) = terminal(error)

    fun tunnelClosed(errorCode: Int) {
        if (errorCode == 0) return
        if (errorCode == NATIVE_ERR_CLOSED) {
            // close notify: a reconnect schedule or CLOSED follows in the
            // same native call — defer to that decision
            pendingCloseError = MqvpnError.fromNativeCode(errorCode)
            return
        }
        // request-level failure (bad key, non-200, rejected cert): the QUIC
        // conn may stay open with no follow-up callback, so terminal here
        terminal(MqvpnError.fromNativeCode(errorCode))
        stop()
    }

    fun nativeStateChanged(newState: Int) {
        when (newState) {
            NATIVE_CONNECTING, NATIVE_AUTHENTICATING -> set(MqvpnState.Connecting)
            // CLOSED with no reconnect scheduled (e.g. the server certificate
            // was rejected): terminal. A clean close leaves no pending error.
            NATIVE_CLOSED -> pendingCloseError?.let { terminal(it) }
            // RECONNECTING arrives as reconnectScheduled; the rest show as Connected
        }
    }

    fun reconnectScheduled(delaySec: Int) {
        // a terminal Error emitted in the same native call, or a teardown in
        // progress, makes the schedule moot — it must not overwrite the Error
        if (tearingDown || last is MqvpnState.Error) return
        if (!established) {
            // never connected (bad address or server down): fail fast instead
            // of an endless Reconnecting; the teardown cancels the armed timer
            terminal(pendingCloseError ?: MqvpnError.fromNativeCode(NATIVE_ERR_CLOSED))
            stop()
            return
        }
        pendingCloseError = null
        set(MqvpnState.Reconnecting(ReconnectInfo(delaySec)))
        onReconnectScheduled(delaySec)
    }

    /** The teardown started: its own close callbacks are not session errors. */
    fun tearingDown() {
        tearingDown = true
    }

    /** The teardown finished; a terminal Error stays on display. */
    fun closed() {
        if (last !is MqvpnState.Error) set(MqvpnState.Disconnected)
    }

    /** The session's first Error wins (it is the most specific); silent while tearing down. */
    private fun terminal(error: MqvpnError) {
        if (tearingDown || last is MqvpnState.Error) return
        set(MqvpnState.Error(error))
    }

    private fun set(state: MqvpnState) {
        last = state
        emit(state)
    }

    companion object {
        // enum mqvpn_client_state in libmqvpn.h
        private const val NATIVE_CONNECTING = 1
        private const val NATIVE_AUTHENTICATING = 2
        private const val NATIVE_CLOSED = 6

        /** MQVPN_ERR_CLOSED in libmqvpn.h: connection closed. */
        private const val NATIVE_ERR_CLOSED = -10
    }
}
