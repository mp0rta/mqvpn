// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.VpnStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionStoreTest {
    private val old = Any()
    private val replacement = Any()

    @Test
    fun aRetiredService_neverWritesAgain_evenAfterAReplacementStarted() {
        // the old service's engine outlived its 2 s stop join: its queued
        // start and its teardown run after the replacement took over
        SessionStore.claim(old)
        SessionStore.retire(old)
        SessionStore.claim(replacement)
        assertTrue(SessionStore.publish(replacement) {
            state.value = MqvpnState.Connecting
            stats.value = VpnStats(bytesTx = 7)
        })

        var oldCallbackRan = false
        assertFalse(SessionStore.publish(old) {
            resetMetrics()
            state.value = MqvpnState.Disconnected
            oldCallbackRan = true // stands for the app callback
        })
        SessionStore.retire(old) // not the owner: changes nothing

        assertFalse(oldCallbackRan)
        assertEquals(MqvpnState.Connecting, SessionStore.state.value)
        assertEquals(VpnStats(bytesTx = 7), SessionStore.stats.value)
        assertTrue(SessionStore.publish(replacement) {})
        SessionStore.retire(replacement)
    }

    @Test
    fun retire_endsALiveStateWhoseTeardownTimedOut() {
        SessionStore.claim(old)
        SessionStore.publish(old) {
            state.value = MqvpnState.Reconnecting(ReconnectInfo(3))
            stats.value = VpnStats(bytesTx = 1)
        }

        SessionStore.retire(old)

        assertEquals(MqvpnState.Disconnected, SessionStore.state.value)
        assertEquals(VpnStats(), SessionStore.stats.value)
    }

    @Test
    fun retire_keepsATerminalError() {
        val error = MqvpnState.Error(MqvpnError.AuthFailed("bad key"))
        SessionStore.claim(old)
        SessionStore.publish(old) { state.value = error }

        SessionStore.retire(old)

        assertEquals(error, SessionStore.state.value)
    }
}
