// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.VpnStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionStoreTest {
    private val old = Any()
    private val replacement = Any()

    @Test
    fun aSupersededSession_cannotOverwriteTheLiveOne() {
        // the old service's teardown outlived its 2 s stop join and runs
        // after the replacement session published its state
        SessionStore.claim(old)
        SessionStore.claim(replacement)
        assertTrue(SessionStore.publish(replacement) {
            state.value = MqvpnState.Connecting
            stats.value = VpnStats(bytesTx = 7)
        })

        assertFalse(SessionStore.publish(old) {
            resetMetrics()
            state.value = MqvpnState.Disconnected
        })
        SessionStore.release(old) // not the owner: changes nothing

        assertEquals(MqvpnState.Connecting, SessionStore.state.value)
        assertEquals(VpnStats(bytesTx = 7), SessionStore.stats.value)
        assertTrue(SessionStore.publish(replacement) {})
    }

    @Test
    fun aReleasedStore_takesNoWrites() {
        SessionStore.claim(old)
        SessionStore.release(old)
        assertFalse(SessionStore.publish(old) {})
    }
}
