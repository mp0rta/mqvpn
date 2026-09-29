// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.ReorderStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A destroyed tunnel (client handle 0) answers every call without a JNI
 * call: a task queued behind the cleanup that destroyed the client (a TUN
 * batch, say) must never reach a freed pointer. Reaching NativeBridge here
 * would throw UnsatisfiedLinkError in the unit-test JVM, so "no exception"
 * is the proof.
 */
class MqvpnTunnelTest {
    private val t = TestReflection.createDummyTunnel()

    @Test
    fun `every call on a destroyed tunnel is refused without JNI`() {
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.setServerAddr("h", 1))
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.connect())
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.disconnect())
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.setTunActive(true, 3))
        assertEquals(-1L, t.addPath(5, "wlan0"))
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.removePath(1L))
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.pathReleased(1L))
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.onTunPacket(ByteArray(4), 0, 4))
        assertEquals(MqvpnTunnel.ERR_INVALID_STATE, t.tick())
        assertEquals(6, t.getState()) // CLOSED
        assertTrue(t.getPaths().isEmpty())
        assertEquals(0L, t.getStats().bytesTx)
        assertEquals(MqvpnTunnel.Interest(0, false, false), t.getInterest())
        // With reorder enabled getReorderStats() passes its own short-circuit
        // and reaches the handle-0 check: an empty ReorderStats, no JNI.
        val reorder = TestReflection.createDummyTunnel(reorderEnabled = true)
        assertEquals(ReorderStats(), reorder.getReorderStats())
    }

    @Test
    fun `destroy on a destroyed tunnel is a no-op`() {
        t.destroy()
        t.destroy()
        assertEquals(0L, t.clientHandle)
    }
}
