// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ReorderJniSmokeTest {
    init { System.loadLibrary("mqvpn_jni") }

    @Test
    fun externalsResolve_noUnsatisfiedLinkError() {
        assertNull(NativeBridge.getReorderStats(0L))

        val reactor = NativeBridge.reactorNew()
        val cfg = NativeBridge.configNew()
        var client = 0L
        try {
            NativeBridge.configSetReorderEnabled(cfg, 1)
            NativeBridge.configAddReorderRule(cfg, 17, 443, 3)
            client = NativeBridge.clientNew(cfg, NoopCallbacks())
            assertTrue(client != 0L)
            // Unconnected: zero-filled, 7 counters plus 12 residence buckets.
            val st = NativeBridge.getReorderStats(client)
            assertNotNull(st)
            assertEquals(19, st!!.size)
            assertTrue(st.all { it == 0L })
        } finally {
            // Destroy goes through the reactor (the only destroy entry point).
            if (client != 0L) NativeBridge.reactorClientDestroy(reactor, client)
            NativeBridge.configFree(cfg)
            NativeBridge.reactorFree(reactor)
        }
    }

    private class NoopCallbacks {
        fun onNativeTunnelConfigReady(assignedIp: ByteArray, prefix: Int, assignedIp6: ByteArray?, prefix6: Int,
                                      serverIp: ByteArray, serverPrefix: Int, mtu: Int, hasV6: Boolean,
                                      hasServerScheduler: Boolean, serverScheduler: Int) {}
        fun onNativeTunnelClosed(errorCode: Int) {}
        fun onNativeStateChanged(oldState: Int, newState: Int) {}
        fun onNativePathEvent(pathHandle: Long, newStatus: Int) {}
        fun onNativeLog(level: Int, message: String) {}
        fun onNativeReconnectScheduled(delaySec: Int) {}
    }
}
