// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.mqvpn.sdk.native_.NativeBridge
import com.mqvpn.sdk.native_.NativeBridgeTestSeams
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The JNI upcalls against the real [TunnelCallbacks], not the by-name mirrors
 * in sdk-native's androidTest: clientNew resolves every method on an
 * implementation of this interface, and each upcall delivers the values C
 * sent (the seam's fixed values, mqvpn_jni.c nativeFireUpcallsForTest).
 */
@RunWith(AndroidJUnit4::class)
class TunnelCallbacksJniTest {
    private class Recorder : TunnelCallbacks {
        val calls = mutableListOf<List<Any?>>()
        override fun onNativeTunnelConfigReady(
            assignedIp: ByteArray, prefix: Int,
            assignedIp6: ByteArray?, prefix6: Int,
            serverIp: ByteArray, serverPrefix: Int,
            mtu: Int, hasV6: Boolean,
            hasServerScheduler: Boolean, serverScheduler: Int,
        ) {
            calls += listOf("config", assignedIp.toList(), prefix, assignedIp6?.toList(), prefix6,
                            serverIp.toList(), serverPrefix, mtu, hasV6, hasServerScheduler, serverScheduler)
        }
        override fun onNativeTunnelClosed(errorCode: Int) { calls += listOf("closed", errorCode) }
        override fun onNativeStateChanged(oldState: Int, newState: Int) { calls += listOf("state", oldState, newState) }
        override fun onNativePathEvent(pathHandle: Long, newStatus: Int) { calls += listOf("path", pathHandle, newStatus) }
        override fun onNativeLog(level: Int, message: String) { calls += listOf("log", level, message) }
        override fun onNativeReconnectScheduled(delaySec: Int) { calls += listOf("reconnect", delaySec) }
    }

    @Test
    fun everyUpcallReachesTheRealInterfaceWithItsValues() {
        val rec = Recorder()
        val cfg = NativeBridge.configNew()
        var reactor = 0L
        var client = 0L
        val calls: List<List<Any?>>
        try {
            reactor = NativeBridge.reactorNew()
            assertTrue(reactor != 0L)
            client = NativeBridge.clientNew(cfg, rec)
            assertTrue("clientNew could not resolve a TunnelCallbacks method", client != 0L)
            assertTrue(NativeBridgeTestSeams.nativeFireUpcallsForTest(client))
            calls = rec.calls.toList() // before destroy, which logs through the same upcall
        } finally {
            if (client != 0L) NativeBridge.reactorClientDestroy(reactor, client)
            if (reactor != 0L) NativeBridge.reactorFree(reactor)
            NativeBridge.configFree(cfg)
        }

        val ip6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
        val config = listOf("config", listOf<Byte>(10, 0, 0, 2), 24, ip6.toList(), 112, listOf<Byte>(10, 0, 0, 1), 30, 1280, true)
        assertEquals(
            listOf(
                config + listOf(true, 3),       // hasServerScheduler, MQVPN_SCHED_WLB_UDP_PIN
                config + listOf(false, 0),      // pre-ABI-3 struct_size: scheduler absent
                listOf("state", 1, 2),          // CONNECTING -> AUTHENTICATING
                listOf("path", 7L, 2),          // MQVPN_PATH_DEGRADED
                listOf("log", 2, "upcall seam"), // MQVPN_LOG_WARN
                listOf("reconnect", 9),
                listOf("closed", -5),           // MQVPN_ERR_AUTH
            ),
            calls,
        )
    }
}
