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
        val reactor = NativeBridge.reactorNew()
        val client = NativeBridge.clientNew(cfg, rec)
        val calls: List<List<Any?>>
        try {
            assertTrue("clientNew could not resolve a TunnelCallbacks method", client != 0L)
            assertTrue(NativeBridgeTestSeams.nativeFireUpcallsForTest(client))
            calls = rec.calls.toList() // before destroy, which logs through the same upcall
        } finally {
            if (client != 0L) NativeBridge.reactorClientDestroy(reactor, client)
            NativeBridge.reactorFree(reactor)
            NativeBridge.configFree(cfg)
        }

        val config = calls.first()
        val ip6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
        assertEquals("config", config[0])
        assertEquals(listOf<Byte>(10, 0, 0, 2), config[1])
        assertEquals(ip6.toList(), config[3])
        assertEquals(listOf<Byte>(10, 0, 0, 1), config[5])
        // prefix, prefix6, serverPrefix, mtu, hasV6, hasServerScheduler, serverScheduler (WLB_UDP_PIN)
        assertEquals(listOf(24, 112, 30, 1280, true, true, 3), listOf(config[2], config[4]) + config.drop(6))
        assertEquals(
            listOf(
                listOf("state", 1, 2),          // CONNECTING -> AUTHENTICATING
                listOf("path", 7L, 2),          // MQVPN_PATH_DEGRADED
                listOf("log", 2, "upcall seam"), // MQVPN_LOG_WARN
                listOf("reconnect", 9),
                listOf("closed", -5),           // MQVPN_ERR_AUTH
            ),
            calls.drop(1),
        )
    }
}
