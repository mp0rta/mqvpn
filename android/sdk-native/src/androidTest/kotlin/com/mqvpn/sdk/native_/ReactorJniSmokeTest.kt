// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Every reactor entry point through the real JNI marshalling, on a device or
 * emulator: wait / wake / add / remove / release / destroy on a loopback
 * socket added before connect (the production order). Behaviour is covered
 * on the Linux host by tests/test_android_reactor.c; this proves the bridge.
 */
@RunWith(AndroidJUnit4::class)
class ReactorJniSmokeTest {
    init { System.loadLibrary("mqvpn_jni") }

    @Test
    fun reactorLifecycle_waitWakeAddRemoveReleaseDestroy() {
        val r = NativeBridge.reactorNew()
        assertTrue(r != 0L)
        try {
            // Empty table: a timed wait runs to its timeout (wide window).
            var t0 = SystemClock.elapsedRealtime()
            assertEquals(0, NativeBridge.reactorWait(r, 0L, 50))
            val idle = SystemClock.elapsedRealtime() - t0
            assertTrue("timed wait took $idle ms", idle >= 30 && idle < 1_000)
            // Nothing attached: no bad fd to hand out.
            assertEquals(-1L, NativeBridge.reactorTakeBadFd(r))

            // A wake from another thread returns a long wait promptly. The waker
            // is joined before any assertion: a failed assert must not reach
            // reactorFree while the waker may still call reactorWake.
            val waker = Thread { Thread.sleep(20); NativeBridge.reactorWake(r) }
            waker.start()
            t0 = SystemClock.elapsedRealtime()
            val woken = NativeBridge.reactorWait(r, 0L, 5_000)
            val waited = SystemClock.elapsedRealtime() - t0
            waker.join()
            assertEquals(0, woken)
            assertTrue("wake did not interrupt the wait ($waited ms)", waited < 1_000)

            val cfg = NativeBridge.configNew()
            val client = NativeBridge.clientNew(cfg, NoopCallbacks())
            var fd = -1
            try {
                assertTrue(client != 0L)
                // A loopback socket; the detached raw fd is ours to close. On API 29+
                // fromDatagramSocket returns a dup, so the DatagramSocket keeps its own fd
                // and must be closed too (AOSP Javadoc); before 29 detachFd() invalidated
                // the socket's shared FileDescriptor and close() is a no-op on the fd.
                val sock = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                fd = ParcelFileDescriptor.fromDatagramSocket(sock).detachFd()
                sock.close()
                val h = NativeBridge.reactorAddPath(r, client, fd, "lo")
                assertTrue("reactorAddPath returned $h", h >= 0)
                // Attached, nothing readable: the wait times out with 0 drains.
                assertEquals(0, NativeBridge.reactorWait(r, client, 10))
                // Orderly removal: remove → close (ours) → released.
                assertEquals(0, NativeBridge.reactorRemovePath(r, client, h))
                ParcelFileDescriptor.adoptFd(fd).close()
                fd = -1
                assertEquals(0, NativeBridge.reactorPathReleased(r, client, h))
                // Released twice: the reactor refuses (argument error), nothing crashes.
                assertEquals(-1, NativeBridge.reactorPathReleased(r, client, h))
            } finally {
                if (client != 0L) NativeBridge.reactorClientDestroy(r, client)
                NativeBridge.configFree(cfg)
                // After destroy: NativeBridge's "close the path fds AFTER this".
                if (fd >= 0) ParcelFileDescriptor.adoptFd(fd).close()
            }
        } finally {
            NativeBridge.reactorFree(r)
        }
    }

    /** Mirrors sdk-core's TunnelCallbacks by name + JNI signature (see PlatformTrustDeviceTest). */
    @Suppress("UNUSED_PARAMETER", "unused")
    private class NoopCallbacks {
        fun onNativeTunnelConfigReady(assignedIp: ByteArray, prefix: Int, assignedIp6: ByteArray?, prefix6: Int,
                                      serverIp: ByteArray, serverPrefix: Int, mtu: Int, hasV6: Boolean) {}
        fun onNativeTunnelClosed(errorCode: Int) {}
        fun onNativeStateChanged(oldState: Int, newState: Int) {}
        fun onNativePathEvent(pathHandle: Long, newStatus: Int) {}
        fun onNativeLog(level: Int, message: String) {}
        fun onNativeReconnectScheduled(delaySec: Int) {}
    }
}
