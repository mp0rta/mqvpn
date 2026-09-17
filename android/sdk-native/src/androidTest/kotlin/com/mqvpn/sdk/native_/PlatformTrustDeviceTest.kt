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
class PlatformTrustDeviceTest {
    private fun fixture(name: String): ByteArray =
        PlatformTrustDeviceTest::class.java.getResourceAsStream("/$name.der")!!.use { it.readBytes() }

    @Test fun realChecker_acceptsChainUnderTestRoot() =
        assertNull(PlatformTrust.verify(arrayOf(fixture("identity-dns"), fixture("chain-intermediate")), "a.example.com"))

    @Test fun realChecker_acceptsIpLeaf_v4AndMappedV6Spellings() {
        val chain = arrayOf(fixture("identity-ip"), fixture("chain-intermediate"))
        assertNull(PlatformTrust.verify(chain, "192.0.2.10"))
        // a host string with ':' must not trip the platform's per-domain network-security-config lookup
        assertNull(PlatformTrust.verify(chain, "::ffff:198.51.100.7"))
        assertNull(PlatformTrust.verify(chain, "::ffff:c633:6407"))
    }

    @Test fun realChecker_rejectsUntrustedChain() {
        val r = PlatformTrust.verify(arrayOf(fixture("other-leaf"), fixture("other-intermediate")), "a.example.com")
        assertNotNull("trusted an untrusted chain", r)
        assertTrue(r!!, r.startsWith("verifier error"))
    }

    @Test fun identity_rejectsHostnameMismatch_onDevice() {
        val r = PlatformTrust.verify(arrayOf(fixture("identity-dns"), fixture("chain-intermediate")), "b.example.com")
        assertTrue(r!!, r.startsWith("certificate hostname mismatch for"))
    }

    @Test fun identity_mixedSanIsNoSan_onDevice() {
        val r = PlatformTrust.verify(arrayOf(fixture("identity-san-mixed"), fixture("chain-intermediate")), "a.example.com")
        assertTrue(r!!, r.startsWith("certificate has no subject alternative name"))
    }

    @Test fun jni_exceptionNeverReadsAsTrusted() =
        assertEquals(-1, NativeBridgeTestSeams.nativeVerifyThrowingForTest(arrayOf(fixture("identity-dns")), "a.example.com"))

    @Test fun jni_productionPathAcceptsUnderTestRoot() =
        assertEquals(0, NativeBridgeTestSeams.nativeVerifyForTest(arrayOf(fixture("identity-dns"), fixture("chain-intermediate")), "a.example.com"))

    @Test fun jni_rejectsNonAsciiHostBeforeUpcall() =
        assertEquals(-1, NativeBridgeTestSeams.nativeVerifyForTest(arrayOf(fixture("identity-dns")), "bücher.example"))

    @Test fun clientNew_installsThePlatformVerifier() {
        val cfg = NativeBridge.configNew()
        val client = NativeBridge.clientNew(cfg, NoopCallbacks())
        try {
            assertTrue(client != 0L)
            // clientNew installs on the handle; ordering vs the config copy is pinned by review (see nativeConfigHasPlatformVerifier)
            assertTrue(NativeBridgeTestSeams.nativeConfigHasPlatformVerifier(cfg))
        } finally {
            if (client != 0L) NativeBridge.clientDestroy(client)
            NativeBridge.configFree(cfg)
        }
    }

    /** Mirrors sdk-core's internal TunnelCallbacks (not on this module's classpath: sdk-core
     *  depends on sdk-native, not the reverse). clientNew resolves these by name + JNI signature:
     *  ([BI[BI[BIIZ)V, (I)V, (II)V, (JI)V, (ILjava/lang/String;)V, (I)V.
     *  Not @Keep: the test APK is not minified; if it ever were, clientNew would return 0 and
     *  the first assert fails. */
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
