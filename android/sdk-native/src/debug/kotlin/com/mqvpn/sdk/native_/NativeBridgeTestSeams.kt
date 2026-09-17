// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

/**
 * Test-only JNI entry points. This file lives in the debug source set and the
 * C side is compiled only under MQVPN_JNI_TEST_SEAMS, so the release AAR and
 * release .so carry none of it.
 */
object NativeBridgeTestSeams {
    init { System.loadLibrary("mqvpn_jni") }

    /** Runs the production PlatformTrust.verify through the exact C marshalling path. 0 = trusted. */
    external fun nativeVerifyForTest(chainDer: Array<ByteArray>, host: String): Int

    /** The marshalling/upcall core (jni_call_verifier) against [throwingVerify]: skips
     *  jni_cert_verify's reject-all guard on purpose; must return -1 (an exception never
     *  reads as trusted). */
    external fun nativeVerifyThrowingForTest(chainDer: Array<ByteArray>, host: String): Int

    /** True when NativeBridge.clientNew installed the platform verifier on this config handle (check after clientNew returned non-zero). */
    external fun nativeConfigHasPlatformVerifier(cfg: Long): Boolean

    @JvmStatic
    @Suppress("UNUSED_PARAMETER")
    fun throwingVerify(chainDer: Array<ByteArray>, host: String): String? = throw IllegalStateException("test")
}
