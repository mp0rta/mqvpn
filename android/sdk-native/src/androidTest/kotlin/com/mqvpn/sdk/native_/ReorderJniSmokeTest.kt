// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import androidx.test.ext.junit.runners.AndroidJUnit4
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
        // Any non-null result must carry the 7 counters plus 12 residence buckets.
        NativeBridge.getReorderStats(0L)?.let { assertTrue(it.size >= 19) }

        val cfg = NativeBridge.configNew()
        try {
            NativeBridge.configSetReorderEnabled(cfg, 1)
            NativeBridge.configAddReorderRule(cfg, 17, 443, 3)
        } finally {
            NativeBridge.configFree(cfg)
        }
    }
}
