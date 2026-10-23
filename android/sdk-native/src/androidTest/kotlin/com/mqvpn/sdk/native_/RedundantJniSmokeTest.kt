// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RedundantJniSmokeTest {
    init { System.loadLibrary("mqvpn_jni") }

    @Test
    fun configSetRedundant_acceptsAndRejects() {
        val cfg = NativeBridge.configNew()
        try {
            assertEquals(0, NativeBridge.configSetRedundant(cfg, true, intArrayOf(4200)))
            assertEquals(0, NativeBridge.configSetRedundant(cfg, true, intArrayOf()))
            assertNotEquals(0, NativeBridge.configSetRedundant(cfg, true, intArrayOf(0)))
            assertNotEquals(0, NativeBridge.configSetRedundant(cfg, true, intArrayOf(65536)))
            assertNotEquals(0, NativeBridge.configSetRedundant(cfg, true, intArrayOf(-1)))
            assertNotEquals(0, NativeBridge.configSetRedundant(cfg, true, IntArray(17) { 4200 }))
        } finally {
            NativeBridge.configFree(cfg)
        }
    }

    @Test
    fun configSetCc_acceptsAndRejects() {
        val cfg = NativeBridge.configNew()
        try {
            for (cc in 0..2) assertEquals(0, NativeBridge.configSetCc(cfg, cc)) // bbr2, bbr, cubic
            assertNotEquals(0, NativeBridge.configSetCc(cfg, 99))
        } finally {
            NativeBridge.configFree(cfg)
        }
    }
}
