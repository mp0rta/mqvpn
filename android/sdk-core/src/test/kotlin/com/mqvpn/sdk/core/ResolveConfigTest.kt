// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.Intent
import android.os.ParcelFileDescriptor
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.TunnelInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ResolveConfigTest {
    class Svc : MqvpnVpnService() {
        fun resolve(intent: Intent?) = resolveConfig(intent)
        override fun onCreateTun(info: TunnelInfo, config: MqvpnConfig): ParcelFileDescriptor =
            throw UnsupportedOperationException()
        override fun onVpnStateChanged(newState: MqvpnState) {}
    }

    // context attached, onCreate (JNI reactor) not run
    private val svc = Robolectric.buildService(Svc::class.java).get()
    private val config = MqvpnConfig(serverAddress = "10.0.0.1", authKey = "k")

    private fun start(c: MqvpnConfig) =
        Intent().putExtra(MqvpnManager.EXTRA_CONFIG_JSON, c.toJson())

    @Test
    fun aStickyRestart_getsTheLastStartedConfig() {
        assertEquals(config, svc.resolve(start(config)))
        assertEquals(config, svc.resolve(null)) // re-delivered without the extra
    }

    @Test
    fun theIntentWinsOverThePersistedConfig() {
        svc.resolve(start(config))
        val next = config.copy(serverAddress = "10.0.0.9")
        assertEquals(next, svc.resolve(start(next)))
        assertEquals(next, svc.resolve(null))
    }

    @Test
    fun nothingToStart_isNull() {
        assertNull(svc.resolve(null))
        assertNull(svc.resolve(Intent().putExtra(MqvpnManager.EXTRA_CONFIG_JSON, "{broken")))
    }
}
