// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class RedundantPlanTest {
    private fun cfg(enabled: Boolean, ports: List<Int>) =
        MqvpnConfig(serverAddress = "h", authKey = "k", redundantEnabled = enabled, redundantPorts = ports)

    @Test fun disabled_yieldsNull() {
        assertNull(planRedundant(cfg(false, listOf(4200))))
    }

    @Test fun enabledWithPorts_keepsOrder() {
        val p = planRedundant(cfg(true, listOf(4200, 9000)))
        assertNotNull(p)
        assertArrayEquals(intArrayOf(4200, 9000), p!!.ports)
    }

    @Test fun enabledWithoutPorts_isAllUdp() {
        assertEquals(0, planRedundant(cfg(true, emptyList()))!!.ports.size)
    }
}
