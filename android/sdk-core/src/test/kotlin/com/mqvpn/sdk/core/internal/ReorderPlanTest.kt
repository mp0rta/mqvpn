// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.*
import org.junit.Test

class ReorderPlanTest {
    private fun cfg(enabled: Boolean, ports: List<Int>,
                    profile: MqvpnConfig.ReorderProfile = MqvpnConfig.ReorderProfile.CELLULAR_BOND) =
        MqvpnConfig(serverAddress = "h", authKey = "k",
                    reorderEnabled = enabled, reorderPorts = ports, reorderProfile = profile)

    @Test fun disabled_yieldsEmptyPlan() {
        val p = planReorder(cfg(false, listOf(443)))
        assertFalse(p.enabled); assertTrue(p.rules.isEmpty())
    }

    @Test fun enabledWithPorts_yieldsRulesPerPort() {
        val p = planReorder(cfg(true, listOf(443, 853), MqvpnConfig.ReorderProfile.FIBER_LTE))
        assertTrue(p.enabled)
        assertEquals(2, p.rules.size)
        assertTrue(p.rules.all { it.proto == 17 && it.profile == 4 })
        assertEquals(setOf(443, 853), p.rules.map { it.port }.toSet())
    }

    @Test fun enabledNoValidPorts_collapsesToDisabledWithWarning() {
        val p = planReorder(cfg(true, emptyList()))
        assertFalse(p.enabled); assertTrue(p.rules.isEmpty())
        assertEquals(1, p.warnings.size)
    }

    @Test fun outOfRangePorts_filteredWithWarning() {
        val p = planReorder(cfg(true, listOf(0, 65536, -1, 443)))
        assertEquals(listOf(443), p.rules.map { it.port })
        assertEquals(3, p.warnings.size)
    }

    @Test fun duplicatePorts_deduped() {
        val p = planReorder(cfg(true, listOf(443, 443, 443)))
        assertEquals(1, p.rules.size)
    }

    @Test fun tooManyPorts_cappedAtMaxRules() {
        val p = planReorder(cfg(true, (1..20).toList()))
        assertEquals(16, p.rules.size)
        assertTrue(p.warnings.any { it.contains("16") })
    }
}
