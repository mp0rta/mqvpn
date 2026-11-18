// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StatsSamplerTest {
    private val s = StatsSampler(100)

    @Test
    fun burstThenIdle_wakesForTheFinalSample() {
        assertTrue(s.shouldSample(1_000))
        assertFalse(s.shouldSample(1_030)) // last packets of the burst: read skipped
        // the engine would sleep 25 s; it wakes at the sample's time instead
        assertEquals(70, s.capWait(25_000, 1_030))
        assertTrue(s.shouldSample(1_100))
        assertEquals(25_000, s.capWait(25_000, 1_100)) // nothing pending: full wait
    }

    @Test
    fun capWait_neverLengthensOrZeroesTheWait() {
        s.shouldSample(1_000)
        s.shouldSample(1_010)
        assertEquals(5, s.capWait(5, 1_010))
        assertEquals(1, s.capWait(25_000, 1_200)) // overdue: wake now, not 0
    }
}
