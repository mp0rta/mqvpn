// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.BandwidthSample
import com.mqvpn.app.ui.Tone
import com.mqvpn.app.ui.fmtElapsed
import com.mqvpn.app.ui.fmtMbps
import com.mqvpn.app.ui.pathCardViews
import com.mqvpn.app.ui.statusView
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.network.PathType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeriveTest {
    private val tunnel = TunnelInfo(
        assignedIp = "10.0.0.2", prefix = 24, serverIp = "10.0.0.1", serverPrefix = 24, mtu = 1280,
    )

    @Test fun connected() {
        val v = statusView(MqvpnState.Connected(tunnel), "00:12:41")
        assertEquals("Connected", v.title)
        assertEquals("Protected · 00:12:41", v.sub)
        assertEquals(Tone.OK, v.tone)
        assertFalse(v.pulsing)
    }

    @Test fun disconnected() {
        val v = statusView(MqvpnState.Disconnected, null)
        assertEquals("Not Connected", v.title)
        assertEquals("Tap the button to connect and protect your traffic", v.sub)
        assertFalse(v.pulsing)
    }

    @Test fun connectingAndReconnectingPulse() {
        for (s in listOf(MqvpnState.Connecting, MqvpnState.Reconnecting(ReconnectInfo(3)))) {
            val v = statusView(s, null)
            assertEquals("Connecting…", v.title)
            assertEquals("Contacting server…", v.sub)
            assertTrue(v.pulsing)
        }
    }

    @Test fun errorShowsMessage() {
        val v = statusView(MqvpnState.Error(MqvpnError.AuthFailed("PSK authentication failed")), null)
        assertEquals("Not Connected", v.title)
        assertEquals("PSK authentication failed", v.sub)
        assertEquals(Tone.WARN, v.tone)
    }

    private fun path(iface: String, status: Int = 1) = PathInfo(1, status, iface, 0, 0, 10)

    @Test fun pathCardsFixedOrderDimAndBar() {
        val sample = BandwidthSample(
            0, 0, 0,
            mapOf("wifi-1" to 40_000_000L, "cellular-2" to 10_000_000L),
            mapOf("wifi-1" to 5_000_000L),
        )
        val v = pathCardViews(
            listOf(path("wifi-1"), path("cellular-2", 3)),
            setOf(PathType.WIFI, PathType.CELLULAR), sample,
        )
        assertEquals(listOf(PathType.WIFI, PathType.CELLULAR, PathType.ETHERNET, PathType.BLUETOOTH), v.map { it.type })
        assertEquals(listOf("Wi-Fi", "Cellular", "Ethernet", "Bluetooth"), v.map { it.name })
        assertEquals(listOf(true, true, false, false), v.map { it.available })
        assertEquals(listOf(true, false, false, false), v.map { it.active })
        assertEquals(40_000_000L, v[0].rateBps) // download rate, as desktop Paths.svelte shows p.rate
        assertEquals(1f, v[0].barFraction, 0f)
        assertEquals(0.25f, v[1].barFraction, 0f)
        assertEquals("Not connected to a paired device", v[3].sub)
        assertEquals("No cable", v[2].sub)
    }

    @Test fun noSampleMeansZeroBars() {
        val v = pathCardViews(emptyList(), setOf(PathType.WIFI), null)
        assertTrue(v.all { it.rateBps == 0L && it.barFraction == 0f })
    }

    @Test fun formats() {
        assertEquals("46.3", fmtMbps(46_300_000))
        assertEquals("123", fmtMbps(123_400_000))
        assertEquals("12:41", fmtElapsed(761))
        assertEquals("1:00:00", fmtElapsed(3600))
        assertEquals("00:45", fmtElapsed(45))
    }
}
