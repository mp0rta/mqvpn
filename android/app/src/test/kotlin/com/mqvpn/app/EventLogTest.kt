// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.EventLog
import com.mqvpn.app.ui.LogEvent
import com.mqvpn.app.ui.eventText
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for the view-independent [EventLog] model: core-state kind
 * dedup, payload-event pass-through, the disconnect/error path-gate, path
 * diffing, and the newest-first ring buffer.
 */
class EventLogTest {

    private fun path(handle: Long, iface: String, status: Int) =
        PathInfo(handle = handle, status = status, iface = iface, bytesTx = 0, bytesRx = 0, srttMs = 0)

    private fun tunnelInfo(assignedIp: String = "10.0.0.2") = TunnelInfo(
        assignedIp = assignedIp,
        prefix = 32,
        serverIp = "1.2.3.4",
        serverPrefix = 32,
        mtu = 1400,
    )

    // -- startup Disconnected is suppressed -------------------------------

    @Test
    fun `startup Disconnected is suppressed`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Disconnected, now = 1L)
        assertEquals(emptyList<LogEvent>(), log.events)
    }

    // -- kind-dedup, not instance equality ---------------------------------

    @Test
    fun `CoreState dedupes by kind across payload changes`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connected(tunnelInfo()), now = 1L)
        log.ingestState(MqvpnState.Connected(tunnelInfo(assignedIp = "10.0.0.3")), now = 2L)

        assertEquals(1, log.events.size)
        assertEquals(LogEvent.Kind.CoreState("Connected"), log.events[0].kind)
    }

    @Test
    fun `CoreState logs again when kind actually changes`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestState(MqvpnState.Connected(tunnelInfo()), now = 2L)

        assertEquals(2, log.events.size)
        assertEquals(LogEvent.Kind.CoreState("Connected"), log.events[0].kind)
        assertEquals(LogEvent.Kind.CoreState("Connecting"), log.events[1].kind)
    }

    // -- Error / Reconnecting payload events fire every time ---------------

    @Test
    fun `Error logs a payload event on every emission`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Error(MqvpnError.TlsError("tls failed")), now = 1L)
        log.ingestState(MqvpnState.Error(MqvpnError.AuthFailed("auth failed")), now = 2L)

        // one CoreState("Error") (kind-deduped) + two Error payload events
        assertEquals(3, log.events.size)
        assertEquals(LogEvent.Kind.Error("auth failed"), log.events[0].kind)
        assertEquals(LogEvent.Kind.Error("tls failed"), log.events[1].kind)
        assertEquals(LogEvent.Kind.CoreState("Error"), log.events[2].kind)
    }

    @Test
    fun `Reconnecting logs a payload event on every emission`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Reconnecting(ReconnectInfo(delaySec = 2)), now = 1L)
        log.ingestState(MqvpnState.Reconnecting(ReconnectInfo(delaySec = 4)), now = 2L)

        assertEquals(3, log.events.size)
        assertEquals(LogEvent.Kind.Reconnecting(4), log.events[0].kind)
        assertEquals(LogEvent.Kind.Reconnecting(2), log.events[1].kind)
        assertEquals(LogEvent.Kind.CoreState("Reconnecting"), log.events[2].kind)
    }

    // -- path gate ----------------------------------------------------------

    @Test
    fun `ingestPaths is a no-op while last state is Disconnected`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L) // open the gate first
        log.ingestState(MqvpnState.Disconnected, now = 2L)
        val before = log.events

        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 3L)

        assertEquals(before, log.events)
    }

    @Test
    fun `ingestPaths is a no-op while last state is Error`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Error(MqvpnError.TlsError("x")), now = 1L)
        val before = log.events

        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        assertEquals(before, log.events)
    }

    @Test
    fun `path gate reopens on Connecting`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Error(MqvpnError.TlsError("x")), now = 1L)
        log.ingestState(MqvpnState.Connecting, now = 2L)

        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 3L)

        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
    }

    @Test
    fun `path gate reopens on Connected`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Disconnected, now = 1L)
        log.ingestState(MqvpnState.Connected(tunnelInfo()), now = 2L)

        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 3L)

        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
    }

    @Test
    fun `entering Disconnected resets the path baseline`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        log.ingestState(MqvpnState.Disconnected, now = 3L)
        log.ingestState(MqvpnState.Connecting, now = 4L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 5L)

        // same handle re-appears as a fresh add, not a status no-op
        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
    }

    // -- diffing --------------------------------------------------------

    @Test
    fun `ingestPaths logs PathAdded for a new handle`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)

        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
    }

    @Test
    fun `ingestPaths logs PathStatus on status change`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        log.ingestPaths(listOf(path(1, "wlan0", 1)), now = 3L)

        assertEquals(LogEvent.Kind.PathStatus("wlan0", 0, 1), log.events[0].kind)
    }

    @Test
    fun `ingestPaths logs PathRemoved with the baseline iface`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        log.ingestPaths(emptyList(), now = 3L)

        assertEquals(LogEvent.Kind.PathRemoved("wlan0"), log.events[0].kind)
    }

    @Test
    fun `same handle with an unchanged status but a different iface logs nothing`() {
        // Deliberate: the diff only tracks (iface, status) per handle, and iface
        // is not itself compared — a bare rename with no status change is not
        // surfaced as an event.
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)
        val before = log.events

        log.ingestPaths(listOf(path(1, "eth0", 0)), now = 3L)

        assertEquals(before, log.events)
    }

    @Test
    fun `handle replacement on the same iface logs remove then add`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)

        log.ingestPaths(listOf(path(2, "wlan0", 0)), now = 3L)

        // newest-first: add is logged after remove, so add is at index 0
        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
        assertEquals(LogEvent.Kind.PathRemoved("wlan0"), log.events[1].kind)
    }

    // -- resetBaseline ------------------------------------------------------

    @Test
    fun `resetBaseline clears paths but keeps history and state memory`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 2L)
        val historySize = log.events.size

        log.resetBaseline()
        log.ingestPaths(listOf(path(1, "wlan0", 0)), now = 3L)

        // path re-added fresh (baseline forgot the handle)
        assertEquals(LogEvent.Kind.PathAdded("wlan0", 0), log.events[0].kind)
        assertEquals(historySize + 1, log.events.size)

        // state memory untouched: re-ingesting Connecting logs nothing new
        val sizeBefore = log.events.size
        log.ingestState(MqvpnState.Connecting, now = 4L)
        assertEquals(sizeBefore, log.events.size)
    }

    // -- ring buffer eviction -------------------------------------------

    @Test
    fun `ring buffer evicts oldest beyond capacity`() {
        val log = EventLog(capacity = 3)
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestState(MqvpnState.Reconnecting(ReconnectInfo(delaySec = 1)), now = 2L)
        log.ingestState(MqvpnState.Connecting, now = 3L)
        log.ingestState(MqvpnState.Reconnecting(ReconnectInfo(delaySec = 2)), now = 4L)

        // oldest events (the first Connecting/Reconnecting CoreState rows) evicted;
        // survivors are the Reconnecting(2) payload + CoreState rows, newest-first
        assertEquals(listOf(4L, 4L, 3L), log.events.map { it.time })
    }

    // -- newest-first order ---------------------------------------------

    @Test
    fun `events are newest-first`() {
        val log = EventLog()
        log.ingestState(MqvpnState.Connecting, now = 1L)
        log.ingestState(MqvpnState.Connected(tunnelInfo()), now = 2L)

        assertEquals(2L, log.events[0].time)
        assertEquals(1L, log.events[1].time)
    }

    // -- eventText rendering ------------------------------------------------

    @Test
    fun `eventText renders CoreState`() {
        assertEquals("core → Connected", eventText(LogEvent.Kind.CoreState("Connected")))
    }

    @Test
    fun `eventText renders PathAdded`() {
        assertEquals("wlan0 added (Active)", eventText(LogEvent.Kind.PathAdded("wlan0", 1)))
    }

    @Test
    fun `eventText renders PathRemoved`() {
        assertEquals("wlan0 removed", eventText(LogEvent.Kind.PathRemoved("wlan0")))
    }

    @Test
    fun `eventText renders PathStatus`() {
        assertEquals(
            "wlan0: Pending → Active",
            eventText(LogEvent.Kind.PathStatus("wlan0", 0, 1)),
        )
    }

    @Test
    fun `eventText renders Error`() {
        assertEquals("error: tls failed", eventText(LogEvent.Kind.Error("tls failed")))
    }

    @Test
    fun `eventText renders Reconnecting`() {
        assertEquals("reconnecting in 4s", eventText(LogEvent.Kind.Reconnecting(4)))
    }
}
