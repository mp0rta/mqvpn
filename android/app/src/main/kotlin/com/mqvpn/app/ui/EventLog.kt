// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import kotlin.reflect.KClass

/**
 * One sparse, info-level event derived from a state/path snapshot diff.
 * Path/status fields stay raw (ints, not display strings) so coloring is the
 * view's job; [Kind.CoreState.label] carries the state subclass's simple
 * name, which the demo UI renders directly. Keeping the event free of any
 * Android/Compose dependency lets the diff logic be exercised in isolation.
 */
data class LogEvent(val time: Long, val kind: Kind) {
    sealed interface Kind {
        data class CoreState(val label: String) : Kind
        data class PathAdded(val iface: String, val status: Int) : Kind
        data class PathRemoved(val iface: String) : Kind
        data class PathStatus(val iface: String, val from: Int, val to: Int) : Kind
        data class Error(val message: String) : Kind
        data class Reconnecting(val delaySec: Int) : Kind
    }
}

/**
 * View-independent event log: diffs consecutive [MqvpnState]/[PathInfo]
 * snapshots into the sparse event classes the dashboard shows (core-state
 * change, path add/remove/status-change, error, reconnect) and keeps a
 * fixed newest-first ring buffer.
 *
 * Core-state rows are deduplicated by *kind* (`state::class`), not instance
 * equality, so repeated emissions of the same state subtype (e.g. two
 * [MqvpnState.Connected] snapshots with different payloads) log once.
 * [MqvpnState.Error] and [MqvpnState.Reconnecting] additionally emit a
 * payload event on every ingestion, independent of that dedup.
 *
 * While the most recently ingested state kind is [MqvpnState.Disconnected]
 * or [MqvpnState.Error], [ingestPaths] is a no-op: this gates against
 * phantom path re-adds during async teardown, when the platform may still
 * deliver a stale path snapshot after the core has already reported the
 * tunnel down.
 */
class EventLog(private val capacity: Int = 20) {

    /** Baseline value for one path handle: the last-seen (iface, status) pair. */
    private data class PathSnapshot(val iface: String, val status: Int)

    private val _events = mutableListOf<LogEvent>()

    /** Newest-first snapshot of the logged events. */
    val events: List<LogEvent>
        get() = _events.toList()

    // Seeded with Disconnected: a fresh log starts in the same "gated,
    // nothing to say yet" posture as an explicit initial Disconnected state,
    // so the very first ingestState(Disconnected) is a no-op.
    private var lastStateKind: KClass<out MqvpnState> = MqvpnState.Disconnected::class

    private val pathBaseline = mutableMapOf<Long, PathSnapshot>()

    fun ingestState(state: MqvpnState, now: Long) {
        val kind = state::class
        if (kind != lastStateKind) {
            append(LogEvent(now, LogEvent.Kind.CoreState(kind.simpleName ?: "Unknown")))
            lastStateKind = kind
        }
        when (state) {
            is MqvpnState.Error ->
                append(LogEvent(now, LogEvent.Kind.Error(state.error.message)))
            is MqvpnState.Reconnecting ->
                append(LogEvent(now, LogEvent.Kind.Reconnecting(state.info.delaySec)))
            else -> Unit
        }
        if (state is MqvpnState.Disconnected || state is MqvpnState.Error) {
            resetBaseline()
        }
    }

    fun ingestPaths(paths: List<PathInfo>, now: Long) {
        if (lastStateKind == MqvpnState.Disconnected::class || lastStateKind == MqvpnState.Error::class) {
            return
        }

        val current = paths.associate { it.handle to PathSnapshot(it.iface, it.status) }

        // Removals are logged first so that, within a single ingestPaths
        // call, an add on the same iface (handle replacement) ends up as
        // the newer of the two rows in the newest-first buffer.
        for ((handle, old) in pathBaseline) {
            if (handle !in current) {
                append(LogEvent(now, LogEvent.Kind.PathRemoved(old.iface)))
            }
        }
        for (p in paths) {
            val old = pathBaseline[p.handle]
            if (old == null) {
                append(LogEvent(now, LogEvent.Kind.PathAdded(p.iface, p.status)))
            } else if (old.status != p.status) {
                // Note: a same-handle iface change with an unchanged status is
                // deliberately not an event — only (handle, status) is diffed.
                append(LogEvent(now, LogEvent.Kind.PathStatus(p.iface, old.status, p.status)))
            }
        }

        pathBaseline.clear()
        pathBaseline.putAll(current)
    }

    /**
     * Forget the path diff baseline (e.g. on disconnect) so a later
     * reconnect logs its paths as fresh additions. Core-state kind memory
     * and event history are intentionally kept.
     */
    fun resetBaseline() {
        pathBaseline.clear()
    }

    private fun append(event: LogEvent) {
        _events.add(0, event) // newest-first
        while (_events.size > capacity) {
            _events.removeAt(_events.lastIndex)
        }
    }
}
