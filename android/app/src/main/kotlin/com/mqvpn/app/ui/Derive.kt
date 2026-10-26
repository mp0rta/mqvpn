// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.network.PathType
import java.util.Locale

// Presentation mapping ported from mqvpn-desktop/src/derive.ts. No Compose imports.

enum class Tone { OK, WARN, MUTED }

data class StatusView(val title: String, val sub: String, val tone: Tone, val pulsing: Boolean)

/** derive.ts statusView (99-120). The "N connections down" suffix is not ported: Android has no per-path role/wasActive. */
fun statusView(state: MqvpnState, elapsed: String?): StatusView = when (state) {
    // derive.ts:101 sub is connStep; the first step text is store.svelte.ts CONNECT_STEPS[0]
    is MqvpnState.Connecting, is MqvpnState.Reconnecting ->
        StatusView("Connecting…", "Contacting server…", Tone.MUTED, true)
    is MqvpnState.Connected ->
        StatusView("Connected", "Protected · ${elapsed ?: fmtElapsed(0)}", Tone.OK, false)
    is MqvpnState.Error -> StatusView("Not Connected", state.error.message, Tone.WARN, false)
    MqvpnState.Disconnected -> StatusView(
        "Not Connected", "Tap the button to connect and protect your traffic", Tone.MUTED, false,
    )
}

data class PathCardView(
    val key: String, val name: String, val sub: String,
    val type: PathType, val available: Boolean, val active: Boolean,
    val rateBps: Long, val barFraction: Float,
)

private val FIXED_TRANSPORTS = listOf(PathType.WIFI, PathType.CELLULAR, PathType.ETHERNET, PathType.BLUETOOTH)

private fun PathType.cardName() = when (this) {
    PathType.WIFI -> "Wi-Fi"
    PathType.CELLULAR -> "Cellular"
    PathType.ETHERNET -> "Ethernet"
    PathType.BLUETOOTH -> "Bluetooth"
    PathType.OTHER -> "Other"
}

/** Iface names are "<type>-<n>" (NetworkMonitor.networkName); legacy prefixes kept. */
private fun ifaceType(iface: String): PathType = when {
    iface.startsWith("wifi") || iface.startsWith("wlan") -> PathType.WIFI
    iface.startsWith("cellular") || iface.startsWith("rmnet") || iface.startsWith("ccmni") -> PathType.CELLULAR
    iface.startsWith("bluetooth") || iface.startsWith("bnep") -> PathType.BLUETOOTH
    iface.startsWith("ethernet") || iface.startsWith("eth") -> PathType.ETHERNET
    else -> PathType.OTHER
}

private const val PATH_STATUS_ACTIVE = 1 // see pathStatusName in EventLog.kt

/** Unavailable sub-lines: desktop "No cable" (backend.ts:86) and the phone mock's Bluetooth line. */
private fun PathType.unavailableSub() = when (this) {
    PathType.ETHERNET -> "No cable"
    PathType.BLUETOOTH -> "Not connected to a paired device"
    else -> "Not connected"
}

fun pathCardViews(paths: List<PathInfo>, available: Set<PathType>, sample: BandwidthSample?): List<PathCardView> {
    // rateBps = download rate: desktop Paths.svelte shows pathViews().rateText = fmtRate(p.rate)
    // (derive.ts:77) and store.svelte.ts:209 defines p.rate as the path's `dl`.
    val rates = FIXED_TRANSPORTS.associateWith { t ->
        paths.filter { ifaceType(it.iface) == t }.sumOf { sample?.perPathDlBps?.get(it.iface) ?: 0L }
    }
    val max = rates.values.maxOrNull() ?: 0L
    return FIXED_TRANSPORTS.map { t ->
        val mine = paths.filter { ifaceType(it.iface) == t }
        val avail = t in available
        val rate = rates.getValue(t)
        PathCardView(
            key = t.name.lowercase(),
            name = t.cardName(),
            sub = when {
                !avail -> t.unavailableSub()
                t == PathType.CELLULAR -> "May use mobile data"
                else -> mine.firstOrNull()?.iface ?: "Ready"
            },
            type = t,
            available = avail,
            active = mine.any { it.status == PATH_STATUS_ACTIVE },
            rateBps = rate,
            barFraction = if (max > 0) rate.toFloat() / max else 0f,
        )
    }
}

/** derive.ts fmtMbps (235): one decimal, none from 100 up. */
fun fmtMbps(bps: Long): String {
    val v = bps / 1_000_000.0
    return String.format(Locale.US, if (v >= 100) "%.0f" else "%.1f", v)
}

/** derive.ts fmtEl (213-220): mm:ss, h:mm:ss (hours unpadded) from one hour. */
fun fmtElapsed(sec: Long): String {
    val h = sec / 3600
    val m = (sec % 3600) / 60
    val s = sec % 60
    return if (h > 0) String.format(Locale.US, "%d:%02d:%02d", h, m, s) else String.format(Locale.US, "%02d:%02d", m, s)
}
