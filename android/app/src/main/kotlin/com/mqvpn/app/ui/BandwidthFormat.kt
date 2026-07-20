// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import java.util.Locale

/** Round up to 1/2/5 × 10^n, minimum 10_000 (10 Kbps) so an idle chart keeps a stable axis. */
fun ceilNice(bps: Long): Long {
    var scale = 10_000L
    while (true) {
        for (m in longArrayOf(1L, 2L, 5L)) {
            val v = scale * m
            if (bps <= v) return v
        }
        scale *= 10
    }
}

/** SI (×1000) formatting: 0 -> "0", 750 -> "750 bps", 12_500 -> "12.5 Kbps". */
fun formatBps(bps: Long): String {
    if (bps == 0L) return "0"
    if (bps < 1_000L) return "$bps bps"
    val (div, unit) = when {
        bps < 1_000_000L -> 1_000.0 to "Kbps"
        bps < 1_000_000_000L -> 1_000_000.0 to "Mbps"
        else -> 1_000_000_000.0 to "Gbps"
    }
    val s = String.format(Locale.US, "%.1f", bps / div).removeSuffix(".0")
    return "$s $unit"
}
