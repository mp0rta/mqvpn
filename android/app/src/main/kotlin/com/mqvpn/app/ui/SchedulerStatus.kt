// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.ui

import com.mqvpn.sdk.core.model.MqvpnConfig.Scheduler
import com.mqvpn.sdk.core.model.TunnelInfo

private fun Scheduler.label(): String = when (this) {
    Scheduler.MIN_RTT -> "minrtt"
    Scheduler.WLB -> "wlb"
    Scheduler.WLB_UDP_PIN -> "wlb_udp_pin"
    Scheduler.BACKUP_FEC -> "backup_fec"
    Scheduler.FAILOVER -> "failover"
}

/** Dashboard line for the server's effective scheduler; null when there is nothing to say. */
fun serverSchedulerLine(info: TunnelInfo): String? {
    val server = info.serverScheduler
    val requested = info.requestedScheduler
    if (server == null) {
        return requested?.let { "Server scheduler: unknown (the server does not report it)" }
    }
    val base = "Server scheduler: ${server.label()}"
    if (requested == null || requested == server) return base
    val why = if (server == Scheduler.BACKUP_FEC) {
        "the server's backup_fec cannot be switched"
    } else {
        "check AllowClientScheduler on the server"
    }
    return "$base (your setting ${requested.label()} is not applied — $why)"
}
