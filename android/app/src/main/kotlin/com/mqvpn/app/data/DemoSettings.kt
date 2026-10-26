// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.data

import com.mqvpn.sdk.core.model.MqvpnConfig

/**
 * Plain, persistable settings model backing the demo app's settings screen.
 * No Android imports: defaults, tolerant enum decode, port-text parsing,
 * and validation are all pure functions so they can be unit tested without
 * an Android runtime.
 */
data class DemoSettings(
    val serverAddress: String = "",
    val serverPort: Int = 443,
    val tlsServerName: String = "",
    val authKey: String = "",
    val insecure: Boolean = false,
    val killSwitch: Boolean = false,
    val reorderEnabled: Boolean = false,
    val reorderProfile: String = MqvpnConfig.ReorderProfile.CELLULAR_BOND.name,
    val reorderPorts: String = "443",
    val redundantEnabled: Boolean = false,
    val redundantPorts: String = "",
    val hybridEnabled: Boolean = false,
    val hybridTcpMode: String = MqvpnConfig.HybridTcpMode.AUTO.name,
    val bluetoothPathEnabled: Boolean = false,
    val pathWifi: Boolean = true,
    val pathCellular: Boolean = true,
    val pathEthernet: Boolean = true,
    val autoReconnect: Boolean = true,
    val scheduler: String = SchedulerChoice.DEFAULT.name,
) {
    enum class SchedulerChoice { DEFAULT, MIN_RTT, WLB }

    fun schedulerChoice(): SchedulerChoice =
        SchedulerChoice.entries.firstOrNull { it.name == scheduler } ?: SchedulerChoice.DEFAULT

    fun reorderProfileEnum(): MqvpnConfig.ReorderProfile =
        MqvpnConfig.ReorderProfile.entries.firstOrNull { it.name == reorderProfile }
            ?: MqvpnConfig.ReorderProfile.CELLULAR_BOND

    fun hybridTcpModeEnum(): MqvpnConfig.HybridTcpMode =
        MqvpnConfig.HybridTcpMode.entries.firstOrNull { it.name == hybridTcpMode }
            ?: MqvpnConfig.HybridTcpMode.AUTO

    fun parsedReorderPorts(): List<Int> =
        reorderPorts.split(",")
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }

    private fun redundantTokens(): List<String> = redundantPorts.split(",").map { it.trim() }

    /** Distinct valid ports; call only when [redundantPortsValid]. */
    fun parsedRedundantPorts(): List<Int> =
        if (redundantPorts.isBlank()) emptyList()
        else redundantTokens().mapNotNull { it.toIntOrNull() }.filter { it in 1..65535 }.distinct()

    /** Same rule as the C parser: all-or-nothing, never degrades to "all UDP". */
    fun redundantPortsValid(): Boolean {
        if (redundantPorts.isBlank()) return true
        val t = redundantPorts.trim()
        val tokens = redundantTokens()
        return t.length < 255 && tokens.size <= MAX_REDUNDANT_PORTS &&
            tokens.all { (it.toIntOrNull() ?: -1) in 1..65535 }
    }

    fun distinctValidPortCount(): Int = parsedReorderPorts().distinct().size

    /** Tokens that are non-blank after trimming but don't parse as a valid 1..65535 port. */
    fun invalidPortTokens(): List<String> =
        reorderPorts.split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() && (it.toIntOrNull() ?: -1) !in 1..65535 }

    /** Fails on an invalid redundant port list instead of widening it to all UDP. */
    fun toMqvpnConfig(): MqvpnConfig {
        require(!redundantEnabled || redundantPortsValid()) {
            "Redundant Ports is not a valid port list"
        }
        return MqvpnConfig(
            serverAddress = serverAddress.trim(),
            serverPort = serverPort,
            tlsServerName = tlsServerName.trim().ifEmpty { null },
            authKey = authKey.trim(),
            insecure = insecure,
            killSwitch = killSwitch,
            reorderEnabled = reorderEnabled,
            reorderProfile = reorderProfileEnum(),
            reorderPorts = parsedReorderPorts(),
            redundantEnabled = redundantEnabled,
            redundantPorts = parsedRedundantPorts(),
            hybridEnabled = hybridEnabled,
            hybridTcpMode = hybridTcpModeEnum(),
            bluetoothPathEnabled = bluetoothPathEnabled,
            wifiPathEnabled = pathWifi,
            cellularPathEnabled = pathCellular,
            ethernetPathEnabled = pathEthernet,
            reconnect = autoReconnect,
            scheduler = when (schedulerChoice()) {
                SchedulerChoice.WLB -> MqvpnConfig.Scheduler.WLB
                else -> MqvpnConfig.Scheduler.MIN_RTT
            },
            requestServerScheduler = schedulerChoice() != SchedulerChoice.DEFAULT,
            // bbr2 slows a path down after random losses, which can leave it too slow for its full copy.
            cc = if (redundantEnabled) MqvpnConfig.CongestionControl.BBR else MqvpnConfig.CongestionControl.BBR2,
        )
    }

    fun hostValid(): Boolean = serverAddress.trim().isNotBlank()

    fun portValid(): Boolean = serverPort in 1..65535

    fun reorderPortsValid(): Boolean = !reorderEnabled || parsedReorderPorts().isNotEmpty()

    /** With every transport off no path is admitted and the tunnel never connects. */
    fun pathPolicyValid(): Boolean = pathWifi || pathCellular || pathEthernet || bluetoothPathEnabled

    fun isValid(): Boolean = hostValid() && portValid() && reorderPortsValid() &&
        (!redundantEnabled || redundantPortsValid()) && pathPolicyValid()

    companion object {
        /**
         * Upper bound on distinct reorder ports the platform layer honors.
         * Mirrors `MQVPN_REORDER_MAX_RULES` in
         * `android/sdk-core/src/main/kotlin/com/mqvpn/sdk/core/internal/ReorderPlan.kt`
         * (and `src/reorder.h`) — keep in sync by hand; grep for
         * `MQVPN_REORDER_MAX_RULES` if either side changes.
         */
        const val MAX_REORDER_PORTS = 16

        /** Mirrors `MQVPN_REDUNDANT_MAX_PORTS` in libmqvpn. */
        const val MAX_REDUNDANT_PORTS = 16
    }
}

/** The three desktop-style "how to split traffic" choices. */
enum class SplitChoice { THROUGHPUT, LOW_LATENCY, REDUNDANT }

/** DEFAULT is shown as LOW_LATENCY (its real conversion is MIN_RTT without a server request). */
fun DemoSettings.splitChoice(): SplitChoice = when {
    redundantEnabled -> SplitChoice.REDUNDANT
    schedulerChoice() == DemoSettings.SchedulerChoice.WLB -> SplitChoice.THROUGHPUT
    else -> SplitChoice.LOW_LATENCY
}

fun DemoSettings.applySplitChoice(c: SplitChoice): DemoSettings = when (c) {
    SplitChoice.THROUGHPUT -> copy(scheduler = DemoSettings.SchedulerChoice.WLB.name, redundantEnabled = false)
    SplitChoice.LOW_LATENCY -> copy(scheduler = DemoSettings.SchedulerChoice.MIN_RTT.name, redundantEnabled = false)
    SplitChoice.REDUNDANT -> copy(scheduler = DemoSettings.SchedulerChoice.MIN_RTT.name, redundantEnabled = true)
}
