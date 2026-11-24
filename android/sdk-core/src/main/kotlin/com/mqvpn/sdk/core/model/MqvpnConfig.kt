// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Parcelize
@Serializable
data class MqvpnConfig(
    /**
     * Bare host: a DNS name or an IP literal, no brackets, characters
     * 0x21-0x7E only, at most 253 characters after one trailing dot is
     * stripped. No trailing dot on a literal (enforced by the verifier, not
     * here). Anything the verifier rejects fails the TLS handshake as
     * "invalid host"; [hostIdentifierError] catches the structural cases up
     * front.
     */
    val serverAddress: String,
    val serverPort: Int = 443,
    /** Same rules as [serverAddress]; when set it is both the SNI and the name the certificate must match. */
    val tlsServerName: String? = null,
    val authKey: String,
    /**
     * Skip server certificate verification (self-signed test servers only).
     * With `false` the certificate is verified against the device CA store and
     * the app's network security config, and must match [tlsServerName] (or
     * [serverAddress]). With `true` the library logs
     * "insecure=1 overrides the configured certificate verifier" once at
     * client creation: expected, it means verification is off.
     */
    val insecure: Boolean = false,
    val multipathEnabled: Boolean = true,
    val scheduler: Scheduler = Scheduler.MIN_RTT,
    /** Ask the server to use [scheduler] for this connection (it may refuse). */
    val requestServerScheduler: Boolean = false,
    /** Congestion control for what this client sends; the server keeps its own for downloads. */
    val cc: CongestionControl = CongestionControl.BBR2,
    /**
     * Minimum level of the library's log lines: this tunnel's own lines,
     * delivered to `MqvpnVpnService.onLog`, and the lines the library writes
     * process-wide, such as the UDP transport's and the reactor's, to logcat
     * under the tag `mqvpn`. The process-wide threshold is set when a tunnel is
     * created, so the tunnel created last decides it.
     */
    val logLevel: LogLevel = LogLevel.INFO,
    val reconnect: Boolean = true,
    val reconnectIntervalSec: Int = 5,
    val killSwitch: Boolean = false,
    val dnsServers: List<String> = listOf("8.8.8.8", "1.1.1.1"),
    val reorderEnabled: Boolean = false,
    val reorderProfile: ReorderProfile = ReorderProfile.CELLULAR_BOND,
    val reorderPorts: List<Int> = emptyList(),
    /** Send each UDP packet over every path at once (uplink). */
    val redundantEnabled: Boolean = false,
    /** Destination ports to duplicate; empty = all UDP. */
    val redundantPorts: List<Int> = emptyList(),
    val hybridEnabled: Boolean = false,
    val hybridTcpMode: HybridTcpMode = HybridTcpMode.AUTO,
    /**
     * Use a Bluetooth-tethered network as a path, and keep it connected next
     * to the others. With `false` a Bluetooth network is never a path, even
     * when Android connects it on its own.
     */
    val bluetoothPathEnabled: Boolean = false,
    /**
     * Largest IP packet the network carries (1280-9000), to size QUIC packets
     * for; 0 = the default packet size. With [pmtud] it is the upper limit.
     */
    val pathMtu: Int = 0,
    /**
     * Discover the path MTU: packets start at a size every path carries and
     * grow while larger probes get through, and go back down if the path
     * gets smaller. The server must enable it too. Android sets the TUN MTU
     * once, when the tunnel comes up, so it stays at 1280 here: the tunnel
     * survives a path that gets smaller, but uploads do not use a larger
     * discovered size.
     */
    val pmtud: Boolean = false,
    // Appended fields only below this line: callers may construct positionally.
    /** Use Wi-Fi networks as paths. Fixed when the tunnel starts. */
    val wifiPathEnabled: Boolean = true,
    /** Use cellular networks as paths. Fixed when the tunnel starts. */
    val cellularPathEnabled: Boolean = true,
    /** Use Ethernet networks as paths. Fixed when the tunnel starts. */
    val ethernetPathEnabled: Boolean = true,
) : Parcelable {

    @Serializable
    enum class Scheduler(val native: Int) {
        MIN_RTT(0),
        WLB(1),
        BACKUP_FEC(2),
        WLB_UDP_PIN(3),

        /** One path carries the traffic; cellular paths are backups, used only while no other path works. */
        FAILOVER(4),
    }

    @Serializable
    enum class CongestionControl(val native: Int) {
        BBR2(0),
        BBR(1),
        CUBIC(2),
    }

    @Serializable
    enum class LogLevel(val native: Int) {
        DEBUG(0),
        INFO(1),
        WARN(2),
        ERROR(3),
    }

    @Serializable
    enum class ReorderProfile(val native: Int) {
        CELLULAR_BOND(3),   // preset: wait=50ms cap=1024
        FIBER_LTE(4),       // preset: wait=50ms cap=2048
    }

    @Serializable
    enum class HybridTcpMode(val native: Int) {
        STREAM(0),   // always use the TCP stream lane
        RAW(1),      // never (bypass the lane)
        AUTO(2),     // per-flow decision at SYN time (default)
    }

    private fun bareHostError(label: String, v: String): String? {
        if (v.isEmpty()) return "$label must not be empty"
        if (v.any { it.code !in 0x21..0x7E }) return "$label must be printable ASCII without spaces"
        if ('[' in v || ']' in v) return "$label must be a bare host without brackets"
        val stripped = if (v.endsWith('.')) v.dropLast(1) else v
        if (stripped.length > 253) return "$label is longer than 253 characters"
        return null
    }

    /**
     * Cheap pre-flight subset of the certificate verifier's host grammar (the
     * full grammar lives in sdk-native and is not reachable from here). Null
     * when both fields are non-empty, contain only characters 0x21-0x7E (no
     * spaces), have no brackets, and are at most 253 characters after one
     * trailing dot; null does not guarantee the verifier accepts the name.
     */
    fun hostIdentifierError(): String? =
        bareHostError("serverAddress", serverAddress) ?: tlsServerName?.let { bareHostError("tlsServerName", it) }

    fun toJson(): String = Json.encodeToString(serializer(), this)

    companion object {
        fun fromJson(json: String): MqvpnConfig =
            Json.decodeFromString(serializer(), json)
    }
}
