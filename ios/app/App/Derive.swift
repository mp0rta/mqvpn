// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
import Foundation

/// Port of android ui/Derive.kt + SchedulerStatus.kt. Foundation only: NEVPNStatus
/// enters as its raw Int.

enum Tone: Equatable { case ok, warn, muted }

enum VpnViewState: Equatable { case disconnected, connecting, connected, reconnecting, error(String) }

/// neStatus = NEVPNStatus.rawValue (invalid 0, disconnected 1, connecting 2,
/// connected 3, reasserting 4, disconnecting 5); clientState 5 = RECONNECTING.
/// Disconnecting is a brief passthrough (the power button is inert there).
func deriveViewState(neStatus: Int, clientState: Int32?, surfacedError: String?) -> VpnViewState {
    switch neStatus {
    case 2: return .connecting
    case 4: return .reconnecting
    case 3: return clientState == 5 ? .reconnecting : .connected
    default: return surfacedError.map { .error($0) } ?? .disconnected
    }
}

struct StatusView: Equatable { var title: String; var sub: String; var tone: Tone; var pulsing: Bool }

func statusView(_ state: VpnViewState, elapsed: String?) -> StatusView {
    switch state {
    case .connecting, .reconnecting:
        return StatusView(title: "Connecting…", sub: "Contacting server…", tone: .muted, pulsing: true)
    case .connected:
        return StatusView(title: "Connected", sub: "Protected · \(elapsed ?? fmtElapsed(0))", tone: .ok, pulsing: false)
    case .error(let m):
        return StatusView(title: "Not Connected", sub: m, tone: .warn, pulsing: false)
    case .disconnected:
        return StatusView(title: "Not Connected", sub: "Tap the button to connect and protect your traffic",
                          tone: .muted, pulsing: false)
    }
}

enum TransportKind: Equatable { case wifi, cellular }

struct DerivePath: Equatable { var iface: String; var status: Int }

struct PathCardView2: Equatable {
    var kind: TransportKind
    var name: String
    var sub: String
    var available: Bool
    var on: Bool
    var active: Bool
    var rateBps: Int64
    var barFraction: Double
}

/// en* -> wifi, pdp_ip* -> cellular, else nil ("other": charted but no card).
func transportKind(iface: String) -> TransportKind? {
    if iface.hasPrefix("en") { return .wifi }
    if iface.hasPrefix("pdp_ip") { return .cellular }
    return nil
}

private let pathStatusActive = 1

func pathCardViews(paths: [DerivePath], available: Set<TransportKind>, sample: BandwidthSample?) -> [PathCardView2] {
    let kinds: [TransportKind] = [.wifi, .cellular]
    let rates = kinds.map { k in
        paths.filter { transportKind(iface: $0.iface) == k }
            .reduce(Int64(0)) { $0 + Int64(sample?.perPathDl[$1.iface] ?? 0) }
    }
    let maxRate = rates.max() ?? 0
    return kinds.enumerated().map { i, k in
        let mine = paths.filter { transportKind(iface: $0.iface) == k }
        let avail = available.contains(k)
        let sub: String
        if !avail { sub = "Not connected" }
        else if k == .cellular { sub = "May use mobile data" }
        else { sub = mine.first?.iface ?? "Ready" }
        let act = mine.contains { $0.status == pathStatusActive }
        return PathCardView2(kind: k, name: k == .wifi ? "Wi-Fi" : "Cellular", sub: sub, available: avail,
                             on: avail, active: act, rateBps: rates[i],
                             barFraction: maxRate > 0 ? Double(rates[i]) / Double(maxRate) : 0)
    }
}

/// Android HomeScreen: m = available && active cards, n = those moving > 1 Mbps.
func usingCounts(cards: [PathCardView2]) -> (n: Int, m: Int) {
    let used = cards.filter { $0.available && $0.active }
    return (used.filter { $0.rateBps > 1_000_000 }.count, used.count)
}

func fmtMbps(_ bps: Double) -> String {
    let v = bps / 1_000_000.0
    return String(format: v >= 100 ? "%.0f" : "%.1f", v)
}

func fmtElapsed(_ sec: Int64) -> String {
    let h = sec / 3600, m = (sec % 3600) / 60, s = sec % 60
    return h > 0 ? String(format: "%d:%02d:%02d", h, m, s) : String(format: "%02d:%02d", m, s)
}

func fmtBytes(_ b: UInt64) -> String {
    let mb = Double(b) / 1_000_000.0
    return mb < 1000 ? String(format: "%.0f MB", mb) : String(format: "%.2f GB", mb / 1000)
}

/// mqvpn_scheduler_t: MINRTT 0, WLB 1, BACKUP_FEC 2, WLB_UDP_PIN 3.
private func schedulerLabel(_ v: Int32) -> String {
    switch v {
    case 0: return "minrtt"
    case 1: return "wlb"
    case 2: return "backup_fec"
    case 3: return "wlb_udp_pin"
    default: return "unknown(\(v))"
    }
}

func serverSchedulerLine(requested: Int32?, server: Int32?) -> String? {
    guard let server = server else {
        return requested != nil ? "Server scheduler: unknown (the server does not report it)" : nil
    }
    let base = "Server scheduler: \(schedulerLabel(server))"
    guard let requested = requested, requested != server else { return base }
    let why = server == 2 ? "the server's backup_fec cannot be switched" : "check AllowClientScheduler on the server"
    return "\(base) (your setting \(schedulerLabel(requested)) is not applied — \(why))"
}

/// Only meaningful when a scheduler was requested (Android: null otherwise).
func schedulerApplied(requested: Int32?, server: Int32?) -> Bool {
    requested != nil && server == requested
}
