// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
import Foundation

/// Port of android ui/Derive.kt + SchedulerStatus.kt. Foundation only: NEVPNStatus
/// enters as its raw Int.

enum Tone: Equatable { case ok, warn, muted }

enum VpnViewState: Equatable { case disconnected, connecting, connected, reconnecting, error(String) }

/// NEVPNStatus raw values: NetworkExtension is not importable in the pure build.
enum NEStatusRaw {
    static let connecting = 2, connected = 3, reasserting = 4
}

/// Disconnecting is a brief passthrough (the power button is inert there).
func deriveViewState(neStatus: Int, clientState: Int32?, surfacedError: String?) -> VpnViewState {
    switch neStatus {
    case NEStatusRaw.connecting: return .connecting
    case NEStatusRaw.reasserting: return .reconnecting
    case NEStatusRaw.connected:
        return clientState == CoreClientState.reconnecting.rawValue ? .reconnecting : .connected
    default: return surfacedError.map { .error($0) } ?? .disconnected
    }
}

/// Title + subtitle under the power button.
struct StatusLine: Equatable { var title: String; var sub: String; var tone: Tone; var pulsing: Bool }

func statusLine(_ state: VpnViewState, elapsed: String?) -> StatusLine {
    switch state {
    case .connecting, .reconnecting:
        return StatusLine(title: "Connecting…", sub: "Contacting server…", tone: .muted, pulsing: true)
    case .connected:
        return StatusLine(title: "Connected", sub: "Protected · \(elapsed ?? fmtElapsed(0))", tone: .ok, pulsing: false)
    case .error(let m):
        return StatusLine(title: "Not Connected", sub: m, tone: .warn, pulsing: false)
    case .disconnected:
        return StatusLine(title: "Not Connected", sub: "Tap the button to connect and protect your traffic",
                          tone: .muted, pulsing: false)
    }
}

extension TransportKind {
    var title: String {
        switch self {
        case .wifi: return "Wi-Fi"
        case .cellular: return "Cellular"
        }
    }
}

/// One live path from the snapshot: interface name, raw mqvpn_path_status_t and
/// the transport the provider bound it to (nil = charted, but no card).
struct LivePath: Equatable { var iface: String; var status: Int32; var kind: TransportKind? }

/// Display model of one transport row (one per TransportKind).
struct PathCard: Equatable {
    var kind: TransportKind
    var sub: String
    var available: Bool
    var active: Bool
    var rateBps: Int64            // download only (perPathDl), as on Android
    var barFraction: Double
    var name: String { kind.title }
}

func pathCards(paths: [LivePath], available: Set<TransportKind>, sample: BandwidthSample?) -> [PathCard] {
    var cards = TransportKind.allCases.map { k -> PathCard in
        let mine = paths.filter { $0.kind == k }
        let avail = available.contains(k)
        let sub: String
        if !avail { sub = "Not connected" }
        else if k == .cellular { sub = "May use mobile data" }
        else { sub = mine.first?.iface ?? "Ready" }
        return PathCard(kind: k, sub: sub, available: avail,
                        active: mine.contains { $0.status == CorePathStatus.active.rawValue },
                        rateBps: mine.reduce(Int64(0)) { $0 + Int64(sample?.perPathDl[$1.iface] ?? 0) },
                        barFraction: 0)
    }
    let maxRate = cards.map(\.rateBps).max() ?? 0
    if maxRate > 0 { for i in cards.indices { cards[i].barFraction = Double(cards[i].rateBps) / Double(maxRate) } }
    return cards
}

extension PathPolicy {
    /// The policy with `kind` set to `on`, or nil when that would turn the last
    /// connection off (never persistable).
    func setting(_ kind: TransportKind, on: Bool) -> PathPolicy? {
        var p = self
        p[kind] = on
        return p.anyEnabled ? p : nil
    }
}

/// Android HomeScreen: m = available && active cards, n = those moving > 1 Mbps.
func usingCounts(cards: [PathCard]) -> (n: Int, m: Int) {
    let used = cards.filter { $0.available && $0.active }
    return (used.filter { $0.rateBps > 1_000_000 }.count, used.count)
}

func fmtMbps(_ bps: Double) -> String {
    let v = bps / 1_000_000.0
    return String(format: v >= 100 ? "%.0f" : "%.1f", v)
}

/// A path card's rate: download only, so it carries the ↓ the Home rate tile uses.
func fmtDownloadRate(_ bps: Int64) -> String { "↓ \(fmtMbps(Double(bps))) Mbps" }

func fmtElapsed(_ sec: Int64) -> String {
    let h = sec / 3600, m = (sec % 3600) / 60, s = sec % 60
    return h > 0 ? String(format: "%d:%02d:%02d", h, m, s) : String(format: "%02d:%02d", m, s)
}

func fmtBytes(_ b: UInt64) -> String {
    let mb = Double(b) / 1_000_000.0
    return mb < 1000 ? String(format: "%.0f MB", mb) : String(format: "%.2f GB", mb / 1000)
}

private func schedulerLabel(_ v: Int32) -> String {
    Scheduler(rawValue: v)?.label ?? "unknown(\(v))"
}

func serverSchedulerLine(requested: Int32?, server: Int32?) -> String? {
    guard let server = server else {
        return requested != nil ? "Server scheduler: unknown (the server does not report it)" : nil
    }
    let base = "Server scheduler: \(schedulerLabel(server))"
    guard let requested = requested, requested != server else { return base }
    let why = Scheduler(rawValue: server) == .backupFec ? "the server's backup_fec cannot be switched" : "check AllowClientScheduler on the server"
    return "\(base) (your setting \(schedulerLabel(requested)) is not applied — \(why))"
}

/// Only meaningful when a scheduler was requested (Android: null otherwise).
func schedulerApplied(requested: Int32?, server: Int32?) -> Bool {
    requested != nil && server == requested
}
