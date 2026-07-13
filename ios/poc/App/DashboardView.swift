// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Single-screen development dashboard: connection header, per-path cards, a
/// one-line stats row, and the bulk-download load tool. Purely a view over the
/// controller's published snapshot — no IPC or diff logic lives here.
struct DashboardView: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var eventLog: EventLog

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                connectionHeader
                pathSection
                statsRow
                BulkDownloadView()
                eventSection
            }
            .padding()
        }
        .task { await controller.loadOrCreateManager() }
    }

    // MARK: - Connection header

    private var connectionHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                StatusBadge(text: controller.statusText.uppercased(), color: headerColor)
                if let cs = controller.snapshot?.clientState {
                    Text("core: \(Self.clientStateName(cs))")
                        .font(.caption).foregroundColor(.secondary)
                }
                Spacer()
            }
            HStack(spacing: 12) {
                Button("Start") { controller.start() }
                    .buttonStyle(.borderedProminent)
                Button("Stop") { controller.stop() }
                    .buttonStyle(.bordered)
            }
        }
    }

    /// NEVPNStatus drives the badge; any recorded load/start error wins as red.
    private var headerColor: Color {
        if controller.statusText.contains("error") { return .red }
        switch controller.status {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        default: return .gray
        }
    }

    // Raw values mirror mqvpn_client_state_t in libmqvpn.h (App target does not
    // link the library); all seven enumerators are covered.
    static func clientStateName(_ s: Int32) -> String {
        switch s {
        case 0: return "IDLE"
        case 1: return "CONNECTING"
        case 2: return "AUTHENTICATING"
        case 3: return "TUNNEL_READY"
        case 4: return "ESTABLISHED"
        case 5: return "RECONNECTING"
        case 6: return "CLOSED"
        default: return "?(\(s))"
        }
    }

    // MARK: - Paths

    private var pathSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Paths").font(.headline)
            if let paths = controller.snapshot?.paths, !paths.isEmpty {
                ForEach(paths, id: \.name) { p in
                    PathCardView(path: p, rateMbps: controller.pathRates[p.name])
                }
            } else {
                Text("no data").font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Stats row

    private var statsRow: some View {
        HStack {
            stat("mem", Self.mbText(controller.snapshot?.footprint ?? 0))
            Divider().frame(height: 28)
            stat("uptime", uptimeText)
            Divider().frame(height: 28)
            stat("total", Self.mbText(totalBytes))
        }
        .frame(maxWidth: .infinity)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(.secondarySystemBackground)))
    }

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.subheadline.monospacedDigit())
            Text(label).font(.caption2).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    private var totalBytes: UInt64 {
        (controller.snapshot?.paths ?? []).reduce(0) { $0 + $1.txBytes + $1.rxBytes }
    }

    /// Uptime is provider-clock based (both fields come from the snapshot), so
    /// no client/provider clock skew enters the display.
    private var uptimeText: String {
        guard let s = controller.snapshot, let since = s.connectedSince else { return "—" }
        let secs = Int(max(0, s.timestamp - since))
        let h = secs / 3600, m = (secs % 3600) / 60, sec = secs % 60
        return h > 0 ? String(format: "%dh %02dm", h, m)
                     : String(format: "%dm %02ds", m, sec)
    }

    private static func mbText(_ b: UInt64) -> String {
        String(format: "%.1f MB", Double(b) / (1024 * 1024))
    }

    // MARK: - Event log

    private var eventSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Events").font(.headline)
            if eventLog.events.isEmpty {
                Text("—").font(.caption).foregroundColor(.secondary)
            } else {
                ForEach(eventLog.events) { e in
                    HStack(spacing: 8) {
                        Image(systemName: Self.eventIcon(e.kind))
                            .font(.caption2)
                            .foregroundColor(Self.eventColor(e.kind))
                            .frame(width: 16)
                        Text(Self.timeFormatter.string(from: e.time))
                            .font(.caption2.monospacedDigit())
                            .foregroundColor(.secondary)
                        Text(Self.eventText(e.kind)).font(.caption)
                        Spacer()
                    }
                }
            }
        }
    }

    // Structured events are named/colored here (the model stays View-free),
    // reusing the same raw→display tables as the header and path cards.
    static func eventText(_ k: LogEvent.Kind) -> String {
        switch k {
        case .coreState(let s):
            return "core → \(clientStateName(s))"
        case .pathAdded(let n, let s):
            return "\(n) added (\(PathCardView.statusName(s)))"
        case .pathRemoved(let n):
            return "\(n) removed"
        case .pathStatus(let n, let from, let to):
            return "\(n): \(PathCardView.statusName(from)) → \(PathCardView.statusName(to))"
        }
    }

    static func eventIcon(_ k: LogEvent.Kind) -> String {
        switch k {
        case .coreState: return "bolt.horizontal.circle"
        case .pathAdded: return "plus.circle"
        case .pathRemoved: return "minus.circle"
        case .pathStatus: return "arrow.triangle.2.circlepath"
        }
    }

    static func eventColor(_ k: LogEvent.Kind) -> Color {
        switch k {
        case .coreState: return .blue
        case .pathAdded: return .green
        case .pathRemoved: return .gray
        case .pathStatus(_, _, let to): return PathCardView.statusColor(to)
        }
    }

    static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

}
