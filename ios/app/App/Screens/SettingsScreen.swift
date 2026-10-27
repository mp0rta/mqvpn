// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

enum SettingsRoute: Hashable { case reorder, hybrid, redundant }

private let addressHint = "Enter a server address, e.g. vpn.example.com:443"

/// Port of android SettingsScreen.kt. Everything is locked while a session is live.
struct SettingsScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    @ObservedObject var eventLog: EventLog
    let onNavigate: (SettingsRoute) -> Void
    let onRunSetup: () -> Void
    @State private var keyShown = false
    @State private var advOpen = false
    @State private var logOpen = false

    private static let clock: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f
    }()
    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    var body: some View {
        let m = controller.settings
        let s = m.draft
        let errors = m.fieldErrors
        let editable = controller.isEditable
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Settings").font(.system(size: 20, weight: .bold)).foregroundColor(mq.text)
                if !editable {
                    Text("Disconnect to change settings.").font(.system(size: 12.5)).lineSpacing(5).foregroundColor(mq.t2)
                }
                if let e = m.saveError { Text(e).font(.system(size: 12)).foregroundColor(mq.red) }
                server(m, s, errors, editable)
                protection(m, s, editable)
                advanced(m, s, errors, editable)
                eventLogSection
                Button(action: onRunSetup) {
                    Text("Run setup assistant again").font(.system(size: 13, weight: .medium))
                        .foregroundColor(editable ? mq.accent : mq.t2).padding(12).frame(maxWidth: .infinity)
                        .background(mq.card, in: RoundedRectangle(cornerRadius: 12))
                }.buttonStyle(.plain).disabled(!editable)
                // App Store guideline 5.1.1: privacy policy link inside the app.
                Link("Privacy policy", destination: URL(string: "https://docs.mqvpn.org/privacy")!)
                    .font(.system(size: 12)).foregroundColor(mq.accent).frame(maxWidth: .infinity)
                Text("mqvpn \(version) · MASQUE over Multipath QUIC").font(.system(size: 10.5)).foregroundColor(mq.t2)
                    .multilineTextAlignment(.center).frame(maxWidth: .infinity).padding(.bottom, 6)
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }

    // MARK: Server

    private func server(_ m: SettingsCore, _ s: AppDraft, _ errors: [AppDraft.Field: String], _ editable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionLabel("Server")
            MqCard(vPad: 4) {
                VStack(alignment: .leading, spacing: 0) {
                    let addrNote: String? = s.server == nil
                        ? (errors[.address] == AppDraft.errPort ? AppDraft.errPort : addressHint) : nil
                    FieldBox(label: "Address", note: addrNote, noteIsError: addrNote != nil) {
                        CommitField(label: "Address", value: s.addressText, enabled: editable, keyboard: .URL) { t in
                            m.update { $0.addressText = t }
                        }
                    }.padding(.vertical, 8)
                    Hairline()
                    FieldBox(label: "TLS server name",
                             note: "The name on the server's certificate, if you connect by IP address") {
                        CommitField(label: "TLS server name", placeholder: "Same as the address",
                                    value: s.tlsServerName, enabled: editable) { t in m.update { $0.tlsServerName = t } }
                    }.padding(.vertical, 8)
                    Hairline()
                    FieldBox(label: "Access key", trailing: AnyView(ShowHide(shown: $keyShown))) {
                        CommitField(label: "Access key", value: s.authKey, enabled: editable, secure: !keyShown) { t in
                            m.update { $0.authKey = t }
                        }
                    }.padding(.vertical, 8)
                    Hairline()
                    ToggleRow(title: "Trust self-signed certificate", caption: "Only for test servers you own",
                              isOn: m.binding(\.insecure), enabled: editable, last: true)
                }
            }
        }
    }

    private func protection(_ m: SettingsCore, _ s: AppDraft, _ editable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionLabel("Protection")
            MqCard(vPad: 4) {
                VStack(spacing: 0) {
                    ToggleRow(title: "Kill switch", caption: "If the VPN drops, block all traffic so nothing leaks",
                              isOn: m.binding(\.protection.killSwitch), enabled: editable)
                    ToggleRow(title: "Reconnect automatically", caption: "Retry every 5 seconds if the server is unreachable",
                              isOn: m.binding(\.protection.autoReconnect), enabled: editable, last: true)
                }
            }
        }
    }

    // MARK: Advanced

    private static let splitOptions: [(SplitChoice, String, String)] = [
        (.throughput, "Throughput", "(recommended) — by each connection’s capacity"),
        (.lowLatency, "Low latency", "— always pick the fastest-responding path"),
        (.redundant, "Redundant",
         "— sends UDP uploads on every connection at once, for streams that tolerate duplicates (SRT, RIST, RTP); uses more data"),
    ]

    private func advanced(_ m: SettingsCore, _ s: AppDraft, _ errors: [AppDraft.Field: String], _ editable: Bool) -> some View {
        let choice = s.split.choice
        let info = viewState(controller) == .connected ? controller.snapshot?.tunnel : nil
        let applied: Bool? = info?.requestedScheduler == nil ? nil
            : schedulerApplied(requested: info?.requestedScheduler, server: info?.serverScheduler)
        let portsNote = s.reorder.portsText.trimmingCharacters(in: .whitespaces)
        return VStack(alignment: .leading, spacing: 7) {
            Disclosure(label: "Advanced", open: advOpen) { advOpen.toggle() }
            if advOpen {
                MqCard(vPad: 4) {
                    VStack(spacing: 0) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("How traffic is split").font(.system(size: 13)).foregroundColor(mq.text)
                            ForEach(Self.splitOptions, id: \.0) { opt, label, dim in
                                RadioRow(label: label, dim: dim, selected: opt == choice, enabled: editable)
                                    .onTapGesture {
                                        // Re-tapping the shown option must not rewrite a preserved legacy combo.
                                        if editable && opt != choice { m.update { $0.split = $0.split.tapped(opt) } }
                                    }
                                if opt == choice, let applied {
                                    let note = applied ? "✓ applied by the server"
                                        : serverSchedulerLine(requested: info?.requestedScheduler, server: info?.serverScheduler)
                                            ?? "not applied by the server"
                                    Text(note).font(.system(size: 11)).foregroundColor(applied ? mq.t2 : mq.orange)
                                        .padding(.leading, 26)
                                }
                                if opt == .redundant && opt == choice {
                                    Button { onNavigate(.redundant) } label: {
                                        Text("Choose UDP ports ›").font(.system(size: 12)).foregroundColor(mq.accent)
                                    }.buttonStyle(.plain).padding(.leading, 26)
                                }
                            }
                        }.padding(.vertical, 11).frame(maxWidth: .infinity, alignment: .leading)
                        Hairline()
                        ToggleRow(title: "Smooth out packet order",
                                  caption: "Re-order packets that arrive mixed-up across connections"
                                    + (portsNote.isEmpty ? "" : " (UDP port\(portsNote.contains(",") ? "s" : "") \(portsNote))"),
                                  isOn: m.binding(\.reorder.enabled), enabled: editable, onOpen: { onNavigate(.reorder) })
                        if let e = errors[.reorderPorts] {
                            Text(e).font(.system(size: 11)).foregroundColor(mq.red).padding(.bottom, 8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        ToggleRow(title: "TCP boost",
                                  caption: "Carry TCP over its own lane — " + HybridDetailScreen.modeName(s.hybrid.tcpMode),
                                  isOn: m.binding(\.hybrid.enabled), enabled: editable, last: true,
                                  onOpen: { onNavigate(.hybrid) })
                    }
                }
            }
        }
    }

    // MARK: Event log

    private var eventLogSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            Disclosure(label: "Event log (\(eventLog.events.count))", open: logOpen) { logOpen.toggle() }
            if logOpen {
                MqCard(vPad: 4) {
                    VStack(spacing: 0) {
                        if eventLog.events.isEmpty {
                            Text("No events.").font(.system(size: 12)).foregroundColor(mq.t2).padding(.vertical, 11)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        ForEach(Array(eventLog.events.enumerated()), id: \.element.id) { i, e in
                            HStack(spacing: 8) {
                                Text(Self.clock.string(from: e.time)).font(.system(size: 11)).foregroundColor(mq.t2)
                                StatusDot(color: dot(eventLevel(e.kind)), size: 7)
                                Text(eventText(e.kind)).font(.system(size: 12)).foregroundColor(mq.text).lineSpacing(3)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }.padding(.vertical, 8)
                            if i != eventLog.events.count - 1 { Hairline() }
                        }
                    }
                }
            }
        }
    }

    private func dot(_ l: EventLevel) -> Color {
        switch l { case .error: return mq.red; case .warn: return mq.orange; case .info: return mq.t2 }
    }
}

private struct Disclosure: View {
    @Environment(\.mq) private var mq
    let label: String
    let open: Bool
    let toggle: () -> Void
    var body: some View {
        Button(action: toggle) {
            HStack(spacing: 6) {
                SectionLabel(label)
                Text(open ? "▼" : "▶").font(.system(size: 10)).foregroundColor(mq.t2)
            }.padding(.vertical, 4)
        }.buttonStyle(.plain)
    }
}
