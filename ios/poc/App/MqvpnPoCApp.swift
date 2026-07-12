// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

@main
struct MqvpnPoCApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var controller = TunnelController()

    var body: some Scene {
        WindowGroup {
            ContentView(controller: controller)
                // Foreground-only polling: pause IPC when not active to avoid
                // battery drain and pointless sendProviderMessage churn.
                .onChange(of: scenePhase) { phase in
                    controller.setScenePhaseActive(phase == .active)
                }
        }
    }
}

/// Minimal PoC container controller: load/save the one NETunnelProviderManager,
/// start/stop it, and — while foregrounded and connected — poll the provider
/// for a development snapshot over `sendProviderMessage`.
@MainActor
final class TunnelController: ObservableObject {
    static let providerBundleID = "com.mp0rta.mqvpnpoc.PacketTunnel"

    @Published var status: NEVPNStatus = .invalid
    @Published var statusText = "not loaded"
    @Published var snapshot: TunnelSnapshot?      // nil = no data
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var pollTimer: Timer?
    private var scenePhaseActive = true           // WindowGroup starts active

    func loadOrCreateManager() async {
        do {
            let existing = try await NETunnelProviderManager.loadAllFromPreferences()
            let m = existing.first ?? NETunnelProviderManager()
            if existing.isEmpty {
                let config = try PoCConfig.fromBundle()
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = Self.providerBundleID
                proto.serverAddress = config.serverHost
                m.protocolConfiguration = proto
                m.localizedDescription = "mqvpn PoC"
                m.isEnabled = true
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            manager = m
            attachObserver(to: m)
            updateStatus(m.connection.status)
        } catch {
            statusText = "load error: \(error.localizedDescription)"
        }
    }

    private func attachObserver(to manager: NETunnelProviderManager) {
        // NotificationCenter's completion closure is not MainActor-isolated
        // even with queue: .main (it is typed @Sendable by the SDK), so hop
        // explicitly before touching @MainActor state.
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self, weak manager] _ in
            Task { @MainActor in
                guard let self, let manager else { return }
                self.updateStatus(manager.connection.status)
            }
        }
    }

    private func updateStatus(_ s: NEVPNStatus) {
        status = s
        statusText = Self.describe(s)
        reconcilePolling()
    }

    func start() {
        guard let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            statusText = "start error: \(error.localizedDescription)"
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    // MARK: - Snapshot polling

    /// Called by the scene on activation changes; gates polling together with
    /// the connection state.
    func setScenePhaseActive(_ active: Bool) {
        scenePhaseActive = active
        reconcilePolling()
    }

    /// Single decision point: poll only while foregrounded AND the tunnel is
    /// up. When the tunnel is down, drop the snapshot so the UI shows no data.
    private func reconcilePolling() {
        let up = (status == .connected || status == .reasserting)
        if scenePhaseActive && up {
            startPolling()
        } else {
            stopPolling()
            if !up { snapshot = nil }
        }
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        poll()   // immediate first sample
        let t = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
        pollTimer = t
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func poll() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        do {
            // Payload is ignored by the provider (command-agnostic); an empty
            // request means "give me the latest snapshot".
            try session.sendProviderMessage(Data()) { [weak self] resp in
                Task { @MainActor in
                    guard let self else { return }
                    guard let resp, let snap = try? ProviderMessage.decode(resp) else {
                        self.snapshot = nil   // no data / undecodable — never crash
                        return
                    }
                    self.snapshot = snap
                }
            }
        } catch {
            snapshot = nil
        }
    }

    private static func describe(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown(\(s.rawValue))"
        }
    }
}

struct ContentView: View {
    @ObservedObject var controller: TunnelController
    @State private var bulkStatus = ""
    @State private var bulkRunning = false

    var body: some View {
        VStack(spacing: 16) {
            Text("mqvpn PoC").font(.title)
            Text(controller.statusText).font(.subheadline)
            HStack(spacing: 12) {
                Button("Start") { controller.start() }
                Button("Stop") { controller.stop() }
            }
            // Task 2 round-trip confirmation: raw snapshot (Task 3 replaces
            // this with the dashboard).
            Text(snapshotSummary).font(.caption.monospaced())
                .multilineTextAlignment(.leading)
            Button(bulkRunning ? "Downloading…" : "Bulk Download (60s)") {
                Task { await runBulkDownload() }
            }
            .disabled(bulkRunning)
            if !bulkStatus.isEmpty {
                Text(bulkStatus).font(.caption).multilineTextAlignment(.center)
            }
        }
        .padding()
        .task { await controller.loadOrCreateManager() }
    }

    private var snapshotSummary: String {
        guard let s = controller.snapshot else { return "snapshot: no data" }
        let paths = s.paths.map { "\($0.name) st=\($0.status) tx=\($0.txBytes) rx=\($0.rxBytes)" }
            .joined(separator: "\n")
        return "state=\(s.clientState) fp=\(s.footprint)\n\(paths)"
    }

    /// Sequential GETs against PoCConfig.bulkURL for ~60s: user-space
    /// traffic through the tunnel for the multipath load gate. Sequential
    /// (not concurrent) so a single active flow drives the gate's per-path
    /// striping observation instead of masking it behind connection fanout.
    private func runBulkDownload() async {
        guard let url = try? PoCConfig.fromBundle().bulkURL else {
            bulkStatus = "no bulkURL configured"
            return
        }
        bulkRunning = true
        defer { bulkRunning = false }
        let deadline = Date().addingTimeInterval(60)
        var totalBytes = 0
        var requestCount = 0
        while Date() < deadline {
            do {
                let (data, _) = try await URLSession.shared.data(from: url)
                totalBytes += data.count
                requestCount += 1
                bulkStatus = "requests=\(requestCount) bytes=\(totalBytes)"
            } catch {
                bulkStatus = "download error: \(error.localizedDescription)"
                break
            }
        }
    }
}
