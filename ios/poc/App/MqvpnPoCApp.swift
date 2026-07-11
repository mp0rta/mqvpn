// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

@main
struct MqvpnPoCApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

/// Minimal PoC container UI: load/save the one NETunnelProviderManager,
/// start/stop it, and drive a bulk download through the tunnel as the
/// multipath load gate's user-space traffic source.
@MainActor
final class TunnelController: ObservableObject {
    static let providerBundleID = "com.mp0rta.mqvpnpoc.PacketTunnel"

    @Published var statusText = "not loaded"
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

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
            statusText = Self.describe(m.connection.status)
        } catch {
            statusText = "load error: \(error.localizedDescription)"
        }
    }

    private func attachObserver(to manager: NETunnelProviderManager) {
        // NotificationCenter's completion closure is not MainActor-isolated
        // even with queue: .main (it is typed @Sendable by the SDK), so hop
        // explicitly before touching @MainActor state (statusText, describe).
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self, weak manager] _ in
            Task { @MainActor in
                guard let self, let manager else { return }
                self.statusText = Self.describe(manager.connection.status)
            }
        }
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
    @StateObject private var controller = TunnelController()
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
