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
            DashboardView(controller: controller, eventLog: controller.eventLog)
                // Foreground-only polling: pause IPC when not active to avoid
                // battery drain and pointless sendProviderMessage churn.
                .onChange(of: scenePhase) { phase in
                    controller.setScenePhaseActive(phase == .active)
                }
        }
    }
}

/// PoC container controller: load/save the one NETunnelProviderManager,
/// start/stop it, and — while foregrounded and connected — poll the provider
/// for a development snapshot over `sendProviderMessage`. Per-path transfer
/// rates are derived here from consecutive snapshots.
@MainActor
final class TunnelController: ObservableObject {
    static let providerBundleID = "com.mp0rta.mqvpnpoc.PacketTunnel"

    @Published var status: NEVPNStatus = .invalid
    @Published var statusText = "not loaded"
    @Published var snapshot: TunnelSnapshot?       // nil = no data
    @Published var pathRates: [String: Double] = [:]   // iface name -> Mbps
    @Published var reorderSettings: ReorderSettings = .disabled
    @Published private(set) var isSaving = false
    /// Observed directly by the dashboard; fed the same snapshot stream.
    let eventLog = EventLog()
    private var prevSnapshot: TunnelSnapshot?
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var pollTimer: Timer?
    private var scenePhaseActive = true            // WindowGroup starts active
    /// Bumped on every up->down transition; a poll response captured under a
    /// stale epoch is discarded even if it arrives after the tunnel comes back
    /// up, since it may describe the wrong session.
    private var sessionEpoch = 0
    /// Ordering key for accepted poll responses, reset at each session boundary.
    private var lastIngestedSeq: UInt64 = 0
    private var lastIngestedTimestamp: Double = 0

    var isEditable: Bool { manager != nil && status == .disconnected }
    static func isUp(_ s: NEVPNStatus) -> Bool { s == .connected || s == .reasserting }

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
            let pc = (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            reorderSettings = ReorderSettings(providerConfiguration: pc) ?? .disabled
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
        let wasUp = Self.isUp(status)
        status = s
        statusText = Self.describe(s)
        if wasUp && !Self.isUp(s) {          // up -> down session boundary
            sessionEpoch += 1
            lastIngestedSeq = 0
            lastIngestedTimestamp = 0
        }
        reconcilePolling()
    }

    func start() {
        guard !isSaving, let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            statusText = "start error: \(error.localizedDescription)"
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    /// Persists reorder settings via the atomic snapshot -> merge -> mutate ->
    /// commit -> refresh sequence in performAtomicSave, the exact function the
    /// host tests fault-inject — so the tested logic IS the production logic.
    func saveReorderSettings(_ new: ReorderSettings) async throws {
        if let e = saveGuard(isSaving: isSaving, isEditable: isEditable, hasManager: manager != nil) {
            throw e
        }
        guard let manager,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            throw SaveError.notReady
        }
        isSaving = true
        defer { isSaving = false }
        try await performAtomicSave(NEConfigStore(manager: manager, proto: proto),
                                    merge: new.toProviderConfiguration())
        reorderSettings = new     // only on success (performAtomicSave rethrows on commit failure)
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
            if !up { clearSnapshot() }
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

    private func clearSnapshot() {
        snapshot = nil
        pathRates = [:]
        prevSnapshot = nil
        lastIngestedSeq = 0
        lastIngestedTimestamp = 0
        eventLog.resetBaseline()
    }

    private func poll() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        let epoch = sessionEpoch
        do {
            // Payload is ignored by the provider (command-agnostic); an empty
            // request means "give me the latest snapshot".
            try session.sendProviderMessage(Data()) { [weak self] resp in
                Task { @MainActor in
                    guard let self else { return }
                    // Pre-decode session check: a stale/late response must never
                    // clear the live snapshot of a newer session.
                    guard self.sessionEpoch == epoch, Self.isUp(self.status) else { return }
                    guard let resp, let snap = try? ProviderMessage.decode(resp) else { return }
                    guard IngestGate.accept(capturedEpoch: epoch, currentEpoch: self.sessionEpoch,
                                            isUp: Self.isUp(self.status), snapSeq: snap.seq,
                                            snapTimestamp: snap.timestamp,
                                            lastSeq: self.lastIngestedSeq,
                                            lastTimestamp: self.lastIngestedTimestamp) else { return }
                    if snap.seq == 0 { self.lastIngestedTimestamp = snap.timestamp }
                    else { self.lastIngestedSeq = snap.seq }
                    self.ingest(snap)
                }
            }
        } catch { /* transient; keep the current snapshot */ }
    }

    /// Compute per-path rates from the previous sample, then publish.
    private func ingest(_ snap: TunnelSnapshot) {
        if let prev = prevSnapshot {
            let dt = snap.timestamp - prev.timestamp
            if dt > 0.05 {
                var prevByName: [String: PathSnapshot] = [:]
                for pp in prev.paths { prevByName[pp.name] = pp }
                var rates: [String: Double] = [:]
                for p in snap.paths {
                    guard let pp = prevByName[p.name] else { continue }
                    // Double avoids UInt64 wrap; a counter reset (path re-add)
                    // yields a negative delta which we clamp to 0.
                    let curBytes = Double(p.txBytes) + Double(p.rxBytes)
                    let oldBytes = Double(pp.txBytes) + Double(pp.rxBytes)
                    let delta = curBytes - oldBytes
                    rates[p.name] = delta > 0 ? delta * 8.0 / dt / 1_000_000.0 : 0.0
                }
                pathRates = rates
            }
        }
        prevSnapshot = snap
        snapshot = snap
        eventLog.ingest(snap)
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

/// Binds performAtomicSave's ReorderConfigStore to the live NE objects.
final class NEConfigStore: ReorderConfigStore {
    private let manager: NETunnelProviderManager
    private let proto: NETunnelProviderProtocol
    init(manager: NETunnelProviderManager, proto: NETunnelProviderProtocol) {
        self.manager = manager; self.proto = proto
    }
    var providerConfiguration: [String: Any]? {
        get { proto.providerConfiguration }
        set { proto.providerConfiguration = newValue }
    }
    func commit() async throws { try await manager.saveToPreferences() }
    func refresh() async throws { try await manager.loadFromPreferences() }
}
