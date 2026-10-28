// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

enum ManagerState: Equatable { case loading, loadFailed(String), absent, loaded }

/// Container controller: load/create the one NETunnelProviderManager,
/// start/stop it and persist the settings draft. State here changes on user
/// actions and session events only; the 1 Hz telemetry lives in `live`.
@MainActor
final class TunnelController: ObservableObject {
    static let providerBundleID = "org.mqvpn.app.PacketTunnel"

    @Published private(set) var state: ManagerState = .loading {
        didSet { recomputeAutosave() }
    }
    @Published private(set) var status: NEVPNStatus = .invalid
    /// Last disconnect / start / save error; cleared once the tunnel leaves .disconnected.
    @Published private(set) var surfacedError: String?
    /// Stored server config unreadable; cleared by the next successful save.
    @Published private(set) var configError: String?
    /// Core state + tunnel info of the live session (nil = no data), republished
    /// from `live` only when they change.
    @Published private(set) var facts: SessionFacts?
    /// Observed directly by the Settings event log; fed the same snapshot stream.
    let eventLog: EventLog
    let live: LiveSession
    /// Autosaving edit model; its DraftStore persists into the manager. Views
    /// observe the controller, which republishes every settings change.
    let settings: SettingsCore

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var scenePhaseActive = true            // WindowGroup starts active
    private var resyncTask: Task<Void, Never>?
    /// First-run setup cover is on screen (suppresses autosave while no manager exists).
    var setupPresented = false { didSet { recomputeAutosave() } }

    init() {
        let log = EventLog()
        eventLog = log
        live = LiveSession(eventLog: log)
        let store = ManagerDraftStore()
        settings = SettingsCore(store: store)
        store.owner = self
        settings.editable = { [weak self] in self?.isEditable ?? false }
        settings.onChange = { [weak self] in self?.objectWillChange.send() }
        live.onFacts = { [weak self] in self?.facts = $0 }
    }

    var viewState: VpnViewState {
        deriveViewState(neStatus: status.rawValue, clientState: facts?.clientState, surfacedError: surfacedError)
    }

    var isEditable: Bool {
        state == .absent || (state == .loaded && status == .disconnected)
    }
    /// A pending or failed autosave does not block Connect: start() flushes first.
    var isConnectable: Bool {
        state == .loaded && status == .disconnected && settings.isValid
    }
    static func isUp(_ s: NEVPNStatus) -> Bool { s == .connected || s == .reasserting }

    private func recomputeAutosave() {
        settings.autosave = !(setupPresented && state == .absent)
    }

    func loadOrCreateManager() async {
        state = .loading
        var serverSettings: ServerSettings?   // nil = unset/corrupt
        do {
            let existing = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let m = existing.first else {
                // No manager yet (or it was removed in iOS Settings): it is created
                // by the first persist (never here).
                manager = nil
                if let observer { NotificationCenter.default.removeObserver(observer) }
                observer = nil
                settings.load(initial: AppDraft(), persisted: false)
                state = .absent
                updateStatus(.invalid)
                return
            }
            manager = nil  // reset until we decide the manager is usable
            guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else {
                state = .loadFailed("config error"); return
            }
            let pc = proto.providerConfiguration
            let psk = try? PSKStore.load(proto.passwordReference)
            if let psk, let s = ServerSettings(providerConfiguration: pc, authKey: psk) {
                serverSettings = s
            } else {
                serverSettings = nil
                // No keys = first run (the dashboard points to Settings);
                // keys that do not parse = corrupt, reported, never overwritten.
                if psk == nil {
                    configError = "access key unreadable — re-enter in Settings"
                } else if ServerSettings.serverKeysPresent(in: pc) {
                    configError = "server config invalid — re-enter in Settings"
                }
            }
            manager = m
            settings.load(initial: Self.draft(from: pc, server: serverSettings), persisted: true)
            attachObserver(to: m)
            state = .loaded
            updateStatus(m.connection.status)
        } catch {
            state = .loadFailed("load error: \(error.localizedDescription)")
        }
    }

    static func draft(from pc: [String: Any]?, server: ServerSettings?) -> AppDraft {
        var d = AppDraft()
        if let s = server {
            d.addressText = ServerAddressField.format(host: s.host, port: s.port)
            d.tlsServerName = s.serverName; d.authKey = s.authKey; d.insecure = s.insecure
        }
        let r = ReorderSettings(providerConfiguration: pc) ?? .disabled
        d.reorder = ReorderDraft(enabled: r.enabled, profile: r.profile,
                                 portsText: r.ports.map(String.init).joined(separator: ","))
        d.hybrid = HybridSettings(providerConfiguration: pc) ?? .disabled
        d.split = SplitSettings(providerConfiguration: pc)
        // A malformed stored list shows as empty text and stays fail-closed until edited.
        d.redundantPortsText = d.split.redundantPortsMalformed
            ? "" : d.split.redundantPorts.map(String.init).joined(separator: ",")
        d.protection = ProtectionSettings(providerConfiguration: pc)
        d.paths = PathPolicy(providerConfiguration: pc)
        return d
    }

    private func attachObserver(to manager: NETunnelProviderManager) {
        if let observer { NotificationCenter.default.removeObserver(observer) }
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
        if s != .disconnected { surfacedError = nil }
        if s == .disconnected { surfaceDisconnectError() }
        reconcilePolling()
    }

    /// The provider's startTunnel throw / cancelTunnelWithError NSError is
    /// only retrievable via fetchLastDisconnectError (iOS 16+); without it
    /// the dashboard shows a bare "disconnected" even for a TLS rejection.
    private func surfaceDisconnectError() {
        guard #available(iOS 16.0, *),
              let session = manager?.connection as? NETunnelProviderSession else { return }
        session.fetchLastDisconnectError { [weak self] err in
            guard let err else { return }
            Task { @MainActor in
                guard let self, self.status == .disconnected else { return }
                // The provider keeps the last error until the next session, and
                // every foreground resync fetches it again: log it once.
                let msg = err.localizedDescription
                guard self.surfacedError != msg else { return }
                self.surfacedError = msg
                self.eventLog.logError(msg)
            }
        }
    }

    /// Connect: flush pending edits first; a failed flush aborts and shows the save error.
    func start() {
        guard isConnectable else { return }
        Task { @MainActor in
            guard await settings.flush() else {
                surfacedError = settings.saveError ?? "Settings could not be saved"
                return
            }
            guard isConnectable, let manager else { return }
            do {
                // iOS clears isEnabled when another VPN configuration is turned on, and
                // the in-memory manager only sees that after a reload; a disabled
                // manager fails startVPNTunnel with configurationDisabled.
                try await manager.loadFromPreferences()
                if !manager.isEnabled {
                    manager.isEnabled = true
                    try await manager.saveToPreferences()
                }
                try manager.connection.startVPNTunnel()
            } catch {
                surfacedError = "start error: \(error.localizedDescription)"
                eventLog.logError(error.localizedDescription)
            }
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    /// DraftStore body: snapshot -> merge -> mutate -> commit -> refresh via
    /// performAtomicSave (the function the host tests fault-inject), creating the
    /// manager on the first persist from `.absent`.
    fileprivate func persistDraft(_ d: AppDraft) async throws {
        if let e = saveGuard(isEditable: isEditable, hasManager: manager != nil || state == .absent) {
            throw e
        }
        guard let addr = d.server else { throw SaveError.notReady }
        let creating = (manager == nil)
        let m: NETunnelProviderManager
        let proto: NETunnelProviderProtocol
        if let existing = manager {
            guard let p = existing.protocolConfiguration as? NETunnelProviderProtocol else {
                throw SaveError.notReady
            }
            m = existing; proto = p
        } else {
            // Placeholder only: NE rejects an empty serverAddress at save.
            // The extension resolves the real peer for tunnelRemoteAddress.
            m = NETunnelProviderManager()
            proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleID
            proto.serverAddress = "mqvpn"
            m.protocolConfiguration = proto
            m.localizedDescription = "mqvpn"
            m.isEnabled = true
        }
        let server = ServerSettings(host: addr.host, port: addr.port, serverName: d.tlsServerName,
                                    authKey: d.authKey, insecure: d.insecure)
        // Every providerConfiguration section the draft owns; a new setting adds one entry.
        let sections: [ProviderConfigSection] = [
            server,
            ReorderSettings(enabled: d.reorder.enabled, profile: d.reorder.profile, ports: d.reorderPorts),
            d.hybrid, d.derivedSplit, d.protection, d.paths,
        ]
        var merged: [String: Any] = [:]
        for section in sections { section.merged(into: &merged) }

        // New keychain item first; the old one goes only after the commit, so
        // a failed save leaves the saved configuration and its PSK untouched.
        let oldRef = proto.passwordReference
        let oldIAN = proto.includeAllNetworks, oldELN = proto.excludeLocalNetworks
        let oldER = proto.enforceRoutes
        let newRef = try PSKStore.add(server.authKey)
        proto.passwordReference = newRef
        // The kill switch lives in the provider (a protected session never
        // ends itself), never in includeAllNetworks: that flag makes NECP deny
        // the provider's cellular-bound socket while Wi-Fi is up (no
        // multipath) and cuts all connectivity during an App Store update.
        // enforceRoutes stays off too: with it on, paths came up but no tunnel
        // traffic flowed on device. All three are written on every save.
        proto.includeAllNetworks = false
        proto.excludeLocalNetworks = false
        proto.enforceRoutes = false
        do {
            try await performAtomicSave(NEConfigStore(manager: m, proto: proto), merge: merged)
        } catch {
            proto.passwordReference = oldRef
            proto.includeAllNetworks = oldIAN
            proto.excludeLocalNetworks = oldELN
            proto.enforceRoutes = oldER
            m.protocolConfiguration = proto   // commit attached the edited copy
            PSKStore.delete(newRef)
            throw error
        }
        PSKStore.delete(oldRef)
        configError = nil   // only on success
        if creating {
            manager = m
            attachObserver(to: m)
            state = .loaded
            updateStatus(m.connection.status)
        }
    }

    // MARK: - Live telemetry gate

    /// Called by the scene on activation changes; gates polling together with
    /// the connection state.
    func setScenePhaseActive(_ active: Bool) {
        let becameActive = active && !scenePhaseActive
        scenePhaseActive = active
        if active, case .loadFailed = state {
            state = .loading   // set synchronously: guards against overlapping loads
            Task { await loadOrCreateManager() }
        } else if becameActive {
            resyncWithSystem()
        }
        reconcilePolling()
    }

    /// Back in the foreground: while the app was away, iOS Settings may have
    /// turned the VPN off, disabled this configuration (another VPN enabled) or
    /// removed it, and a status notification is not guaranteed to arrive. Re-read
    /// the stored configuration; a removed one goes through the launch load,
    /// which shows setup. The draft is untouched otherwise.
    private func resyncWithSystem() {
        guard resyncTask == nil, let m = manager else { return }
        resyncTask = Task {
            defer { resyncTask = nil }
            let stillStored = (try? await NETunnelProviderManager.loadAllFromPreferences())
                .map { !$0.isEmpty }
            guard manager === m else { return }   // a load or first save replaced it meanwhile
            if stillStored == false {
                await loadOrCreateManager()
                return
            }
            try? await m.loadFromPreferences()
            guard manager === m else { return }
            updateStatus(m.connection.status)
        }
    }

    private func reconcilePolling() {
        live.update(session: manager?.connection as? NETunnelProviderSession,
                    isUp: Self.isUp(status), foreground: scenePhaseActive)
    }
}

/// DraftStore adapter: forwards to the controller's single persist routine.
@MainActor
final class ManagerDraftStore: DraftStore {
    weak var owner: TunnelController?
    func persist(_ draft: AppDraft) async throws {
        guard let owner else { throw SaveError.notReady }
        try await owner.persistDraft(draft)
    }
}

/// Binds performAtomicSave's ProviderConfigStore to the live NE objects.
final class NEConfigStore: ProviderConfigStore {
    private let manager: NETunnelProviderManager
    private let proto: NETunnelProviderProtocol
    init(manager: NETunnelProviderManager, proto: NETunnelProviderProtocol) {
        self.manager = manager; self.proto = proto
    }
    var providerConfiguration: [String: Any]? {
        get { proto.providerConfiguration }
        set { proto.providerConfiguration = newValue }
    }
    // Re-attach before saving: iOS 27 copies the protocol on get/set, so edits
    // to `proto` after it was read or attached never reach a bare save.
    func commit() async throws {
        manager.protocolConfiguration = proto
        try await manager.saveToPreferences()
    }
    func refresh() async throws { try await manager.loadFromPreferences() }
}
