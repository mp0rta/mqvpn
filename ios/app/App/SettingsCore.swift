// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

struct ReorderDraft: Equatable {
    var enabled = false
    var profile = ReorderSettings.profileCellularBond
    var portsText = ""
}

struct HybridDraft: Equatable {
    var enabled = false
    var tcpMode = HybridSettings.modeAuto
}

/// Everything the Settings screen edits. Port fields keep the RAW text so an
/// invalid edit ("443,bad") is representable, shows its error and blocks
/// autosave; validated values derive at persist time.
struct AppDraft: Equatable {
    var addressText = ""
    var tlsServerName = ""
    var authKey = ""
    var insecure = false
    var reorder = ReorderDraft()
    var hybrid = HybridDraft()
    var split = SplitSettings(scheduler: nil, redundantEnabled: false,
                              redundantPorts: [], redundantPortsMalformed: false)
    var redundantPortsText = ""
    var protection = ProtectionSettings()
    var paths = PathPolicy()

    static let errAddress = "Enter a server address"
    static let errPort = "Port must be 1-65535"
    static let errReorderPorts = "Enter at least one valid port"
    static let errRedundantPorts = "Enter ports as a comma-separated list (1-65535)"
    static let errPaths = "Turn on at least one connection type"

    /// nil = not a valid host[:port].
    var server: (host: String, port: Int)? { ServerAddressField.parse(addressText) }

    /// The reorder ports that take effect: valid, unique, capped at maxRules.
    var reorderPorts: [Int] {
        Array(ReorderSettings.scanPorts(reorder.portsText).valid.prefix(ReorderSettings.maxRules))
    }

    /// SplitSettings to persist. A valid ports text always yields malformed=false
    /// (a user's valid edit never inherits a stale flag); an untouched malformed
    /// list (flag set, empty text) stays as-is so the provider keeps failing closed.
    var derivedSplit: SplitSettings {
        var s = split
        if s.redundantPortsMalformed && redundantPortsText.trimmingCharacters(in: .whitespaces).isEmpty {
            return s
        }
        if let ports = SplitSettings.parseRedundantPorts(redundantPortsText) {
            s.redundantPorts = ports
            s.redundantPortsMalformed = false
        }
        return s
    }

    func fieldErrors() -> [String: String] {
        var e: [String: String] = [:]
        if server == nil { e["address"] = Self.addressError(addressText) }
        if reorder.enabled && reorderPorts.isEmpty { e["reorderPorts"] = Self.errReorderPorts }
        if split.redundantEnabled && SplitSettings.parseRedundantPorts(redundantPortsText) == nil {
            e["redundantPorts"] = Self.errRedundantPorts
        }
        if !paths.anyEnabled { e["paths"] = Self.errPaths }
        return e
    }

    var isValid: Bool { fieldErrors().isEmpty }

    private static func addressError(_ text: String) -> String {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return errAddress }
        // "host:bad" / "[v6]:bad" is a port problem; anything else is not an address.
        if t.hasPrefix("[") {
            if let close = t.firstIndex(of: "]"), t[t.index(after: close)...].hasPrefix(":") { return errPort }
        } else if t.filter({ $0 == ":" }).count == 1, !t.hasPrefix(":") {
            return errPort
        }
        return errAddress
    }
}

protocol DraftStore {
    func persist(_ draft: AppDraft) async throws
}

/// The SettingsViewModel contract (Android parity): immediate local edits,
/// serialized conflated latest-wins autosave of VALID drafts. Foundation +
/// concurrency only; TunnelController republishes `onChange` to SwiftUI.
@MainActor
final class SettingsCore {
    private(set) var draft = AppDraft()
    private(set) var fieldErrors: [String: String] = [:]
    private(set) var saveError: String?
    private(set) var lastPersisted: AppDraft?
    /// False only while first-run setup is presented with no manager.
    var autosave = true
    var editable: () -> Bool = { true }
    var onChange: () -> Void = {}

    private let store: DraftStore
    private var worker: Task<Void, Never>?

    init(store: DraftStore) { self.store = store }

    func load(initial: AppDraft, persisted: Bool) {
        draft = initial
        lastPersisted = persisted ? initial : nil
        fieldErrors = initial.fieldErrors()
        saveError = nil
        onChange()
    }

    func update(_ transform: (inout AppDraft) -> Void) {
        guard editable() else { return }
        let before = draft
        var d = draft
        transform(&d)
        // Editing the ports text replaces a stored malformed list.
        if d.redundantPortsText != before.redundantPortsText { d.split.redundantPortsMalformed = false }
        draft = d
        fieldErrors = d.fieldErrors()
        onChange()
        if autosave && d.isValid { startWorker() }
    }

    /// Explicit persist of the current valid draft (Finish Setup); leaves autosave
    /// on when it succeeds. Runs on the same worker as autosave, so persists never overlap
    /// and edits made mid-persist land before success.
    func commitFirst() async -> Bool {
        guard draft.isValid else { return false }
        let wasAutosave = autosave
        autosave = true
        let ok = await flush()
        if !ok { autosave = wasAutosave }
        onChange()
        return ok
    }

    /// True iff everything edited so far is persisted.
    func flush() async -> Bool {
        if autosave {
            if worker == nil { startWorker() }
            if let w = worker { await w.value }
        }
        return lastPersisted == draft
    }

    private func startWorker() {
        guard worker == nil else { return }
        worker = Task { @MainActor [weak self] in
            await self?.drainLoop()
            self?.worker = nil
        }
    }

    private func drainLoop() async {
        while true {
            let d = draft
            guard d.isValid, d != lastPersisted else { return }
            do {
                try await store.persist(d)
                lastPersisted = d; saveError = nil
            } catch {
                saveError = "Save failed: \(error.localizedDescription)"
                onChange()
                if draft == d { return }   // same draft would just fail again
                continue
            }
            onChange()
        }
    }
}
