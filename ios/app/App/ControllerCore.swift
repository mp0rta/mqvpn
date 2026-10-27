// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

enum SaveError: Error, Equatable { case notEditable, notReady }

/// Save guard order: authority, then readiness. Returns the error to throw, or
/// nil to proceed. Re-entry is impossible: SettingsCore's single worker is the
/// only caller of the persist routine.
func saveGuard(isEditable: Bool, hasManager: Bool) -> SaveError? {
    if !isEditable { return .notEditable }
    if !hasManager { return .notReady }
    return nil
}

/// Abstraction over the NE config store so the atomic-save sequence is
/// host-testable with fault injection. TunnelController adapts NEVPNManager +
/// its NETunnelProviderProtocol to this; the test uses an in-memory fake.
protocol ProviderConfigStore: AnyObject {
    var providerConfiguration: [String: Any]? { get set }
    func commit() async throws    // NEVPNManager.saveToPreferences
    func refresh() async throws   // NEVPNManager.loadFromPreferences
}

/// The REAL atomic-save sequence used by production and exercised by tests:
/// snapshot -> merge -> mutate -> commit (on throw, roll back the in-memory
/// config and rethrow) -> best-effort refresh (a post-commit refresh failure is
/// non-fatal; the value is already persisted).
func performAtomicSave(_ store: ProviderConfigStore, merge: [String: Any]) async throws {
    let backup = store.providerConfiguration
    var merged = backup ?? [:]
    for (k, v) in merge { merged[k] = v }
    store.providerConfiguration = merged
    do { try await store.commit() }
    catch { store.providerConfiguration = backup; throw error }   // pre-commit rollback
    try? await store.refresh()
}

/// Per-reply ingest decision. Owns the session epoch, the seq baseline and the
/// sample cursor; pure so the boot-change ordering is tested. App and extension
/// ship in one bundle, so every reply carries seq >= 1 and a non-zero bootId.
struct SnapshotIngestState {
    enum Verdict: Equatable {
        case drop
        case ingest(fresh: [TunnelSample], resetHistories: Bool)
    }

    private(set) var epoch = 0
    private var lastSeq: UInt64 = 0
    private(set) var cursor = SampleCursor()

    /// up -> down: invalidate in-flight replies, restart the seq baseline.
    mutating func sessionEnded() { epoch += 1; lastSeq = 0 }

    /// Snapshot cleared (tunnel down / backgrounded-down): baseline + cursor restart.
    mutating func clear() { lastSeq = 0; cursor = SampleCursor() }

    /// Order: the reply must belong to the current epoch of an up tunnel. A new
    /// bootId (provider restarted, seq back near 1) bumps the epoch so every other
    /// in-flight reply drops, resets the seq baseline and asks for a history reset,
    /// all before the seq comparison; then the cursor dedups the samples.
    mutating func accept(replyEpoch: Int, isUp: Bool, snapshot snap: TunnelSnapshot) -> Verdict {
        guard replyEpoch == epoch, isUp else { return .drop }
        let reset = snap.bootId != cursor.request?.bootId
        if reset { epoch += 1; lastSeq = 0 }
        guard snap.seq > lastSeq else { return .drop }
        lastSeq = snap.seq
        let (_, fresh) = cursor.accept(bootId: snap.bootId, samples: snap.samples)
        return .ingest(fresh: fresh, resetHistories: reset)
    }
}
