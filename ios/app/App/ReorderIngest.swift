// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

enum SaveError: Error, Equatable { case inProgress, notEditable, notReady }

/// Save guard order: re-entry FIRST (never a false success), then authority,
/// then readiness. Returns the error to throw, or nil to proceed.
func saveGuard(isSaving: Bool, isEditable: Bool, hasManager: Bool) -> SaveError? {
    if isSaving { return .inProgress }
    if !isEditable { return .notEditable }
    if !hasManager { return .notReady }
    return nil
}

/// Abstraction over the NE config store so the atomic-save sequence is
/// host-testable with fault injection. TunnelController adapts NEVPNManager +
/// its NETunnelProviderProtocol to this; the test uses an in-memory fake.
protocol ReorderConfigStore: AnyObject {
    var providerConfiguration: [String: Any]? { get set }
    func commit() async throws    // NEVPNManager.saveToPreferences
    func refresh() async throws   // NEVPNManager.loadFromPreferences
}

/// The REAL atomic-save sequence used by production and exercised by tests:
/// snapshot -> merge -> mutate -> commit (on throw, roll back the in-memory
/// config and rethrow) -> best-effort refresh (a post-commit refresh failure is
/// non-fatal; the value is already persisted).
func performAtomicSave(_ store: ReorderConfigStore, merge: [String: Any]) async throws {
    let backup = store.providerConfiguration
    var merged = backup ?? [:]
    for (k, v) in merge { merged[k] = v }
    store.providerConfiguration = merged
    do { try await store.commit() }
    catch { store.providerConfiguration = backup; throw error }   // pre-commit rollback
    try? await store.refresh()
}

/// Ingest gate: accept a poll response only if its captured epoch still matches,
/// the tunnel is still up, and it is newer than the last ingested by the
/// monotonic `seq`. The legacy `seq==0` branch (wall-clock ordering for old-wire
/// payloads) applies ONLY in a legacy session (lastSeq == 0), so a legacy
/// response can never slip in after a modern (seq>=1) snapshot was accepted.
enum IngestGate {
    static func accept(capturedEpoch: Int, currentEpoch: Int, isUp: Bool,
                       snapSeq: UInt64, snapTimestamp: Double,
                       lastSeq: UInt64, lastTimestamp: Double) -> Bool {
        guard capturedEpoch == currentEpoch, isUp else { return false }
        if snapSeq == 0 { return lastSeq == 0 && snapTimestamp > lastTimestamp }
        return snapSeq > lastSeq
    }
}

/// Per-reply ingest decision, owned state: session epoch, seq/timestamp
/// baselines and the sample cursor. Pure so the boot-change ordering is tested.
struct SnapshotIngestState {
    enum Verdict: Equatable {
        case drop
        case ingest(fresh: [TunnelSample], resetHistories: Bool, newEpoch: Int)
    }

    private(set) var epoch = 0
    private var lastSeq: UInt64 = 0
    private var lastTimestamp: Double = 0
    private(set) var cursor = SampleCursor()

    /// up -> down: invalidate in-flight replies, restart ordering baselines.
    mutating func sessionEnded() { epoch += 1; lastSeq = 0; lastTimestamp = 0 }

    /// Snapshot cleared (tunnel down / backgrounded-down): baselines + cursor restart.
    mutating func clear() { lastSeq = 0; lastTimestamp = 0; cursor = SampleCursor() }

    /// Order: epoch/up pre-check; on a bootId change bump the epoch (dropping every
    /// other in-flight reply), adopt it for THIS reply, reset baselines and ask for
    /// a history reset - all before the seq comparison; then IngestGate; then cursor dedup.
    mutating func accept(replyEpoch: Int, isUp: Bool, snapshot snap: TunnelSnapshot) -> Verdict {
        guard replyEpoch == epoch, isUp else { return .drop }
        var captured = replyEpoch
        var reset = false
        if snap.bootId != cursor.request?.bootId {
            epoch += 1; captured = epoch
            lastSeq = 0; lastTimestamp = 0
            reset = true
        }
        guard IngestGate.accept(capturedEpoch: captured, currentEpoch: epoch, isUp: isUp,
                                snapSeq: snap.seq, snapTimestamp: snap.timestamp,
                                lastSeq: lastSeq, lastTimestamp: lastTimestamp) else {
            return .drop
        }
        if snap.seq == 0 { lastTimestamp = snap.timestamp } else { lastSeq = snap.seq }
        let (_, fresh) = cursor.accept(bootId: snap.bootId, samples: snap.samples)
        return .ingest(fresh: fresh, resetHistories: reset, newEpoch: epoch)
    }
}
