// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// One sparse, info-level event derived from a snapshot diff. The event is
/// STRUCTURED (raw enum values, not display strings): naming/coloring is the
/// view's job, which keeps this model free of any View dependency and lets the
/// diff logic be exercised in isolation.
struct LogEvent: Identifiable {
    let id = UUID()
    let time: Date
    let kind: Kind

    enum Kind {
        case coreState(Int32)                              // (c) tunnel/core state
        case pathAdded(name: String, status: Int32)        // (a) path appeared
        case pathRemoved(name: String)                     // (a) path disappeared
        case pathStatus(name: String, from: Int32, to: Int32)  // (b) status change
    }
}

/// View-independent event log: diffs consecutive `TunnelSnapshot`s into the
/// three sparse event classes the dashboard shows (path add/remove, path status
/// transition, core-state change) and keeps a fixed newest-first ring buffer.
/// Deliberately silent about per-tick byte/rate churn — only structural changes
/// are logged. `ingest` takes an injectable clock so the diff logic is fully
/// deterministic under test.
final class EventLog: ObservableObject {
    @Published private(set) var events: [LogEvent] = []
    private let capacity = 20
    private var prevPaths: [String: Int32] = [:]   // name -> status raw
    private var prevState: Int32?

    func ingest(_ snap: TunnelSnapshot, now: Date = Date()) {
        // (c) core state change
        if prevState != snap.clientState {
            append(LogEvent(time: now, kind: .coreState(snap.clientState)))
            prevState = snap.clientState
        }
        var cur: [String: Int32] = [:]
        for p in snap.paths { cur[p.name] = p.status }
        // (a) additions + (b) status transitions
        for p in snap.paths {
            if let old = prevPaths[p.name] {
                if old != p.status {
                    append(LogEvent(time: now,
                                    kind: .pathStatus(name: p.name, from: old, to: p.status)))
                }
            } else {
                append(LogEvent(time: now, kind: .pathAdded(name: p.name, status: p.status)))
            }
        }
        // (a) removals
        for name in prevPaths.keys where cur[name] == nil {
            append(LogEvent(time: now, kind: .pathRemoved(name: name)))
        }
        prevPaths = cur
    }

    /// Forget the diff baseline (e.g. on disconnect) so a later reconnect logs
    /// its paths as fresh additions. The event history is intentionally kept.
    func resetBaseline() {
        prevPaths = [:]
        prevState = nil
    }

    private func append(_ event: LogEvent) {
        events.insert(event, at: 0)   // newest-first
        if events.count > capacity {
            events.removeLast(events.count - capacity)
        }
    }
}
