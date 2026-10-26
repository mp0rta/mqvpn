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
        case error(String)                                 // surfaced connect/disconnect error
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
    private var prevState: String?

    func ingest(_ snap: TunnelSnapshot, now: Date = Date()) {
        // (c) core state change
        let label = clientStateName(snap.clientState)   // Android class names: 1->2->3 is one line
        if prevState != label {
            append(LogEvent(time: now, kind: .coreState(snap.clientState)))
            prevState = label
        }
        // Diff LIVE paths only. After a reconnect the core can transiently
        // return a stale CLOSED slot (mqvpn_path_status_t CLOSED = 4) next to
        // the live path for the same interface — get_paths never shrinks
        // n_paths, so a reaped slot lingers a poll or two. Keyed by interface
        // name, that duplicate would fabricate en0 active<->closed churn every
        // tick. A path leaving the live set is logged as a removal instead.
        let live = snap.paths.filter { $0.status != 4 }
        var cur: [String: Int32] = [:]
        for p in live { cur[p.name] = p.status }
        // (a) additions + (b) status transitions
        for p in live {
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

    func logError(_ message: String, now: Date = Date()) {
        append(LogEvent(time: now, kind: .error(message)))
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

// Display text/levels (Foundation only; the Settings view maps level -> color).
// Raw values mirror mqvpn_client_state_t / mqvpn_path_status_t in libmqvpn.h.

func clientStateName(_ s: Int32) -> String {
    switch s {
    case 0, 6: return "Disconnected"
    case 1, 2, 3: return "Connecting"
    case 4: return "Connected"
    case 5: return "Reconnecting"
    default: return "?(\(s))"
    }
}

func pathStatusName(_ s: Int32) -> String {
    switch s {
    case 0: return "Pending"
    case 1: return "Active"
    case 2: return "Degraded"
    case 3: return "Standby"
    case 4: return "Closed"
    default: return "Unknown"
    }
}

func eventText(_ k: LogEvent.Kind) -> String {
    switch k {
    case .coreState(let s): return "core → \(clientStateName(s))"
    case .pathAdded(let n, let s): return "\(n) added (\(pathStatusName(s)))"
    case .pathRemoved(let n): return "\(n) removed"
    case .pathStatus(let n, let from, let to): return "\(n): \(pathStatusName(from)) → \(pathStatusName(to))"
    case .error(let m): return "error: \(m)"
    }
}

enum EventLevel { case error, warn, info }

/// Android levelDot: red error; orange RECONNECTING and path removed; else muted.
func eventLevel(_ k: LogEvent.Kind) -> EventLevel {
    switch k {
    case .error: return .error
    case .pathRemoved: return .warn
    case .coreState(let s): return s == 5 ? .warn : .info
    default: return .info
    }
}
