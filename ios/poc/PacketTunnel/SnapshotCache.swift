// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Darwin

/// Tick-thread producer of the app-facing `TunnelSnapshot`.
///
/// THREADING (single-direction hand-off): the ONLY writer of `latest` is
/// `collect()`, which runs on the tick thread (fired by a Timer added to that
/// run loop in `start()`, the same pattern GateMetrics uses). The ONLY reader
/// is `read()`, called from `handleAppMessage`'s arbitrary NE thread. `lock`
/// guards just that one hand-off cell; nothing else is shared. The engine's
/// `state()`/`paths()` accessors are tick-thread-confined, so they are touched
/// only inside `collect()`, never from the reader.
final class SnapshotCache {
    private let engine: MqvpnEngine
    private let lock = NSLock()
    private var latest: TunnelSnapshot?
    private var timer: Timer?
    /// Tick-thread-confined: first-ESTABLISHED wall-clock, for uptime display.
    private var connectedSince: Double?
    /// Tick-thread-confined: provider-side monotonic ordering key, one per
    /// produced snapshot (lets the app detect stalls/reordered reads).
    private var seq: UInt64 = 0

    init(engine: MqvpnEngine) {
        self.engine = engine
    }

    /// MUST be called on the tick thread (inside `engine.perform{}`), like
    /// GateMetrics.start(). Adds a 1 s producer timer to the tick run loop —
    /// the same cadence as PathBinder's reconcile poll.
    func start() {
        collect()   // seed one snapshot immediately so an early poll has data
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.collect()
        }
        RunLoop.current.add(t, forMode: .default)
        timer = t
    }

    /// Reader for `handleAppMessage` (any thread). Returns nil until the first
    /// snapshot is produced.
    func read() -> TunnelSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return latest
    }

    /// Tick thread only (fired by the Timer added in `start()`).
    private func collect() {
        let state = engine.state()
        let now = Date().timeIntervalSince1970
        // Latch handshake-completion wall-clock on first ESTABLISHED; clear it
        // whenever the session leaves the connected state so a reconnect
        // restarts the displayed uptime.
        if state == MQVPN_STATE_ESTABLISHED {
            if connectedSince == nil { connectedSince = now }
        } else {
            connectedSince = nil
        }
        var paths: [PathSnapshot] = []
        for p in engine.paths() {
            let name = withUnsafeBytes(of: p.name) { raw -> String in
                String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            paths.append(PathSnapshot(name: name, status: Int32(p.status.rawValue),
                                      txBytes: p.bytes_tx, rxBytes: p.bytes_rx))
        }
        seq &+= 1
        let snap = TunnelSnapshot(timestamp: now, clientState: Int32(state.rawValue),
                                  connectedSince: connectedSince,
                                  footprint: Self.physFootprint(), paths: paths,
                                  seq: seq, reorderConfigured: engine.reorderConfigured,
                                  reorder: engine.reorderStats())
        lock.lock()
        latest = snap
        lock.unlock()
    }

    /// task_info(TASK_VM_INFO) phys_footprint, bytes. Replicated from
    /// GateMetrics (which the UI task must not modify) — a self-contained read
    /// with no shared state, so duplication carries no coupling.
    private static func physFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return 0 }
        return info.phys_footprint
    }
}
