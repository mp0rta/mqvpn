// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

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
    private let binder: PathBinder
    private let lock = NSLock()
    private var latest: TunnelSnapshot?
    private var timer: Timer?
    /// Tick-thread-confined: first-ESTABLISHED wall-clock, for uptime display.
    private var connectedSince: Double?
    /// Tick-thread-confined: provider-side monotonic ordering key, one per
    /// produced snapshot (lets the app detect stalls/reordered reads).
    private var seq: UInt64 = 0
    /// Tick-thread-confined; the reader gets copies through `lock`.
    private let ring = SampleRing()
    /// Random per provider start: lets the app tell a restarted provider
    /// (seq back at 1) from a continuing one.
    private let bootId = UInt64.random(in: 1...UInt64.max)

    init(engine: MqvpnEngine, binder: PathBinder) {
        self.engine = engine
        self.binder = binder
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
    /// Samples: nil request or a different bootId => the full ring, else
    /// only those newer than request.sinceSeq.
    func read(request: (sinceSeq: UInt64, bootId: UInt64)?) -> Data? {
        lock.lock()
        guard let l = latest else { lock.unlock(); return nil }
        let since: UInt64? = (request?.bootId == bootId) ? request?.sinceSeq : nil
        let samples = ring.since(since)
        lock.unlock()
        var snap = l
        snap.samples = samples
        return try? ProviderMessage.encode(snap)
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
        let kinds = binder.pathKinds()
        for p in engine.paths() {
            // Skip reaped CLOSED slots: get_paths never shrinks n_paths, so a
            // path removed on reconnect lingers as a frozen CLOSED entry for a
            // poll or two, next to the live same-name path. Surfacing it makes
            // the dashboard show a dead duplicate card and feeds EventLog a
            // name collision (defense-in-depth with EventLog's own filter).
            if p.status == MQVPN_PATH_CLOSED { continue }
            let name = withUnsafeBytes(of: p.name) { raw -> String in
                String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            paths.append(PathSnapshot(name: name, status: Int32(p.status.rawValue),
                                      txBytes: p.bytes_tx, rxBytes: p.bytes_rx, kind: kinds[name]))
        }
        // seq must stay >= 1: SampleRing treats seq 0 as its "nothing seen" hazard.
        seq &+= 1
        let stats = engine.stats()
        let reorder = engine.reorderStats()
        let sample = TunnelSample(
            seq: seq, wallMs: UInt64(now * 1000),
            monoMs: UInt64(mqvpn_ios_clock_us(nil) / 1000),
            paths: paths.map { SamplePath(name: $0.name, txBytes: $0.txBytes, rxBytes: $0.rxBytes) },
            bytesTx: stats?.bytesTx ?? 0, bytesRx: stats?.bytesRx ?? 0,
            dgramSent: stats?.dgramSent ?? 0, dgramLost: stats?.dgramLost ?? 0,
            delivered: reorder?.delivered ?? 0, gapCount: reorder?.gapCount ?? 0,
            gapFilled: reorder?.gapFilled ?? 0, gapTimeout: reorder?.gapTimeout ?? 0,
            ackDemote: reorder?.ackDemote ?? 0,
            residenceBuckets: reorder?.residenceBuckets ?? [])
        let snap = TunnelSnapshot(timestamp: now, clientState: Int32(state.rawValue),
                                  connectedSince: connectedSince, paths: paths,
                                  seq: seq, reorderConfigured: engine.reorderConfigured,
                                  reorder: reorder, tunnel: engine.tunnelInfo, stats: stats,
                                  bootId: bootId)
        lock.lock()
        ring.append(sample)
        latest = snap
        lock.unlock()
    }
}
