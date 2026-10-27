// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

/// Everything the live views draw, as one value: published once per accepted
/// provider reply, so a 1 Hz tick is one SwiftUI update.
struct LiveFrame {
    var snapshot: TunnelSnapshot?          // nil = no data
    var bandwidth: [BandwidthSample] = []
    var slots: [String: Int] = [:]         // iface -> chart color slot
    var reorder: [ReorderSample] = []
    var dgramLoss: Double?                 // upload DATAGRAM loss over 30 s; nil = no data
}

/// The parts of a snapshot that change only on session events. TunnelController
/// republishes them on change, so views that need them (Settings, the status
/// line) do not observe the 1 Hz telemetry.
struct SessionFacts: Equatable {
    var clientState: Int32
    var tunnel: TunnelInfoSnapshot?
}

/// Live telemetry: while the app is foregrounded and the tunnel is up, polls the
/// provider once a second over `sendProviderMessage` and feeds the 30 s
/// histories from the provider's sample ring. Kept apart from TunnelController
/// so only the views that show live data re-render at 1 Hz.
@MainActor
final class LiveSession: ObservableObject {
    @Published private(set) var frame = LiveFrame()
    /// Called with the new facts whenever they change (nil = no data).
    var onFacts: (SessionFacts?) -> Void = { _ in }

    private let eventLog: EventLog
    private let bandwidthHistory = BandwidthHistory()
    private let reorderHistory = ReorderHistory()
    private let dgramLossWindow = DgramLossWindow()
    private var dgramLoss: Double?
    /// Epoch, seq/timestamp baselines and sample cursor (pure, tested).
    private var ingestState = SnapshotIngestState()
    private var session: NETunnelProviderSession?
    private var wasUp = false
    private var facts: SessionFacts?
    private var pollTimer: Timer?
    /// One request in flight at a time; a reply that never comes frees the slot
    /// after `replyTimeout`.
    private var inFlightSince: Date?
    private var pollToken = 0
    private static let replyTimeout: TimeInterval = 3

    init(eventLog: EventLog) { self.eventLog = eventLog }

    /// Single decision point: poll only while foregrounded AND the tunnel is up.
    /// When the tunnel is down, drop the data so the UI shows none.
    func update(session: NETunnelProviderSession?, isUp: Bool, foreground: Bool) {
        self.session = session
        if wasUp && !isUp { ingestState.sessionEnded() }   // up -> down session boundary
        wasUp = isUp
        if foreground && isUp {
            startPolling()
        } else {
            stopPolling()
            if !isUp { clear() }
        }
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        poll()   // immediate first sample
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
        // .common: keep ticking while a scroll view is tracking.
        RunLoop.main.add(t, forMode: .common)
        pollTimer = t
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
        inFlightSince = nil
    }

    private func clear() {
        ingestState.clear()
        clearHistories()
        eventLog.resetBaseline()
        publish(snapshot: nil)
    }

    private func clearHistories() {
        bandwidthHistory.clear()
        reorderHistory.clear()
        dgramLossWindow.clear()
        dgramLoss = nil
    }

    private func poll() {
        guard let session else { return }
        if let t = inFlightSince, Date().timeIntervalSince(t) < Self.replyTimeout { return }
        pollToken &+= 1
        let token = pollToken
        let polledEpoch = ingestState.epoch
        inFlightSince = Date()
        do {
            // The cursor tells the provider which ring samples are still needed.
            try session.sendProviderMessage(SnapshotRequest.encode(cursor: ingestState.cursor.request)) { [weak self] resp in
                Task { @MainActor in
                    guard let self else { return }
                    if self.pollToken == token { self.inFlightSince = nil }
                    // Cheap early-out before decoding; accept() is the authoritative gate.
                    guard self.ingestState.epoch == polledEpoch, self.wasUp else { return }
                    guard let resp, let snap = try? ProviderMessage.decode(resp) else { return }
                    switch self.ingestState.accept(replyEpoch: polledEpoch, isUp: self.wasUp, snapshot: snap) {
                    case .drop: return
                    case .ingest(let fresh, let reset):
                        if reset { self.clearHistories() }
                        self.ingest(snap, fresh: fresh)
                    }
                }
            }
        } catch {
            inFlightSince = nil   // transient; keep the current data
        }
    }

    /// Feed fresh ring samples to the histories, then publish once.
    private func ingest(_ snap: TunnelSnapshot, fresh: [TunnelSample]) {
        for s in fresh {
            let wall = Int64(s.wallMs)
            bandwidthHistory.onTick(paths: s.paths.map { (name: $0.name, tx: $0.txBytes, rx: $0.rxBytes) },
                                    monoMs: s.monoMs, wallMs: wall)
            if snap.reorderConfigured {
                reorderHistory.onTick(delivered: s.delivered, gapCount: s.gapCount, gapFilled: s.gapFilled,
                                      gapTimeout: s.gapTimeout, ackDemote: s.ackDemote,
                                      buckets: s.residenceBuckets, wallMs: wall)
            }
            dgramLoss = dgramLossWindow.onTick(sent: s.dgramSent, lost: s.dgramLost, wallMs: wall)
        }
        eventLog.ingest(snap)
        publish(snapshot: snap)
    }

    private func publish(snapshot: TunnelSnapshot?) {
        frame = LiveFrame(snapshot: snapshot, bandwidth: bandwidthHistory.samples, slots: bandwidthHistory.slots,
                          reorder: reorderHistory.samples, dgramLoss: dgramLoss)
        let f = snapshot.map { SessionFacts(clientState: $0.clientState, tunnel: $0.tunnel) }
        if f != facts {
            facts = f
            onFacts(f)
        }
    }
}
