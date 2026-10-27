// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Provider-side ring of the last 31 samples (one per second, ~30 s window).
final class SampleRing {
    static let capacity = 31
    private var buf: [TunnelSample] = []

    func append(_ s: TunnelSample) {
        buf.append(s)
        if buf.count > Self.capacity { buf.removeFirst(buf.count - Self.capacity) }
    }

    /// nil / ahead of newest (session restart) / older than oldest-1 (gap) => all.
    func since(_ seq: UInt64?) -> [TunnelSample] {
        guard let seq = seq, let first = buf.first, let last = buf.last,
              seq <= last.seq, seq >= first.seq &- 1 else { return buf }
        return buf.filter { $0.seq > seq }
    }

    func clear() { buf.removeAll() }
}

/// App-side consumer of the sample protocol: dedups overlapping replies and
/// detects provider restarts via bootId.
struct SampleCursor {
    private var bootId: UInt64?
    private var lastReplayedSeq: UInt64 = 0

    mutating func accept(bootId: UInt64, samples: [TunnelSample]) -> (reset: Bool, fresh: [TunnelSample]) {
        let reset = self.bootId != bootId
        if reset { self.bootId = bootId; lastReplayedSeq = 0 }
        let fresh = reset ? samples : samples.filter { $0.seq > lastReplayedSeq }
        if let m = fresh.map({ $0.seq }).max() { lastReplayedSeq = max(lastReplayedSeq, m) }
        return (reset, fresh)
    }

    /// nil until a bootId is known (=> provider sends the full ring).
    var request: (sinceSeq: UInt64, bootId: UInt64)? {
        bootId.map { (lastReplayedSeq, $0) }
    }
}

/// Request payload app -> provider. nil cursor / empty / undecodable => nil (full ring).
enum SnapshotRequest {
    private struct Wire: Codable { let sinceSeq: UInt64; let bootId: UInt64 }

    static func encode(cursor: (sinceSeq: UInt64, bootId: UInt64)?) -> Data {
        guard let c = cursor else { return Data() }
        return (try? JSONEncoder().encode(Wire(sinceSeq: c.sinceSeq, bootId: c.bootId))) ?? Data()
    }

    static func decode(_ data: Data) -> (sinceSeq: UInt64, bootId: UInt64)? {
        guard !data.isEmpty, let w = try? JSONDecoder().decode(Wire.self, from: data) else { return nil }
        return (w.sinceSeq, w.bootId)
    }
}
