// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Wire schema for the provider -> app development snapshot, shared by both
/// targets. The extension produces it on its tick thread; the container app
/// polls for it via `sendProviderMessage`. Pure Foundation types only — the
/// App target does not link libmqvpn, so raw enum values cross the boundary
/// as integers and the app maps them to display names itself.
struct TunnelSnapshot: Codable {
    let timestamp: Double          // Date().timeIntervalSince1970 (provider side)
    let clientState: Int32         // mqvpn_client_get_state raw value
    let connectedSince: Double?    // first-ESTABLISHED wall-clock (uptime display)
    let footprint: UInt64          // task_vm_info phys_footprint, bytes
    let paths: [PathSnapshot]
    let seq: UInt64                    // provider-monotonic ordering key
    let reorderConfigured: Bool        // core enabled with >=1 rule (provider truth)
    let reorder: ReorderStatsSnapshot? // nil = layout-unavailable / not present

    // Explicit memberwise init: the NEW fields default so the existing producer
    // (SnapshotCache) compiles until it is updated to pass real values.
    init(timestamp: Double, clientState: Int32, connectedSince: Double?,
         footprint: UInt64, paths: [PathSnapshot],
         seq: UInt64 = 0, reorderConfigured: Bool = false,
         reorder: ReorderStatsSnapshot? = nil) {
        self.timestamp = timestamp; self.clientState = clientState
        self.connectedSince = connectedSince; self.footprint = footprint
        self.paths = paths; self.seq = seq
        self.reorderConfigured = reorderConfigured; self.reorder = reorder
    }
}

struct PathSnapshot: Codable {
    let name: String               // interface name (en0 / pdp_ip0)
    let status: Int32              // mqvpn_path_status_t raw value
    let txBytes: UInt64
    let rxBytes: UInt64
}

struct ReorderStatsSnapshot: Codable, Equatable {
    let delivered: UInt64      // delivered_count
    let gapCount: UInt64       // gap_count
    let gapFilled: UInt64      // gap_filled_count
    let gapTimeout: UInt64     // gap_timeout_count
    let ackDemote: UInt64      // ack_demote_count
    let bufferedP50Ms: Double  // buffered_percentile(0.50)
    let bufferedP99Ms: Double  // buffered_percentile(0.99)
}

/// The ONLY place the wire codec is chosen. Both sides call through here, so
/// swapping JSON for a binary plist (or any other Codable format) is a
/// one-function change with no callers to touch.
enum ProviderMessage {
    static func encode(_ snapshot: TunnelSnapshot) throws -> Data {
        try JSONEncoder().encode(snapshot)
    }

    static func decode(_ data: Data) throws -> TunnelSnapshot {
        try JSONDecoder().decode(TunnelSnapshot.self, from: data)
    }
}

// A synthesized Codable would THROW on an old-wire payload missing the new
// non-optional keys, dropping the whole snapshot. This explicit decoder
// defaults them instead. Kept as a second initializer so the memberwise init
// the producer uses is preserved.
extension TunnelSnapshot {
    enum CodingKeys: String, CodingKey {
        case timestamp, clientState, connectedSince, footprint, paths
        case seq, reorderConfigured, reorder
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            timestamp: try c.decode(Double.self, forKey: .timestamp),
            clientState: try c.decode(Int32.self, forKey: .clientState),
            connectedSince: try c.decodeIfPresent(Double.self, forKey: .connectedSince),
            footprint: try c.decode(UInt64.self, forKey: .footprint),
            paths: try c.decode([PathSnapshot].self, forKey: .paths),
            seq: try c.decodeIfPresent(UInt64.self, forKey: .seq) ?? 0,
            reorderConfigured: try c.decodeIfPresent(Bool.self, forKey: .reorderConfigured) ?? false,
            reorder: try c.decodeIfPresent(ReorderStatsSnapshot.self, forKey: .reorder))
    }
}
