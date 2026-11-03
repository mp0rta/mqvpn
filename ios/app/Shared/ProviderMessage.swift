// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Wire schema for the provider -> app development snapshot, shared by both
/// targets. The extension produces it on its tick thread; the container app
/// polls for it via `sendProviderMessage`. Pure Foundation types only — the
/// App target does not link libmqvpn, so raw enum values cross the boundary
/// as integers and the app maps them to display names itself. App and extension
/// ship in one bundle, so both sides always speak the same schema: no old-wire
/// fallbacks.
struct TunnelSnapshot: Codable {
    let timestamp: Double          // Date().timeIntervalSince1970 (provider side)
    let clientState: Int32         // mqvpn_client_get_state raw value
    let connectedSince: Double?    // first-ESTABLISHED wall-clock (uptime display)
    let paths: [PathSnapshot]
    let seq: UInt64                    // provider-monotonic ordering key
    let reorderConfigured: Bool        // core enabled with >=1 rule (provider truth)
    let reorder: ReorderStatsSnapshot? // nil = layout-unavailable / not present
    let tunnel: TunnelInfoSnapshot?    // nil = not yet established
    let stats: StatsSnapshot?
    var samples: [TunnelSample]        // ring replay, filled per request (see SampleRing)
    let bootId: UInt64                 // random per provider start

    // The producer (SnapshotCache) passes every field; the defaults keep test fixtures short.
    init(timestamp: Double, clientState: Int32, connectedSince: Double?,
         paths: [PathSnapshot],
         seq: UInt64 = 0, reorderConfigured: Bool = false,
         reorder: ReorderStatsSnapshot? = nil,
         tunnel: TunnelInfoSnapshot? = nil, stats: StatsSnapshot? = nil,
         samples: [TunnelSample] = [], bootId: UInt64 = 0) {
        self.timestamp = timestamp; self.clientState = clientState
        self.connectedSince = connectedSince
        self.paths = paths; self.seq = seq
        self.reorderConfigured = reorderConfigured; self.reorder = reorder
        self.tunnel = tunnel; self.stats = stats
        self.samples = samples; self.bootId = bootId
    }
}

/// mqvpn_client_state_t raw values (libmqvpn.h). The wire keeps the Int32 so
/// an unknown future value still decodes; map it with `init(rawValue:)`.
enum CoreClientState: Int32 {
    case idle, connecting, authenticating, tunnelReady, established, reconnecting, closed
}

/// mqvpn_path_status_t raw values (libmqvpn.h).
enum CorePathStatus: Int32 {
    case pending, active, degraded, standby, closed
}

/// mqvpn_scheduler_t raw values (libmqvpn.h). The wire keeps the Int32 so an
/// unknown future value still decodes; map it with `init(rawValue:)`.
enum Scheduler: Int32 {
    case minrtt = 0, wlb = 1, backupFec = 2, wlbUdpPin = 3

    /// The config-file spelling (`Scheduler = ...`).
    var label: String {
        switch self {
        case .minrtt: return "minrtt"
        case .wlb: return "wlb"
        case .backupFec: return "backup_fec"
        case .wlbUdpPin: return "wlb_udp_pin"
        }
    }
}

struct PathSnapshot: Codable {
    let name: String               // interface name (en0 / pdp_ip0)
    let status: Int32              // mqvpn_path_status_t raw value
    let txBytes: UInt64
    let rxBytes: UInt64
    /// The transport the provider bound this path to; nil = not one it manages.
    var kind: TransportKind? = nil
}

struct SamplePath: Codable, Equatable {
    let name: String
    let txBytes: UInt64
    let rxBytes: UInt64
}

struct TunnelSample: Codable, Equatable {
    let seq: UInt64
    let wallMs: UInt64
    let monoMs: UInt64
    let paths: [SamplePath]
    let bytesTx: UInt64
    let bytesRx: UInt64
    let dgramSent: UInt64
    let dgramLost: UInt64
    let delivered: UInt64
    let gapCount: UInt64
    let gapFilled: UInt64
    let gapTimeout: UInt64
    let ackDemote: UInt64
    let residenceBuckets: [UInt64]
}

struct TunnelInfoSnapshot: Codable, Equatable {
    let assignedIp: String
    let assignedIp6: String?       // nil = no IPv6 assigned
    let mtu: Int32
    let serverScheduler: Int32?
    let requestedScheduler: Int32?
}

struct StatsSnapshot: Codable, Equatable {
    let bytesTx: UInt64
    let bytesRx: UInt64
    let dgramSent: UInt64
    let dgramLost: UInt64
    let srttMs: Double
}

struct ReorderStatsSnapshot: Codable, Equatable {
    let delivered: UInt64      // delivered_count
    let gapCount: UInt64       // gap_count
    let gapFilled: UInt64      // gap_filled_count
    let gapTimeout: UInt64     // gap_timeout_count
    let ackDemote: UInt64      // ack_demote_count
    let residenceBuckets: [UInt64]
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
