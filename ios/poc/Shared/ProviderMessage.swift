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
}

struct PathSnapshot: Codable {
    let name: String               // interface name (en0 / pdp_ip0)
    let status: Int32              // mqvpn_path_status_t raw value
    let txBytes: UInt64
    let rxBytes: UInt64
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
