// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Small pill used for both the connection header and the path status. Kept
/// here (rather than a separate file) because it exists only to render the
/// status enums this card decodes.
struct StatusBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.22)))
            .foregroundColor(color)
    }
}

/// One card per path in the snapshot: interface icon + name, status badge, and
/// cumulative tx/rx with an instantaneous rate.
struct PathCardView: View {
    let path: PathSnapshot
    let rateMbps: Double?

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: Self.icon(for: path.name))
                .font(.title2)
                .frame(width: 30)
                .foregroundColor(Self.statusColor(path.status))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(path.name).font(.headline)
                    StatusBadge(text: Self.statusName(path.status),
                                color: Self.statusColor(path.status))
                }
                HStack(spacing: 14) {
                    Label(Self.mbText(path.txBytes), systemImage: "arrow.up")
                    Label(Self.mbText(path.rxBytes), systemImage: "arrow.down")
                    if let r = rateMbps {
                        Text(String(format: "%.2f Mbps", r))
                            .foregroundColor(.secondary)
                    }
                }
                .font(.caption)
            }
            Spacer()
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(.secondarySystemBackground)))
    }

    private static func mbText(_ b: UInt64) -> String {
        String(format: "%.1f MB", Double(b) / (1024 * 1024))
    }

    /// Interface-name → SF Symbol. en* = Wi-Fi, pdp_ip* = cellular radio.
    static func icon(for name: String) -> String {
        if name.hasPrefix("en") { return "wifi" }
        if name.hasPrefix("pdp_ip") { return "antenna.radiowaves.left.and.right" }
        return "network"
    }

    // Raw values mirror mqvpn_path_status_t in libmqvpn.h. The App target does
    // not link libmqvpn, so this display mapping is maintained here by hand;
    // all five enumerators are covered (0..4), with `default` guarding future
    // additions.
    static func statusName(_ s: Int32) -> String {
        switch s {
        case 0: return "PENDING"
        case 1: return "ACTIVE"
        case 2: return "DEGRADED"
        case 3: return "STANDBY"
        case 4: return "CLOSED"
        default: return "?(\(s))"
        }
    }

    static func statusColor(_ s: Int32) -> Color {
        switch s {
        case 1: return .green            // ACTIVE
        case 0, 3: return .yellow        // PENDING / STANDBY (validating-ish)
        case 2: return .orange           // DEGRADED
        case 4: return .gray             // CLOSED
        default: return .red
        }
    }
}
