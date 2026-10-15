// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Reorder buffer monitor. The caller shows it only when the provider reports
/// reorderConfigured; with activity it renders counters, else a muted idle note.
struct ReorderStatsCard: View {
    let stats: ReorderStatsSnapshot

    private var fillRate: String {
        stats.gapCount > 0
            ? String(format: "%.1f%%", Double(stats.gapFilled) * 100 / Double(stats.gapCount))
            : "—"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Reorder Buffer").font(.headline)
            if stats.delivered > 0 || stats.gapCount > 0 {
                Text("Delivered: \(stats.delivered) | Gaps: \(stats.gapCount) (filled \(fillRate))")
                Text("Timeout: \(stats.gapTimeout) | ACK demote: \(stats.ackDemote)").font(.caption)
                Text(String(format: "Buffered latency: p50=%.1fms p99=%.1fms",
                            stats.bufferedP50Ms, stats.bufferedP99Ms)).font(.caption)
            } else {
                Text("configured — no reorder activity yet")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding().background(Color.secondary.opacity(0.1)).cornerRadius(8)
    }
}
