// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Owns the bulk-download run state. A stable ObservableObject (not View
/// @State) so the async loop and its progress ticker survive dashboard
/// re-renders.
@MainActor
final class BulkDownloadModel: ObservableObject {
    @Published var running = false
    @Published var elapsed = 0.0
    @Published var requests = 0
    @Published var totalBytes = 0
    @Published var message = ""

    let duration = 60.0
    private var ticker: Timer?

    var megabytes: Double { Double(totalBytes) / (1024 * 1024) }
    var throughput: Double { elapsed > 0 ? megabytes / elapsed : 0 }

    /// ~60s of sequential GETs against PoCConfig.bulkURL: user-space traffic
    /// through the tunnel for the multipath load gate. Sequential (NOT
    /// concurrent) so a single active flow drives the gate's per-path striping
    /// observation instead of masking it behind connection fanout.
    func run() async {
        guard !running else { return }
        guard let url = try? PoCConfig.fromBundle().bulkURL else {
            message = "no bulkURL configured"
            return
        }
        running = true
        requests = 0; totalBytes = 0; elapsed = 0; message = ""
        let start = Date()
        // Advance elapsed/progress smoothly even while one GET is in flight.
        ticker = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.running else { return }
                self.elapsed = min(Date().timeIntervalSince(start), self.duration)
            }
        }
        let deadline = start.addingTimeInterval(duration)
        while Date() < deadline {
            do {
                let (data, _) = try await URLSession.shared.data(from: url)
                totalBytes += data.count
                requests += 1
            } catch {
                message = "download error: \(error.localizedDescription)"
                break
            }
        }
        ticker?.invalidate(); ticker = nil
        elapsed = min(Date().timeIntervalSince(start), duration)
        running = false
    }
}

/// Bulk load tool: a single button plus a progress bar and the run metrics
/// (elapsed / requests / total MB / throughput).
struct BulkDownloadView: View {
    @StateObject private var model = BulkDownloadModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Bulk Download").font(.headline)
            Button(model.running ? "Downloading…" : "Run (60s)") {
                Task { await model.run() }
            }
            .buttonStyle(.bordered)
            .disabled(model.running)
            if model.running || model.requests > 0 {
                ProgressView(value: min(model.elapsed, model.duration), total: model.duration)
                HStack {
                    metric("elapsed", String(format: "%.0fs", model.elapsed))
                    metric("reqs", "\(model.requests)")
                    metric("total", String(format: "%.1f MB", model.megabytes))
                    metric("MB/s", String(format: "%.2f", model.throughput))
                }
            }
            if !model.message.isEmpty {
                Text(model.message).font(.caption).foregroundColor(.secondary)
            }
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.caption.monospacedDigit())
            Text(label).font(.caption2).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}
