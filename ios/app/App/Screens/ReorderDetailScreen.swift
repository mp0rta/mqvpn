// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android ReorderDetailScreen.kt.
struct ReorderDetailScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    let back: () -> Void

    /// Trimmed non-empty tokens that are not a valid port (1-65535).
    private static func invalidTokens(_ text: String) -> [String] {
        text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !(Int($0).map { (1...65535).contains($0) } ?? false) }
    }

    var body: some View {
        let m = controller.settingsModel!
        let d = m.draft
        let editable = controller.isEditable
        let distinct = Set(d.reorder.portsText.split(separator: ",").compactMap {
            Int($0.trimmingCharacters(in: .whitespaces)).flatMap { (1...65535).contains($0) ? $0 : nil }
        }).count
        let invalid = Self.invalidTokens(d.reorder.portsText)
        DetailScaffold(title: "Smooth out packet order", back: back) {
            Text("Re-orders packets that arrive mixed-up across connections, so apps see them in order. It only touches UDP traffic on the ports below.")
                .font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.t2)
            HStack {
                Text("Profile").font(.system(size: 13)).foregroundColor(mq.text)
                Spacer()
                Picker("Profile", selection: m.binding(\.reorder.profile)) {
                    Text("CELLULAR BOND").tag(ReorderSettings.profileCellularBond)
                    Text("FIBER LTE").tag(ReorderSettings.profileFiberLTE)
                }.pickerStyle(.menu).tint(mq.accent).disabled(!editable)
            }
            let e = m.fieldErrors["reorderPorts"]
            FieldBox(label: "UDP ports", note: e ?? "Comma-separated, e.g. 443", noteIsError: e != nil) {
                CommitField(label: "UDP ports", value: d.reorder.portsText, enabled: editable) { t in
                    m.update { $0.reorder.portsText = t }
                }
            }
            if distinct > ReorderSettings.maxRules {
                Text("Only the first \(ReorderSettings.maxRules) ports take effect").font(.system(size: 12)).foregroundColor(MqTheme.warning)
            }
            if !invalid.isEmpty {
                Text("Invalid ports ignored: " + invalid.joined(separator: ", ")).font(.system(size: 12)).foregroundColor(MqTheme.warning)
            }
        }
    }
}
