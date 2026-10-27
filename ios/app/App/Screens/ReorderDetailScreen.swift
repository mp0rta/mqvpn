// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android ReorderDetailScreen.kt.
struct ReorderDetailScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    let back: () -> Void

    var body: some View {
        let m = controller.settings
        let d = m.draft
        let editable = controller.isEditable
        let scan = ReorderSettings.scanPorts(d.reorder.portsText)
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
            let e = m.fieldErrors[.reorderPorts]
            FieldBox(label: "UDP ports", note: e ?? "Comma-separated, e.g. 443", noteIsError: e != nil) {
                CommitField(label: "UDP ports", value: d.reorder.portsText, enabled: editable) { t in
                    m.update { $0.reorder.portsText = t }
                }
            }
            if scan.valid.count > ReorderSettings.maxRules {
                Text("Only the first \(ReorderSettings.maxRules) ports take effect").font(.system(size: 12)).foregroundColor(MqTheme.warning)
            }
            if !scan.invalid.isEmpty {
                Text("Invalid ports ignored: " + scan.invalid.joined(separator: ", ")).font(.system(size: 12)).foregroundColor(MqTheme.warning)
            }
        }
    }
}
