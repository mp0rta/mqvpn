// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android ReorderDetailScreen.kt.
struct ReorderDetailScreen: View {
    @Environment(\.mq) private var mq
    let form: SettingsForm
    let back: () -> Void

    var body: some View {
        let d = form.draft
        let editable = form.editable
        let scan = ReorderSettings.scanPorts(d.reorder.portsText)
        DetailScaffold(title: "Smooth out packet order", back: back) {
            Text("Re-orders packets that arrive mixed-up across connections, so apps see them in order. It only touches UDP traffic on the ports below.")
                .mqFont(13).lineSpacing(5).foregroundColor(mq.t2)
            HStack {
                Text("Profile").mqFont(13).foregroundColor(mq.text)
                Spacer()
                Picker("Profile", selection: form.binding(\.reorder.profile)) {
                    Text("CELLULAR BOND").tag(ReorderSettings.profileCellularBond)
                    Text("FIBER LTE").tag(ReorderSettings.profileFiberLTE)
                }.pickerStyle(.menu).tint(mq.accent).disabled(!editable)
            }
            let e = form.errors[.reorderPorts]
            FieldBox(label: "UDP ports", note: e ?? "Comma-separated, e.g. 443", noteIsError: e != nil) {
                CommitField(label: "UDP ports", value: d.reorder.portsText, enabled: editable) { t in
                    form.update { $0.reorder.portsText = t }
                }
            }
            if scan.valid.count > ReorderSettings.maxRules {
                Text("Only the first \(ReorderSettings.maxRules) ports take effect").mqFont(12).foregroundColor(MqTheme.warning)
            }
            if !scan.invalid.isEmpty {
                Text("Invalid ports ignored: " + scan.invalid.joined(separator: ", ")).mqFont(12).foregroundColor(MqTheme.warning)
            }
        }
    }
}
