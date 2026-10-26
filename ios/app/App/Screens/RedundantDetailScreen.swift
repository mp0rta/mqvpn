// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android RedundantDetailScreen.kt.
struct RedundantDetailScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    let back: () -> Void

    var body: some View {
        let m = controller.settingsModel!
        let d = m.draft
        let e = m.fieldErrors["redundantPorts"]
        // A stored list that could not be read shows blank while the provider copies no UDP.
        let unreadable = d.split.redundantEnabled && d.split.redundantPortsMalformed
            && d.redundantPortsText.trimmingCharacters(in: .whitespaces).isEmpty
        DetailScaffold(title: "Redundant", back: back) {
            Text("Sends copies of UDP packets over more than one connection at once, which helps live streams keep going when a connection drops. Uses up to twice the data with two connections, three times with three.")
                .font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.t2)
            FieldBox(label: "UDP ports",
                     note: e ?? "Leave empty to copy all UDP. Up to \(SplitSettings.maxRedundantPorts) ports, comma-separated.",
                     noteIsError: e != nil) {
                CommitField(label: "UDP ports", value: d.redundantPortsText, enabled: controller.isEditable) { t in
                    m.update { $0.redundantPortsText = t }
                }
            }
            if unreadable {
                Text("The saved port list could not be read, so no UDP is being copied. Enter the ports again to fix it.")
                    .font(.system(size: 12)).foregroundColor(MqTheme.warning)
            }
        }
    }
}
