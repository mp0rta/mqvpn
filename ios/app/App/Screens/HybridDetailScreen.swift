// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android HybridDetailScreen.kt.
struct HybridDetailScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    let back: () -> Void

    static func modeName(_ mode: Int) -> String {
        switch mode {
        case HybridSettings.modeStream: return "Stream"
        case HybridSettings.modeRaw: return "Raw"
        default: return "Auto"
        }
    }

    var body: some View {
        let m = controller.settingsModel!
        DetailScaffold(title: "TCP boost", back: back) {
            Text("Carries TCP over its own lane so it can use several connections. Needs hybrid support on the server; TCP connections fail otherwise.")
                .font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.t2)
            HStack {
                Text("TCP mode").font(.system(size: 13)).foregroundColor(mq.text)
                Spacer()
                Picker("TCP mode", selection: m.binding(\.hybrid.tcpMode)) {
                    ForEach([HybridSettings.modeAuto, HybridSettings.modeStream, HybridSettings.modeRaw], id: \.self) {
                        Text(Self.modeName($0)).tag($0)
                    }
                }.pickerStyle(.menu).tint(mq.accent).disabled(!controller.isEditable)
            }
            Text("Auto decides per connection. Stream always uses the lane. Raw never does.")
                .font(.system(size: 12)).lineSpacing(3).foregroundColor(mq.t2)
        }
    }
}
