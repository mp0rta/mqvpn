// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android SetupScreen.kt (three steps). `onDone` dismisses the cover (Skip / Finish).
struct SetupScreen: View {
    @Environment(\.mq) private var mq
    @ScaledMetric(relativeTo: .subheadline) private var backWidth: CGFloat = 90
    let form: SettingsForm
    let available: Set<TransportKind>
    /// Persists the draft (creating the VPN configuration); nil on success, else the error to show.
    let finish: @MainActor () async -> String?
    let onDone: () -> Void
    @State private var step = 0
    @State private var tried = false
    @State private var keyShown = false
    @State private var finishing = false
    @State private var finishError: String?
    @State private var lastPathBlocked = false
    /// Step 2 text as typed; nil = untouched. Continue applies it itself, since the
    /// fields' focus-loss commit lands only on a later SwiftUI update.
    @State private var typedAddress: String?
    @State private var typedKey: String?

    var body: some View {
        let s = form.draft
        VStack(alignment: .leading, spacing: 0) {
            Text("Step \(step + 1) of 3").mqFont(11, .semibold).foregroundColor(mq.t2)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch step {
                    case 0: welcome
                    case 1: server(s)
                    default: connections(s)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
            }
            VStack(spacing: 10) {
                if step == 0 {
                    // App Review 5.4: the data declaration must be on screen before
                    // any use, so it sits above both Get Started and Skip.
                    Text("mqvpn collects no data. Your traffic goes only to the server you set up. [Privacy policy](https://docs.mqvpn.org/privacy)")
                        .mqFont(12).foregroundColor(mq.t2).tint(mq.accent)
                        .multilineTextAlignment(.center).frame(maxWidth: .infinity)
                    PrimaryButton("Get Started") { step = 1 }
                    Button(action: onDone) {
                        Text("Skip setup").mqFont(13).foregroundColor(mq.t2).frame(maxWidth: .infinity).padding(8)
                    }.buttonStyle(.plain)
                } else {
                    HStack(spacing: 10) {
                        SecondaryButton("Back") { step -= 1 }.frame(width: backWidth)
                        if step == 1 {
                            PrimaryButton("Continue") { continueFromServer() }
                        } else {
                            PrimaryButton("Finish Setup") { runFinish() }.disabled(!s.paths.anyEnabled || finishing)
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 24).padding(.top, 24).padding(.bottom, 20)
        .background(mq.win.ignoresSafeArea())
    }

    private func continueFromServer() {
        endEditing()
        // Decide on the typed text itself: `form` is this render's value, not the edited draft.
        var d = form.draft
        if let a = typedAddress { d.addressText = a }
        if let k = typedKey { d.authKey = k }
        if d != form.draft {
            let (a, k) = (d.addressText, d.authKey)
            form.update { $0.addressText = a; $0.authKey = k }
        }
        if d.server != nil { step = 2 } else { tried = true }
    }

    private func runFinish() {
        finishing = true; finishError = nil
        Task { @MainActor in
            if let e = await finish() { finishError = e } else { onDone() }
            finishing = false
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(spacing: 18) {
                MqvpnMark().frame(width: 96, height: 96).accessibilityHidden(true)
                Text("All your connections.\nOne stronger connection.").mqFont(22, .bold)
                    .foregroundColor(mq.text).multilineTextAlignment(.center)
            }.frame(maxWidth: .infinity).padding(.top, 28)
            VStack(alignment: .leading, spacing: 12) {
                bullet("Uses Wi\u{2011}Fi and Cellular at the same time for more speed")
                bullet("If one connection drops, the others take over instantly — calls and downloads keep going")
                bullet("All traffic is encrypted, end to end")
            }
        }
    }

    private func bullet(_ t: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "checkmark").mqFont(13, .bold).foregroundColor(mq.green).accessibilityHidden(true)
            Text(t).mqFont(13).lineSpacing(5).foregroundColor(mq.text)
        }
    }

    private func heading(_ t: String) -> some View {
        Text(t).mqFont(20, .bold).foregroundColor(mq.text).accessibilityAddTraits(.isHeader)
    }

    private func server(_ s: AppDraft) -> some View {
        let bad = (tried || !s.addressText.trimmingCharacters(in: .whitespaces).isEmpty) && s.server == nil
        return VStack(alignment: .leading, spacing: 16) {
            heading("Connect to your server")
            Text("Your server admin gives you these two values. On your own server, run mqvpn --genkey to create a key.")
                .mqFont(13).lineSpacing(5).foregroundColor(mq.t2)
            FieldBox(label: "Server address", note: bad ? "Enter a server address, e.g. vpn.example.com:443" : nil, noteIsError: bad) {
                CommitField(label: "Server address", value: s.addressText, keyboard: .URL,
                            onType: { typedAddress = $0 }) { t in form.update { $0.addressText = t } }
            }
            FieldBox(label: "Access key", trailing: AnyView(ShowHide(shown: $keyShown))) {
                CommitField(label: "Access key", value: s.authKey, secure: !keyShown,
                            onType: { typedKey = $0 }) { t in form.update { $0.authKey = t } }
            }
            MqCard {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 0) {
                        Text("Trust self-signed certificate").mqFont(13).foregroundColor(mq.text)
                        Text("Only for test servers you own. Turn off once your server has a real certificate.")
                            .mqFont(11).lineSpacing(3).foregroundColor(mq.t2)
                    }
                    Toggle("Trust self-signed certificate", isOn: form.binding(\.insecure)).labelsHidden().tint(mq.accent)
                }
            }
            Text("iOS will ask for permission to add a VPN configuration when you finish setup.")
                .mqFont(12).lineSpacing(3).foregroundColor(mq.t2)
        }
    }

    private func connections(_ s: AppDraft) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            heading("Your connections")
            Text("We found these on your device. Use carries traffic; Off leaves a connection out. Change this anytime in Paths.")
                .mqFont(13).lineSpacing(5).foregroundColor(mq.t2)
            ForEach(TransportKind.allCases, id: \.self) { kind in
                let found = available.contains(kind)
                MqCard {
                    VStack(alignment: .leading, spacing: 10) {
                        VStack(alignment: .leading, spacing: 0) {
                            Text(kind.title).mqFont(13, .semibold).foregroundColor(mq.text)
                            Text(found ? kind.setupCaption : "Not available").mqFont(11).foregroundColor(mq.t2)
                        }
                        if found {
                            UseOffSegmented(isOn: s.paths[kind]) { want in
                                guard let p = s.paths.setting(kind, on: want) else { lastPathBlocked = true; return }
                                lastPathBlocked = false
                                form.update { $0.paths = p }
                            }
                            .accessibilityLabel(kind.title)
                        }
                    }
                }.opacity(found ? 1 : 0.5)
            }
            if lastPathBlocked { Text(lastPathCaption).mqFont(12).foregroundColor(mq.red) }
            if let e = form.errors[.paths] { Text(e).mqFont(12).foregroundColor(mq.red) }
            if let e = finishError { Text(e).mqFont(12).foregroundColor(mq.red) }
        }
    }
}

private extension TransportKind {
    var setupCaption: String {
        switch self {
        case .wifi: return "Wireless network"
        case .cellular: return "May use mobile data"
        }
    }
}

/// The mqvpn mark on its app-icon tile (geometry from ic_launcher_foreground.xml,
/// 64x64 source). The tile keeps the joint dot visible in both themes; on the
/// bare background a theme-colored dot vanishes into the gap between the pills.
private struct MqvpnMark: View {
    var body: some View {
        Canvas { ctx, size in
            let k = size.width / 64
            ctx.fill(Path(roundedRect: CGRect(origin: .zero, size: size), cornerRadius: 14 * k, style: .continuous),
                     with: .color(Color(argb: 0xFFE9E1FB)))
            func pill(_ x: CGFloat, _ y: CGFloat) -> Path {
                Path(roundedRect: CGRect(x: x * k, y: y * k, width: 34 * k, height: 14 * k), cornerRadius: 7 * k)
            }
            ctx.fill(pill(8, 14), with: .color(Color(argb: 0xFFB8A3F6)))
            ctx.fill(pill(22, 36), with: .linearGradient(
                Gradient(colors: [Color(argb: 0xFF8B5CF6), Color(argb: 0xFF5B21B6)]),
                startPoint: CGPoint(x: 22 * k, y: 36 * k), endPoint: CGPoint(x: 56 * k, y: 50 * k)))
            ctx.fill(Path(ellipseIn: CGRect(x: 28 * k, y: 28 * k, width: 8 * k, height: 8 * k)), with: .color(Color(argb: 0xFFFBFAFF)))
        }
    }
}
