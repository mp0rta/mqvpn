// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android SetupScreen.kt (three steps). `onDone` dismisses the cover (Skip / Finish).
struct SetupScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    @ObservedObject var availability: TransportAvailability
    let onDone: () -> Void
    @State private var step = 0
    @State private var tried = false
    @State private var keyShown = false
    @State private var finishing = false
    @State private var finishError: String?
    @State private var lastPathBlocked = false

    var body: some View {
        let m = controller.settings
        let s = m.draft
        VStack(alignment: .leading, spacing: 0) {
            Text("Step \(step + 1) of 3").font(.system(size: 11, weight: .semibold)).foregroundColor(mq.t2)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch step {
                    case 0: welcome
                    case 1: server(m, s)
                    default: connections(m, s)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
            }
            VStack(spacing: 10) {
                if step == 0 {
                    PrimaryButton("Get Started") { step = 1 }
                    Button(action: onDone) {
                        Text("Skip setup").font(.system(size: 13)).foregroundColor(mq.t2).frame(maxWidth: .infinity).padding(8)
                    }.buttonStyle(.plain)
                } else {
                    HStack(spacing: 10) {
                        SecondaryButton("Back") { step -= 1 }.frame(width: 90)
                        if step == 1 {
                            PrimaryButton("Continue") { commitThen { if m.draft.server != nil { step = 2 } else { tried = true } } }
                        } else {
                            PrimaryButton("Finish Setup") { finish(m) }.disabled(!s.paths.anyEnabled || finishing)
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 24).padding(.top, 24).padding(.bottom, 20)
        .background(mq.win.ignoresSafeArea())
    }

    /// Resign focus so the field commits, then run `next` against the committed draft.
    private func commitThen(_ next: @escaping () -> Void) {
        endEditing()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 60_000_000)
            next()
        }
    }

    private func finish(_ m: SettingsCore) {
        finishing = true; finishError = nil
        Task { @MainActor in
            if await m.commitFirst() { onDone() }
            else { finishError = m.saveError ?? m.fieldErrors.values.sorted().first ?? "Settings could not be saved" }
            finishing = false
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(spacing: 18) {
                MqvpnMark(joint: mq.win).frame(width: 96, height: 96)
                Text("All your connections.\nOne stronger connection.").font(.system(size: 22, weight: .bold))
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
            Text("✓").fontWeight(.bold).foregroundColor(mq.green)
            Text(t).font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.text)
        }
    }

    private func heading(_ t: String) -> some View {
        Text(t).font(.system(size: 20, weight: .bold)).foregroundColor(mq.text)
    }

    private func server(_ m: SettingsCore, _ s: AppDraft) -> some View {
        let bad = (tried || !s.addressText.trimmingCharacters(in: .whitespaces).isEmpty) && s.server == nil
        return VStack(alignment: .leading, spacing: 16) {
            heading("Connect to your server")
            Text("Your server admin gives you these two values. On your own server, run mqvpn --genkey to create a key.")
                .font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.t2)
            FieldBox(label: "Server address", note: bad ? "Enter a server address, e.g. vpn.example.com:443" : nil, noteIsError: bad) {
                CommitField(label: "Server address", value: s.addressText, keyboard: .URL) { t in m.update { $0.addressText = t } }
            }
            FieldBox(label: "Access key", trailing: AnyView(ShowHide(shown: $keyShown))) {
                CommitField(label: "Access key", value: s.authKey, secure: !keyShown) { t in m.update { $0.authKey = t } }
            }
            MqCard {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 0) {
                        Text("Trust self-signed certificate").font(.system(size: 13)).foregroundColor(mq.text)
                        Text("Only for test servers you own. Turn off once your server has a real certificate.")
                            .font(.system(size: 11)).lineSpacing(3).foregroundColor(mq.t2)
                    }
                    Toggle("Trust self-signed certificate", isOn: m.binding(\.insecure)).labelsHidden().tint(mq.accent)
                }
            }
            Text("iOS will ask for permission to add a VPN configuration when you finish setup.")
                .font(.system(size: 12)).lineSpacing(3).foregroundColor(mq.t2)
        }
    }

    private func connections(_ m: SettingsCore, _ s: AppDraft) -> some View {
        let rows: [(TransportKind, String, String, Bool, Bool)] = [
            (.wifi, "Wi\u{2011}Fi", "Wireless network", availability.wifi, s.paths.wifi),
            (.cellular, "Cellular", "May use mobile data", availability.cellular, s.paths.cellular),
        ]
        return VStack(alignment: .leading, spacing: 16) {
            heading("Your connections")
            Text("We found these on your device. Use carries traffic; Off leaves a connection out. Change this anytime in Paths.")
                .font(.system(size: 13)).lineSpacing(5).foregroundColor(mq.t2)
            ForEach(rows, id: \.0.hashValue) { kind, name, sub, found, on in
                MqCard {
                    VStack(alignment: .leading, spacing: 10) {
                        VStack(alignment: .leading, spacing: 0) {
                            Text(name).font(.system(size: 13, weight: .semibold)).foregroundColor(mq.text)
                            Text(found ? sub : "Not available").font(.system(size: 11)).foregroundColor(mq.t2)
                        }
                        if found {
                            UseOffSegmented(isOn: on) { want in
                                guard let p = s.paths.setting(kind, on: want) else { lastPathBlocked = true; return }
                                lastPathBlocked = false
                                m.update { $0.paths = p }
                            }
                        }
                    }
                }.opacity(found ? 1 : 0.5)
            }
            if lastPathBlocked { Text(lastPathCaption).font(.system(size: 12)).foregroundColor(mq.red) }
            if let e = m.fieldErrors["paths"] { Text(e).font(.system(size: 12)).foregroundColor(mq.red) }
            if let e = finishError { Text(e).font(.system(size: 12)).foregroundColor(mq.red) }
        }
    }
}

/// The mqvpn mark without its tile (geometry from ic_launcher_foreground.xml, 64x64 source).
/// The joint dot follows the background so dark mode shows no stark blob.
private struct MqvpnMark: View {
    let joint: Color
    var body: some View {
        Canvas { ctx, size in
            let k = size.width / 64
            func pill(_ x: CGFloat, _ y: CGFloat) -> Path {
                Path(roundedRect: CGRect(x: x * k, y: y * k, width: 34 * k, height: 14 * k), cornerRadius: 7 * k)
            }
            ctx.fill(pill(8, 14), with: .color(Color(argb: 0xFFB8A3F6)))
            ctx.fill(pill(22, 36), with: .linearGradient(
                Gradient(colors: [Color(argb: 0xFF8B5CF6), Color(argb: 0xFF5B21B6)]),
                startPoint: CGPoint(x: 22 * k, y: 36 * k), endPoint: CGPoint(x: 56 * k, y: 50 * k)))
            ctx.fill(Path(ellipseIn: CGRect(x: 28 * k, y: 28 * k, width: 8 * k, height: 8 * k)), with: .color(joint))
        }
    }
}
