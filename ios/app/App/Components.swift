// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Ports of the android ui/components + HomeScreen helpers. Render-only: no logic.

struct MqCard<Content: View>: View {
    @Environment(\.mq) private var mq
    var hPad: CGFloat = 14
    var vPad: CGFloat = 12   // rows cards use vPad 4 (PaddingValuesRows)
    let content: Content
    init(hPad: CGFloat = 14, vPad: CGFloat = 12, @ViewBuilder content: () -> Content) {
        self.hPad = hPad; self.vPad = vPad; self.content = content()
    }
    var body: some View {
        content.padding(.horizontal, hPad).padding(.vertical, vPad)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(mq.card, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct Hairline: View {
    @Environment(\.mq) private var mq
    var body: some View { Rectangle().fill(mq.sep).frame(height: 1) }
}

struct SectionLabel: View {
    @Environment(\.mq) private var mq
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.system(size: 11, weight: .semibold)).tracking(0.5)
            .foregroundColor(mq.t2).padding(.horizontal, 4)
    }
}

struct StatusDot: View {
    let color: Color
    var size: CGFloat = 8
    var body: some View { Circle().fill(color).frame(width: size, height: size) }
}

struct ToggleRow: View {
    @Environment(\.mq) private var mq
    let title: String
    let caption: String?
    @Binding var isOn: Bool
    var enabled: Bool = true
    var last: Bool = false
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 13)).foregroundColor(mq.text)
                    if let caption {
                        Text(caption).font(.system(size: 11)).foregroundColor(mq.t2).lineSpacing(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 0)
                Toggle("", isOn: $isOn).labelsHidden().tint(mq.accent).disabled(!enabled)
            }.padding(.vertical, 11)
            if !last { Hairline() }
        }
    }
}

struct KvRow: View {
    @Environment(\.mq) private var mq
    let key: String
    let value: String
    var tick: Bool = false
    var last: Bool = false
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(key).foregroundColor(mq.t2)
                Spacer(minLength: 8)
                (Text(value).foregroundColor(mq.text) + Text(tick ? " ✓" : "").foregroundColor(mq.green))
                    .fontWeight(.medium)
            }.font(.system(size: 12.5)).padding(.vertical, 10)
            if !last { Hairline() }
        }
    }
}

struct RateTile: View {
    @Environment(\.mq) private var mq
    let label: String
    let mbps: String
    let arrowColor: Color
    var arrow: String = "↑"
    var body: some View {
        MqCard {
            VStack(alignment: .leading, spacing: 2) {
                (Text(arrow).fontWeight(.bold).foregroundColor(arrowColor) + Text(" \(label)").foregroundColor(mq.t2))
                    .font(.system(size: 11))
                (Text(mbps).font(.system(size: 19, weight: .bold)).foregroundColor(mq.text)
                    + Text(" Mbps").font(.system(size: 11, weight: .medium)).foregroundColor(mq.t2))
            }
        }
    }
}

struct PrimaryButton: View {
    @Environment(\.mq) private var mq
    @Environment(\.isEnabled) private var isEnabled
    let title: String
    let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: 15, weight: .semibold)).foregroundColor(.white)
                .padding(.vertical, 12).frame(maxWidth: .infinity)
                .background(mq.accent.opacity(isEnabled ? 1 : 0.4), in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }
}

struct SecondaryButton: View {
    @Environment(\.mq) private var mq
    @Environment(\.isEnabled) private var isEnabled
    let title: String
    let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: 15, weight: .semibold)).foregroundColor(mq.accent.opacity(isEnabled ? 1 : 0.4))
                .padding(.vertical, 12).frame(maxWidth: .infinity)
                .background(mq.fill, in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }
}

/// Use / Off segmented control (android UseOffSegmented).
struct UseOffSegmented: View {
    @Environment(\.mq) private var mq
    let isOn: Bool
    var enabled: Bool = true
    let onChange: (Bool) -> Void
    var body: some View {
        HStack(spacing: 0) {
            ForEach([("Use", true), ("Off", false)], id: \.0) { label, v in
                let sel = isOn == v
                Text(label).font(.system(size: 13, weight: sel ? .semibold : .regular)).foregroundColor(mq.text)
                    .padding(.vertical, 6).frame(maxWidth: .infinity)
                    .background {
                        if sel {
                            RoundedRectangle(cornerRadius: 6).fill(mq.card).shadow(color: mq.segsh, radius: 3, x: 0, y: 1)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { if enabled { onChange(v) } }
                    .accessibilityAddTraits(sel ? [.isButton, .isSelected] : .isButton)
            }
        }
        .padding(2).background(mq.fill, in: RoundedRectangle(cornerRadius: 8))
        .opacity(enabled ? 1 : 0.5)
    }
}

struct RadioRow: View {
    @Environment(\.mq) private var mq
    let label: String
    var dim: String? = nil
    let selected: Bool
    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle().stroke(selected ? mq.accent : mq.fill2, lineWidth: 2).frame(width: 18, height: 18)
                if selected { Circle().fill(mq.accent).frame(width: 10, height: 10) }
            }
            Text(label).font(.system(size: 13)).foregroundColor(mq.text)
            if let dim { Text(dim).font(.system(size: 11)).foregroundColor(mq.t2) }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 8).contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// Detail page chrome: "‹ Settings" back link, bold title, scrolling content (padding h20 v12, gap 14).
struct DetailScaffold<Content: View>: View {
    @Environment(\.mq) private var mq
    let title: String
    let back: () -> Void
    let content: Content
    init(title: String, back: @escaping () -> Void, @ViewBuilder content: () -> Content) {
        self.title = title; self.back = back; self.content = content()
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Button(action: back) { Text("‹ Settings").font(.system(size: 14)).foregroundColor(mq.accent) }
                    .buttonStyle(.plain)
                Text(title).font(.system(size: 20, weight: .bold)).foregroundColor(mq.text)
                content
            }.padding(.horizontal, 20).padding(.vertical, 12).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }
}
