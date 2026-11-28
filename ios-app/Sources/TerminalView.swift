import SwiftUI
import UIKit

/// Hidden UIKeyInput responder so users type directly into the full-screen terminal
/// with zero bottom input text box — matching iSH's native iOS terminal UX.
private struct TerminalKeyInputBridge: UIViewRepresentable {
    @Binding var isFirstResponder: Bool
    var onInsertText: (String) -> Void
    var onDeleteBackward: () -> Void

    func makeUIView(context: Context) -> KeyCaptureView {
        let view = KeyCaptureView()
        view.onInsertText = onInsertText
        view.onDeleteBackward = onDeleteBackward
        return view
    }

    func updateUIView(_ uiView: KeyCaptureView, context: Context) {
        uiView.onInsertText = onInsertText
        uiView.onDeleteBackward = onDeleteBackward
        if isFirstResponder && !uiView.isFirstResponder {
            DispatchQueue.main.async { _ = uiView.becomeFirstResponder() }
        } else if !isFirstResponder && uiView.isFirstResponder {
            DispatchQueue.main.async { _ = uiView.resignFirstResponder() }
        }
    }

    final class KeyCaptureView: UIView, UIKeyInput, UITextInputTraits {
        var onInsertText: ((String) -> Void)?
        var onDeleteBackward: (() -> Void)?

        var autocapitalizationType: UITextAutocapitalizationType = .none
        var autocorrectionType: UITextAutocorrectionType = .no
        var smartQuotesType: UITextSmartQuotesType = .no
        var smartDashesType: UITextSmartDashesType = .no
        var keyboardAppearance: UIKeyboardAppearance = .dark
        var returnKeyType: UIReturnKeyType = .default

        override var canBecomeFirstResponder: Bool { true }
        var hasText: Bool { true }

        func insertText(_ text: String) {
            onInsertText?(text)
        }

        func deleteBackward() {
            onDeleteBackward?()
        }
    }
}

struct TerminalView: View {
    @ObservedObject var session: ITerminalSession
    @State private var keyboardActive: Bool = true
    @State private var showArrows: Bool = false
    @State private var cursorVisible: Bool = true

    private let cursorTimer = Timer.publish(every: 0.55, on: .main, in: .common).autoconnect()
    private let barBg = Color(red: 0.15, green: 0.15, blue: 0.16)
    private let keyBg = Color(red: 0.28, green: 0.28, blue: 0.30)

    var body: some View {
        VStack(spacing: 0) {
            // Pure full-screen edge-to-edge black terminal canvas (iSH style)
            ZStack(alignment: .topLeading) {
                TerminalKeyInputBridge(
                    isFirstResponder: $keyboardActive,
                    onInsertText: { session.handleTypedText($0) },
                    onDeleteBackward: { session.handleBackspace() }
                )
                .frame(width: 1, height: 1)
                .opacity(0.01)

                ScrollViewReader { proxy in
                    ScrollView {
                        (Text(session.outputLog)
                            + Text(session.pendingInput)
                            + Text(cursorVisible ? "█" : " "))
                            .font(.system(size: session.fontSize, design: .monospaced))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 10)
                            .padding(.top, 8)
                            .padding(.bottom, 16)
                            .id("BOTTOM")
                    }
                    .background(Color.black)
                    .contentShape(Rectangle())
                    .onTapGesture { keyboardActive = true }
                    .onChange(of: session.outputLog) { _ in
                        proxy.scrollTo("BOTTOM", anchor: .bottom)
                    }
                    .onChange(of: session.pendingInput) { _ in
                        proxy.scrollTo("BOTTOM", anchor: .bottom)
                    }
                }
            }
            .background(Color.black)

            // iSH-style compact dark accessory toolbar right above the keyboard
            HStack(spacing: 8) {
                ishKey(systemName: "arrow.right.to.line") {
                    session.handleTypedText("\t")
                }

                ishKey(systemName: "control", highlighted: session.ctrlActive) {
                    session.ctrlActive.toggle()
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                }

                ishKey(systemName: "escape") {
                    session.sendCtrlC()
                }

                if showArrows {
                    ishKey(systemName: "arrow.up") { session.navigateHistory(up: true) }
                    ishKey(systemName: "arrow.down") { session.navigateHistory(up: false) }
                    ishKey(systemName: "xmark") { showArrows = false }
                } else {
                    ishKey(systemName: "arrow.up.and.down.and.arrow.left.and.right") {
                        showArrows = true
                    }
                }

                Spacer()

                Menu {
                    Button { session.bootShell() } label: {
                        Label("Restart /bin/sh", systemImage: "play.fill")
                    }
                    Button { session.clearOutput() } label: {
                        Label("Clear Screen", systemImage: "trash")
                    }
                    Divider()
                    Button { session.fontSize = min(22, session.fontSize + 1) } label: {
                        Label("Larger Font", systemImage: "textformat.size.larger")
                    }
                    Button { session.fontSize = max(10, session.fontSize - 1) } label: {
                        Label("Smaller Font", systemImage: "textformat.size.smaller")
                    }
                    Divider()
                    Button(role: .destructive) { session.resetRootFS() } label: {
                        Label("Reset Alpine RootFS", systemImage: "arrow.counterclockwise")
                    }
                } label: {
                    Image(systemName: "gearshape")
                        .font(.system(size: 18))
                        .foregroundStyle(.white)
                        .frame(width: 34, height: 32)
                }

                Button {
                    if let str = UIPasteboard.general.string {
                        session.handleTypedText(str)
                    }
                } label: {
                    Image(systemName: "doc.on.clipboard")
                        .font(.system(size: 17))
                        .foregroundStyle(.white)
                        .frame(width: 34, height: 32)
                }

                Button {
                    keyboardActive.toggle()
                } label: {
                    Image(systemName: keyboardActive ? "keyboard.chevron.compact.down" : "keyboard")
                        .font(.system(size: 18))
                        .foregroundStyle(.white)
                        .frame(width: 34, height: 32)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(barBg)
        }
        .background(Color.black.ignoresSafeArea())
        .onReceive(cursorTimer) { _ in
            cursorVisible.toggle()
        }
    }

    private func ishKey(systemName: String, highlighted: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(highlighted ? .black : .white)
                .frame(width: 36, height: 32)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(highlighted ? Color.white : keyBg)
                )
        }
    }
}
