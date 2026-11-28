import SwiftUI
import UIKit

struct TerminalView: View {
    @ObservedObject var session: ITerminalSession
    @State private var inputLine: String = ""
    @State private var historyIndex: Int? = nil
    @FocusState private var isInputFocused: Bool

    private let bgCanvas = Color(red: 0.04, green: 0.05, blue: 0.08)
    private let bgChrome = Color(red: 0.09, green: 0.11, blue: 0.15)
    private let fgText = Color(red: 0.86, green: 0.94, blue: 0.88)
    private let accentGreen = Color(red: 0.24, green: 0.82, blue: 0.48)

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Terminal Output Viewport
                ScrollViewReader { proxy in
                    ScrollView {
                        Text(session.outputLog.isEmpty ? "iTerminal · WebKit JSC JIT\n" : session.outputLog)
                            .font(.system(size: session.fontSize, design: .monospaced))
                            .foregroundStyle(fgText)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .id("BOTTOM")
                    }
                    .background(bgCanvas)
                    .contentShape(Rectangle())
                    .onTapGesture { isInputFocused = true }
                    .onChange(of: session.outputLog) { _ in
                        proxy.scrollTo("BOTTOM", anchor: .bottom)
                    }
                }

                // Quick Accessory Key Bar (Terminal keys + History)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        accessoryKey("CTRL-C", tint: .red) { session.sendCtrlC() }
                        accessoryKey("EOF", tint: .orange) { session.sendEOF() }
                        accessoryKey("↑") { navigateHistory(up: true) }
                        accessoryKey("↓") { navigateHistory(up: false) }
                        accessoryKey("TAB") { inputLine.append("\t") }
                        accessoryKey("|") { inputLine.append("|") }
                        accessoryKey("/") { inputLine.append("/") }
                        accessoryKey("-") { inputLine.append("-") }
                        accessoryKey("~") { inputLine.append("~") }
                        accessoryKey(">") { inputLine.append(">") }
                        accessoryKey("&") { inputLine.append("&") }
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                }
                .background(bgChrome.opacity(0.95))
                .overlay(alignment: .top) { Divider().opacity(0.4) }

                // Command Input Bar
                HStack(spacing: 8) {
                    Text("#")
                        .font(.system(size: 15, weight: .bold, design: .monospaced))
                        .foregroundStyle(accentGreen)

                    TextField("Enter Linux command...", text: $inputLine)
                        .font(.system(size: 14, design: .monospaced))
                        .foregroundStyle(.white)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .focused($isInputFocused)
                        .submitLabel(.send)
                        .onSubmit(submitLine)

                    Button(action: submitLine) {
                        Image(systemName: "return")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundStyle(.black)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .background(accentGreen, in: RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(bgChrome)
            }
            .background(bgCanvas)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(session.isRunning ? accentGreen : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(session.statusText)
                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                ToolbarItem(placement: .principal) {
                    Text("iTerminal")
                        .font(.system(size: 15, weight: .bold, design: .monospaced))
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button { session.bootShell() } label: {
                            Label("Restart /bin/sh", systemImage: "play.fill")
                        }
                        Button { session.clearOutput() } label: {
                            Label("Clear Screen", systemImage: "trash")
                        }
                        Divider()
                        Button { session.fontSize = min(20, session.fontSize + 1) } label: {
                            Label("Increase Font", systemImage: "textformat.size.larger")
                        }
                        Button { session.fontSize = max(10, session.fontSize - 1) } label: {
                            Label("Decrease Font", systemImage: "textformat.size.smaller")
                        }
                        Divider()
                        Button(role: .destructive) { session.resetRootFS() } label: {
                            Label("Reset Alpine RootFS", systemImage: "arrow.counterclockwise")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.system(size: 17))
                            .foregroundStyle(accentGreen)
                    }
                }
            }
        }
    }

    private func accessoryKey(_ label: String, tint: Color = .white, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(tint == .white ? Color(white: 0.9) : tint)
                .padding(.horizontal, 9)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(tint == .white ? Color(white: 0.18) : tint.opacity(0.18))
                )
        }
    }

    private func navigateHistory(up: Bool) {
        let hist = session.commandHistory
        guard !hist.isEmpty else { return }
        if up {
            if let idx = historyIndex {
                historyIndex = max(0, idx - 1)
            } else {
                historyIndex = hist.count - 1
            }
            if let idx = historyIndex { inputLine = hist[idx] }
        } else {
            guard let idx = historyIndex else { return }
            if idx + 1 < hist.count {
                historyIndex = idx + 1
                inputLine = hist[idx + 1]
            } else {
                historyIndex = nil
                inputLine = ""
            }
        }
    }

    private func submitLine() {
        let line = inputLine
        inputLine = ""
        historyIndex = nil
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        session.sendLine(line)
        isInputFocused = true
    }
}
