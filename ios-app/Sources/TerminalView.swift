import SwiftUI

struct TerminalView: View {
    @ObservedObject var session: ITerminalSession
    @State private var inputLine: String = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(session.isRunning ? Color.green : (session.isReady ? Color.yellow : Color.orange))
                        .frame(width: 8, height: 8)
                    Text(session.statusText)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer()
                    Button("Boot sh") {
                        session.bootShell()
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .buttonStyle(.bordered)
                    .tint(.green)

                    Button("Ctrl-C") {
                        session.sendCtrlC()
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button("Clear") {
                        session.outputLog = ""
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(white: 0.1))

                Divider()

                ScrollViewReader { proxy in
                    ScrollView {
                        Text(session.outputLog.isEmpty ? "iTerminal (WebKit JSC JIT)\nInitializing...\n" : session.outputLog)
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundStyle(Color(red: 0.85, green: 0.96, blue: 0.85))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(12)
                            .id("BOTTOM")
                    }
                    .background(Color.black)
                    .onChange(of: session.outputLog) { _ in
                        withAnimation(.easeOut(duration: 0.1)) {
                            proxy.scrollTo("BOTTOM", anchor: .bottom)
                        }
                    }
                }

                Divider()

                HStack(spacing: 8) {
                    Text("$")
                        .font(.system(size: 14, weight: .bold, design: .monospaced))
                        .foregroundStyle(.green)

                    TextField("Enter command or stdin...", text: $inputLine)
                        .font(.system(size: 14, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .submitLabel(.send)
                        .onSubmit(submitLine)

                    Button("Send", action: submitLine)
                        .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        .buttonStyle(.borderedProminent)
                        .tint(.green)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(Color(white: 0.1))
            }
            .navigationTitle("iTerminal")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func submitLine() {
        let line = inputLine
        inputLine = ""
        session.sendLine(line)
    }
}
