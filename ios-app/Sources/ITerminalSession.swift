import Combine
import Foundation
import UIKit

@MainActor
public final class ITerminalSession: ObservableObject, GuestHostDelegate {
    @Published public var outputLog: String = ""
    @Published public var pendingInput: String = ""
    @Published public var isRunning: Bool = false
    @Published public var isReady: Bool = false
    @Published public var statusText: String = "Initializing"
    @Published public var fontSize: CGFloat = 14
    @Published public var ctrlActive: Bool = false
    @Published public var commandHistory: [String] = []

    public let bridge = WasmGuestBridgeV2()

    private var stdinBuffer = Data()
    private var pendingStdinMaxLen: Int = 0
    private var pendingStdinCompletion: ((Result<Data, Error>) -> Void)?
    private var historyIndex: Int? = nil

    private var documentsURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    private var snapshotURL: URL {
        documentsURL.appendingPathComponent("iTerminalRootFS.json")
    }

    public init() {
        bridge.delegate = self
    }

    public func startBundledRuntime() {
        guard !isReady else { return }
        guard let runtimeJS = loadBundledJS(named: "iterminal-runtime") else {
            appendOutput("[iTerminal] Missing bundled iterminal-runtime.js\n")
            return
        }
        statusText = "Starting JSC JIT..."
        bridge.setup(runtimeJS: runtimeJS) { [weak self] err in
            Task { @MainActor in
                guard let self = self else { return }
                if let err = err {
                    self.appendOutput("[iTerminal] Bootstrap error: \(err.localizedDescription)\n")
                    return
                }
                self.isReady = true
                self.mountAndBootDefaultShell()
            }
        }
    }

    private func loadBundledJS(named name: String) -> String? {
        let candidates: [URL?] = [
            Bundle.main.url(forResource: name, withExtension: "js"),
            Bundle.main.url(forResource: name, withExtension: "js", subdirectory: "runtime"),
        ]
        for url in candidates.compactMap({ $0 }) {
            if let text = try? String(contentsOf: url, encoding: .utf8) { return text }
        }
        return nil
    }

    private func findRootFSTarURL() -> URL? {
        let userTar = documentsURL.appendingPathComponent("minirootfs.tar")
        if FileManager.default.fileExists(atPath: userTar.path) { return userTar }
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "alpine-minirootfs", withExtension: "tar"),
            Bundle.main.url(forResource: "alpine-minirootfs", withExtension: "tar", subdirectory: "runtime"),
        ]
        return candidates.compactMap({ $0 }).first
    }

    public func mountAndBootDefaultShell() {
        if FileManager.default.fileExists(atPath: snapshotURL.path) {
            try? bridge.loadRootFS(from: snapshotURL)
            bootShell()
            return
        }
        guard let tarURL = findRootFSTarURL(), let tarData = try? Data(contentsOf: tarURL) else {
            appendOutput("Welcome to iTerminal (WebKit JSC JIT)\nNo alpine-minirootfs.tar found.\n")
            return
        }
        bridge.mountTar(tarData) { [weak self] result in
            Task { @MainActor in
                guard let self = self else { return }
                switch result {
                case .success:
                    self.bootShell()
                case .failure(let err):
                    self.appendOutput("[iTerminal] Mount error: \(err.localizedDescription)\n")
                }
            }
        }
    }

    public func bootShell() {
        guard isReady else { return }
        stdinBuffer.removeAll()
        pendingInput = ""
        pendingStdinCompletion = nil
        pendingStdinMaxLen = 0
        isRunning = true
        statusText = "/bin/sh"
        if outputLog.isEmpty {
            outputLog = "Welcome to Alpine!\n\nRunning on iTerminal (WebKit JSC JIT, no JIT entitlement).\n\n"
        }
        bridge.runFromVFS(
            path: "/bin/sh",
            argv: ["/bin/sh", "-i"],
            envp: [
                "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
                "HOME=/root",
                "TERM=dumb",
                "PS1=iPhone:\\w# ",
            ]
        )
    }

    /// Direct character/keystream input from iSH-style full-screen keyboard bridge.
    public func handleTypedText(_ text: String) {
        if ctrlActive {
            ctrlActive = false
            let lower = text.lowercased()
            if lower == "c" { sendCtrlC(); return }
            if lower == "d" { sendEOF(); return }
            if lower == "l" { clearOutput(); return }
        }
        for ch in text {
            if ch == "\n" || ch == "\r" {
                let line = pendingInput
                pendingInput = ""
                historyIndex = nil
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty && commandHistory.last != trimmed {
                    commandHistory.append(trimmed)
                    if commandHistory.count > 100 { commandHistory.removeFirst() }
                }
                sendRawData(Data((line + "\n").utf8))
            } else {
                pendingInput.append(ch)
            }
        }
    }

    public func handleBackspace() {
        if !pendingInput.isEmpty {
            pendingInput.removeLast()
        }
    }

    public func navigateHistory(up: Bool) {
        guard !commandHistory.isEmpty else { return }
        if up {
            if let idx = historyIndex { historyIndex = max(0, idx - 1) }
            else { historyIndex = commandHistory.count - 1 }
            if let idx = historyIndex { pendingInput = commandHistory[idx] }
        } else {
            guard let idx = historyIndex else { return }
            if idx + 1 < commandHistory.count {
                historyIndex = idx + 1
                pendingInput = commandHistory[idx + 1]
            } else {
                historyIndex = nil
                pendingInput = ""
            }
        }
    }

    public func sendRawData(_ data: Data) {
        stdinBuffer.append(data)
        drainStdinIfWaiting()
    }

    public func sendEOF() {
        if let completion = pendingStdinCompletion {
            pendingStdinCompletion = nil
            pendingStdinMaxLen = 0
            completion(.success(Data()))
        }
    }

    private func drainStdinIfWaiting() {
        guard !stdinBuffer.isEmpty, let completion = pendingStdinCompletion else { return }
        let count = min(max(1, pendingStdinMaxLen), stdinBuffer.count)
        let chunk = Data(stdinBuffer.prefix(count))
        stdinBuffer.removeFirst(count)
        pendingStdinCompletion = nil
        pendingStdinMaxLen = 0
        completion(.success(chunk))
    }

    public func sendCtrlC() {
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        pendingInput = ""
        stdinBuffer.removeAll()
        appendOutput("^C\n")
        bridge.sendInterrupt(signal: 2)
    }

    public func resetRootFS() {
        try? FileManager.default.removeItem(at: snapshotURL)
        outputLog = ""
        pendingInput = ""
        mountAndBootDefaultShell()
    }

    public func persistRootFS() {
        bridge.saveRootFS(to: snapshotURL)
    }

    public func clearOutput() {
        outputLog = ""
    }

    private func stripANSI(_ text: String) -> String {
        let cleaned = text.replacingOccurrences(
            of: "\\u{001B}\\[[0-9;?]*[ -/]*[@-~]",
            with: "",
            options: .regularExpression
        )
        return cleaned.replacingOccurrences(of: "\r", with: "")
    }

    private func appendOutput(_ text: String) {
        outputLog.append(stripANSI(text))
        if outputLog.count > 48000 {
            outputLog = String(outputLog.suffix(36000))
        }
    }

    // MARK: - GuestHostDelegate

    nonisolated public func guestDidWriteStdout(_ text: String) {
        Task { @MainActor in self.appendOutput(text) }
    }

    nonisolated public func guestDidWriteStderr(_ text: String) {
        Task { @MainActor in self.appendOutput(text) }
    }

    nonisolated public func guestDidExit(pid: Int, exitCode: Int) {
        Task { @MainActor in
            self.isRunning = false
            self.statusText = "Exited (\(exitCode))"
            self.appendOutput("\n[exited: \(exitCode)]\n")
            self.persistRootFS()
        }
    }

    nonisolated public func guestRequestStdin(
        maxLen: Int,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        Task { @MainActor in
            if !self.stdinBuffer.isEmpty {
                let count = min(max(1, maxLen), self.stdinBuffer.count)
                let chunk = Data(self.stdinBuffer.prefix(count))
                self.stdinBuffer.removeFirst(count)
                completion(.success(chunk))
            } else {
                self.pendingStdinMaxLen = maxLen
                self.pendingStdinCompletion = completion
            }
        }
    }

    nonisolated public func guestWebContentProcessDidTerminate() {
        Task { @MainActor in
            self.isRunning = false
            self.isReady = false
            self.appendOutput("\n[iTerminal] WebContent terminated by iOS Jetsam.\n")
        }
    }
}
