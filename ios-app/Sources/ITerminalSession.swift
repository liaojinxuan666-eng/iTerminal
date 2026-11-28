import Combine
import Foundation
import UIKit

@MainActor
public final class ITerminalSession: ObservableObject, GuestHostDelegate {
    @Published public var outputLog: String = ""
    @Published public var isRunning: Bool = false
    @Published public var isReady: Bool = false
    @Published public var statusText: String = "Initializing"
    @Published public var fontSize: CGFloat = 13
    @Published public var commandHistory: [String] = []

    public let bridge = WasmGuestBridgeV2()

    // Lossless byte-stream stdin buffer (handles 1-byte read(0, &ch, 1) from busybox ash!)
    private var stdinBuffer = Data()
    private var pendingStdinMaxLen: Int = 0
    private var pendingStdinCompletion: ((Result<Data, Error>) -> Void)?

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
            statusText = "Missing runtime"
            return
        }
        statusText = "Starting JSC JIT..."
        bridge.setup(runtimeJS: runtimeJS) { [weak self] err in
            Task { @MainActor in
                guard let self = self else { return }
                if let err = err {
                    self.statusText = "Error"
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
            appendOutput("[iTerminal] Alpine RootFS restored.\n")
            bootShell()
            return
        }
        guard let tarURL = findRootFSTarURL(), let tarData = try? Data(contentsOf: tarURL) else {
            statusText = "No RootFS"
            appendOutput("[iTerminal] No alpine-minirootfs.tar found.\n")
            return
        }
        statusText = "Mounting RootFS..."
        appendOutput("[iTerminal] Mounting \(tarURL.lastPathComponent) (\(tarData.count / 1024) KB)...\n")
        bridge.mountTar(tarData) { [weak self] result in
            Task { @MainActor in
                guard let self = self else { return }
                switch result {
                case .success(let count):
                    self.appendOutput("[iTerminal] Mounted \(count) entries.\n")
                    self.bootShell()
                case .failure(let err):
                    self.statusText = "Mount failed"
                    self.appendOutput("[iTerminal] Mount error: \(err.localizedDescription)\n")
                }
            }
        }
    }

    public func bootShell() {
        guard isReady else { return }
        stdinBuffer.removeAll()
        pendingStdinCompletion = nil
        pendingStdinMaxLen = 0
        isRunning = true
        statusText = "/bin/sh · JSC JIT"
        bridge.runFromVFS(
            path: "/bin/sh",
            argv: ["/bin/sh", "-i"],
            envp: ["PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=/root", "TERM=dumb", "PS1=# "]
        )
    }

    /// Push a full command line into the byte-stream stdin buffer (lossless for 1-byte reads).
    public func sendLine(_ line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty && commandHistory.last != trimmed {
            commandHistory.append(trimmed)
            if commandHistory.count > 100 { commandHistory.removeFirst() }
        }
        sendRawData(Data((line + "\n").utf8))
    }

    /// Push raw bytes (e.g. Tab, Ctrl-D) into stdin without duplicating echo.
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
        stdinBuffer.removeAll()
        bridge.sendInterrupt(signal: 2)
    }

    public func resetRootFS() {
        try? FileManager.default.removeItem(at: snapshotURL)
        outputLog = "[iTerminal] Resetting Alpine RootFS...\n"
        mountAndBootDefaultShell()
    }

    public func persistRootFS() {
        bridge.saveRootFS(to: snapshotURL)
    }

    public func clearOutput() {
        outputLog = ""
    }

    private func stripANSI(_ text: String) -> String {
        // Clean CSI escape sequences (e.g. \x1b[32m, \x1b[0m, \x1b[K) and \r
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
            self.appendOutput("\n[process exited with code \(exitCode)]\n")
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
            self.statusText = "Jetsam Killed"
            self.appendOutput("\n[iTerminal] WebContent terminated by iOS Jetsam. Tap Restart in menu.\n")
        }
    }
}
