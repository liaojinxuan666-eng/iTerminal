import Combine
import Foundation

@MainActor
public final class ITerminalSession: ObservableObject, GuestHostDelegate {
    @Published public var outputLog: String = ""
    @Published public var isRunning: Bool = false
    @Published public var isReady: Bool = false
    @Published public var statusText: String = "Idle"

    public let bridge = WasmGuestBridgeV2()
    private var stdinQueue: [Data] = []
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

    /// Loads the single esbuild-compiled `iterminal-runtime.js` bundle from `Bundle.main`.
    public func startBundledRuntime() {
        guard !isReady else { return }
        guard let runtimeJS = loadBundledJS(named: "iterminal-runtime") else {
            statusText = "Missing bundled iterminal-runtime.js"
            return
        }
        statusText = "Bootstrapping WebKit JIT..."
        bridge.setup(runtimeJS: runtimeJS) { [weak self] err in
            Task { @MainActor in
                guard let self = self else { return }
                if let err = err {
                    self.statusText = "Bootstrap error: \(err.localizedDescription)"
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
            outputLog.append("[iTerminal] Restored RootFS snapshot from Documents.\n")
            bootShell()
            return
        }
        guard let tarURL = findRootFSTarURL(), let tarData = try? Data(contentsOf: tarURL) else {
            statusText = "Ready (no minirootfs.tar bundled)"
            outputLog.append("[iTerminal] No alpine-minirootfs.tar found. Place minirootfs.tar in Documents.\n")
            return
        }
        statusText = "Extracting Alpine rootfs..."
        outputLog.append("[iTerminal] Mounting \(tarURL.lastPathComponent) (\(tarData.count / 1024) KB)...\n")
        bridge.mountTar(tarData) { [weak self] result in
            Task { @MainActor in
                guard let self = self else { return }
                switch result {
                case .success(let count):
                    self.outputLog.append("[iTerminal] Mounted \(count) entries into MemFS.\n")
                    self.bootShell()
                case .failure(let err):
                    self.statusText = "RootFS mount failed"
                    self.outputLog.append("[iTerminal] Mount error: \(err.localizedDescription)\n")
                }
            }
        }
    }

    public func bootShell() {
        guard isReady else { return }
        isRunning = true
        statusText = "Running /bin/sh (WebKit JSC JIT)"
        outputLog.append("[iTerminal] Booting /bin/sh...\n")
        bridge.runFromVFS(path: "/bin/sh", argv: ["/bin/sh", "-i"], envp: ["PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=/root", "TERM=dumb", "PS1=# "])
    }

    public func sendLine(_ line: String) {
        let data = Data((line + "\n").utf8)
        outputLog.append("$ " + line + "\n")
        if let completion = pendingStdinCompletion {
            pendingStdinCompletion = nil
            completion(.success(data))
        } else {
            stdinQueue.append(data)
        }
    }

    public func sendCtrlC() {
        bridge.sendInterrupt(signal: 2)
    }

    public func persistRootFS() {
        bridge.saveRootFS(to: snapshotURL)
    }

    private func appendOutput(_ text: String) {
        self.outputLog.append(text)
        if self.outputLog.count > 32000 {
            self.outputLog = String(self.outputLog.suffix(24000))
        }
    }

    nonisolated public func guestDidWriteStdout(_ text: String) {
        Task { @MainActor in self.appendOutput(text) }
    }

    nonisolated public func guestDidWriteStderr(_ text: String) {
        Task { @MainActor in self.appendOutput(text) }
    }

    nonisolated public func guestDidExit(pid: Int, exitCode: Int) {
        Task { @MainActor in
            self.isRunning = false
            self.statusText = "Exited (pid=\(pid), code=\(exitCode))"
            self.persistRootFS()
        }
    }

    nonisolated public func guestRequestStdin(
        maxLen: Int,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        Task { @MainActor in
            if !self.stdinQueue.isEmpty {
                let next = self.stdinQueue.removeFirst()
                completion(.success(next.prefix(maxLen)))
            } else {
                self.pendingStdinCompletion = completion
            }
        }
    }

    nonisolated public func guestWebContentProcessDidTerminate() {
        Task { @MainActor in
            self.isRunning = false
            self.isReady = false
            self.statusText = "WebContent terminated by iOS Jetsam"
        }
    }
}
