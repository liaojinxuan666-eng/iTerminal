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

    /// Automatically loads bundled `wasm-jit` JS runtime files from `Bundle.main` and starts WebKit JIT.
    public func startBundledRuntime() {
        guard !isReady else { return }
        guard let encoderJS = loadBundledJS(named: "wasm-encoder-v2"),
              let dbtRuntimeJS = loadBundledJS(named: "dbt-runtime"),
              let vfsMemFSJS = loadBundledJS(named: "vfs-memfs"),
              let rootfsTarJS = loadBundledJS(named: "rootfs-tar"),
              let vmmSyscallsJS = loadBundledJS(named: "vmm-syscalls"),
              let guestV2JS = loadBundledJS(named: "guest-v2") else {
            statusText = "Missing bundled wasm-jit runtime JS files"
            return
        }
        startRuntime(
            encoderJS: encoderJS,
            dbtRuntimeJS: dbtRuntimeJS,
            vfsMemFSJS: vfsMemFSJS,
            rootfsTarJS: rootfsTarJS,
            vmmSyscallsJS: vmmSyscallsJS,
            guestV2JS: guestV2JS
        )
    }

    private func loadBundledJS(named name: String) -> String? {
        let candidates: [URL?] = [
            Bundle.main.url(forResource: name, withExtension: "js"),
            Bundle.main.url(forResource: name, withExtension: "js", subdirectory: "runtime"),
        ]
        for url in candidates.compactMap({ $0 }) {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                return text
            }
        }
        return nil
    }

    public func startRuntime(
        encoderJS: String,
        dbtRuntimeJS: String,
        vfsMemFSJS: String,
        rootfsTarJS: String,
        vmmSyscallsJS: String,
        guestV2JS: String
    ) {
        statusText = "Bootstrapping WebKit JIT..."
        let combinedVfs = vfsMemFSJS + "\n;\n" + rootfsTarJS
        bridge.setup(
            encoderJS: encoderJS,
            dbtRuntimeJS: dbtRuntimeJS,
            vfsMemFSJS: combinedVfs,
            vmmSyscallsJS: vmmSyscallsJS,
            guestV2JS: guestV2JS
        ) { [weak self] err in
            Task { @MainActor in
                guard let self = self else { return }
                if let err = err {
                    self.statusText = "Bootstrap error: \(err.localizedDescription)"
                    return
                }
                if FileManager.default.fileExists(atPath: self.snapshotURL.path) {
                    try? self.bridge.loadRootFS(from: self.snapshotURL)
                }
                self.isReady = true
                self.statusText = "Ready (WebKit JSC JIT active)"
            }
        }
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

    // MARK: - GuestHostDelegate

    nonisolated public func guestDidWriteStdout(_ text: String) {
        Task { @MainActor in self.outputLog.append(text) }
    }

    nonisolated public func guestDidWriteStderr(_ text: String) {
        Task { @MainActor in self.outputLog.append(text) }
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
