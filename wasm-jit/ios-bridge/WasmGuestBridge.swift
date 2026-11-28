import Foundation
import Network
import WebKit

public protocol GuestHostDelegate: AnyObject {
    func guestDidWriteStdout(_ text: String)
    func guestDidWriteStderr(_ text: String)
    func guestDidExit(pid: Int, exitCode: Int)
    func guestRequestStdin(maxLen: Int, completion: @escaping (Result<Data, Error>) -> Void)
    func guestWebContentProcessDidTerminate()
}

public final class ITerminalSchemeHandler: NSObject, WKURLSchemeHandler {
    private let bundleHTML: String

    public init(bundleHTML: String) { self.bundleHTML = bundleHTML }

    public func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url else { return }
        let data = Data(bundleHTML.utf8)
        let headers: [String: String] = [
            "Content-Type": "text/html; charset=utf-8",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cache-Control": "no-store",
        ]
        if let response = HTTPURLResponse(
            url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers
        ) {
            urlSchemeTask.didReceive(response)
            urlSchemeTask.didReceive(data)
            urlSchemeTask.didFinish()
        }
    }

    public func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}
}

/// iTerminal wasm-jit v2.3 WKWebView Host Bridge:
/// - Runs on-device AArch64->WASM DBT + PIE/PT_INTERP dynamic binaries inside JSC JIT
/// - Bridges blocking BSD TCP sockets to iOS Network.framework (NWConnection)
/// - Persists MemFS snapshots to iOS app Documents sandbox
public final class WasmGuestBridgeV2: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    private var webView: WKWebView!
    public weak var delegate: GuestHostDelegate?
    private var isBootstrapped = false

    private let netQueue = DispatchQueue(label: "com.iterminal.net")
    private var sockets: [Int: NWConnection] = [:]
    private var nextSockId = 1

    public override init() { super.init() }

    public func setup(
        encoderJS: String,
        dbtRuntimeJS: String,
        vfsMemFSJS: String,
        vmmSyscallsJS: String,
        guestV2JS: String,
        completion: @escaping (Error?) -> Void
    ) {
        let config = WKWebViewConfiguration()
        let contentController = WKUserContentController()
        contentController.add(self, name: "iosHost")

        let combined = [encoderJS, dbtRuntimeJS, vfsMemFSJS, vmmSyscallsJS, guestV2JS]
            .joined(separator: "\n;\n")
        let script = WKUserScript(source: combined, injectionTime: .atDocumentEnd, forMainFrameOnly: true)
        contentController.addUserScript(script)
        config.userContentController = contentController

        let schemeHandler = ITerminalSchemeHandler(bundleHTML: "<!doctype html><html><body></body></html>")
        config.setURLSchemeHandler(schemeHandler, forURLScheme: "iterminal-host")

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        self.webView = wv

        if let url = URL(string: "iterminal-host://runtime/index.html") {
            wv.load(URLRequest(url: url))
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                self?.isBootstrapped = true
                completion(nil)
            }
        } else {
            completion(NSError(domain: "WasmGuestBridgeV2", code: -1))
        }
    }

    public func mountFile(path: String, data: Data, mode: Int = 0o755) {
        guard isBootstrapped else { return }
        let escaped = path.replacingOccurrences(of: "'", with: "\\'")
        evalJS("window.__iTerminalMountFile('\(escaped)', '\(data.base64EncodedString())', \(mode));")
    }

    public func mountSymlink(target: String, linkPath: String) {
        guard isBootstrapped else { return }
        let t = target.replacingOccurrences(of: "'", with: "\\'")
        let l = linkPath.replacingOccurrences(of: "'", with: "\\'")
        evalJS("window.__iTerminalMountSymlink('\(t)', '\(l)');")
    }

    /// Persist MemFS state to iOS sandbox `Documents/iTerminalRootFS.json`.
    public func saveRootFS(to url: URL, completion: ((Error?) -> Void)? = nil) {
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript("window.__iTerminalExportFS();") { result, error in
                if let error = error { completion?(error); return }
                guard let json = result as? String else { completion?(nil); return }
                do {
                    try json.write(to: url, atomically: true, encoding: .utf8)
                    completion?(nil)
                } catch {
                    completion?(error)
                }
            }
        }
    }

    /// Restore MemFS state from iOS sandbox `Documents/iTerminalRootFS.json`.
    public func loadRootFS(from url: URL) throws {
        let json = try String(contentsOf: url, encoding: .utf8)
        let data = try JSONSerialization.data(withJSONObject: [json])
        if let arrStr = String(data: data, encoding: .utf8) {
            evalJS("window.__iTerminalImportFS((\(arrStr))[0]);")
        }
    }

    public func resizeTerminal(rows: Int, cols: Int) {
        guard isBootstrapped else { return }
        evalJS("window.__iTerminalResize(\(rows), \(cols));")
    }

    public func sendInterrupt(signal: Int = 2) {
        guard isBootstrapped else { return }
        evalJS("window.__iTerminalSignal(\(signal));")
    }

    public func runELF(
        _ elfData: Data,
        argv: [String] = ["/bin/sh"],
        envp: [String] = ["PATH=/bin:/usr/bin", "HOME=/root", "TERM=xterm-256color"],
        exePath: String? = nil,
        sliceBudget: Int = 4096
    ) {
        guard isBootstrapped else { return }
        var opts: [String: Any] = ["argv": argv, "envp": envp, "sliceBudget": sliceBudget]
        if let exePath = exePath { opts["exePath"] = exePath }
        let optsJSON = (try? JSONSerialization.data(withJSONObject: opts))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        evalJS("window.__iTerminalRunELF('\(elfData.base64EncodedString())', \(optsJSON));")
    }

    private func evalJS(_ js: String) {
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    // MARK: - WKScriptMessageHandler

    public func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard message.name == "iosHost", let body = message.body as? [String: Any],
              let type = body["type"] as? String else { return }

        switch type {
        case "stdout":
            if let text = body["text"] as? String { delegate?.guestDidWriteStdout(text) }
        case "stderr":
            if let text = body["text"] as? String { delegate?.guestDidWriteStderr(text) }
        case "exit":
            delegate?.guestDidExit(pid: body["pid"] as? Int ?? 1, exitCode: body["exitCode"] as? Int ?? 0)
        case "host_req":
            guard let reqId = body["reqId"] as? Int, let op = body["op"] as? String else { return }
            let args = body["args"] as? [String: Any] ?? [:]
            handleHostRequest(reqId: reqId, op: op, args: args)
        default:
            break
        }
    }

    private func handleHostRequest(reqId: Int, op: String, args: [String: Any]) {
        switch op {
        case "read_stdin":
            let maxLen = args["maxLen"] as? Int ?? 1024
            delegate?.guestRequestStdin(maxLen: maxLen) { [weak self] result in
                switch result {
                case .success(let data): self?.resolveString(reqId: reqId, value: data.base64EncodedString())
                case .failure(let err): self?.resolveError(reqId: reqId, error: err)
                }
            }
        case "tcp_connect":
            guard let host = args["host"] as? String,
                  let portNum = args["port"] as? Int,
                  let port = NWEndpoint.Port(rawValue: UInt16(portNum)) else {
                resolveError(reqId: reqId, error: NSError(domain: "Net", code: -22))
                return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
            let sockId = nextSockId
            nextSockId += 1
            var settled = false
            conn.stateUpdateHandler = { [weak self] state in
                guard !settled else { return }
                switch state {
                case .ready:
                    settled = true
                    self?.sockets[sockId] = conn
                    self?.resolveNumber(reqId: reqId, value: sockId)
                case .failed(let err):
                    settled = true
                    self?.resolveError(reqId: reqId, error: err)
                default:
                    break
                }
            }
            conn.start(queue: netQueue)
        case "tcp_send":
            guard let sockId = args["sockId"] as? Int,
                  let b64 = args["data"] as? String,
                  let data = Data(base64Encoded: b64),
                  let conn = sockets[sockId] else {
                resolveNumber(reqId: reqId, value: -9)
                return
            }
            conn.send(content: data, completion: .contentProcessed { [weak self] err in
                if let err = err { self?.resolveError(reqId: reqId, error: err) }
                else { self?.resolveNumber(reqId: reqId, value: data.count) }
            })
        case "tcp_recv":
            guard let sockId = args["sockId"] as? Int,
                  let maxLen = args["maxLen"] as? Int,
                  let conn = sockets[sockId] else {
                resolveString(reqId: reqId, value: "")
                return
            }
            conn.receive(minimumIncompleteLength: 1, maximumLength: maxLen) { [weak self] data, _, _, err in
                if let err = err { self?.resolveError(reqId: reqId, error: err) }
                else { self?.resolveString(reqId: reqId, value: (data ?? Data()).base64EncodedString()) }
            }
        case "tcp_close":
            if let sockId = args["sockId"] as? Int, let conn = sockets.removeValue(forKey: sockId) {
                conn.cancel()
            }
        default:
            break
        }
    }

    private func resolveString(reqId: Int, value: String) {
        evalJS("window.__iTerminalResolveHostReq(\(reqId), '\(value)', null);")
    }

    private func resolveNumber(reqId: Int, value: Int) {
        evalJS("window.__iTerminalResolveHostReq(\(reqId), \(value), null);")
    }

    private func resolveError(reqId: Int, error: Error) {
        let escaped = error.localizedDescription.replacingOccurrences(of: "'", with: "\\'")
        evalJS("window.__iTerminalResolveHostReq(\(reqId), null, '\(escaped)');")
    }

    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        isBootstrapped = false
        for conn in sockets.values { conn.cancel() }
        sockets.removeAll()
        delegate?.guestWebContentProcessDidTerminate()
    }
}
