import Foundation
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

    public init(bundleHTML: String) {
        self.bundleHTML = bundleHTML
    }

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

public final class WasmGuestBridgeV2: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    private var webView: WKWebView!
    public weak var delegate: GuestHostDelegate?
    private var isBootstrapped = false

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
        let b64 = data.base64EncodedString()
        let escaped = path.replacingOccurrences(of: "'", with: "\\'")
        evalJS("window.__iTerminalMountFile('\(escaped)', '\(b64)', \(mode));")
    }

    /// Register BusyBox applet symlinks (e.g. target: "/bin/busybox", linkPath: "/bin/sh").
    public func mountSymlink(target: String, linkPath: String) {
        guard isBootstrapped else { return }
        let t = target.replacingOccurrences(of: "'", with: "\\'")
        let l = linkPath.replacingOccurrences(of: "'", with: "\\'")
        evalJS("window.__iTerminalMountSymlink('\(t)', '\(l)');")
    }

    /// Sync iOS terminal grid dimensions to guest TTY (updates TIOCGWINSZ & sends SIGWINCH).
    public func resizeTerminal(rows: Int, cols: Int) {
        guard isBootstrapped else { return }
        evalJS("window.__iTerminalResize(\(rows), \(cols));")
    }

    /// Deliver POSIX signal (default SIGINT=2 for Ctrl-C) to foreground guest process.
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
        let b64 = elfData.base64EncodedString()
        var opts: [String: Any] = ["argv": argv, "envp": envp, "sliceBudget": sliceBudget]
        if let exePath = exePath { opts["exePath"] = exePath }
        let optsJSON = (try? JSONSerialization.data(withJSONObject: opts))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        evalJS("window.__iTerminalRunELF('\(b64)', \(optsJSON));")
    }

    private func evalJS(_ js: String) {
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

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
            if op == "read_stdin" {
                let maxLen = args["maxLen"] as? Int ?? 1024
                delegate?.guestRequestStdin(maxLen: maxLen) { [weak self] result in
                    self?.resolveHostRequest(reqId: reqId, result: result)
                }
            }
        default:
            break
        }
    }

    private func resolveHostRequest(reqId: Int, result: Result<Data, Error>) {
        switch result {
        case .success(let data):
            evalJS("window.__iTerminalResolveHostReq(\(reqId), '\(data.base64EncodedString())', null);")
        case .failure(let err):
            let escaped = err.localizedDescription.replacingOccurrences(of: "'", with: "\\'")
            evalJS("window.__iTerminalResolveHostReq(\(reqId), null, '\(escaped)');")
        }
    }

    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        isBootstrapped = false
        delegate?.guestWebContentProcessDidTerminate()
    }
}
