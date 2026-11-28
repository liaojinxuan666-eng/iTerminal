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
            url: url,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: headers
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

    public override init() {
        super.init()
    }

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

    /// Mount an ELF binary or data file into the in-memory VFS (e.g., `/bin/busybox`).
    public func mountFile(path: String, data: Data, mode: Int = 0o755) {
        guard isBootstrapped else { return }
        let b64 = data.base64EncodedString()
        let escapedPath = path.replacingOccurrences(of: "'", with: "\\'")
        let js = "window.__iTerminalMountFile('\(escapedPath)', '\(b64)', \(mode));"
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    /// Execute an unmodified AArch64 Linux ELF64 binary with argv/envp on-device via DBT + JSC JIT.
    public func runELF(
        _ elfData: Data,
        argv: [String] = ["/bin/app"],
        envp: [String] = ["PATH=/bin:/usr/bin", "HOME=/root"],
        sliceBudget: Int = 4096
    ) {
        guard isBootstrapped else { return }
        let b64 = elfData.base64EncodedString()
        let opts: [String: Any] = ["argv": argv, "envp": envp, "sliceBudget": sliceBudget]
        let optsJSON = (try? JSONSerialization.data(withJSONObject: opts))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        let js = "window.__iTerminalRunELF('\(b64)', \(optsJSON));"
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
        let js: String
        switch result {
        case .success(let data):
            js = "window.__iTerminalResolveHostReq(\(reqId), '\(data.base64EncodedString())', null);"
        case .failure(let err):
            let escaped = err.localizedDescription.replacingOccurrences(of: "'", with: "\\'")
            js = "window.__iTerminalResolveHostReq(\(reqId), null, '\(escaped)');"
        }
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        isBootstrapped = false
        delegate?.guestWebContentProcessDidTerminate()
    }
}
