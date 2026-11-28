import Foundation
import WebKit

/// Delegate for PTY I/O and host-side sandboxed rootfs operations.
public protocol GuestHostDelegate: AnyObject {
    func guestDidWriteStdout(_ text: String)
    func guestDidWriteStderr(_ text: String)
    func guestDidExit(pid: Int, exitCode: Int)
    /// Asynchronously supply up to `maxLen` bytes of PTY stdin (returns empty Data on EOF).
    func guestRequestStdin(maxLen: Int, completion: @escaping (Result<Data, Error>) -> Void)
    /// Called if iOS Jetsam terminates the out-of-process WKWebView WebContent process.
    func guestWebContentProcessDidTerminate()
}

/// Optional custom WKURLSchemeHandler (`iterminal-host://`) enabling future Web Worker
/// isolation with Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy headers
/// (for SharedArrayBuffer + Atomics.wait) or synchronous Worker XHR RPC.
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

/// Upgraded WKWebView host bridge for iTerminal wasm-jit v2:
/// - Runs on-device AArch64->WASM dynamic translation directly inside WebKit's JSC JIT
/// - Bridges suspendable blocking syscalls (PTY read, sandbox I/O) via reqId Promise callbacks
/// - Handles Jetsam WebContent termination notifications cleanly
public final class WasmGuestBridgeV2: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    private var webView: WKWebView!
    public weak var delegate: GuestHostDelegate?
    private var isBootstrapped = false

    public override init() {
        super.init()
    }

    /// Initialize headless WKWebView with wasm-jit v2 runtime scripts injected.
    public func setup(
        encoderJS: String,
        dbtRuntimeJS: String,
        vmmSyscallsJS: String,
        guestV2JS: String,
        completion: @escaping (Error?) -> Void
    ) {
        let config = WKWebViewConfiguration()
        let contentController = WKUserContentController()
        contentController.add(self, name: "iosHost")

        let combined = [encoderJS, dbtRuntimeJS, vmmSyscallsJS, guestV2JS].joined(separator: "\n;\n")
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

    /// Execute an unmodified AArch64 Linux ELF64 binary directly on-device via DBT + JSC JIT.
    public func runELF(_ elfData: Data, sliceBudget: Int = 4096) {
        guard isBootstrapped else { return }
        let b64 = elfData.base64EncodedString()
        let js = "window.__iTerminalRunELF('\(b64)', { sliceBudget: \(sliceBudget) });"
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
            if let text = body["text"] as? String {
                delegate?.guestDidWriteStdout(text)
            }
        case "stderr":
            if let text = body["text"] as? String {
                delegate?.guestDidWriteStderr(text)
            }
        case "exit":
            let pid = body["pid"] as? Int ?? 1
            let code = body["exitCode"] as? Int ?? 0
            delegate?.guestDidExit(pid: pid, exitCode: code)
        case "host_req":
            guard let reqId = body["reqId"] as? Int,
                  let op = body["op"] as? String else { return }
            let args = body["args"] as? [String: Any] ?? [:]
            handleAsyncHostRequest(reqId: reqId, op: op, args: args)
        default:
            break
        }
    }

    private func handleAsyncHostRequest(reqId: Int, op: String, args: [String: Any]) {
        switch op {
        case "read_stdin":
            let maxLen = args["maxLen"] as? Int ?? 1024
            delegate?.guestRequestStdin(maxLen: maxLen) { [weak self] result in
                self?.resolveHostRequest(reqId: reqId, result: result)
            }
        default:
            resolveHostRequest(
                reqId: reqId,
                result: .failure(NSError(domain: "WasmGuestBridgeV2", code: -38, userInfo: [
                    NSLocalizedDescriptionKey: "Unsupported host op: \(op)"
                ]))
            )
        }
    }

    private func resolveHostRequest(reqId: Int, result: Result<Data, Error>) {
        let js: String
        switch result {
        case .success(let data):
            let b64 = data.base64EncodedString()
            js = "window.__iTerminalResolveHostReq(\(reqId), '\(b64)', null);"
        case .failure(let err):
            let escaped = err.localizedDescription.replacingOccurrences(of: "'", with: "\\'")
            js = "window.__iTerminalResolveHostReq(\(reqId), null, '\(escaped)');"
        }
        DispatchQueue.main.async { [weak self] in
            self?.webView.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    // MARK: - WKNavigationDelegate (Jetsam Recovery)

    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        isBootstrapped = false
        delegate?.guestWebContentProcessDidTerminate()
    }
}
