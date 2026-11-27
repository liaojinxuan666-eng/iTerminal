/*
 * WasmGuestBridge.swift — iOS 宿主侧桥接
 *
 * 架构：
 *   Swift App ──WKScriptMessageHandler──> guest.js (WKWebView) ──WASM import──> JIT 执行的 guest 代码
 *   Swift App <─evaluateJavaScript────── guest.js
 *
 * 为什么不需要 JIT entitlement：
 *   机器码由 WebKit 的 JavaScriptCore 在 WebContent 进程内生成（BBQ/OMG）。
 *   宿主 App 只发消息、收消息，从未 mmap PROT_EXEC 或调用 W^X 违规 API。
 *   iOS 14.5+ 的 WKWebView 已具备 JIT 能力（系统签名进程）。
 *
 * 注意：iOS 17+ 建议使用 WKWebView 的 `allowsRunAsApp` / 默认配置即可；
 *       不要用已废弃的 UIWebView（无 JIT）。
 */

import Foundation
import WebKit

/// guest 输出的终端数据
struct GuestOutput: Sendable {
    let fd: Int32
    let text: String
}

/// guest 退出结果
struct GuestResult: Sendable {
    let exitCode: Int32
    let outputs: [GuestOutput]
    let steps: Int
}

/// Swift 侧注入给 guest.js 的 syscall 处理器
protocol GuestSyscallHandler: AnyObject {
    /// 处理 guest.js 无法在 JS 内完成的 syscall（文件、socket 等）
    /// - Returns: 写入 x0 的返回值（会收窄为 32 位）
    func handle(syscall name: String, args: [Int], from guest: WasmGuestBridge) -> Int
}

@MainActor
final class WasmGuestBridge: NSObject, WKScriptMessageHandler, WKNavigationDelegate {

    private let webView: WKWebView
    private weak var syscallHandler: GuestSyscallHandler?
    private var pendingContinuation: CheckedContinuation<GuestResult, Error>?
    private var collectedOutput: [GuestOutput] = []

    /// 加载 guest.js 时使用的消息名（JS 侧 window.webkit.messageHandlers.iosHost）
    private static let messageName = "iosHost"

    init(syscallHandler: GuestSyscallHandler? = nil) {
        self.syscallHandler = syscallHandler
        let config = WKWebViewConfiguration()
        // 关键：允许 WASM JIT 所需的设置（WKWebView 默认已启用，这里显式声明意图）
        config.allowsInlineMediaPlayback = false
        let contentController = WKUserContentController()
        config.userContentController = contentController
        self.webView = WKWebView(frame: .zero, configuration: config)
        super.init()
        // 消息处理器在 setup() 里注册（需要 self，不能在 init 阶段捕获）
    }

    /// 在 WebView 就绪后调用，注册消息处理器并加载 guest.js
    func setup(guestJS: URL, wasm: URL) async throws {
        let controller = webView.configuration.userContentController
        controller.removeScriptMessageHandler(forName: Self.messageName)
        controller.add(self, name: Self.messageName)

        // 先注入 guest.js，再注入 wasm 字节（base64）
        let js = try String(contentsOf: guestJS, encoding: .utf8)
        let wasmData = try Data(contentsOf: wasm)
        let b64 = wasmData.base64EncodedString()

        let bootstrap = """
        \(js)
        window.__wasmB64 = "\(b64)";
        function b64ToBytes(b64) {
          const bin = atob(b64);
          const out = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
          return out;
        }
        window.__guestReady = false;
        (async () => {
          window.__guest = new GuestProcess(b64ToBytes(window.__wasmB64), {
            entryBlock: 0,
            onSyscall: (name, payload) => {
              window.webkit.messageHandlers.iosHost.postMessage({
                type: "syscall", name: name, payload: payload
              });
              return window.__syscallReturn[name] || 0;
            }
          });
          await window.__guest.init();
          window.__guestReady = true;
        })();
        """
        let script = WKUserScript(source: bootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: true)
        webView.configuration.userContentController.addUserScript(script)
        // 加载空白页触发 atDocumentStart 脚本注入；run() 里会等待 __guestReady
        webView.loadHTMLString("<html><body></body></html>", baseURL: nil)
    }

    /// 运行 guest 并等待结果
    func run() async throws -> GuestResult {
        // 等待 guestReady
        try await waitForGuestReady()
        collectedOutput = []
        return try await withCheckedThrowingContinuation { cont in
            pendingContinuation = cont
            webView.evaluateJavaScript(
                "(function(){ const r = window.__guest.run(); return r; })()",
                completionHandler: { [weak self] result, error in
                    guard let self = self else { return }
                    if let error = error {
                        Task { @MainActor in
                            if self.pendingContinuation != nil {
                                self.pendingContinuation?.resume(throwing: error)
                                self.pendingContinuation = nil
                            }
                        }
                    }
                    // 正常路径：结果通过 exit syscall 消息 resume。
                    // 若 guest 没有调用 exit（步数耗尽），result 里带回退结果。
                    if error == nil, let dict = result as? [String: Any],
                       let steps = dict["steps"] as? Int {
                        Task { @MainActor in
                            guard self.pendingContinuation != nil else { return }
                            let r = GuestResult(exitCode: -1, outputs: self.collectedOutput, steps: steps)
                            self.pendingContinuation?.resume(returning: r)
                            self.pendingContinuation = nil
                        }
                    }
                }
            )
        }
    }

    private func waitForGuestReady() async throws {
        for _ in 0..<100 {
            let ready = try await webView.evaluateJavaScript("window.__guestReady === true") as? Bool ?? false
            if ready { return }
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
        throw BridgeError.guestNotReady
    }

    // MARK: - WKScriptMessageHandler

    nonisolated func userContentController(_ userContentController: WKUserContentController,
                                           didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let type = body["type"] as? String else { return }
        Task { @MainActor in
            switch type {
            case "syscall":
                let name = body["name"] as? String ?? ""
                let payload = body["payload"] as? [String: Any] ?? [:]
                self.handleJS(syscall: name, payload: payload)
            default:
                break
            }
        }
    }

    private func handleJS(syscall name: String, payload: [String: Any]) {
        if name == "write" {
            let fd = payload["fd"] as? Int ?? 1
            let text = payload["text"] as? String ?? ""
            collectedOutput.append(GuestOutput(fd: Int32(fd), text: text))
        } else if name == "exit" {
            let code = payload["code"] as? Int ?? 0
            let result = GuestResult(exitCode: Int32(code), outputs: collectedOutput,
                                     steps: 0)
            pendingContinuation?.resume(returning: result)
            pendingContinuation = nil
        } else {
            // 交给 Swift 侧处理复杂 syscall（文件、socket 等）
            let args = ["a0", "a1", "a2", "a3", "a4", "a5"].compactMap { payload[$0] as? Int }
            let ret = syscallHandler?.handle(syscall: name, args: args, from: self) ?? -1
            // 把返回值写回 JS：window.__syscallReturn[name]，供同步 syscall import 读取
            webView.evaluateJavaScript(
                "window.__syscallReturn = window.__syscallReturn || {}; window.__syscallReturn['\(name)'] = \(ret);",
                completionHandler: nil)
        }
    }

    enum BridgeError: Error {
        case guestNotReady
        case invalidWasm
    }
}
