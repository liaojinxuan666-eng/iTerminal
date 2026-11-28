(function (root) {
  'use strict';

  /**
   * WKWebView Guest Runtime v2
   * Bridges WasmDBT + WasmVmmSyscalls to Swift's WKScriptMessageHandler ("iosHost").
   * Supports asynchronous suspendable syscalls (PTY stdin read, Swift FileManager I/O)
   * without blocking the WebContent main thread.
   */
  class IOSGuestRuntime {
    constructor() {
      this.engine = new root.WasmDBT.DBTEngine();
      this.pendingHostReqs = new Map();
      this.nextReqId = 1;
      this.encoder = new TextEncoder();
      this.decoder = new TextDecoder();
    }

    _postToSwift(payload) {
      if (root.webkit && root.webkit.messageHandlers && root.webkit.messageHandlers.iosHost) {
        root.webkit.messageHandlers.iosHost.postMessage(payload);
      }
    }

    _requestSwiftAsync(op, args) {
      const reqId = this.nextReqId++;
      return new Promise((resolve, reject) => {
        this.pendingHostReqs.set(reqId, { resolve, reject });
        this._postToSwift({ type: 'host_req', reqId, op, args });
      });
    }

    // Called from Swift via evaluateJavaScript("window.__iTerminalResolveHostReq(reqId, base64Data, err)")
    resolveHostRequest(reqId, base64Data, errorMsg) {
      const entry = this.pendingHostReqs.get(reqId);
      if (!entry) return;
      this.pendingHostReqs.delete(reqId);
      if (errorMsg) {
        entry.reject(new Error(errorMsg));
        return;
      }
      entry.resolve(base64ToBytes(base64Data || ''));
    }

    async runELFBase64(elfBase64, opts = {}) {
      const elfBytes = base64ToBytes(elfBase64);
      const kernel = new root.WasmVmmSyscalls.GuestKernel(this.engine, {
        onStdout: (bytes) => {
          this._postToSwift({ type: 'stdout', text: this.decoder.decode(bytes) });
        },
        onStderr: (bytes) => {
          this._postToSwift({ type: 'stderr', text: this.decoder.decode(bytes) });
        },
        readStdinAsync: (maxLen) => this._requestSwiftAsync('read_stdin', { maxLen }),
      });

      const proc = kernel.spawnELF(elfBytes, opts);
      const exited = await kernel.runAll({ sliceBudget: opts.sliceBudget || 4096 });
      const exitCode = exited.get(proc.pid) ?? 0;
      this._postToSwift({ type: 'exit', pid: proc.pid, exitCode });
      return exitCode;
    }
  }

  function base64ToBytes(b64) {
    if (!b64) return new Uint8Array(0);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const runtime = new IOSGuestRuntime();
  root.__iTerminalRuntime = runtime;
  root.__iTerminalResolveHostReq = (reqId, b64, err) => runtime.resolveHostRequest(reqId, b64, err);
  root.__iTerminalRunELF = (elfB64, opts) => runtime.runELFBase64(elfB64, opts);
})(typeof globalThis !== 'undefined' ? globalThis : window);
