(function (root) {
  'use strict';

  /**
   * WKWebView Guest Runtime v2.1
   * Bridges WasmDBT + WasmMemFS + WasmVmmSyscalls to Swift's WKScriptMessageHandler ("iosHost").
   * Supports pre-populated VFS (/bin ELF binaries, /etc configs), argv/envp/auxv,
   * execve/fork/pipe2, and asynchronous suspendable syscalls (PTY stdin).
   */
  class IOSGuestRuntime {
    constructor() {
      this.engine = new root.WasmDBT.DBTEngine();
      this.fs = new root.WasmMemFS.MemFS();
      this.pendingHostReqs = new Map();
      this.nextReqId = 1;
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

    /**
     * Pre-populate files (including AArch64 ELF binaries under /bin/...) into MemFS.
     */
    mountBase64File(path, base64Data, mode = 0o755) {
      this.fs.writeFile(path, base64ToBytes(base64Data), mode);
    }

    async runELFBase64(elfBase64, opts = {}) {
      const elfBytes = base64ToBytes(elfBase64);
      const kernel = new root.WasmVmmSyscalls.GuestKernel(this.engine, {
        fs: this.fs,
        onStdout: (bytes) => {
          this._postToSwift({ type: 'stdout', text: this.decoder.decode(bytes) });
        },
        onStderr: (bytes) => {
          this._postToSwift({ type: 'stderr', text: this.decoder.decode(bytes) });
        },
        readStdinAsync: (maxLen) => this._requestSwiftAsync('read_stdin', { maxLen }),
      });

      const proc = kernel.spawnELF(elfBytes, {
        cwd: opts.cwd || '/',
        argv: opts.argv || ['/bin/app'],
        envp: opts.envp || ['PATH=/bin:/usr/bin', 'HOME=/root'],
      });
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
  root.__iTerminalMountFile = (path, b64, mode) => runtime.mountBase64File(path, b64, mode);
  root.__iTerminalRunELF = (elfB64, opts) => runtime.runELFBase64(elfB64, opts);
})(typeof globalThis !== 'undefined' ? globalThis : window);
