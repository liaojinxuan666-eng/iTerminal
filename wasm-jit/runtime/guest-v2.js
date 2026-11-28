(function (root) {
  'use strict';

  /**
   * WKWebView Guest Runtime v2.3
   * - On-device AArch64->WASM DBT + PIE/PT_INTERP dynamic linker loading
   * - BusyBox symlinks, live TTY resize, Ctrl-C SIGINT
   * - Async BSD TCP socket bridge to Swift Network.framework (NWConnection)
   * - MemFS snapshot export/import for iOS Documents sandbox persistence
   */
  class IOSGuestRuntime {
    constructor() {
      this.engine = new root.WasmDBT.DBTEngine();
      this.fs = new root.WasmMemFS.MemFS();
      this.activeKernel = null;
      this.activeRootPid = 1;
      this.ttyRows = 24;
      this.ttyCols = 80;
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

    resolveHostRequest(reqId, value, errorMsg) {
      const entry = this.pendingHostReqs.get(reqId);
      if (!entry) return;
      this.pendingHostReqs.delete(reqId);
      if (errorMsg) { entry.reject(new Error(errorMsg)); return; }
      entry.resolve(value);
    }

    mountBase64File(path, base64Data, mode = 0o755) {
      this.fs.writeFile(path, base64ToBytes(base64Data), mode);
    }

    mountSymlink(target, linkPath) {
      this.fs.symlink(target, linkPath);
    }

    mountTarBase64(base64Tar) {
      return root.WasmRootFSTar.extractTarToMemFS(base64ToBytes(base64Tar), this.fs);
    }

    exportSnapshot() {
      return this.fs.serialize();
    }

    importSnapshot(jsonStr) {
      this.fs = root.WasmMemFS.MemFS.deserialize(jsonStr);
    }

    resizeTerminal(rows, cols) {
      this.ttyRows = rows;
      this.ttyCols = cols;
      if (this.activeKernel) this.activeKernel.resizeTerminal(rows, cols);
    }

    sendSignal(sig, pid) {
      if (this.activeKernel) this.activeKernel.sendSignal(pid || this.activeRootPid, sig);
    }

    _createSwiftNetAdapter() {
      return {
        connect: (host, port) => this._requestSwiftAsync('tcp_connect', { host, port }),
        send: (sockId, bytes) =>
          this._requestSwiftAsync('tcp_send', { sockId, data: bytesToBase64(bytes) }),
        recv: (sockId, maxLen) =>
          this._requestSwiftAsync('tcp_recv', { sockId, maxLen }).then((b64) => base64ToBytes(b64)),
        close: (sockId) => {
          this._postToSwift({ type: 'host_req', reqId: 0, op: 'tcp_close', args: { sockId } });
        },
      };
    }

    async runELFBase64(elfBase64, opts = {}) {
      const elfBytes = base64ToBytes(elfBase64);
      const kernel = new root.WasmVmmSyscalls.GuestKernel(this.engine, {
        fs: this.fs,
        rows: this.ttyRows,
        cols: this.ttyCols,
        onStdout: (bytes) => this._postToSwift({ type: 'stdout', text: this.decoder.decode(bytes) }),
        onStderr: (bytes) => this._postToSwift({ type: 'stderr', text: this.decoder.decode(bytes) }),
        readStdinAsync: (maxLen) =>
          this._requestSwiftAsync('read_stdin', { maxLen }).then((b64) => base64ToBytes(b64)),
        net: this._createSwiftNetAdapter(),
      });

      this.activeKernel = kernel;
      const proc = kernel.spawnELF(elfBytes, {
        cwd: opts.cwd || '/',
        argv: opts.argv || ['/bin/app'],
        envp: opts.envp || ['PATH=/bin:/usr/bin', 'HOME=/root', 'TERM=xterm-256color'],
        exePath: opts.exePath,
      });
      this.activeRootPid = proc.pid;

      const exited = await kernel.runAll({ sliceBudget: opts.sliceBudget || 4096 });
      const exitCode = exited.get(proc.pid) ?? 0;
      this.activeKernel = null;
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

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  const runtime = new IOSGuestRuntime();
  root.__iTerminalRuntime = runtime;
  root.__iTerminalResolveHostReq = (reqId, val, err) => runtime.resolveHostRequest(reqId, val, err);
  root.__iTerminalMountFile = (path, b64, mode) => runtime.mountBase64File(path, b64, mode);
  root.__iTerminalMountSymlink = (target, linkPath) => runtime.mountSymlink(target, linkPath);
  root.__iTerminalMountTar = (b64) => runtime.mountTarBase64(b64);
  root.__iTerminalExportFS = () => runtime.exportSnapshot();
  root.__iTerminalImportFS = (json) => runtime.importSnapshot(json);
  root.__iTerminalResize = (rows, cols) => runtime.resizeTerminal(rows, cols);
  root.__iTerminalSignal = (sig, pid) => runtime.sendSignal(sig, pid);
  root.__iTerminalRunELF = (elfB64, opts) => runtime.runELFBase64(elfB64, opts);
})(typeof globalThis !== 'undefined' ? globalThis : window);
