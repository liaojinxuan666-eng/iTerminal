import { DBTEngine } from '../src/dbt-runtime';
import { extractTarToMemFS } from '../src/rootfs-tar';
import { MemFS } from '../src/vfs-memfs';
import { GuestKernel, NetAdapter } from '../src/vmm-syscalls';

interface WebKitMessageHandler {
  postMessage(message: unknown): void;
}

interface PendingReq {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

export interface RunELFOpts {
  cwd?: string;
  argv?: string[];
  envp?: string[];
  exePath?: string;
  sliceBudget?: number;
}

declare global {
  interface Window {
    webkit?: {
      messageHandlers?: {
        iosHost?: WebKitMessageHandler;
      };
    };
    __iTerminalRuntime?: IOSGuestRuntime;
    __iTerminalResolveHostReq?: (reqId: number, val: unknown, err: string | null) => void;
    __iTerminalMountFile?: (path: string, b64: string, mode?: number) => void;
    __iTerminalMountSymlink?: (target: string, linkPath: string) => void;
    __iTerminalMountTar?: (b64: string) => number;
    __iTerminalExportFS?: () => string;
    __iTerminalImportFS?: (json: string) => void;
    __iTerminalResize?: (rows: number, cols: number) => void;
    __iTerminalSignal?: (sig: number, pid?: number) => void;
    __iTerminalRunELF?: (elfB64: string, opts?: RunELFOpts) => Promise<number>;
    __iTerminalRunVFS?: (path: string, opts?: RunELFOpts) => Promise<number>;
  }
}

function base64ToBytes(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export class IOSGuestRuntime {
  private engine = new DBTEngine();
  private fs = new MemFS();
  private activeKernel: GuestKernel | null = null;
  private activeRootPid = 1;
  private ttyRows = 24;
  private ttyCols = 80;
  private pendingHostReqs = new Map<number, PendingReq>();
  private nextReqId = 1;
  private decoder = new TextDecoder();
  private outBuf = '';
  private errBuf = '';
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  private _flushOutput(): void {
    if (this.flushTimer !== null) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.outBuf.length > 0) {
      const text = this.outBuf;
      this.outBuf = '';
      this._postToSwift({ type: 'stdout', text });
    }
    if (this.errBuf.length > 0) {
      const text = this.errBuf;
      this.errBuf = '';
      this._postToSwift({ type: 'stderr', text });
    }
  }

  private _queueOutput(stream: 'stdout' | 'stderr', bytes: Uint8Array): void {
    const chunk = this.decoder.decode(bytes, { stream: true });
    if (stream === 'stdout') this.outBuf += chunk;
    else this.errBuf += chunk;
    if (this.outBuf.length + this.errBuf.length >= 4096) {
      this._flushOutput();
      return;
    }
    if (this.flushTimer === null) {
      this.flushTimer = setTimeout(() => this._flushOutput(), 16);
    }
  }

  private _postToSwift(payload: Record<string, unknown>): void {
    window.webkit?.messageHandlers?.iosHost?.postMessage(payload);
  }

  private _requestSwiftAsync<T>(op: string, args: Record<string, unknown>): Promise<T> {
    const reqId = this.nextReqId++;
    return new Promise<T>((resolve, reject) => {
      this.pendingHostReqs.set(reqId, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this._postToSwift({ type: 'host_req', reqId, op, args });
    });
  }

  resolveHostRequest(reqId: number, value: unknown, errorMsg: string | null): void {
    const entry = this.pendingHostReqs.get(reqId);
    if (!entry) return;
    this.pendingHostReqs.delete(reqId);
    if (errorMsg) {
      entry.reject(new Error(errorMsg));
      return;
    }
    entry.resolve(value);
  }

  mountBase64File(path: string, base64Data: string, mode = 0o755): void {
    this.fs.writeFile(path, base64ToBytes(base64Data), mode);
  }

  mountSymlink(target: string, linkPath: string): void {
    this.fs.symlink(target, linkPath);
  }

  mountTarBase64(base64Tar: string): number {
    return extractTarToMemFS(base64ToBytes(base64Tar), this.fs);
  }

  exportSnapshot(): string {
    return this.fs.serialize();
  }

  importSnapshot(jsonStr: string): void {
    this.fs = MemFS.deserialize(jsonStr);
  }

  resizeTerminal(rows: number, cols: number): void {
    this.ttyRows = rows;
    this.ttyCols = cols;
    if (this.activeKernel) this.activeKernel.resizeTerminal(rows, cols);
  }

  sendSignal(sig: number, pid?: number): void {
    if (this.activeKernel) this.activeKernel.sendSignal(pid || this.activeRootPid, sig);
  }

  private _createSwiftNetAdapter(): NetAdapter {
    return {
      connect: (host, port) => this._requestSwiftAsync<number>('tcp_connect', { host, port }),
      send: (sockId, bytes) =>
        this._requestSwiftAsync<number>('tcp_send', { sockId, data: bytesToBase64(bytes) }),
      recv: (sockId, maxLen) =>
        this._requestSwiftAsync<string>('tcp_recv', { sockId, maxLen }).then(base64ToBytes),
      close: (sockId) => {
        this._postToSwift({ type: 'host_req', reqId: 0, op: 'tcp_close', args: { sockId } });
      },
    };
  }

  private async _runELFBytes(elfBytes: Uint8Array, opts: RunELFOpts = {}): Promise<number> {
    try {
      const kernel = new GuestKernel(this.engine, {
        fs: this.fs,
        rows: this.ttyRows,
        cols: this.ttyCols,
        onStdout: (bytes) => this._queueOutput('stdout', bytes),
        onStderr: (bytes) => this._queueOutput('stderr', bytes),
        readStdinAsync: (maxLen) => {
          this._flushOutput();
          return this._requestSwiftAsync<string>('read_stdin', { maxLen }).then(base64ToBytes);
        },
        net: this._createSwiftNetAdapter(),
      });

      this.activeKernel = kernel;
      const proc = kernel.spawnELF(elfBytes, {
        cwd: opts.cwd || '/',
        argv: opts.argv || ['/bin/sh'],
        envp: opts.envp || ['PATH=/bin:/sbin:/usr/bin:/usr/sbin', 'HOME=/root', 'TERM=dumb', 'PS1=# '],
        exePath: opts.exePath,
      });
      this.activeRootPid = proc.pid;

      const exited = await kernel.runAll({ sliceBudget: opts.sliceBudget || 4096 });
      const exitCode = exited.get(proc.pid) ?? 0;
      this.activeKernel = null;
      this._flushOutput();
      this._postToSwift({ type: 'exit', pid: proc.pid, exitCode });
      return exitCode;
    } catch (err) {
      this.activeKernel = null;
      const msg = err instanceof Error ? err.message : String(err);
      this._flushOutput();
      this._postToSwift({ type: 'stderr', text: `\n[iTerminal fault] ${msg}\n` });
      this._postToSwift({ type: 'exit', pid: this.activeRootPid, exitCode: 1 });
      return 1;
    }
  }

  async runELFBase64(elfBase64: string, opts: RunELFOpts = {}): Promise<number> {
    return this._runELFBytes(base64ToBytes(elfBase64), opts);
  }

  async runFromVFS(path: string, opts: RunELFOpts = {}): Promise<number> {
    const resolved = this.fs.resolveSymlinks(path);
    const elfBytes = this.fs.readFile(resolved);
    if (!elfBytes) {
      this._postToSwift({ type: 'stderr', text: `[iTerminal] Binary not found in VFS: ${path}\n` });
      this._postToSwift({ type: 'exit', pid: 0, exitCode: 127 });
      return 127;
    }
    return this._runELFBytes(elfBytes, {
      ...opts,
      argv: opts.argv || [path],
      exePath: resolved,
    });
  }
}

const runtime = new IOSGuestRuntime();
window.__iTerminalRuntime = runtime;
window.__iTerminalResolveHostReq = (reqId, val, err) => runtime.resolveHostRequest(reqId, val, err);
window.__iTerminalMountFile = (path, b64, mode) => runtime.mountBase64File(path, b64, mode);
window.__iTerminalMountSymlink = (target, linkPath) => runtime.mountSymlink(target, linkPath);
window.__iTerminalMountTar = (b64) => runtime.mountTarBase64(b64);
window.__iTerminalExportFS = () => runtime.exportSnapshot();
window.__iTerminalImportFS = (json) => runtime.importSnapshot(json);
window.__iTerminalResize = (rows, cols) => runtime.resizeTerminal(rows, cols);
window.__iTerminalSignal = (sig, pid) => runtime.sendSignal(sig, pid);
window.__iTerminalRunELF = (elfB64, opts) => runtime.runELFBase64(elfB64, opts);
window.__iTerminalRunVFS = (path, opts) => runtime.runFromVFS(path, opts);
