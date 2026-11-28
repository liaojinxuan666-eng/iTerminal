import { DBTEngine, GuestCPU, STATUS, formatFaultDiagnostic, loadELF64 } from './dbt-runtime';
import { DirEntry, MemFS, normalizePath } from './vfs-memfs';

const PAGE_SIZE = 4096;
const AT_FDCWD = -100;

export const SYS = {
  GETCWD: 17,
  DUP3: 24,
  FCNTL: 25,
  IOCTL: 29,
  MKDIRAT: 34,
  UNLINKAT: 35,
  SYMLINKAT: 36,
  FACCESSAT: 48,
  CHDIR: 49,
  OPENAT: 56,
  CLOSE: 57,
  PIPE2: 59,
  GETDENTS64: 61,
  LSEEK: 62,
  READ: 63,
  WRITE: 64,
  READV: 65,
  WRITEV: 66,
  PREAD64: 67,
  PWRITE64: 68,
  PPOLL: 73,
  READLINKAT: 78,
  NEWFSTATAT: 79,
  FSTAT: 80,
  EXIT: 93,
  EXIT_GROUP: 94,
  SET_TID_ADDRESS: 96,
  FUTEX: 98,
  SET_ROBUST_LIST: 99,
  NANOSLEEP: 101,
  CLOCK_GETTIME: 113,
  KILL: 129,
  TKILL: 130,
  TGKILL: 131,
  SIGALTSTACK: 132,
  RT_SIGACTION: 134,
  RT_SIGPROCMASK: 135,
  SETPGID: 154,
  GETPGID: 155,
  UNAME: 160,
  UMASK: 166,
  PRCTL: 167,
  GETPID: 172,
  GETPPID: 173,
  GETUID: 174,
  GETEUID: 175,
  GETGID: 176,
  GETEGID: 177,
  GETTID: 178,
  SOCKET: 198,
  CONNECT: 203,
  SENDTO: 206,
  RECVFROM: 207,
  SETSOCKOPT: 208,
  GETSOCKOPT: 209,
  BRK: 214,
  MUNMAP: 215,
  CLONE: 220,
  EXECVE: 221,
  MMAP: 222,
  MPROTECT: 226,
  MADVISE: 233,
  WAIT4: 260,
  PRLIMIT64: 261,
  RENAMEAT2: 276,
  GETRANDOM: 278,
} as const;

export const SIG = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGKILL: 9,
  SIGPIPE: 13,
  SIGTERM: 15,
  SIGCHLD: 17,
  SIGWINCH: 28,
} as const;

export const IOCTL_CMD = {
  TCGETS: 0x5401,
  TCSETS: 0x5402,
  TCSETSW: 0x5403,
  TCSETSF: 0x5404,
  TIOCGPGRP: 0x540f,
  TIOCSPGRP: 0x5410,
  TIOCGWINSZ: 0x5413,
  TIOCSWINSZ: 0x5414,
} as const;

export const ERRNO = {
  EPERM: 1,
  ENOENT: 2,
  ESRCH: 3,
  EINTR: 4,
  EBADF: 9,
  ECHILD: 10,
  EAGAIN: 11,
  ENOMEM: 12,
  EACCES: 13,
  ENOTDIR: 20,
  EINVAL: 22,
  ENOTTY: 25,
  ENOSYS: 38,
} as const;

export interface NetAdapter {
  connect(host: string, port: number): Promise<number>;
  send(sockId: number, bytes: Uint8Array): Promise<number>;
  recv(sockId: number, maxLen: number): Promise<Uint8Array>;
  close(sockId: number): void;
}

export interface HostAdapter {
  fs?: MemFS;
  rows?: number;
  cols?: number;
  onStdout?: (bytes: Uint8Array) => void;
  onStderr?: (bytes: Uint8Array) => void;
  readStdinAsync?: (maxLen: number) => Promise<Uint8Array>;
  net?: NetAdapter;
}

export interface SpawnOptions {
  cwd?: string;
  argv?: string[];
  envp?: string[];
  exePath?: string;
}

export interface RunOptions {
  sliceBudget?: number;
  mode?: 'wasm' | 'js';
}

interface FreeRegion {
  addr: number;
  len: number;
}

interface MappingRecord {
  len: number;
  prot: number;
  flags: number;
}

type FdEntry =
  | { kind: 'stdin' | 'stdout' | 'stderr'; isTty: boolean; path?: undefined; pipe?: undefined; sockId?: undefined }
  | { kind: 'file' | 'dir'; path: string; offset: number; dirEntries: DirEntry[] | null; dirIdx: number; isTty?: false; pipe?: undefined; sockId?: undefined }
  | { kind: 'pipe_r' | 'pipe_w'; pipe: PipeBuffer; isTty?: false; path?: undefined; sockId?: undefined }
  | { kind: 'socket'; domain: number; type: number; proto: number; sockId: number | null; isTty?: false; path?: undefined; pipe?: undefined };

export interface GuestProc {
  pid: number;
  ppid: number;
  pgid: number;
  exePath: string;
  cwd: string;
  umask: number;
  state: 'runnable' | 'blocked' | 'exited';
  exitCode: number;
  termSignal: number;
  pendingPromise: Promise<void> | null;
  sigHandlers: Map<number, bigint>;
  pendingSignals: number[];
  fds: Map<number, FdEntry>;
  nextFd: number;
  vmm: CompactVMM;
  cpu: GuestCPU;
}

function alignUp(n: number, align: number): number {
  return (n + align - 1) & ~(align - 1);
}

export class CompactVMM {
  brkStart: number;
  brkCurrent: number;
  mmapBase: number;
  mmapCursor: number;
  freeList: FreeRegion[] = [];
  mappings = new Map<number, MappingRecord>();

  constructor(brkStart: number, mmapBase = 0x01000000) {
    this.brkStart = alignUp(brkStart, PAGE_SIZE);
    this.brkCurrent = this.brkStart;
    this.mmapBase = Math.max(alignUp(mmapBase, PAGE_SIZE), this.brkStart + 0x100000);
    this.mmapCursor = this.mmapBase;
  }

  clone(): CompactVMM {
    const c = new CompactVMM(this.brkStart, this.mmapBase);
    c.brkCurrent = this.brkCurrent;
    c.mmapCursor = this.mmapCursor;
    c.freeList = this.freeList.map((r) => ({ ...r }));
    c.mappings = new Map(Array.from(this.mappings.entries()).map(([k, v]) => [k, { ...v }]));
    return c;
  }

  brk(cpu: GuestCPU, newBrk: number): number {
    if (newBrk === 0 || newBrk < this.brkStart) return this.brkCurrent;
    const aligned = alignUp(newBrk, PAGE_SIZE);
    if (aligned >= this.mmapBase) return this.brkCurrent;
    cpu.ensureMemory(aligned);
    if (aligned > this.brkCurrent) cpu.u8.fill(0, this.brkCurrent, aligned);
    this.brkCurrent = newBrk;
    return this.brkCurrent;
  }

  mmap(cpu: GuestCPU, addrHint: number, length: number, prot: number, flags: number): number {
    if (length <= 0) return -ERRNO.EINVAL;
    const len = alignUp(length, PAGE_SIZE);
    const MAP_FIXED = 0x10;
    if ((flags & MAP_FIXED) !== 0 && addrHint >= 0x10000) {
      const fixedAddr = addrHint & ~(PAGE_SIZE - 1);
      cpu.ensureMemory(fixedAddr + len);
      cpu.u8.fill(0, fixedAddr, fixedAddr + len);
      this.mappings.set(fixedAddr, { len, prot, flags });
      if (fixedAddr + len > this.mmapCursor) this.mmapCursor = alignUp(fixedAddr + len, PAGE_SIZE);
      return fixedAddr;
    }
    for (let i = 0; i < this.freeList.length; i++) {
      const slot = this.freeList[i];
      if (slot.len >= len) {
        const addr = slot.addr;
        if (slot.len === len) this.freeList.splice(i, 1);
        else {
          slot.addr += len;
          slot.len -= len;
        }
        cpu.ensureMemory(addr + len);
        cpu.u8.fill(0, addr, addr + len);
        this.mappings.set(addr, { len, prot, flags });
        return addr;
      }
    }
    const addr = this.mmapCursor;
    this.mmapCursor += len;
    cpu.ensureMemory(addr + len);
    cpu.u8.fill(0, addr, addr + len);
    this.mappings.set(addr, { len, prot, flags });
    return addr;
  }

  munmap(addr: number, _length: number): number {
    const rec = this.mappings.get(addr);
    if (!rec) return -ERRNO.EINVAL;
    this.mappings.delete(addr);
    this.freeList.push({ addr, len: rec.len });
    return 0;
  }
}

export class PipeBuffer {
  chunks: Uint8Array[] = [];
  readers = 1;
  writers = 1;
  private waiters: Array<() => void> = [];

  write(bytes: Uint8Array): number {
    this.chunks.push(new Uint8Array(bytes));
    this._wakeWaiters();
    return bytes.length;
  }

  tryRead(maxLen: number): Uint8Array | null {
    if (this.chunks.length === 0) return this.writers === 0 ? new Uint8Array(0) : null;
    const first = this.chunks[0];
    if (first.length <= maxLen) {
      this.chunks.shift();
      return first;
    }
    const slice = first.subarray(0, maxLen);
    this.chunks[0] = first.subarray(maxLen);
    return slice;
  }

  waitReadable(): Promise<void> {
    if (this.chunks.length > 0 || this.writers === 0) return Promise.resolve();
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  closeWriter(): void {
    this.writers = Math.max(0, this.writers - 1);
    if (this.writers === 0) this._wakeWaiters();
  }

  closeReader(): void {
    this.readers = Math.max(0, this.readers - 1);
  }

  private _wakeWaiters(): void {
    const list = this.waiters.splice(0, this.waiters.length);
    for (const fn of list) fn();
  }
}

export function setupInitialStack(
  cpu: GuestCPU,
  stackTop: number,
  argv: string[] = ['/bin/app'],
  envp: string[] = ['PATH=/bin:/usr/bin'],
  auxvExtras: [number, number][] = []
): number {
  const enc = new TextEncoder();
  let sp = stackTop >>> 0;
  cpu.ensureMemory(sp + 0x1000);

  sp -= 16;
  const randomPtr = sp;
  for (let i = 0; i < 16; i++) cpu.u8[randomPtr + i] = (i * 37 + 13) & 0xff;

  const writeCString = (s: string): number => {
    const bytes = enc.encode(s + '\0');
    sp -= bytes.length;
    cpu.u8.set(bytes, sp);
    return sp;
  };

  const envPtrs = envp.map(writeCString);
  const argPtrs = argv.map(writeCString);
  sp &= ~0xf;

  const auxv: [number, number][] = [
    ...auxvExtras,
    [6, PAGE_SIZE],
    [11, 0],
    [12, 0],
    [13, 0],
    [14, 0],
    [25, randomPtr],
    [0, 0],
  ];

  const totalQwords = 1 + argPtrs.length + 1 + envPtrs.length + 1 + auxv.length * 2;
  sp -= totalQwords * 8;
  sp &= ~0xf;

  const dv = cpu.view;
  let cur = sp;
  const push64 = (v: number): void => {
    dv.setBigUint64(cur, BigInt(v >>> 0), true);
    cur += 8;
  };

  push64(argPtrs.length);
  for (const p of argPtrs) push64(p);
  push64(0);
  for (const p of envPtrs) push64(p);
  push64(0);
  for (const [k, v] of auxv) {
    push64(k);
    push64(v);
  }

  cpu.setReg(31, sp);
  return sp;
}

function readCString(u8: Uint8Array, ptr: number, maxLen = 4096): string {
  let end = ptr;
  while (end < u8.length && end - ptr < maxLen && u8[end] !== 0) end++;
  return new TextDecoder().decode(u8.subarray(ptr, end));
}

function readCStringArray(cpu: GuestCPU, arrPtr: number, maxCount = 256): string[] {
  if (!arrPtr) return [];
  const out: string[] = [];
  const dv = cpu.view;
  const u8 = cpu.u8;
  for (let i = 0; i < maxCount; i++) {
    const p = Number(dv.getBigUint64(arrPtr + i * 8, true));
    if (p === 0) break;
    out.push(readCString(u8, p));
  }
  return out;
}

export class GuestKernel {
  engine: DBTEngine;
  fs: MemFS;
  tty: { rows: number; cols: number; fgPgrp: number };
  host: {
    onStdout: (bytes: Uint8Array) => void;
    onStderr: (bytes: Uint8Array) => void;
    readStdinAsync: ((maxLen: number) => Promise<Uint8Array>) | null;
    net: NetAdapter | null;
  };
  nextPid = 1;
  processes = new Map<number, GuestProc>();
  exited = new Map<number, number>();
  private waiters: Array<{ resolve: () => void }> = [];

  constructor(engine: DBTEngine, hostAdapter: HostAdapter = {}) {
    this.engine = engine;
    this.fs = hostAdapter.fs || new MemFS();
    this.tty = {
      rows: hostAdapter.rows || 24,
      cols: hostAdapter.cols || 80,
      fgPgrp: 1,
    };
    this.host = {
      onStdout: hostAdapter.onStdout || (() => {}),
      onStderr: hostAdapter.onStderr || (() => {}),
      readStdinAsync: hostAdapter.readStdinAsync || null,
      net: hostAdapter.net || null,
    };
  }

  resizeTerminal(rows: number, cols: number): void {
    this.tty.rows = rows;
    this.tty.cols = cols;
    for (const proc of this.processes.values()) {
      if (proc.state !== 'exited') this.sendSignal(proc.pid, SIG.SIGWINCH);
    }
  }

  sendSignal(pid: number, sig: number): boolean {
    const proc = this.processes.get(pid);
    if (!proc || proc.state === 'exited') return false;
    proc.pendingSignals.push(sig);
    return true;
  }

  private _loadELFWithInterp(cpu: GuestCPU, elfBytes: Uint8Array): { brkStart: number; auxvExtras: [number, number][] } {
    const mainInfo = loadELF64(cpu, elfBytes);
    let interpBase = 0;
    let startEntry = mainInfo.entry;
    let brkStart = mainInfo.brkStart;

    if (mainInfo.interpPath) {
      const interpBytes = this.fs.readFile(mainInfo.interpPath);
      if (!interpBytes) {
        throw new Error(`Dynamic linker not found in VFS: ${mainInfo.interpPath}`);
      }
      const interpInfo = loadELF64(cpu, interpBytes, {
        loadBias: 0x00400000,
        noSetPC: false,
      });
      interpBase = interpInfo.loadBias;
      startEntry = interpInfo.entry;
      brkStart = Math.max(brkStart, interpInfo.brkStart);
    }

    cpu.setPC(startEntry);
    const auxvExtras: [number, number][] = [
      [3, mainInfo.phdrVaddr],
      [4, mainInfo.phentsize],
      [5, mainInfo.phnum],
      [7, interpBase],
      [9, mainInfo.entry],
    ];
    return { brkStart, auxvExtras };
  }

  spawnELF(elfBytes: Uint8Array, opts: SpawnOptions = {}): GuestProc {
    const pid = this.nextPid++;
    const argv = opts.argv || ['/bin/app'];
    const proc: GuestProc = {
      pid,
      ppid: 0,
      pgid: pid,
      exePath: opts.exePath || argv[0] || '/bin/app',
      cwd: opts.cwd || '/',
      umask: 0o022,
      state: 'runnable',
      exitCode: 0,
      termSignal: 0,
      pendingPromise: null,
      sigHandlers: new Map(),
      pendingSignals: [],
      fds: new Map<number, FdEntry>([
        [0, { kind: 'stdin', isTty: true }],
        [1, { kind: 'stdout', isTty: true }],
        [2, { kind: 'stderr', isTty: true }],
      ]),
      nextFd: 3,
      vmm: null as unknown as CompactVMM,
      cpu: null as unknown as GuestCPU,
    };

    const cpu = new GuestCPU(this.engine, () => this._handleSyscall(proc), 256, 8192);
    const { brkStart, auxvExtras } = this._loadELFWithInterp(cpu, elfBytes);
    setupInitialStack(cpu, 0x00fff000, argv, opts.envp || ['PATH=/bin:/usr/bin', 'TERM=xterm-256color'], auxvExtras);

    proc.cpu = cpu;
    proc.vmm = new CompactVMM(Math.max(brkStart, 0x00800000), 0x01000000);
    this.processes.set(pid, proc);
    return proc;
  }

  _deliverPendingSignals(proc: GuestProc): boolean {
    while (proc.pendingSignals.length > 0) {
      const sig = proc.pendingSignals.shift()!;
      const handler = proc.sigHandlers.get(sig) || 0n;
      if (handler === 1n) continue;
      if (sig === SIG.SIGWINCH || sig === SIG.SIGCHLD) continue;
      if (handler === 0n) {
        proc.termSignal = sig;
        proc.exitCode = 128 + sig;
        proc.state = 'exited';
        this._onProcessExit(proc);
        return true;
      }
    }
    return false;
  }

  async runAll(opts: RunOptions = {}): Promise<Map<number, number>> {
    const sliceBudget = opts.sliceBudget || 4096;
    const mode = opts.mode || 'wasm';

    let lastYield = Date.now();
    while (true) {
      let anyRunnable = false;
      const blockedPromises: Promise<void>[] = [];

      for (const proc of this.processes.values()) {
        if (proc.state === 'exited') continue;
        if (this._deliverPendingSignals(proc)) continue;
        if (proc.state === 'blocked') {
          if (proc.pendingPromise) blockedPromises.push(proc.pendingPromise);
          continue;
        }

        anyRunnable = true;
        const status =
          mode === 'js'
            ? proc.cpu.stepJSPerBlock(sliceBudget)
            : proc.cpu.stepWasmLoop(sliceBudget);

        if (status === STATUS.EXIT) {
          proc.state = 'exited';
          this._onProcessExit(proc);
        } else if (status === STATUS.SYSCALL_PENDING) {
          proc.state = 'blocked';
          if (proc.pendingPromise) blockedPromises.push(proc.pendingPromise);
        } else if (status === STATUS.FAULT) {
          throw new Error(`Guest fault in pid=${proc.pid}: ${formatFaultDiagnostic(proc.cpu)}`);
        }
      }

      if (!anyRunnable) {
        if (blockedPromises.length === 0) break;
        await Promise.race(blockedPromises);
        lastYield = Date.now();
      } else if (Date.now() - lastYield >= 8) {
        // Yield to WKWebView / Node event loop so UI, Ctrl-C, and stdin never freeze!
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        lastYield = Date.now();
      }
    }
    return this.exited;
  }

  private _onProcessExit(proc: GuestProc): void {
    for (const fdObj of proc.fds.values()) {
      if (fdObj.kind === 'pipe_r') fdObj.pipe.closeReader();
      if (fdObj.kind === 'pipe_w') fdObj.pipe.closeWriter();
      if (fdObj.kind === 'socket' && fdObj.sockId && this.host.net) this.host.net.close(fdObj.sockId);
    }
    proc.fds.clear();
    this.exited.set(proc.pid, proc.exitCode);
    const list = this.waiters.splice(0, this.waiters.length);
    for (const w of list) w.resolve();
  }

  private _suspend(proc: GuestProc, promise: Promise<number>): number {
    proc.state = 'blocked';
    proc.pendingPromise = promise.then((retVal) => {
      proc.cpu.setReg(0, BigInt.asUintN(64, BigInt(retVal)));
      proc.pendingPromise = null;
      if (proc.state !== 'exited') proc.state = 'runnable';
    });
    return STATUS.SYSCALL_PENDING;
  }

  private _resolvePathAt(proc: GuestProc, dirfd: number, pathStr: string): string {
    if (pathStr.startsWith('/')) return normalizePath(pathStr);
    if ((dirfd | 0) === AT_FDCWD) return normalizePath(pathStr, proc.cwd);
    const fdObj = proc.fds.get(dirfd);
    const base = fdObj && fdObj.path ? fdObj.path : proc.cwd;
    return normalizePath(pathStr, base);
  }

  private _closeFd(proc: GuestProc, fd: number): boolean {
    const fdObj = proc.fds.get(fd);
    if (!fdObj) return false;
    if (fdObj.kind === 'pipe_r') fdObj.pipe.closeReader();
    if (fdObj.kind === 'pipe_w') fdObj.pipe.closeWriter();
    if (fdObj.kind === 'socket' && fdObj.sockId && this.host.net) this.host.net.close(fdObj.sockId);
    proc.fds.delete(fd);
    return true;
  }

  private _handleSyscall(proc: GuestProc): number {
    const cpu = proc.cpu;
    const nr = Number(cpu.getReg(8));
    const a0 = Number(cpu.getReg(0));
    const a1 = Number(cpu.getReg(1));
    const a2 = Number(cpu.getReg(2));
    const a3 = Number(cpu.getReg(3));
    const a4 = Number(cpu.getReg(4));
    const a5 = Number(cpu.getReg(5));

    const ret = (v: number): number => {
      cpu.setReg(0, BigInt.asUintN(64, BigInt(v)));
      return STATUS.CONTINUE;
    };

    switch (nr) {
      case SYS.EXIT:
      case SYS.EXIT_GROUP:
        proc.exitCode = a0 & 0xff;
        return STATUS.EXIT;

      case SYS.GETPID: return ret(proc.pid);
      case SYS.GETPPID: return ret(proc.ppid);
      case SYS.GETPGID: return ret(proc.pgid);
      case SYS.SETPGID: proc.pgid = a1 || proc.pid; return ret(0);
      case SYS.GETUID:
      case SYS.GETEUID:
      case SYS.GETGID:
      case SYS.GETEGID:
        return ret(0);

      case SYS.UMASK: {
        const old = proc.umask;
        proc.umask = a0 & 0o777;
        return ret(old);
      }

      case SYS.SET_TID_ADDRESS:
      case SYS.GETTID:
        return ret(proc.pid);
      case SYS.SET_ROBUST_LIST:
      case SYS.SIGALTSTACK:
      case SYS.PRCTL:
      case SYS.MADVISE:
      case SYS.FUTEX:
      case SYS.MPROTECT:
      case SYS.FCNTL:
      case SYS.RT_SIGPROCMASK:
      case SYS.SETSOCKOPT:
      case SYS.GETSOCKOPT:
        return ret(0);

      case SYS.BRK: return ret(proc.vmm.brk(cpu, a0));
      case SYS.MUNMAP: return ret(proc.vmm.munmap(a0, a1));

      case SYS.MMAP: {
        const addr = proc.vmm.mmap(cpu, a0, a1, a2, a3);
        if (addr < 0) return ret(addr);
        const MAP_ANONYMOUS = 0x20;
        const fd = a4 | 0;
        if ((a3 & MAP_ANONYMOUS) === 0 && fd >= 0) {
          const fdObj = proc.fds.get(fd);
          if (!fdObj || fdObj.kind !== 'file') return ret(-ERRNO.EBADF);
          const fileData = this.fs.readFile(fdObj.path) || new Uint8Array(0);
          const fileOff = a5 >>> 0;
          if (fileOff < fileData.length) {
            const copyLen = Math.min(a1, fileData.length - fileOff);
            cpu.u8.set(fileData.subarray(fileOff, fileOff + copyLen), addr);
          }
        }
        return ret(addr);
      }

      case SYS.SOCKET: {
        const fd = proc.nextFd++;
        proc.fds.set(fd, { kind: 'socket', domain: a0, type: a1, proto: a2, sockId: null });
        return ret(fd);
      }

      case SYS.CONNECT: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'socket') return ret(-ERRNO.EBADF);
        if (!this.host.net) return ret(-ERRNO.ENOSYS);
        const family = cpu.view.getUint16(a1, true);
        if (family !== 2) return ret(-ERRNO.EINVAL);
        const port = cpu.view.getUint16(a1 + 2, false);
        const ip = `${cpu.u8[a1 + 4]}.${cpu.u8[a1 + 5]}.${cpu.u8[a1 + 6]}.${cpu.u8[a1 + 7]}`;
        return this._suspend(
          proc,
          this.host.net.connect(ip, port).then((sockId) => {
            fdObj.sockId = sockId;
            return 0;
          })
        );
      }

      case SYS.SENDTO: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'socket' || !fdObj.sockId || !this.host.net) return ret(-ERRNO.EBADF);
        const bytes = cpu.u8.slice(a1, a1 + a2);
        return this._suspend(proc, this.host.net.send(fdObj.sockId, bytes));
      }

      case SYS.RECVFROM: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'socket' || !fdObj.sockId || !this.host.net) return ret(-ERRNO.EBADF);
        return this._suspend(
          proc,
          this.host.net.recv(fdObj.sockId, a2).then((data) => {
            const n = Math.min(a2, data.length);
            cpu.u8.set(data.subarray(0, n), a1);
            return n;
          })
        );
      }

      case SYS.GETRANDOM: {
        for (let i = 0; i < a1; i++) cpu.u8[a0 + i] = Math.floor(Math.random() * 256);
        return ret(a1);
      }

      case SYS.PRLIMIT64: {
        if (a3) {
          cpu.view.setBigUint64(a3, 0x10000000n, true);
          cpu.view.setBigUint64(a3 + 8, 0x10000000n, true);
        }
        return ret(0);
      }

      case SYS.RT_SIGACTION: {
        if (a2) cpu.view.setBigUint64(a2, proc.sigHandlers.get(a0) || 0n, true);
        if (a1) proc.sigHandlers.set(a0, cpu.view.getBigUint64(a1, true));
        return ret(0);
      }

      case SYS.KILL:
      case SYS.TKILL:
      case SYS.TGKILL: {
        const targetPid = nr === SYS.TGKILL ? a1 : a0;
        const sig = nr === SYS.TGKILL ? a2 : a1;
        return ret(this.sendSignal(targetPid, sig) ? 0 : -ERRNO.ESRCH);
      }

      case SYS.IOCTL: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || !fdObj.isTty) return ret(-ERRNO.ENOTTY);
        const cmd = a1 >>> 0;
        if (cmd === IOCTL_CMD.TIOCGWINSZ) {
          cpu.view.setUint16(a2 + 0, this.tty.rows, true);
          cpu.view.setUint16(a2 + 2, this.tty.cols, true);
          cpu.view.setUint16(a2 + 4, 0, true);
          cpu.view.setUint16(a2 + 6, 0, true);
          return ret(0);
        }
        if (cmd === IOCTL_CMD.TIOCSWINSZ) {
          this.tty.rows = cpu.view.getUint16(a2 + 0, true);
          this.tty.cols = cpu.view.getUint16(a2 + 2, true);
          return ret(0);
        }
        if (cmd === IOCTL_CMD.TIOCGPGRP) { cpu.view.setInt32(a2, this.tty.fgPgrp, true); return ret(0); }
        if (cmd === IOCTL_CMD.TIOCSPGRP) { this.tty.fgPgrp = cpu.view.getInt32(a2, true); return ret(0); }
        if (cmd === IOCTL_CMD.TCGETS || cmd === IOCTL_CMD.TCSETS || cmd === IOCTL_CMD.TCSETSW || cmd === IOCTL_CMD.TCSETSF) {
          if (cmd === IOCTL_CMD.TCGETS) cpu.u8.fill(0, a2, a2 + 60);
          return ret(0);
        }
        return ret(-ERRNO.ENOTTY);
      }

      case SYS.GETCWD: {
        const bytes = new TextEncoder().encode(proc.cwd + '\0');
        if (bytes.length > a1) return ret(-ERRNO.EINVAL);
        cpu.u8.set(bytes, a0);
        return ret(a0);
      }

      case SYS.CHDIR: {
        const p = normalizePath(readCString(cpu.u8, a0), proc.cwd);
        const st = this.fs.stat(p);
        if (!st) return ret(-ERRNO.ENOENT);
        if (!st.isDir) return ret(-ERRNO.ENOTDIR);
        proc.cwd = p;
        return ret(0);
      }

      case SYS.MKDIRAT:
        this.fs.mkdirp(this._resolvePathAt(proc, a0, readCString(cpu.u8, a1)));
        return ret(0);

      case SYS.UNLINKAT:
        return ret(this.fs.unlink(this._resolvePathAt(proc, a0, readCString(cpu.u8, a1))) ? 0 : -ERRNO.ENOENT);

      case SYS.SYMLINKAT:
        this.fs.symlink(readCString(cpu.u8, a0), this._resolvePathAt(proc, a1, readCString(cpu.u8, a2)));
        return ret(0);

      case SYS.RENAMEAT2:
        return ret(
          this.fs.rename(
            this._resolvePathAt(proc, a0, readCString(cpu.u8, a1)),
            this._resolvePathAt(proc, a2, readCString(cpu.u8, a3))
          )
            ? 0
            : -ERRNO.ENOENT
        );

      case SYS.FACCESSAT:
        return ret(this.fs.stat(this._resolvePathAt(proc, a0, readCString(cpu.u8, a1))) ? 0 : -ERRNO.ENOENT);

      case SYS.READLINKAT: {
        const full = this._resolvePathAt(proc, a0, readCString(cpu.u8, a1));
        const target =
          full === '/proc/self/exe' || full === `/proc/${proc.pid}/exe`
            ? proc.exePath
            : this.fs.readlink(full);
        if (!target) return ret(-ERRNO.ENOENT);
        const bytes = new TextEncoder().encode(target);
        const n = Math.min(a3, bytes.length);
        cpu.u8.set(bytes.subarray(0, n), a2);
        return ret(n);
      }

      case SYS.OPENAT: {
        const full = this._resolvePathAt(proc, a0, readCString(cpu.u8, a1));
        const O_CREAT = 0o100;
        let st = this.fs.stat(full);
        if (!st && (a2 & O_CREAT) !== 0) {
          this.fs.writeFile(full, new Uint8Array(0));
          st = this.fs.stat(full);
        }
        if (!st) return ret(-ERRNO.ENOENT);
        const fd = proc.nextFd++;
        proc.fds.set(fd, {
          kind: st.isDir ? 'dir' : 'file',
          path: this.fs.resolveSymlinks(full),
          offset: 0,
          dirEntries: st.isDir ? this.fs.listDir(full) : null,
          dirIdx: 0,
        });
        return ret(fd);
      }

      case SYS.FSTAT: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj) return ret(-ERRNO.EBADF);
        if (fdObj.path) {
          const st = this.fs.stat(fdObj.path);
          if (!st) return ret(-ERRNO.ENOENT);
          MemFS.writeAArch64Stat(cpu.view, a1, st);
          return ret(0);
        }
        MemFS.writeAArch64Stat(cpu.view, a1, { ino: 1, mode: 0o020666, size: 0, mtime: 0 });
        return ret(0);
      }

      case SYS.NEWFSTATAT: {
        const full = this._resolvePathAt(proc, a0, readCString(cpu.u8, a1));
        const st = this.fs.stat(full, '/', (a3 & 0x100) === 0);
        if (!st) return ret(-ERRNO.ENOENT);
        MemFS.writeAArch64Stat(cpu.view, a2, st);
        return ret(0);
      }

      case SYS.GETDENTS64: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'dir') return ret(-ERRNO.ENOTDIR);
        const entries = fdObj.dirEntries || [];
        const enc = new TextEncoder();
        const dv = cpu.view;
        let written = 0;
        while (fdObj.dirIdx < entries.length) {
          const e = entries[fdObj.dirIdx];
          const nameBytes = enc.encode(e.name + '\0');
          const reclen = alignUp(19 + nameBytes.length, 8);
          if (written + reclen > a2) break;
          const base = a1 + written;
          dv.setBigUint64(base + 0, BigInt(e.ino), true);
          dv.setBigInt64(base + 8, BigInt(fdObj.dirIdx + 1), true);
          dv.setUint16(base + 16, reclen, true);
          dv.setUint8(base + 18, e.type);
          cpu.u8.set(nameBytes, base + 19);
          for (let z = 19 + nameBytes.length; z < reclen; z++) cpu.u8[base + z] = 0;
          written += reclen;
          fdObj.dirIdx++;
        }
        return ret(written);
      }

      case SYS.LSEEK: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'file') return ret(-ERRNO.EBADF);
        const data = this.fs.readFile(fdObj.path) || new Uint8Array(0);
        let next = fdObj.offset;
        if (a2 === 0) next = a1;
        else if (a2 === 1) next = fdObj.offset + a1;
        else if (a2 === 2) next = data.length + a1;
        fdObj.offset = Math.max(0, next);
        return ret(fdObj.offset);
      }

      case SYS.DUP3: {
        const oldObj = proc.fds.get(a0);
        if (!oldObj) return ret(-ERRNO.EBADF);
        if (a0 === a1) return ret(-ERRNO.EINVAL);
        this._closeFd(proc, a1);
        if (oldObj.kind === 'pipe_r') oldObj.pipe.readers++;
        if (oldObj.kind === 'pipe_w') oldObj.pipe.writers++;
        proc.fds.set(a1, { ...oldObj });
        return ret(a1);
      }

      case SYS.UNAME: {
        const fields = ['Linux', 'iterminal', '6.1.0-wasm-jit', '#1 SMP', 'aarch64', 'local'];
        const enc = new TextEncoder();
        cpu.u8.fill(0, a0, a0 + 65 * 6);
        for (let i = 0; i < fields.length; i++) cpu.u8.set(enc.encode(fields[i]), a0 + i * 65);
        return ret(0);
      }

      case SYS.WRITE: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj) return ret(-ERRNO.EBADF);
        const bytes = cpu.u8.slice(a1, a1 + a2);
        if (fdObj.kind === 'stdout') { this.host.onStdout(bytes); return ret(bytes.length); }
        if (fdObj.kind === 'stderr') { this.host.onStderr(bytes); return ret(bytes.length); }
        if (fdObj.kind === 'pipe_w') return ret(fdObj.pipe.write(bytes));
        if (fdObj.kind === 'file') {
          const cur = this.fs.readFile(fdObj.path) || new Uint8Array(0);
          const merged = new Uint8Array(Math.max(cur.length, fdObj.offset + bytes.length));
          merged.set(cur, 0);
          merged.set(bytes, fdObj.offset);
          this.fs.writeFile(fdObj.path, merged);
          fdObj.offset += bytes.length;
          return ret(bytes.length);
        }
        return ret(-ERRNO.EBADF);
      }

      case SYS.WRITEV: {
        let total = 0;
        const dv = cpu.view;
        for (let i = 0; i < a2; i++) {
          const iovBase = Number(dv.getBigUint64(a1 + i * 16, true));
          const iovLen = Number(dv.getBigUint64(a1 + i * 16 + 8, true));
          if (iovLen === 0) continue;
          const fdObj = proc.fds.get(a0);
          if (!fdObj) return ret(-ERRNO.EBADF);
          const bytes = cpu.u8.slice(iovBase, iovBase + iovLen);
          if (fdObj.kind === 'stdout') this.host.onStdout(bytes);
          else if (fdObj.kind === 'stderr') this.host.onStderr(bytes);
          else if (fdObj.kind === 'pipe_w') fdObj.pipe.write(bytes);
          total += bytes.length;
        }
        return ret(total);
      }

      case SYS.READV: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'file') return ret(-ERRNO.EBADF);
        const fileData = this.fs.readFile(fdObj.path) || new Uint8Array(0);
        let total = 0;
        const dv = cpu.view;
        for (let i = 0; i < a2; i++) {
          const iovBase = Number(dv.getBigUint64(a1 + i * 16, true));
          const iovLen = Number(dv.getBigUint64(a1 + i * 16 + 8, true));
          const avail = Math.max(0, fileData.length - fdObj.offset);
          const n = Math.min(iovLen, avail);
          if (n > 0) {
            cpu.u8.set(fileData.subarray(fdObj.offset, fdObj.offset + n), iovBase);
            fdObj.offset += n;
            total += n;
          }
        }
        return ret(total);
      }

      case SYS.PREAD64: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'file') return ret(-ERRNO.EBADF);
        const fileData = this.fs.readFile(fdObj.path) || new Uint8Array(0);
        const off = a3 >>> 0;
        const avail = Math.max(0, fileData.length - off);
        const n = Math.min(a2, avail);
        if (n > 0) cpu.u8.set(fileData.subarray(off, off + n), a1);
        return ret(n);
      }

      case SYS.PWRITE64: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj || fdObj.kind !== 'file') return ret(-ERRNO.EBADF);
        const cur = this.fs.readFile(fdObj.path) || new Uint8Array(0);
        const off = a3 >>> 0;
        const bytes = cpu.u8.slice(a1, a1 + a2);
        const merged = new Uint8Array(Math.max(cur.length, off + bytes.length));
        merged.set(cur, 0);
        merged.set(bytes, off);
        this.fs.writeFile(fdObj.path, merged);
        return ret(bytes.length);
      }

      case SYS.READ: {
        const fdObj = proc.fds.get(a0);
        if (!fdObj) return ret(-ERRNO.EBADF);
        if (fdObj.kind === 'file') {
          const data = this.fs.readFile(fdObj.path) || new Uint8Array(0);
          const avail = Math.max(0, data.length - fdObj.offset);
          const n = Math.min(a2, avail);
          cpu.u8.set(data.subarray(fdObj.offset, fdObj.offset + n), a1);
          fdObj.offset += n;
          return ret(n);
        }
        if (fdObj.kind === 'stdin') {
          if (!this.host.readStdinAsync) return ret(0);
          return this._suspend(
            proc,
            this.host.readStdinAsync(a2).then((data) => {
              const n = Math.min(a2, data.length);
              cpu.u8.set(data.subarray(0, n), a1);
              return n;
            })
          );
        }
        if (fdObj.kind === 'pipe_r') {
          const chunk = fdObj.pipe.tryRead(a2);
          if (chunk !== null) { cpu.u8.set(chunk, a1); return ret(chunk.length); }
          return this._suspend(
            proc,
            fdObj.pipe.waitReadable().then(() => {
              const data = fdObj.pipe.tryRead(a2) || new Uint8Array(0);
              cpu.u8.set(data, a1);
              return data.length;
            })
          );
        }
        return ret(-ERRNO.EBADF);
      }

      case SYS.PIPE2: {
        const pipe = new PipeBuffer();
        const rfd = proc.nextFd++;
        const wfd = proc.nextFd++;
        proc.fds.set(rfd, { kind: 'pipe_r', pipe });
        proc.fds.set(wfd, { kind: 'pipe_w', pipe });
        cpu.view.setInt32(a0, rfd, true);
        cpu.view.setInt32(a0 + 4, wfd, true);
        return ret(0);
      }

      case SYS.CLOSE:
        return ret(this._closeFd(proc, a0) ? 0 : -ERRNO.EBADF);

      case SYS.CLONE: {
        const childPid = this.nextPid++;
        const childFds = new Map<number, FdEntry>();
        for (const [fd, obj] of proc.fds.entries()) {
          if (obj.kind === 'pipe_r') obj.pipe.readers++;
          if (obj.kind === 'pipe_w') obj.pipe.writers++;
          childFds.set(fd, { ...obj });
        }
        const childProc: GuestProc = {
          pid: childPid,
          ppid: proc.pid,
          pgid: proc.pgid,
          exePath: proc.exePath,
          cwd: proc.cwd,
          umask: proc.umask,
          state: 'runnable',
          exitCode: 0,
          termSignal: 0,
          pendingPromise: null,
          sigHandlers: new Map(proc.sigHandlers),
          pendingSignals: [],
          fds: childFds,
          nextFd: proc.nextFd,
          vmm: proc.vmm.clone(),
          cpu: null as unknown as GuestCPU,
        };
        childProc.cpu = proc.cpu.cloneForFork(() => this._handleSyscall(childProc));
        childProc.cpu.setReg(0, 0n);
        this.processes.set(childPid, childProc);
        return ret(childPid);
      }

      case SYS.EXECVE: {
        const path = normalizePath(readCString(cpu.u8, a0), proc.cwd);
        const resolved = this.fs.resolveSymlinks(path);
        const elfBytes = this.fs.readFile(resolved);
        if (!elfBytes) return ret(-ERRNO.ENOENT);
        const argv = readCStringArray(cpu, a1);
        const envp = readCStringArray(cpu, a2);

        proc.exePath = resolved;
        proc.sigHandlers.clear();
        cpu.resetForExec();
        const { brkStart, auxvExtras } = this._loadELFWithInterp(cpu, elfBytes);
        setupInitialStack(cpu, 0x00fff000, argv.length ? argv : [path], envp, auxvExtras);
        proc.vmm = new CompactVMM(Math.max(brkStart, 0x00800000), 0x01000000);
        return STATUS.CONTINUE;
      }

      case SYS.WAIT4: {
        const targetPid = a0 | 0;
        const statusPtr = a1;
        const tryReap = (): number | null => {
          for (const [pid, code] of this.exited.entries()) {
            const p = this.processes.get(pid);
            if (p && p.ppid === proc.pid && (targetPid === -1 || targetPid === pid)) {
              this.exited.delete(pid);
              if (statusPtr) {
                const wstatus = p.termSignal ? p.termSignal & 0x7f : (code & 0xff) << 8;
                cpu.view.setInt32(statusPtr, wstatus, true);
              }
              return pid;
            }
          }
          return null;
        };
        const reaped = tryReap();
        if (reaped !== null) return ret(reaped);

        return this._suspend(
          proc,
          new Promise<number>((resolve) => {
            const check = (): void => {
              const r = tryReap();
              if (r !== null) resolve(r);
              else this.waiters.push({ resolve: check });
            };
            this.waiters.push({ resolve: check });
          })
        );
      }

      case SYS.PPOLL: {
        // ppoll(fds, nfds, tmo_p, sigmask) — mark stdin/readable pipes as POLLIN (1)
        const nfds = a1 >>> 0;
        let ready = 0;
        for (let i = 0; i < nfds; i++) {
          const base = a0 + i * 8;
          const fd = cpu.view.getInt32(base, true);
          const events = cpu.view.getInt16(base + 4, true);
          const fdObj = proc.fds.get(fd);
          let revents = 0;
          if (fdObj) {
            if ((events & 1) !== 0) {
              if (fdObj.kind === 'stdin' || fdObj.kind === 'file') revents |= 1;
              else if (fdObj.kind === 'pipe_r' && (fdObj.pipe.chunks.length > 0 || fdObj.pipe.writers === 0)) revents |= 1;
            }
            if ((events & 4) !== 0 && (fdObj.kind === 'stdout' || fdObj.kind === 'stderr' || fdObj.kind === 'pipe_w')) {
              revents |= 4;
            }
          }
          cpu.view.setInt16(base + 6, revents, true);
          if (revents !== 0) ready++;
        }
        return ret(ready);
      }

      case SYS.NANOSLEEP: {
        const sec = Number(cpu.view.getBigInt64(a0, true));
        const nsec = Number(cpu.view.getBigInt64(a0 + 8, true));
        const ms = Math.min(Math.max(0, sec * 1000 + Math.floor(nsec / 1e6)), 5000);
        return this._suspend(proc, new Promise<number>((resolve) => setTimeout(() => resolve(0), ms)));
      }

      case SYS.CLOCK_GETTIME: {
        const nowMs = Date.now();
        cpu.view.setBigInt64(a1, BigInt(Math.floor(nowMs / 1000)), true);
        cpu.view.setBigInt64(a1 + 8, BigInt((nowMs % 1000) * 1000000), true);
        return ret(0);
      }

      default:
        return ret(-ERRNO.ENOSYS);
    }
  }
}
