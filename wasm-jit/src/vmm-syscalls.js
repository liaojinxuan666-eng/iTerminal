(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./dbt-runtime'), require('./vfs-memfs'));
  } else {
    root.WasmVmmSyscalls = factory(root.WasmDBT, root.WasmMemFS);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (WasmDBT, WasmMemFS) {
  'use strict';

  const { STATUS } = WasmDBT;
  const { MemFS, normalizePath } = WasmMemFS;
  const PAGE_SIZE = 4096;
  const AT_FDCWD = -100;

  const SYS = {
    GETCWD: 17,
    DUP3: 24,
    FCNTL: 25,
    IOCTL: 29,
    MKDIRAT: 34,
    UNLINKAT: 35,
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
    NEWFSTATAT: 79,
    FSTAT: 80,
    EXIT: 93,
    EXIT_GROUP: 94,
    SET_TID_ADDRESS: 96,
    CLOCK_GETTIME: 113,
    UNAME: 160,
    GETPID: 172,
    GETPPID: 173,
    GETUID: 174,
    GETEUID: 175,
    GETGID: 176,
    GETEGID: 177,
    BRK: 214,
    MUNMAP: 215,
    CLONE: 220,
    EXECVE: 221,
    MMAP: 222,
    MPROTECT: 226,
    WAIT4: 260,
  };

  const ERRNO = {
    EPERM: 1,
    ENOENT: 2,
    EBADF: 9,
    ECHILD: 10,
    EAGAIN: 11,
    ENOMEM: 12,
    EACCES: 13,
    ENOTDIR: 20,
    EINVAL: 22,
    ENOTTY: 25,
    ENOSYS: 38,
  };

  class CompactVMM {
    constructor(brkStart, mmapBase = 0x00200000) {
      this.brkStart = alignUp(brkStart, PAGE_SIZE);
      this.brkCurrent = this.brkStart;
      this.mmapBase = Math.max(alignUp(mmapBase, PAGE_SIZE), this.brkStart + 0x100000);
      this.mmapCursor = this.mmapBase;
      this.freeList = [];
      this.mappings = new Map();
    }

    clone() {
      const c = new CompactVMM(this.brkStart, this.mmapBase);
      c.brkCurrent = this.brkCurrent;
      c.mmapCursor = this.mmapCursor;
      c.freeList = this.freeList.map((r) => ({ ...r }));
      c.mappings = new Map(Array.from(this.mappings.entries()).map(([k, v]) => [k, { ...v }]));
      return c;
    }

    brk(cpu, newBrk) {
      if (newBrk === 0 || newBrk < this.brkStart) return this.brkCurrent;
      const aligned = alignUp(newBrk, PAGE_SIZE);
      if (aligned >= this.mmapBase) return this.brkCurrent;
      cpu.ensureMemory(aligned);
      if (aligned > this.brkCurrent) {
        cpu.u8.fill(0, this.brkCurrent, aligned);
      }
      this.brkCurrent = newBrk;
      return this.brkCurrent;
    }

    mmap(cpu, addrHint, length, prot, flags) {
      if (length <= 0) return -ERRNO.EINVAL;
      const len = alignUp(length, PAGE_SIZE);
      for (let i = 0; i < this.freeList.length; i++) {
        const slot = this.freeList[i];
        if (slot.len >= len) {
          const addr = slot.addr;
          if (slot.len === len) this.freeList.splice(i, 1);
          else { slot.addr += len; slot.len -= len; }
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

    munmap(addr, length) {
      const rec = this.mappings.get(addr);
      if (!rec) return -ERRNO.EINVAL;
      this.mappings.delete(addr);
      this.freeList.push({ addr, len: rec.len });
      return 0;
    }
  }

  class PipeBuffer {
    constructor() {
      this.chunks = [];
      this.readers = 1;
      this.writers = 1;
      this.waiters = [];
    }

    write(bytes) {
      this.chunks.push(new Uint8Array(bytes));
      this._wakeWaiters();
      return bytes.length;
    }

    tryRead(maxLen) {
      if (this.chunks.length === 0) {
        return this.writers === 0 ? new Uint8Array(0) : null;
      }
      const first = this.chunks[0];
      if (first.length <= maxLen) {
        this.chunks.shift();
        return first;
      }
      const slice = first.subarray(0, maxLen);
      this.chunks[0] = first.subarray(maxLen);
      return slice;
    }

    waitReadable() {
      if (this.chunks.length > 0 || this.writers === 0) return Promise.resolve();
      return new Promise((resolve) => this.waiters.push(resolve));
    }

    closeWriter() {
      this.writers = Math.max(0, this.writers - 1);
      if (this.writers === 0) this._wakeWaiters();
    }

    closeReader() {
      this.readers = Math.max(0, this.readers - 1);
    }

    _wakeWaiters() {
      const list = this.waiters.splice(0, this.waiters.length);
      for (const fn of list) fn();
    }
  }

  // ---------------------------------------------------------------------------
  // Build Linux AArch64 initial stack: [argc, argv..., 0, envp..., 0, auxv..., 0, 0]
  // ---------------------------------------------------------------------------
  function setupInitialStack(cpu, stackTop, argv = ['/bin/app'], envp = ['PATH=/bin:/usr/bin']) {
    const enc = new TextEncoder();
    let sp = stackTop >>> 0;
    cpu.ensureMemory(sp + 0x1000);

    // 16 random bytes for AT_RANDOM
    sp -= 16;
    const randomPtr = sp;
    for (let i = 0; i < 16; i++) cpu.u8[randomPtr + i] = (i * 37 + 13) & 0xff;

    const writeCString = (s) => {
      const bytes = enc.encode(s + '\0');
      sp -= bytes.length;
      cpu.u8.set(bytes, sp);
      return sp;
    };

    const envPtrs = envp.map(writeCString);
    const argPtrs = argv.map(writeCString);

    // Align down to 16 bytes
    sp &= ~0xf;

    const auxv = [
      [6, PAGE_SIZE],   // AT_PAGESZ
      [11, 0],          // AT_UID
      [12, 0],          // AT_EUID
      [13, 0],          // AT_GID
      [14, 0],          // AT_EGID
      [25, randomPtr],  // AT_RANDOM
      [0, 0],           // AT_NULL
    ];

    const totalQwords = 1 + argPtrs.length + 1 + envPtrs.length + 1 + auxv.length * 2;
    sp -= totalQwords * 8;
    sp &= ~0xf; // AArch64 ABI requires 16-byte aligned SP at _start

    const dv = cpu.view;
    let cur = sp;
    const push64 = (v) => {
      dv.setBigUint64(cur, BigInt(v >>> 0), true);
      cur += 8;
    };

    push64(argPtrs.length); // argc
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

  function readCString(u8, ptr, maxLen = 4096) {
    let end = ptr;
    while (end < u8.length && end - ptr < maxLen && u8[end] !== 0) end++;
    return new TextDecoder().decode(u8.subarray(ptr, end));
  }

  function readCStringArray(cpu, arrPtr, maxCount = 256) {
    if (!arrPtr) return [];
    const out = [];
    const dv = cpu.view;
    const u8 = cpu.u8;
    for (let i = 0; i < maxCount; i++) {
      const p = Number(dv.getBigUint64(arrPtr + i * 8, true));
      if (p === 0) break;
      out.push(readCString(u8, p));
    }
    return out;
  }

  class GuestKernel {
    constructor(engine, hostAdapter = {}) {
      this.engine = engine;
      this.fs = hostAdapter.fs || new MemFS();
      this.host = {
        onStdout: hostAdapter.onStdout || (() => {}),
        onStderr: hostAdapter.onStderr || (() => {}),
        readStdinAsync: hostAdapter.readStdinAsync || null,
      };
      this.nextPid = 1;
      this.processes = new Map();
      this.exited = new Map();
      this.waiters = [];
    }

    spawnELF(elfBytes, opts = {}) {
      const pid = this.nextPid++;
      const proc = {
        pid,
        ppid: 0,
        cwd: opts.cwd || '/',
        state: 'runnable',
        exitCode: 0,
        pendingPromise: null,
        fds: new Map([
          [0, { kind: 'stdin' }],
          [1, { kind: 'stdout' }],
          [2, { kind: 'stderr' }],
        ]),
        nextFd: 3,
        vmm: null,
        cpu: null,
      };

      const cpu = new WasmDBT.GuestCPU(this.engine, () => this._handleSyscall(proc), 64, 4096);
      const { brkStart } = WasmDBT.loadELF64(cpu, elfBytes);
      setupInitialStack(cpu, 0x001ff000, opts.argv || ['/bin/app'], opts.envp || ['PATH=/bin']);

      proc.cpu = cpu;
      proc.vmm = new CompactVMM(brkStart, 0x00200000);
      this.processes.set(pid, proc);
      return proc;
    }

    async runAll(opts = {}) {
      const sliceBudget = opts.sliceBudget || 4096;
      const mode = opts.mode || 'wasm';

      while (true) {
        let anyRunnable = false;
        const blockedPromises = [];

        for (const proc of this.processes.values()) {
          if (proc.state === 'exited') continue;
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
            throw new Error(`Guest fault in pid=${proc.pid} at PC=0x${proc.cpu.getPC().toString(16)}`);
          }
        }

        if (!anyRunnable) {
          if (blockedPromises.length === 0) break;
          await Promise.race(blockedPromises);
        }
      }
      return this.exited;
    }

    _onProcessExit(proc) {
      for (const fdObj of proc.fds.values()) {
        if (fdObj.kind === 'pipe_r') fdObj.pipe.closeReader();
        if (fdObj.kind === 'pipe_w') fdObj.pipe.closeWriter();
      }
      proc.fds.clear();
      this.exited.set(proc.pid, proc.exitCode);
      const list = this.waiters.splice(0, this.waiters.length);
      for (const w of list) w.resolve();
    }

    _suspend(proc, promise) {
      proc.state = 'blocked';
      proc.pendingPromise = promise.then((retVal) => {
        proc.cpu.setReg(0, BigInt.asUintN(64, BigInt(retVal)));
        proc.pendingPromise = null;
        proc.state = 'runnable';
      });
      return STATUS.SYSCALL_PENDING;
    }

    _resolvePathAt(proc, dirfd, pathStr) {
      if (pathStr.startsWith('/')) return normalizePath(pathStr);
      if ((dirfd | 0) === AT_FDCWD) return normalizePath(pathStr, proc.cwd);
      const fdObj = proc.fds.get(dirfd);
      const base = fdObj && fdObj.path ? fdObj.path : proc.cwd;
      return normalizePath(pathStr, base);
    }

    _closeFd(proc, fd) {
      const fdObj = proc.fds.get(fd);
      if (!fdObj) return false;
      if (fdObj.kind === 'pipe_r') fdObj.pipe.closeReader();
      if (fdObj.kind === 'pipe_w') fdObj.pipe.closeWriter();
      proc.fds.delete(fd);
      return true;
    }

    _handleSyscall(proc) {
      const cpu = proc.cpu;
      const nr = Number(cpu.getReg(8));
      const a0 = Number(cpu.getReg(0));
      const a1 = Number(cpu.getReg(1));
      const a2 = Number(cpu.getReg(2));
      const a3 = Number(cpu.getReg(3));

      const ret = (v) => {
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
        case SYS.GETUID:
        case SYS.GETEUID:
        case SYS.GETGID:
        case SYS.GETEGID:
          return ret(0);

        case SYS.SET_TID_ADDRESS:
          return ret(proc.pid);

        case SYS.BRK: return ret(proc.vmm.brk(cpu, a0));
        case SYS.MMAP: return ret(proc.vmm.mmap(cpu, a0, a1, a2, a3));
        case SYS.MUNMAP: return ret(proc.vmm.munmap(a0, a1));
        case SYS.MPROTECT: return ret(0);

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

        case SYS.OPENAT: {
          const rel = readCString(cpu.u8, a1);
          const full = this._resolvePathAt(proc, a0, rel);
          const flags = a2;
          const O_CREAT = 0o100;
          let st = this.fs.stat(full);
          if (!st && (flags & O_CREAT)) {
            this.fs.writeFile(full, new Uint8Array(0));
            st = this.fs.stat(full);
          }
          if (!st) return ret(-ERRNO.ENOENT);
          const fd = proc.nextFd++;
          proc.fds.set(fd, {
            kind: st.isDir ? 'dir' : 'file',
            path: full,
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
          const rel = readCString(cpu.u8, a1);
          const full = this._resolvePathAt(proc, a0, rel);
          const st = this.fs.stat(full);
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

        case SYS.FCNTL:
          return ret(0);

        case SYS.IOCTL:
          return ret(-ERRNO.ENOTTY);

        case SYS.UNAME: {
          const fields = ['Linux', 'iterminal', '6.1.0-wasm-jit', '#1 SMP', 'aarch64', 'local'];
          const enc = new TextEncoder();
          cpu.u8.fill(0, a0, a0 + 65 * 6);
          for (let i = 0; i < fields.length; i++) {
            cpu.u8.set(enc.encode(fields[i]), a0 + i * 65);
          }
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
            if (chunk !== null) {
              cpu.u8.set(chunk, a1);
              return ret(chunk.length);
            }
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
          const childFds = new Map();
          for (const [fd, obj] of proc.fds.entries()) {
            if (obj.kind === 'pipe_r') obj.pipe.readers++;
            if (obj.kind === 'pipe_w') obj.pipe.writers++;
            childFds.set(fd, { ...obj });
          }
          const childProc = {
            pid: childPid,
            ppid: proc.pid,
            cwd: proc.cwd,
            state: 'runnable',
            exitCode: 0,
            pendingPromise: null,
            fds: childFds,
            nextFd: proc.nextFd,
            vmm: proc.vmm.clone(),
            cpu: null,
          };
          childProc.cpu = proc.cpu.cloneForFork(() => this._handleSyscall(childProc));
          childProc.cpu.setReg(0, 0n);
          this.processes.set(childPid, childProc);
          return ret(childPid);
        }

        case SYS.EXECVE: {
          const path = normalizePath(readCString(cpu.u8, a0), proc.cwd);
          const elfBytes = this.fs.readFile(path);
          if (!elfBytes) return ret(-ERRNO.ENOENT);
          const argv = readCStringArray(cpu, a1);
          const envp = readCStringArray(cpu, a2);

          // Replace process image in-place while preserving PID & open FDs (pipes/stdout!)
          cpu.resetForExec();
          const { brkStart } = WasmDBT.loadELF64(cpu, elfBytes);
          setupInitialStack(cpu, 0x001ff000, argv.length ? argv : [path], envp);
          proc.vmm = new CompactVMM(brkStart, 0x00200000);
          return STATUS.CONTINUE;
        }

        case SYS.WAIT4: {
          const targetPid = a0 | 0;
          const statusPtr = a1;
          const tryReap = () => {
            for (const [pid, code] of this.exited.entries()) {
              const p = this.processes.get(pid);
              if (p && p.ppid === proc.pid && (targetPid === -1 || targetPid === pid)) {
                this.exited.delete(pid);
                if (statusPtr) cpu.view.setInt32(statusPtr, (code & 0xff) << 8, true);
                return pid;
              }
            }
            return null;
          };
          const reaped = tryReap();
          if (reaped !== null) return ret(reaped);

          return this._suspend(
            proc,
            new Promise((resolve) => {
              const check = () => {
                const r = tryReap();
                if (r !== null) resolve(r);
                else this.waiters.push({ resolve: check });
              };
              this.waiters.push({ resolve: check });
            })
          );
        }

        case SYS.CLOCK_GETTIME: {
          const nowMs = Date.now();
          const sec = BigInt(Math.floor(nowMs / 1000));
          const nsec = BigInt((nowMs % 1000) * 1000000);
          cpu.view.setBigInt64(a1, sec, true);
          cpu.view.setBigInt64(a1 + 8, nsec, true);
          return ret(0);
        }

        default:
          return ret(-ERRNO.ENOSYS);
      }
    }
  }

  function alignUp(n, align) {
    return (n + align - 1) & ~(align - 1);
  }

  return { SYS, ERRNO, CompactVMM, PipeBuffer, GuestKernel, setupInitialStack };
});
