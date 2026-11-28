(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./dbt-runtime'));
  } else {
    root.WasmVmmSyscalls = factory(root.WasmDBT);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (WasmDBT) {
  'use strict';

  const { STATUS } = WasmDBT;
  const PAGE_SIZE = 4096;

  // Linux AArch64 syscall numbers
  const SYS = {
    GETCWD: 17,
    DUP3: 24,
    FCNTL: 25,
    IOCTL: 29,
    OPENAT: 56,
    CLOSE: 57,
    PIPE2: 59,
    GETDENTS64: 61,
    LSEEK: 62,
    READ: 63,
    WRITE: 64,
    EXIT: 93,
    EXIT_GROUP: 94,
    CLOCK_GETTIME: 113,
    UNAME: 160,
    GETPID: 172,
    GETPPID: 173,
    BRK: 214,
    MUNMAP: 215,
    CLONE: 220,
    MMAP: 222,
    MPROTECT: 226,
    WAIT4: 260,
  };

  const ERRNO = {
    EPERM: 1,
    ENOENT: 2,
    ECHILD: 10,
    EAGAIN: 11,
    ENOMEM: 12,
    EBADF: 9,
    EINVAL: 22,
    ENOSYS: 38,
  };

  // ---------------------------------------------------------------------------
  // Compact 32-bit Virtual Memory Allocator (brk + mmap + munmap)
  // Keeps all guest addresses inside WASM 32-bit linear memory (< 0x7FFF_0000)
  // ---------------------------------------------------------------------------
  class CompactVMM {
    constructor(brkStart, mmapBase = 0x00200000) {
      this.brkStart = alignUp(brkStart, PAGE_SIZE);
      this.brkCurrent = this.brkStart;
      this.mmapBase = Math.max(alignUp(mmapBase, PAGE_SIZE), this.brkStart + 0x100000);
      this.mmapCursor = this.mmapBase;
      this.freeList = []; // { addr, len }
      this.mappings = new Map(); // addr -> { len, prot, flags }
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
      if (aligned >= this.mmapBase) return this.brkCurrent; // prevent collision with mmap
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

      // First-fit from freeList
      for (let i = 0; i < this.freeList.length; i++) {
        const slot = this.freeList[i];
        if (slot.len >= len) {
          const addr = slot.addr;
          if (slot.len === len) {
            this.freeList.splice(i, 1);
          } else {
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

    munmap(addr, length) {
      const rec = this.mappings.get(addr);
      if (!rec) return -ERRNO.EINVAL;
      this.mappings.delete(addr);
      this.freeList.push({ addr, len: rec.len });
      return 0;
    }
  }

  // ---------------------------------------------------------------------------
  // Shared In-Memory Pipe (supports blocking read + EOF across forked processes)
  // ---------------------------------------------------------------------------
  class PipeBuffer {
    constructor() {
      this.chunks = [];
      this.readers = 1;
      this.writers = 1;
      this.waiters = []; // resolve callbacks when data arrives or writers==0
    }

    write(bytes) {
      this.chunks.push(new Uint8Array(bytes));
      this._wakeWaiters();
      return bytes.length;
    }

    tryRead(maxLen) {
      if (this.chunks.length === 0) {
        return this.writers === 0 ? new Uint8Array(0) : null; // null => would block
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
  // GuestKernel: Multi-process cooperative scheduler + async suspendable syscalls
  // ---------------------------------------------------------------------------
  class GuestKernel {
    constructor(engine, hostAdapter = {}) {
      this.engine = engine;
      this.host = {
        onStdout: hostAdapter.onStdout || (() => {}),
        onStderr: hostAdapter.onStderr || (() => {}),
        readStdinAsync: hostAdapter.readStdinAsync || null,
        fs: hostAdapter.fs || null,
      };
      this.nextPid = 1;
      this.processes = new Map(); // pid -> GuestProc
      this.exited = new Map();    // pid -> exitCode
      this.waiters = [];          // { pid, resolve }
    }

    spawnELF(elfBytes, opts = {}) {
      const pid = this.nextPid++;
      const proc = {
        pid,
        ppid: 0,
        cwd: opts.cwd || '/',
        state: 'runnable', // runnable | blocked | exited
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
      // Place stack at 0x001F_F000 (below default mmapBase 0x0020_0000)
      const stackTop = 0x001ff000;
      cpu.ensureMemory(stackTop + 0x1000);
      cpu.setReg(31, stackTop);

      proc.cpu = cpu;
      proc.vmm = new CompactVMM(brkStart, 0x00200000);
      this.processes.set(pid, proc);
      return proc;
    }

    // Main cooperative scheduler loop (handles fork, pipes, and async Swift/host I/O!)
    async runAll(opts = {}) {
      const sliceBudget = opts.sliceBudget || 4096;
      const mode = opts.mode || 'wasm'; // 'wasm' or 'js'

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
          if (blockedPromises.length === 0) break; // all processes exited
          await Promise.race(blockedPromises);
        }
      }
      return this.exited;
    }

    _onProcessExit(proc) {
      // Close all open pipe endpoints so readers get EOF
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

        case SYS.GETPID:
          return ret(proc.pid);

        case SYS.GETPPID:
          return ret(proc.ppid);

        case SYS.BRK:
          return ret(proc.vmm.brk(cpu, a0));

        case SYS.MMAP:
          return ret(proc.vmm.mmap(cpu, a0, a1, a2, a3));

        case SYS.MUNMAP:
          return ret(proc.vmm.munmap(a0, a1));

        case SYS.MPROTECT:
          return ret(0);

        case SYS.WRITE: {
          const fdObj = proc.fds.get(a0);
          if (!fdObj) return ret(-ERRNO.EBADF);
          const bytes = cpu.u8.slice(a1, a1 + a2);
          if (fdObj.kind === 'stdout') {
            this.host.onStdout(bytes);
            return ret(bytes.length);
          }
          if (fdObj.kind === 'stderr') {
            this.host.onStderr(bytes);
            return ret(bytes.length);
          }
          if (fdObj.kind === 'pipe_w') {
            return ret(fdObj.pipe.write(bytes));
          }
          return ret(-ERRNO.EBADF);
        }

        case SYS.READ: {
          const fdObj = proc.fds.get(a0);
          if (!fdObj) return ret(-ERRNO.EBADF);
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
            // Suspend cleanly until writer writes or closes!
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

        case SYS.CLOSE: {
          const fdObj = proc.fds.get(a0);
          if (!fdObj) return ret(-ERRNO.EBADF);
          if (fdObj.kind === 'pipe_r') fdObj.pipe.closeReader();
          if (fdObj.kind === 'pipe_w') fdObj.pipe.closeWriter();
          proc.fds.delete(a0);
          return ret(0);
        }

        case SYS.CLONE: {
          // Fork-style clone: snapshot registers + linear memory + FDs
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
          // Child returns 0 in x0, parent returns childPid in x0
          childProc.cpu.setReg(0, 0n);
          this.processes.set(childPid, childProc);
          return ret(childPid);
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

  return { SYS, ERRNO, CompactVMM, PipeBuffer, GuestKernel };
});
