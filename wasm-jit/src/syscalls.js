/*
 * syscalls.js — 可复用的 Linux syscall 实现层
 *
 * 设计要点：
 * - 与宿主解耦：所有 syscall 通过一个 `env` 对象访问宿主能力
 *   （内存、输入缓冲、文件、输出回调）。Node 宿主和 iOS WKWebView
 *   宿主提供不同的 env，但 syscall 逻辑完全一致。
 * - 覆盖终端最小集：write/read/exit/brk/mmap/getpid/uname 等。
 *
 * AArch64 Linux syscall 号（arch/arm64/include/uapi/asm/unistd.h）
 */

'use strict';

const ERR = {
    ENOSYS: -38,
    EBADF: -9,
    EINVAL: -22,
    ENOMEM: -12,
};

/**
 * 创建 syscall 表。
 * @param {object} env 宿主环境：
 *   - memory: WebAssembly.Memory
 *   - input: Uint8Array/Buffer 输入缓冲（read 用）
 *   - onWrite(fd, bytes): 输出回调
 *   - files: Map<fd, Uint8Array> 可选，预置文件
 *   - verbose: 是否打印未实现 syscall
 */
function createSyscalls(env) {
    const mem = () => new Uint8Array(env.memory.buffer);
    const output = env.onWrite || (() => {});
    let brk = env.brkStart || (0x400000 + 0x200000);
    let mmapNext = env.mmapStart || (0x500000);

    const table = {
        // ---- 输出 ----
        64: (fd, buf, len) => {          // write
            if (fd !== 1 && fd !== 2) return ERR.EBADF;
            const u = mem();
            const bytes = Buffer.from(u.subarray(buf, buf + len));
            output(fd, bytes);
            return len;
        },

        // ---- 输入（终端核心）----
        63: (fd, buf, len) => {          // read
            if (fd !== 0) return ERR.EBADF;
            const input = env.input;
            if (!input) return 0;        // EOF
            const u = mem();
            const pos = env.inputPos || 0;
            const n = Math.min(len, input.length - pos);
            for (let i = 0; i < n; i++) u[buf + i] = input[pos + i];
            env.inputPos = pos + n;
            return n;
        },

        // ---- 进程生命周期 ----
        // code 可能是 BigInt（WASM i64 原始值），必须先按 BigInt 取低 8 位再转 Number。
        // 若先 Number() 会因 >2^53 丢精度，低字节被污染（曾导致 exit code 恒为 0）。
        93: code => { env.onExit?.(Number(BigInt(code) & 0xffn)); return 0; },   // exit
        94: code => { env.onExit?.(Number(BigInt(code) & 0xffn)); return 0; },   // exit_group

        // ---- 进程信息 ----
        172: () => 4242,                 // getpid
        176: () => 0,                    // getuid
        177: () => 0,                    // geteuid
        178: () => 4242,                 // gettid

        // ---- uname ----
        189: addr => {
            const u = mem();
            const put = (off, s) => { for (let i = 0; i < s.length; i++) u[addr + off + i] = s.charCodeAt(i); };
            put(0, 'Linux'); put(65, 'wasm-jit'); put(130, '6.1.0'); put(195, '#1'); put(260, 'aarch64');
            return 0;
        },

        // ---- 内存管理 ----
        214: addr => {                   // brk
            if (addr === 0) return brk;
            if (addr > brk) brk = addr;
            return brk;
        },
        215: (addr, len, prot, flags, fd, off) => { // mmap
            // 简化：忽略 prot/flags/fd，从 mmapNext 递增分配匿名页
            const page = 4096;
            const size = Math.ceil(len / page) * page;
            const ret = mmapNext;
            mmapNext += size;
            return ret;
        },
        216: (addr, len) => 0,            // munmap

        // ---- 时间（简化）----
        169: (ts, tz) => {                // gettimeofday
            const u = mem();
            const now = BigInt(Date.now());
            const sec = Number(now / 1000n), usec = Number(now % 1000n) * 1000;
            const dv = new DataView(env.memory.buffer);
            dv.setBigInt64(ts, BigInt(sec), true);
            dv.setInt32(ts + 8, usec, true);
            return 0;
        },

    };

    return {
        table,
        dispatch(nr, args) {
            const fn = table[Number(nr)];
            if (!fn) {
                if (env.verbose) console.error(`[syscall] 未实现 nr=${nr}`);
                return ERR.ENOSYS;
            }
            return fn(...args) || 0;
        },
        get brk() { return brk; },
        get mmapNext() { return mmapNext; },
    };
}

module.exports = { createSyscalls, ERR };
