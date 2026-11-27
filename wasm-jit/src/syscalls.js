/*
 * syscalls.js — 可复用的 Linux syscall 实现层
 *
 * 设计要点：
 * - 与宿主解耦：所有 syscall 通过一个 `env` 对象访问宿主能力
 *   （内存、输入缓冲、输出回调、文件系统）。Node 宿主和 iOS WKWebView
 *   宿主提供不同的 env，但 syscall 逻辑完全一致。
 * - 覆盖终端最小集：write/read/openat/close/lseek/fstat/getdents64 +
 *   进程/内存/uname 等。
 *
 * AArch64 Linux syscall 号（arch/arm64/include/uapi/asm/unistd.h）
 */

'use strict';

const ERR = {
    ENOSYS: -38,
    EBADF: -9,
    EINVAL: -22,
    ENOMEM: -12,
    ENOENT: -2,
    EACCES: -13,
    EISDIR: -21,
    ENOTDIR: -20,
    ERANGE: -34,
    ENOTTY: -25,
};

const AT_FDCWD = -100;

// 无 Node 依赖：TextDecoder/TextEncoder 在 Node 与浏览器 WKWebView 都存在
const _decoder = new TextDecoder('utf-8');
const _encoder = new TextEncoder();

/**
 * 创建 syscall 表。
 * @param {object} env 宿主环境：
 *   - memory: WebAssembly.Memory
 *   - input: Uint8Array/Buffer 输入缓冲（read 用）
 *   - onWrite(fd, bytes): 输出回调
 *   - fs: 文件系统适配器（见 hostfs-node.js / ios 内存 fs）
 *   - verbose: 是否打印未实现 syscall
 */
function createSyscalls(env) {
    const mem = () => new Uint8Array(env.memory.buffer);
    const dv = () => new DataView(env.memory.buffer);
    const output = env.onWrite || (() => {});
    const fs = env.fs || null;
    let brk = env.brkStart || (0x400000 + 0x200000);
    let mmapNext = env.mmapStart || (0x500000);

    // guest fd 表：0/1/2 由本层直接处理，文件 fd 从 3 分配
    let nextFd = 3;
    const handles = new Map();
    const handleOf = fd => handles.get(fd);

    /** 从 WASM 线性内存读 NUL 结尾的 C 字符串（UTF-8） */
    function cstr(ptr) {
        if (!ptr) return '';
        const u = mem();
        let end = ptr;
        while (end < u.length && u[end] !== 0) end++;
        return _decoder.decode(u.subarray(ptr, end));
    }

    /** 把 statObj 按 AArch64 内核 ABI 写入 guest 内存（128 字节） */
    function writeStat(addr, s) {
        const d = dv();
        d.setBigUint64(addr + 0, BigInt(s.dev), true);
        d.setBigUint64(addr + 8, BigInt(s.ino), true);
        d.setUint32(addr + 16, s.mode >>> 0, true);
        d.setUint32(addr + 20, s.nlink >>> 0, true);
        d.setUint32(addr + 24, s.uid >>> 0, true);
        d.setUint32(addr + 28, s.gid >>> 0, true);
        d.setBigUint64(addr + 32, BigInt(s.rdev), true);
        // +40 __pad1
        d.setBigInt64(addr + 48, BigInt(s.size), true);
        d.setInt32(addr + 56, s.blksize | 0, true);
        // +60 __pad2
        d.setBigInt64(addr + 64, BigInt(s.blocks), true);
        d.setBigInt64(addr + 72, BigInt(s.atime), true);
        d.setBigUint64(addr + 80, BigInt(s.atimeNs), true);
        d.setBigInt64(addr + 88, BigInt(s.mtime), true);
        d.setBigUint64(addr + 96, BigInt(s.mtimeNs), true);
        d.setBigInt64(addr + 104, BigInt(s.ctime), true);
        d.setBigUint64(addr + 112, BigInt(s.ctimeNs), true);
        // +120/124 __unused4/5
        return 0;
    }

    const table = {
        // ---- 输出 ----
        64: (fd, buf, len) => {          // write
            const h = handleOf(fd);
            if (h) {
                const r = fs.write(h, mem().subarray(buf, buf + len));
                return typeof r === 'number' ? r : 0;
            }
            if (fd !== 1 && fd !== 2) return ERR.EBADF;
            const bytes = mem().subarray(buf, buf + len);   // Uint8Array 视图
            output(fd, bytes);
            return len;
        },

        66: (fd, iov, iovcnt) => {       // writev
            const d = dv();
            let total = 0;
            for (let i = 0; i < iovcnt; i++) {
                const base = Number(d.getBigUint64(iov + i * 16, true));
                const len = Number(d.getBigUint64(iov + i * 16 + 8, true));
                total += table[64](fd, base, len);
            }
            return total;
        },

        // ---- 输入（终端核心）----
        63: (fd, buf, len) => {          // read
            const h = handleOf(fd);
            if (h) {
                const r = fs.read(h, len);
                if (typeof r === 'number') return r;   // 负数 errno
                mem().set(r.subarray(0, len), buf);
                return r.length;
            }
            if (fd !== 0) return ERR.EBADF;
            const input = env.input;
            if (!input) return 0;        // EOF
            const pos = env.inputPos || 0;
            const n = Math.min(len, input.length - pos);
            for (let i = 0; i < n; i++) mem()[buf + i] = input[pos + i];
            env.inputPos = pos + n;
            return n;
        },

        65: (fd, iov, iovcnt) => {       // readv
            const d = dv();
            let total = 0;
            for (let i = 0; i < iovcnt; i++) {
                const base = Number(d.getBigUint64(iov + i * 16, true));
                const len = Number(d.getBigUint64(iov + i * 16 + 8, true));
                total += table[63](fd, base, len);
            }
            return total;
        },

        // ---- 文件操作 ----
        56: (dirfd, pathPtr, flags, mode) => { // openat
            if (!fs) return ERR.ENOSYS;
            const dirHandle = dirfd === AT_FDCWD ? null : handleOf(dirfd);
            const h = fs.openat(dirHandle, cstr(pathPtr), flags, mode);
            if (typeof h === 'number') return h; // 负数 errno
            const fd = nextFd++;
            handles.set(fd, h);
            return fd;
        },

        57: fd => {                     // close
            const h = handleOf(fd);
            if (!h) return ERR.EBADF;
            handles.delete(fd);
            return fs.close(h);
        },

        62: (fd, offset, whence) => {    // lseek
            const h = handleOf(fd);
            if (!h) return ERR.EBADF;
            return fs.lseek(h, offset, whence);
        },

        79: (dirfd, pathPtr, statPtr, flags) => { // newfstatat
            if (!fs) return ERR.ENOSYS;
            const dirHandle = dirfd === AT_FDCWD ? null : handleOf(dirfd);
            const h = fs.openat(dirHandle, cstr(pathPtr), 0, 0);
            if (typeof h === 'number') return h;
            const s = fs.fstat(h);
            fs.close(h);
            if (typeof s === 'number') return s;
            return writeStat(statPtr, s);
        },

        80: (fd, statPtr) => {           // fstat
            const h = handleOf(fd);
            if (!h) return ERR.EBADF;
            const s = fs.fstat(h);
            if (typeof s === 'number') return s;
            return writeStat(statPtr, s);
        },

        96: (buf, size) => {             // getcwd
            if (!fs) return ERR.ENOSYS;
            const s = fs.getcwd() + '\0';
            if (s.length > size) return ERR.ERANGE;
            mem().set(_encoder.encode(s), buf);
            return buf;
        },

        217: (fd, buf, size) => {        // getdents64
            const h = handleOf(fd);
            if (!h) return ERR.EBADF;
            const ents = fs.getdents(h);
            if (typeof ents === 'number') return ents;
            const u = mem(), d = dv();
            let off = 0;
            for (const e of ents) {
                const name = _encoder.encode(e.name);
                const reclen = Math.ceil((19 + name.length + 1) / 8) * 8;
                if (off + reclen > size) break;
                d.setBigUint64(buf + off, BigInt(e.ino), true);
                d.setBigInt64(buf + off + 8, BigInt(e.off), true);
                d.setUint16(buf + off + 16, reclen, true);
                d.setUint8(buf + off + 18, e.type);
                u.set(name, buf + off + 19);
                u[buf + off + 19 + name.length] = 0;
                off += reclen;
            }
            return off;
        },

        25: (fd, cmd) => {               // fcntl（简化：只支持查询标志）
            const h = handleOf(fd);
            if (!h && fd > 2) return ERR.EBADF;
            if (cmd === 0 || cmd === 1 || cmd === 3 || cmd === 4) return 0;
            return ERR.EINVAL;
        },

        29: () => ERR.ENOTTY,            // ioctl（非 tty，简化）

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
            dv().setBigInt64(ts, BigInt(sec), true);
            dv().setInt32(ts + 8, usec, true);
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

/* UMD：Node 用 module.exports，浏览器/WKWebView 挂到全局供 guest.js 复用同一份逻辑 */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { createSyscalls, ERR };
} else if (typeof globalThis !== 'undefined') {
    globalThis.WasmSyscalls = { createSyscalls, ERR };
}
