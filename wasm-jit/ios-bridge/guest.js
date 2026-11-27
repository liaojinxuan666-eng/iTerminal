/*
 * guest.js — 运行在 WKWebView 里的宿主。
 *
 * 职责：
 *   1. 实例化预翻译的 WASM 模块（JIT 由 WebKit JavaScriptCore 完成）；
 *   2. 提供 syscall import —— 直接复用 src/syscalls.js（同一份逻辑），
 *      文件系统能力由 Swift 通过 `options.fs` 适配器注入；
 *   3. 驱动基本块调度（bb0..bbN），直到 guest 退出。
 *
 * 关键点：宿主 App 不需要 JIT entitlement。JIT 发生在 WebContent 进程，
 * 该进程由系统签名并持有 WKWebView 的 JIT 能力（iOS 14.5+ BBQ/OMG tier）。
 * guest.js 自身不生成任何机器码，只实例化已有的 WASM 字节码。
 *
 * 依赖：src/syscalls.js 需先以 <script> 加载，暴露 globalThis.WasmSyscalls；
 *       在 Node 测试中可通过 options.Syscalls 注入。
 */

'use strict';

(function (global) {
    class GuestProcess {
        constructor(wasmBytes, options = {}) {
            this.wasmBytes = wasmBytes;
            this.entryBlock = options.entryBlock || 0;
            this.memPages = options.memPages || 16;
            this.memory = new WebAssembly.Memory({ initial: this.memPages });
            this.exports = null;
            this.exitCode = null;
            this.output = [];
            this.onSyscall = options.onSyscall || null; // -> (name, payload) => result
            this.input = options.input || null;          // read syscall 的输入数据
            this.inputPos = 0;
            this.fs = options.fs || null;                // 文件系统适配器（Swift 注入）
            this.Syscalls = options.Syscalls || global.WasmSyscalls;
            this.steps = 0;
            this.maxSteps = options.maxSteps || 50_000_000;
            this.sc = null;
        }

        async init() {
            if (!this.Syscalls || !this.Syscalls.createSyscalls) {
                throw new Error('缺少 WasmSyscalls（需先加载 src/syscalls.js）');
            }
            const encoder = new TextEncoder();
            this.sc = this.Syscalls.createSyscalls({
                memory: this.memory,
                input: this.input,
                fs: this.fs,
                onWrite: (fd, bytes) => {
                    const copy = new Uint8Array(bytes); // 拷贝视图
                    const text = new TextDecoder('utf-8').decode(copy);
                    this.output.push({ fd, text, bytes: Array.from(copy) });
                    if (this.onSyscall) this.onSyscall('write', { fd, text });
                },
                onExit: code => {
                    this.exitCode = code;
                    if (this.onSyscall) this.onSyscall('exit', { code });
                },
                // 供 Swift 观察其它 syscall（透传）
                onSyscall: this.onSyscall,
            });

            const imports = {
                env: {
                    memory: this.memory,
                    syscall: (nr, a0, a1, a2, a3, a4, a5) => {
                        // exit/exit_group 必须保留 BigInt 原始值（低 8 位不能被 2^53 转换污染）
                        if (nr === 93n || nr === 94n) {
                            return BigInt(this.sc.dispatch(nr, [a0]));
                        }
                        const nums = [a0, a1, a2, a3, a4, a5].map(x => Number(x));
                        // 让 Swift 有机会观察文件系统类调用
                        const name = GuestProcess.SYSCALLS[Number(nr)];
                        if (name && this.onSyscall && GuestProcess.FS_SYSCALLS.has(Number(nr))) {
                            this.onSyscall(name, { a0: nums[0], a1: nums[1], a2: nums[2] });
                        }
                        return BigInt(this.sc.dispatch(nr, nums));
                    },
                },
            };
            const mod = await WebAssembly.compile(this.wasmBytes);
            const inst = await WebAssembly.instantiate(mod, imports);
            this.exports = inst.exports;
            return this;
        }

        /** 执行直到 guest 退出。返回 { exitCode, output, steps } */
        run() {
            if (!this.exports) throw new Error('GuestProcess 未初始化');
            let bb = this.entryBlock;
            while (bb >= 0 && this.steps < this.maxSteps) {
                bb = this.exports['bb' + bb]();
                this.steps++;
            }
            return {
                exitCode: this.exitCode,
                output: this.output,
                steps: this.steps,
                hitStepLimit: this.steps >= this.maxSteps,
            };
        }
    }

    GuestProcess.SYSCALLS = {
        25: 'fcntl', 29: 'ioctl',
        56: 'openat', 57: 'close', 62: 'lseek',
        63: 'read', 64: 'write', 65: 'readv', 66: 'writev',
        79: 'newfstatat', 80: 'fstat', 96: 'getcwd',
        93: 'exit', 94: 'exit_group',
        169: 'gettimeofday',
        172: 'getpid', 176: 'getuid', 177: 'geteuid', 178: 'gettid',
        189: 'uname', 214: 'brk', 215: 'mmap', 216: 'munmap', 217: 'getdents64',
    };
    GuestProcess.FS_SYSCALLS = new Set([56, 57, 62, 79, 80, 96, 217]);

    global.GuestProcess = GuestProcess;
})(typeof window !== 'undefined' ? window : globalThis);
