/*
 * guest.js — 运行在 WKWebView 里的宿主。
 *
 * 职责：
 *   1. 实例化预翻译的 WASM 模块（JIT 由 WebKit JavaScriptCore 完成）；
 *   2. 提供 syscall import，把 POSIX 调用通过 WKScriptMessageHandler 桥到 Swift；
 *   3. 驱动基本块调度（bb0..bbN），直到 guest 退出。
 *
 * 关键点：宿主 App 不需要 JIT entitlement。JIT 发生在 WebContent 进程，
 * 该进程由系统签名并持有 WKWebView 的 JIT 能力（iOS 14.5+ BBQ/OMG tier）。
 * guest.js 自身不生成任何机器码，只实例化已有的 WASM 字节码。
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
            this.steps = 0;
            this.maxSteps = options.maxSteps || 50_000_000;
        }

        async init() {
            const imports = {
                env: {
                    memory: this.memory,
                    syscall: (nr, a0, a1, a2, a3, a4, a5) => this._syscall(
                        Number(nr), Number(a0), Number(a1), Number(a2),
                        Number(a3), Number(a4), Number(a5)),
                },
            };
            const mod = await WebAssembly.compile(this.wasmBytes);
            const inst = await WebAssembly.instantiate(mod, imports);
            this.exports = inst.exports;
            return this;
        }

        /** i64 返回值用 BigInt；Swift 桥用 number，这里统一收窄到 32 位有符号 */
        _syscall(nr, a0, a1, a2, a3, a4, a5) {
            const name = GuestProcess.SYSCALLS[nr] || ('syscall_' + nr);
            let result = 0;

            switch (nr) {
                case 64: { // write
                    const bytes = new Uint8Array(this.memory.buffer, a1, a2);
                    const text = new TextDecoder('utf-8').decode(bytes);
                    this.output.push({ fd: a0, text, bytes: Array.from(bytes) });
                    if (this.onSyscall) this.onSyscall('write', { fd: a0, text });
                    result = a2;
                    break;
                }
                case 63: { // read
                    if (a0 !== 0) { result = -9; break; } // EBADF
                    if (!this.input) { result = 0; break; } // EOF
                    const u = new Uint8Array(this.memory.buffer);
                    const n = Math.min(a2, this.input.length - this.inputPos);
                    for (let i = 0; i < n; i++) u[a1 + i] = this.input[this.inputPos + i];
                    this.inputPos += n;
                    result = n;
                    break;
                }
                case 93: // exit
                case 94: { // exit_group
                    this.exitCode = a0 & 0xff;
                    if (this.onSyscall) this.onSyscall('exit', { code: this.exitCode });
                    result = 0;
                    break;
                }
                default:
                    if (this.onSyscall) result = this.onSyscall(name, { a0, a1, a2, a3, a4, a5 }) || 0;
                    break;
            }
            return BigInt(result | 0);
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
        63: 'read', 64: 'write',
        93: 'exit', 94: 'exit_group',
        169: 'gettimeofday',
        172: 'getpid', 176: 'getuid', 177: 'geteuid', 178: 'gettid',
        189: 'uname', 214: 'brk', 215: 'mmap', 216: 'munmap',
        80: 'fstat', 96: 'getcwd',
    };

    global.GuestProcess = GuestProcess;
})(typeof window !== 'undefined' ? window : globalThis);
