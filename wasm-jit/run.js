/*
 * run.js — Node 宿主：加载 AArch64 ELF，翻译为 WASM，提供 syscall import，执行。
 *
 * 在 iOS 上，这个文件里的 syscall 实现会换成 WKWebView 里的 JS，
 * 再通过 WKScriptMessageHandler 桥到 Swift。核心翻译器完全不变。
 */

'use strict';
const fs = require('fs');
const { translateELF } = require('./src/translator');

function run(elfPath, opts = {}) {
    const t = translateELF(elfPath, { memPages: opts.memPages || 16 });

    if (!t.validate()) {
        // 用 WebAssembly.Module 触发详细编译错误
        try { new WebAssembly.Module(t.binary); } catch (e) { throw new Error('WASM 模块非法: ' + e.message); }
    }
    if (opts.dumpWasm) fs.writeFileSync(opts.dumpWasm, t.binary);

    const memory = new WebAssembly.Memory({ initial: opts.memPages || 16 });
    const output = [];
    let exitCode = null;

    const syscalls = {
        // write(fd, buf, len)
        64: (fd, buf, len) => {
            if (fd !== 1 && fd !== 2) return -1;
            const bytes = Buffer.from(memory.buffer, buf, len);
            output.push(bytes);
            return len;
        },
        // exit(code)
        93: code => { exitCode = Number(code) & 0xff; return 0; },
        // exit_group(code)
        94: code => { exitCode = Number(code) & 0xff; return 0; },
        // getpid
        172: () => 4242,
        // gettid
        178: () => 4242,
        // uname(addr) — 填充简化 utsname
        189: addr => {
            const u = new Uint8Array(memory.buffer);
            const put = (off, s) => { for (let i = 0; i < s.length; i++) u[addr + off + i] = s.charCodeAt(i); };
            put(0, 'Linux'); put(65, 'wasm-jit'); put(130, '6.1.0'); put(195, '#1'); put(260, 'aarch64');
            return 0;
        },
        // brk(addr) — 简化：固定返回当前断点
        214: addr => { return 0x400000 + 0x200000; },
    };

    const imports = {
        env: {
            memory,
            syscall: (nr, a0, a1, a2, a3, a4, a5) => {
                const fn = syscalls[Number(nr)];
                if (!fn) {
                    if (opts.verbose) console.error(`[syscall] 未实现 nr=${nr}`);
                    return -1; // ENOSYS
                }
                // WASM i64 参数是 BigInt，宿主 JS 侧统一转成 Number
                const nums = [a0, a1, a2, a3, a4, a5].map(x => Number(x));
                return BigInt(fn(...nums) || 0);
            },
        },
    };

    const inst = new WebAssembly.Instance(new WebAssembly.Module(t.binary), imports);
    const exports = inst.exports;
    let bb = t.entryBlock;
    let steps = 0;
    const maxSteps = opts.maxSteps || 5_000_000;
    const visited = new Set();

    while (bb >= 0 && steps < maxSteps) {
        if (opts.trace) visited.add(bb);
        bb = exports['bb' + bb]();
        steps++;
    }

    const text = Buffer.concat(output).toString('utf8');
    return { text, exitCode, steps, blockCount: t.blockCount, entryBlock: t.entryBlock,
             wasmBytes: t.binary.length, visited: [...visited].sort((a, b) => a - b) };
}

/* ============ CLI ============ */
if (require.main === module) {
    const args = process.argv.slice(2);
    const elfPath = args[0];
    if (!elfPath) { console.error('用法: node run.js <aarch64-elf> [--trace] [--verbose] [--dump out.wasm]'); process.exit(1); }
    const opts = {
        trace: args.includes('--trace'),
        verbose: args.includes('--verbose'),
        maxSteps: 20_000_000,
    };
    const di = args.indexOf('--dump');
    if (di >= 0) opts.dumpWasm = args[di + 1];

    try {
        const r = run(elfPath, opts);
        process.stdout.write(r.text);
        console.error(`\n[wasm-jit] 块数=${r.blockCount} 入口块=${r.entryBlock} 步数=${r.steps} WASM=${r.wasmBytes}B`);
        console.error(`[wasm-jit] guest 退出码=${r.exitCode}`);
        if (opts.trace) console.error(`[wasm-jit] 访问过的块=${JSON.stringify(r.visited)}`);
        process.exit(r.exitCode ?? 0);
    } catch (e) {
        console.error('运行失败:', e.stack || e);
        process.exit(1);
    }
}

module.exports = { run };
