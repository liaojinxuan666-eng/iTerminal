/*
 * run.js — Node 宿主：加载 AArch64 ELF，翻译为 WASM，提供 syscall import，执行。
 *
 * 在 iOS 上，这个文件里的 syscall 实现会换成 WKWebView 里的 JS，
 * 再通过 WKScriptMessageHandler 桥到 Swift。核心翻译器完全不变。
 */

'use strict';
const fs = require('fs');
const { translateELF } = require('./src/translator');
const { createSyscalls } = require('./src/syscalls');
const { createNodeFS } = require('./src/hostfs-node');

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

    const sc = createSyscalls({
        memory,
        input: opts.input || null,
        verbose: opts.verbose,
        fs: createNodeFS(opts.rootfs || null, opts.cwd || '/'),
        onWrite: (fd, bytes) => output.push(Buffer.from(bytes)),  // 拷贝视图，避免被后续访存覆盖
        onExit: code => { exitCode = code; },
    });

    const imports = {
        env: {
            memory,
            syscall: (nr, a0, a1, a2, a3, a4, a5) => {
                // exit/exit_group 必须保留 BigInt 原始值（低 8 位不能被 2^53 转换污染）
                if (nr === 93n || nr === 94n) return BigInt(sc.dispatch(nr, [a0]));
                // 其余 syscall：WASM i64 参数转 Number（地址/长度均远小于 2^53）
                const nums = [a0, a1, a2, a3, a4, a5].map(x => Number(x));
                return BigInt(sc.dispatch(nr, nums));
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
    if (!elfPath) { console.error('用法: node run.js <aarch64-elf> [--trace] [--verbose] [--rootfs DIR] [--dump out.wasm]'); process.exit(1); }
    const opts = {
        trace: args.includes('--trace'),
        verbose: args.includes('--verbose'),
        maxSteps: 20_000_000,
    };
    const di = args.indexOf('--dump');
    if (di >= 0) opts.dumpWasm = args[di + 1];
    const ri = args.indexOf('--rootfs');
    if (ri >= 0) opts.rootfs = args[ri + 1];

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
