/*
 * regression.js — 引擎指令级回归测试
 *
 * 每个用例是一个未修改的 aarch64 Linux ELF（手写汇编或真实 gcc 产物），
 * 通过 translator 翻译成 WASM 后在 Node JIT 宿主执行，断言退出码/输出。
 *
 * 用法: node tests/regression.js
 */
'use strict';
const path = require('path');
const fs = require('fs');
const { run } = require('../run.js');

const HERE = __dirname;
let pass = 0, fail = 0;
function check(name, got, want) {
    if (got === want) { pass++; console.log(`  OK   ${name.padEnd(24)} = ${got}`); }
    else { fail++; console.log(`  FAIL ${name.padEnd(24)} got=${got} want=${want}`); }
}

/* ---- 1. 基线端到端（真实 gcc C + 手写汇编）---- */
console.log('\n[1] 端到端基线');
const baselines = [
    ['minimal', 55, 'Hello from pure AArch64 Linux binary!\n'],
    ['verify', 12, 'test: mul/div/call/uname/write...\nPASS: all AArch64 ops verified!\n\u0000\u0000'],
    ['real_c', 71, 'K'],
];
for (const [name, code, out] of baselines) {
    const r = run(path.join(HERE, name));
    check(name + '.exit', r.exitCode, code);
    check(name + '.out', r.text, out);
}
{
    const r = run(path.join(HERE, 'echo'), { input: Buffer.from('HelloTerm!') });
    check('echo.exit', r.exitCode, 10);
    check('echo.out', r.text, 'HelloTerm!');
}

/* ---- 2. 指令级测试（exit code 携带运算结果低 8 位）---- */
console.log('\n[2] 指令级');
const asmDir = path.join(HERE, 'asm');
function runExitBatch(prefix) {
    const expFile = path.join(asmDir, prefix + '_expected.txt');
    const exp = {};
    for (const line of fs.readFileSync(expFile, 'utf8').trim().split('\n')) {
        const [k, v] = line.split(' ');
        if (!isNaN(Number(v))) exp[k] = Number(v);
    }
    for (const [n, want] of Object.entries(exp)) {
        const elf = path.join(asmDir, 'elf_' + prefix + '_' + n);
        const r = run(elf);
        check(prefix + ':' + n, r.exitCode, want);
    }
}
runExitBatch('asm');   // MOVZ/MOVK/EOR/ANDI/UBFX/LSL-imm/BIC
runExitBatch('asm2');  // UBFIZ/变量移位/SBFX/MVN/EON
check('asm:regldr', run(path.join(asmDir, 'elf_asm_regldr')).exitCode, 0x33);

console.log(`\n结果: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
